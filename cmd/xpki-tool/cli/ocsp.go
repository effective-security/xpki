package cli

import (
	"fmt"
	"os"
	"path"
	"time"

	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/x/print"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ocsp"
)

// OCSPCmd is the parent for crl command
type OCSPCmd struct {
	Info  OCSPInfoCmd  `cmd:"" help:"prints OCSP info"`
	Fetch OCSPFetchCmd `cmd:"" help:"fetch OCSP from certificate"`
}

// OCSPInfoCmd specifies flags for OCSP info command
type OCSPInfoCmd struct {
	In     string `kong:"arg" required:"" help:"OCSP file name"`
	Issuer string
}

// Run the command
func (a *OCSPInfoCmd) Run(ctx *Cli) error {
	// Load DER
	der, err := ctx.ReadFile(a.In)
	if err != nil {
		return errors.WithMessage(err, "unable to load OCSP file")
	}

	res, err := ocsp.ParseResponse(der, nil)
	if err != nil {
		return errors.WithMessage(err, "unable to prase OCSP")
	}

	print.OCSPResponse(ctx.Writer(), res, true)

	return nil
}

// OCSPFetchCmd specifies flags to fetch OCSP
type OCSPFetchCmd struct {
	Cert  string `kong:"arg" required:"" help:"certificate file name"`
	CA    string `help:"optional, CA bundle file"`
	Out   string `help:"output folder name"`
	Proxy string `help:"optional, proxy address or DC name"`
	Print bool
}

// Run the command
func (a *OCSPFetchCmd) Run(ctx *Cli) error {
	w := ctx.Writer()

	// Load PEM
	certBytes, err := ctx.ReadFile(a.Cert)
	if err != nil {
		return errors.WithMessage(err, "unable to load PEM file")
	}

	list, err := certutil.ParseChainFromPEM(certBytes)
	if err != nil {
		return errors.WithMessage(err, "unable to parse PEM")
	}
	if len(list) == 0 {
		return errors.Errorf("certificate not found in PEM")
	}
	crt := list[0]

	if len(crt.OCSPServer) < 1 {
		logger.KV(xlog.DEBUG, "reason", "certificate does not have OCSP URL", "cn", crt.Subject.String())
		return nil
	}

	issuer := certutil.FindIssuer(crt, list, nil)
	if issuer == nil && a.CA != "" {
		cas, err := os.ReadFile(a.CA)
		if err != nil {
			return errors.WithMessage(err, "unable to load CA bundle")
		}
		list, err := certutil.ParseChainFromPEM(cas)
		if err != nil {
			return errors.WithMessage(err, "unable to parse issuers PEM")
		}
		issuer = certutil.FindIssuer(crt, list, nil)
	}

	if issuer == nil {
		return errors.Errorf("unable to find issuer")
	}

	timeout := time.Second * time.Duration(ctx.Timeout)
	client, err := httpClient(a.Proxy, timeout)
	if err != nil {
		return err
	}

	for _, url := range crt.OCSPServer {
		logger.KV(xlog.DEBUG, "status", "fetching OCSP", "url", url)
		status, der, err := OCSPValidation(client, crt, issuer, url)

		if err != nil {
			fmt.Fprintf(w, "%s : ERROR: %s\n", url, err.Error())
		} else {
			fmt.Fprintf(w, "%s: %v\n", url, statusMap[status])

			if a.Out != "" {
				filename := path.Join(a.Out, fmt.Sprintf("%s.ocsp", certutil.GetIssuerID(crt)))
				err = os.WriteFile(filename, der, 0644)
				if err != nil {
					return errors.Wrapf(err, "unable to write OCSP: %s", filename)
				}
			}
			if a.Print {
				res, err := ocsp.ParseResponse(der, nil)
				if err != nil {
					return errors.Wrapf(err, "unable to prase OCSP")
				}

				print.OCSPResponse(w, res, true)
			}
		}
	}

	return nil
}
