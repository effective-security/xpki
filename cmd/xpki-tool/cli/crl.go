package cli

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"path"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/x/print"
	"github.com/pkg/errors"
)

// CRLCmd provides commands for CRL
type CRLCmd struct {
	Info  CRLInfoCmd  `cmd:"" help:"print CRL info"`
	Fetch CRLFetchCmd `cmd:"" help:"fetch CRL"`
}

// CRLInfoCmd prints crl info
type CRLInfoCmd struct {
	In string `kong:"arg" required:"" help:"DER-encoded CRL"`
}

// Run the command
func (a *CRLInfoCmd) Run(ctx *Cli) error {
	// Load CRL
	der, err := ctx.ReadFile(a.In)
	if err != nil {
		return errors.WithMessage(err, "unable to load CRL file")
	}

	crl, err := x509.ParseCRL(der)
	if err != nil {
		return errors.WithMessage(err, "unable to prase CRL")
	}

	print.CertificateList(ctx.Writer(), crl)

	return nil
}

// CRLFetchCmd specifies flags for CRLFetch action
type CRLFetchCmd struct {
	Cert   string `kong:"arg" required:"" help:"certificate file name"`
	Output string `required:"" help:"output folder name"`
	All    bool   `help:"fetch entire chain"`
	Proxy  string `help:"optional, proxy address or DC name"`
	Print  bool
}

// Run the command
func (a *CRLFetchCmd) Run(ctx *Cli) error {
	w := ctx.Writer()

	// Load PEM
	pem, err := ctx.ReadFile(a.Cert)
	if err != nil {
		return errors.WithMessage(err, "unable to load PEM file")
	}

	list, err := certutil.ParseChainFromPEM(pem)
	if err != nil {
		return errors.WithMessage(err, "unable to parse PEM")
	}

	if !a.All {
		// take only leaf cert
		list = list[:1]
	}

	client, err := httpClient(a.Proxy)
	if err != nil {
		return errors.WithStack(err)
	}
	for _, crt := range list {
		if len(crt.CRLDistributionPoints) < 1 {
			logger.Infof("CRL DP is not present: CN=%q\n", crt.Subject.String())
			continue
		}

		crldp := crt.CRLDistributionPoints[0]
		logger.Infof("fetching CRL from %q\n", crldp)

		body, err := download(client, crldp)
		if err != nil {
			return errors.WithStack(err)
		}

		crl, err := x509.ParseCRL(body)
		if err != nil {
			return errors.WithMessage(err, "unable to prase CRL")
		}
		if a.Print {
			fmt.Fprintf(w, "=================================================\n")
			print.CertificateList(w, crl)
		}

		if a.Output != "" {
			filename := path.Join(a.Output, fmt.Sprintf("%s.crl", certutil.GetIssuerID(crt)))
			err = ioutil.WriteFile(filename, body, 0644)
			if err != nil {
				return errors.WithMessagef(err, "unable to write CRL: %s", filename)
			}
		}
	}
	return nil
}
