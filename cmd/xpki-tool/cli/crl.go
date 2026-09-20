package cli

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/x/print"
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

	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return errors.WithMessage(err, "unable to parse CRL")
	}

	print.CertificateList(ctx.Writer(), crl)

	return nil
}

// CRLFetchCmd specifies flags for CRLFetch action
type CRLFetchCmd struct {
	Cert   string `kong:"arg" required:"" help:"certificate file name"`
	Output string `help:"output folder name; required unless --print is set"`
	All    bool   `help:"fetch entire chain"`
	Proxy  string `help:"optional, proxy address or DC name"`
	Print  bool   `help:"print the fetched CRL"`
}

// Run the command
func (a *CRLFetchCmd) Run(ctx *Cli) error {
	if a.Output == "" && !a.Print {
		return errors.New("either --output or --print is required")
	}

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

	if len(list) == 0 {
		return errors.New("certificate not found in PEM")
	}
	if !a.All {
		// take only leaf cert
		list = list[:1]
	}

	client, err := httpClient(a.Proxy, time.Second*time.Duration(ctx.Timeout))
	if err != nil {
		return err
	}
	fetched := 0
	for _, crt := range list {
		if len(crt.CRLDistributionPoints) < 1 {
			logger.KV(xlog.DEBUG, "reason", "CRL DP is not present", "CN", crt.Subject.String())
			continue
		}
		fetched++

		crldp := crt.CRLDistributionPoints[0]
		logger.KV(xlog.DEBUG, "status", "fetching CRL", "url", crldp)

		body, err := download(ctx.Context(), client, crldp)
		if err != nil {
			return err
		}

		crl, err := x509.ParseRevocationList(body)
		if err != nil {
			return errors.Wrapf(err, "unable to parse CRL")
		}
		if a.Print {
			_, _ = fmt.Fprintf(w, "=================================================\n")
			print.CertificateList(w, crl)
		}

		if a.Output != "" {
			filename := filepath.Join(a.Output, fmt.Sprintf("%s.crl", certutil.GetIssuerID(crt)))
			err = os.WriteFile(filename, body, 0644)
			if err != nil {
				return errors.Wrapf(err, "unable to write CRL: %s", filename)
			}
		}
	}
	if fetched == 0 {
		return errors.New("no CRL distribution point found in the selected certificates")
	}
	return nil
}
