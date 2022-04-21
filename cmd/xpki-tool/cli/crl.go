package cli

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/x/print"
	"github.com/pkg/errors"
)

// CrlCmd provides commands for CRL
type CrlCmd struct {
	Info  CrlInfoCmd  `cmd:"" help:"print CRL info"`
	Fetch CRLFetchCmd `cmd:"" help:"fetch CRL"`
}

// CrlInfoCmd specifies flags for Info command
type CrlInfoCmd struct {
	Crl string `kong:"arg" required:"" help:"CSR file name"`
}

// Run the command
func (a *CrlInfoCmd) Run(ctx *Cli) error {
	// Load CRL
	der, err := ctx.ReadFile(a.Crl)
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

	for _, crt := range list {
		if len(crt.CRLDistributionPoints) < 1 {
			logger.Infof("CRL DP is not present; CN=%q\n", crt.Subject.String())
			continue
		}

		crldp := crt.CRLDistributionPoints[0]
		logger.Infof("fetching CRL from %q\n", crldp)

		body, err := download(crldp)
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

func download(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to fetch from %s", url)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithMessagef(err, "unable to download from %s", url)
	}

	return body, nil
}
