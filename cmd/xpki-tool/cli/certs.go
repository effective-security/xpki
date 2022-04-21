package cli

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/x/print"
	"github.com/pkg/errors"
)

// CertsCmd provides certificates commands
type CertsCmd struct {
	Info     CertInfoCmd     `cmd:"" help:"print certificate info"`
	Validate CertValidateCmd `cmd:"" help:"validates certificate"`
}

// CertInfoCmd specifies flags for CertInfo action
type CertInfoCmd struct {
	In        string `kong:"arg" required:"" help:"certificate file name"`
	Out       string `help:"optional, output file to save parsed certificates"`
	NotAfter  string `help:"optional, filter certificates by NotAfter time"`
	NoExpired *bool  `help:"optional, filter non-expired certificates"`
}

// Run the command
func (a *CertInfoCmd) Run(ctx *Cli) error {
	// Load PEM
	pem, err := ctx.ReadFile(a.In)
	if err != nil {
		return errors.WithMessage(err, "unable to load PEM file")
	}

	list, err := certutil.ParseChainFromPEM(pem)
	if err != nil {
		return errors.WithMessage(err, "unable to parse PEM")
	}

	now := time.Now().UTC()
	if a.NoExpired != nil && *a.NoExpired == true {
		list = filterByNotAfter(list, now)
	}

	if a.NotAfter != "" {
		d, err := time.ParseDuration(a.NotAfter)
		if err != nil {
			return errors.WithMessage(err, "unable to parse --not-after")
		}
		list = filterByAfter(list, now.Add(d))
	}

	print.Certificates(ctx.Writer(), list)

	if a.Out != "" {
		f, err := os.OpenFile(a.Out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0664)
		if err != nil {
			return errors.WithMessage(err, "unable to create file")
		}
		defer f.Close()

		certutil.EncodeToPEM(f, true, list...)
	}

	return nil
}

func filterByNotAfter(list []*x509.Certificate, notAfter time.Time) []*x509.Certificate {
	filtered := make([]*x509.Certificate, 0, len(list))
	for _, c := range list {
		if c.NotAfter.After(notAfter) {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

func filterByAfter(list []*x509.Certificate, notAfter time.Time) []*x509.Certificate {
	filtered := make([]*x509.Certificate, 0, len(list))
	for _, c := range list {
		if !c.NotAfter.After(notAfter) {
			filtered = append(filtered, c)
		}
	}
	return filtered
}

// CertValidateCmd specifies flags for Validate action
type CertValidateCmd struct {
	Cert string `kong:"arg" required:"" help:"certificate file name"`
	CA   string `help:"optional, CA bundle file"`
	Root string `help:"optional, Trusted Roots file"`
	Out  string `help:"optional, output file to save certificate chain"`
}

// Run the command
func (a *CertValidateCmd) Run(ctx *Cli) error {
	var err error
	var certBytes, cas []byte

	// set roots to empty
	roots := []byte("# empty Root bundle\n")

	certBytes, err = ctx.ReadFile(a.Cert)
	if err != nil {
		return errors.WithMessage(err, "unable to load cert")
	}

	if a.CA != "" {
		cas, err = ioutil.ReadFile(a.CA)
		if err != nil {
			return errors.WithMessage(err, "unable to load CA bundle")
		}
	}
	if a.Root != "" {
		roots, err = ioutil.ReadFile(a.Root)
		if err != nil {
			return errors.WithMessage(err, "unable to load Root bundle")
		}
	}

	w := ctx.Writer()
	bundle, bundleStatus, err := certutil.VerifyBundleFromPEM(certBytes, cas, roots)
	if err != nil {
		if crt, err2 := certutil.ParseFromPEM(certBytes); err2 == nil {
			print.Certificate(w, crt)
		}
		return errors.WithMessage(err, "unable to verify certificate")
	}

	if bundleStatus.IsUntrusted() {
		fmt.Fprintf(w, "ERROR: The cert is untrusted\n")
	}

	chain := bundle.Chain
	if bundle.RootCert != nil {
		chain = append(chain, bundle.RootCert)
	}

	print.Certificates(w, chain)

	if len(bundleStatus.ExpiringSKIs) > 0 {
		fmt.Fprintf(w, "WARNING: Expiring SKI:\n")
		for _, ski := range bundleStatus.ExpiringSKIs {
			fmt.Fprintf(w, "  -- %s\n", ski)
		}
	}
	if len(bundleStatus.Untrusted) > 0 {
		fmt.Fprintf(w, "WARNING: Untrusted SKI:\n")
		for _, ski := range bundleStatus.Untrusted {
			fmt.Fprintf(w, "  -- %s\n", ski)
		}
	}

	if a.Out != "" {
		pem := bundle.CertPEM + "\n" + bundle.CACertsPEM
		err = ioutil.WriteFile(a.Out, []byte(pem), 0664)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	return nil
}
