package cli

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/effective-security/xpki/x/print"
	"github.com/pkg/errors"
)

// CsrInfoCmd specifies flags for Info command
type CsrInfoCmd struct {
	Csr string `kong:"arg" required:"" help:"CSR file name"`
}

// Run the command
func (a *CsrInfoCmd) Run(ctx *Cli) error {
	// Load CSR
	csrb, err := ctx.ReadFile(a.Csr)
	if err != nil {
		return errors.WithMessage(err, "unable to load CSR file")
	}

	block, _ := pem.Decode(csrb)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return errors.New("invalid CSR file")
	}

	csrv, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return errors.WithMessage(err, "unable to prase CSR")
	}

	print.CertificateRequest(ctx.Writer(), csrv)

	return nil
}
