package cli

import (
	"github.com/effective-security/xpki/x/print"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ocsp"
)

// OcspInfoCmd specifies flags for Info command
type OcspInfoCmd struct {
	Ocsp string `kong:"arg" required:"" help:"OCSP file name"`
}

// Run the command
func (a *OcspInfoCmd) Run(ctx *Cli) error {
	// Load DER
	der, err := ctx.ReadFile(a.Ocsp)
	if err != nil {
		return errors.WithMessage(err, "unable to load OCSP file")
	}

	res, err := ocsp.ParseResponse(der, nil)
	if err != nil {
		return errors.WithMessage(err, "unable to prase OCSP")
	}

	print.OCSPResponse(ctx.Writer(), res)

	return nil
}
