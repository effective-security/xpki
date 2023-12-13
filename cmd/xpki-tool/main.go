package main

import (
	"io"
	"os"

	"github.com/alecthomas/kong"
	"github.com/effective-security/x/ctl"
	"github.com/effective-security/xpki/cmd/xpki-tool/cli"
	"github.com/effective-security/xpki/internal/version"
	logger "github.com/sirupsen/logrus"
)

type app struct {
	cli.Cli

	CsrInfo cli.CsrInfoCmd `cmd:"" help:"print CSR info"`
	Crl     cli.CRLCmd     `cmd:"" help:"CRL commands"`
	Cert    cli.CertsCmd   `cmd:"" help:"Certificate commands"`
	Ocsp    cli.OCSPCmd    `cmd:"" help:"OCSP commands"`
}

func main() {
	logger.SetReportCaller(true)
	logger.SetFormatter(&logger.TextFormatter{})

	realMain(os.Args, os.Stdout, os.Stderr, os.Exit)
}

func realMain(args []string, out io.Writer, errout io.Writer, exit func(int)) {
	cl := app{
		Cli: cli.Cli{},
	}
	cl.Cli.WithErrWriter(errout).
		WithWriter(out)

	parser, err := kong.New(&cl,
		kong.Name("xpki-tool"),
		kong.Description("PKI tools"),
		//kong.UsageOnError(),
		kong.Writers(out, errout),
		kong.Exit(exit),
		ctl.BoolPtrMapper,
		kong.ConfigureHelp(kong.HelpOptions{
			Compact: true,
		}),
		kong.Vars{
			"version": version.Current().String(),
		})
	if err != nil {
		panic(err)
	}

	ctx, err := parser.Parse(args[1:])
	parser.FatalIfErrorf(err)

	if ctx != nil {
		err = ctx.Run(&cl.Cli)
		ctx.FatalIfErrorf(err)
	}
}
