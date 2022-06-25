package main

import (
	"io"
	"os"

	"github.com/alecthomas/kong"
	"github.com/effective-security/xpki/cmd/hsm-tool/cli"
	"github.com/effective-security/xpki/internal/version"
	"github.com/effective-security/xpki/x/ctl"
	logger "github.com/sirupsen/logrus"
)

type app struct {
	cli.Cli

	Hsm cli.HsmCmd `cmd:"" help:"HSM commands"`
	Csr cli.CsrCmd `cmd:"" help:"Csr commands"`
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
		kong.Name("hsm-tool"),
		kong.Description("CLI tool for HSM or KMS"),
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
