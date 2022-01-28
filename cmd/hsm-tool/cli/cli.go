package cli

import (
	"io"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/x/ctl"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
)

var logger = xlog.NewPackageLogger("github.com/effective-security/xpki", "cli")

// Cli provides CLI context to run commands
type Cli struct {
	Cfg      string `help:"Location of HSM config file" required:"" type:"path"`
	Debug    bool   `short:"D" help:"Enable debug mode"`
	LogLevel string `short:"l" help:"Set the logging level (debug|info|warn|error)" default:"error"`

	// Stdin is the source to read from, typically set to os.Stdin
	stdin io.Reader
	// Output is the destination for all output from the command, typically set to os.Stdout
	output io.Writer
	// ErrOutput is the destinaton for errors.
	// If not set, errors will be written to os.StdError
	errOutput io.Writer

	ctx    context.Context
	crypto *cryptoprov.Crypto
}

// Context for requests
func (c *Cli) Context() context.Context {
	if c.ctx == nil {
		c.ctx = context.Background()
	}
	return c.ctx
}

// Reader is the source to read from, typically set to os.Stdin
func (c *Cli) Reader() io.Reader {
	if c.stdin != nil {
		return c.stdin
	}
	return os.Stdin
}

// WithReader allows to specify a custom reader
func (c *Cli) WithReader(reader io.Reader) *Cli {
	c.stdin = reader
	return c
}

// Writer returns a writer for control output
func (c *Cli) Writer() io.Writer {
	if c.output != nil {
		return c.output
	}
	return os.Stdout
}

// WithWriter allows to specify a custom writer
func (c *Cli) WithWriter(out io.Writer) *Cli {
	c.output = out
	return c
}

// ErrWriter returns a writer for control output
func (c *Cli) ErrWriter() io.Writer {
	if c.errOutput != nil {
		return c.errOutput
	}
	return os.Stderr
}

// WithErrWriter allows to specify a custom error writer
func (c *Cli) WithErrWriter(out io.Writer) *Cli {
	c.errOutput = out
	return c
}

// AfterApply hook loads config
func (c *Cli) AfterApply(app *kong.Kong, vars kong.Vars) error {
	if c.Debug {
		xlog.SetGlobalLogLevel(xlog.DEBUG)
	} else {
		val := strings.TrimLeft(c.LogLevel, "=")
		l, err := xlog.ParseLevel(strings.ToUpper(val))
		if err != nil {
			return errors.WithStack(err)
		}
		xlog.SetGlobalLogLevel(l)
	}

	return nil
}

// WriteJSON prints response to out
func (c *Cli) WriteJSON(value interface{}) error {
	return ctl.WriteJSON(c.Writer(), value)
}

// CryptoProv loads Crypto provider
func (c *Cli) CryptoProv() *cryptoprov.Crypto {
	if c.crypto != nil {
		return c.crypto
	}
	if c.Cfg == "" {
		logger.Panicf("use --cfg flag to specify PKCS11 config file")
	}
	var err error
	c.crypto, err = cryptoprov.Load(c.Cfg, nil)
	if err != nil {
		logger.Panicf("unable to initialize crypto providers: [%v]", err)
	}

	return c.crypto
}
