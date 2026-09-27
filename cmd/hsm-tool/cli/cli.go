package cli

import (
	"context"
	"io"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/x/ctl"
	"github.com/effective-security/xlog"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/x/print"

	// register supported
	_ "github.com/effective-security/xpki/crypto11"
	_ "github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	_ "github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
)

// Cli provides CLI context to run commands
type Cli struct {
	Version  ctl.VersionFlag `name:"version" help:"Print version information and quit" hidden:""`
	Cfg      string          `help:"Location of HSM config file, as default crypto provider" required:""`
	Crypto   []string        `help:"Location of additional HSM config files" type:"path"`
	PlainKey bool            `help:"Generate plain key"`
	Debug    bool            `short:"D" help:"Enable debug mode"`
	LogLevel string          `short:"l" help:"Set the logging level (debug|info|warn|error)" default:"error"`

	// Stdin is the source to read from, typically set to os.Stdin
	stdin io.Reader
	// Output is the destination for all output from the command, typically set to os.Stdout
	output io.Writer
	// ErrOutput is the destination for errors.
	// If not set, errors will be written to os.StdError
	errOutput io.Writer

	ctx               context.Context
	crypto            *cryptoprov.Crypto
	defaultCryptoProv cryptoprov.Provider
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
	xlog.SetFormatter(xlog.NewPrettyFormatter(c.ErrWriter()))
	if c.Debug {
		xlog.SetGlobalLogLevel(xlog.DEBUG)
	} else {
		val := strings.TrimLeft(c.LogLevel, "=")
		l, err := xlog.ParseLevel(strings.ToUpper(val))
		if err != nil {
			return err
		}
		xlog.SetGlobalLogLevel(l)
	}

	return nil
}

// WriteJSON prints response to out
func (c *Cli) WriteJSON(value any) {
	print.JSON(c.Writer(), value)
}

// CryptoProv loads the crypto providers from --cfg and --crypto on the
// first call, and returns them with the default provider: an in-memory
// provider with --plain-key, otherwise the provider of --cfg ("inmem" and
// "plain" name the in-memory provider). It returns an error, for the
// command to fail with, when --cfg is empty or a provider cannot be
// initialized (XPKI-084).
func (c *Cli) CryptoProv() (*cryptoprov.Crypto, cryptoprov.Provider, error) {
	if c.crypto == nil {
		if c.Cfg == "" {
			return nil, nil, errors.New("use --cfg flag to specify PKCS11 config file")
		}
		var (
			crypto *cryptoprov.Crypto
			err    error
		)
		if c.Cfg == "inmem" || c.Cfg == "plain" {
			crypto, err = cryptoprov.New(inmemcrypto.NewProvider(), nil)
		} else {
			crypto, err = cryptoprov.Load(c.Cfg, c.Crypto)
		}
		if err != nil {
			return nil, nil, errors.WithMessagef(err, "unable to initialize crypto providers: %s, %v",
				c.Cfg, c.Crypto)
		}
		c.crypto = crypto
	}

	if c.defaultCryptoProv == nil {
		if c.PlainKey {
			c.defaultCryptoProv = inmemcrypto.NewProvider()
		} else {
			c.defaultCryptoProv = c.crypto.Default()
		}
	}

	return c.crypto, c.defaultCryptoProv, nil
}

// ReadFile reads from stdin if the file is "-"
func (c *Cli) ReadFile(filename string) ([]byte, error) {
	if filename == "" {
		return nil, errors.New("empty file name")
	}
	if filename == "-" {
		return io.ReadAll(c.Reader())
	}
	return os.ReadFile(filename)
}
