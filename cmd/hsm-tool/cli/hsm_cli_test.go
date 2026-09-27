package cli

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/effective-security/x/ctl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContext(t *testing.T) {
	var c Cli

	assert.NotNil(t, c.ErrWriter())
	assert.NotNil(t, c.Writer())
	assert.NotNil(t, c.Reader())

	c.WithErrWriter(os.Stderr)
	c.WithReader(os.Stdin)
	c.WithWriter(os.Stdout)

	assert.NotNil(t, c.Context())
	assert.NotNil(t, c.ErrWriter())
	assert.NotNil(t, c.Writer())
	assert.NotNil(t, c.Reader())

	out := bytes.NewBuffer([]byte{})
	c.WithWriter(out)
	c.WriteJSON(struct{}{})
	assert.Equal(t, "{}\n", out.String())
}

// TestParse builds a fresh parser and destination for every case (XPKI-101):
// kong keeps the flags it has already seen, so a shared parser accepts a
// later invocation without the required --cfg.
func TestParse(t *testing.T) {
	type app struct {
		Cli

		Cmd struct {
			Ptr *bool `help:"test bool ptr"`
		} `kong:"cmd"`
	}
	ptr := func(b bool) *bool { return &b }

	for _, tc := range []struct {
		name string
		args []string
		ptr  *bool
		err  string
	}{
		{
			name: "bool ptr false",
			args: []string{"--cfg=hsm.cfg", "cmd", "--ptr=false", "-D"},
			ptr:  ptr(false),
		},
		{
			name: "bool ptr true with log level",
			args: []string{"--cfg=hsm.cfg", "cmd", "--ptr=true", "-l=W"},
			ptr:  ptr(true),
		},
		{
			name: "invalid log level",
			args: []string{"--cfg=hsm.cfg", "cmd", "--ptr=false", "-l=123"},
			err:  "unable to parse log level: 123",
		},
		{
			name: "missing cfg",
			args: []string{"cmd", "--ptr=true"},
			err:  "missing flags: --cfg=STRING",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cl app
			p := mustNew(t, &cl)
			ctx, err := p.Parse(tc.args)
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "cmd", ctx.Command())
			assert.Equal(t, "hsm.cfg", cl.Cfg)
			if assert.NotNil(t, cl.Cmd.Ptr) {
				assert.Equal(t, *tc.ptr, *cl.Cmd.Ptr)
			}
		})
	}
}

func mustNew(t *testing.T, cli any, options ...kong.Option) *kong.Kong {
	t.Helper()
	options = append([]kong.Option{
		kong.Name("test"),
		kong.Exit(func(int) {
			t.Helper()
			t.Fatalf("unexpected exit()")
		}),
		ctl.BoolPtrMapper,
	}, options...)
	parser, err := kong.New(cli, options...)
	require.NoError(t, err)

	return parser
}

// TestCryptoProv checks that a missing or bad --cfg is an error of the
// command, not a panic (XPKI-084).
func TestCryptoProv(t *testing.T) {
	t.Run("missing cfg", func(t *testing.T) {
		c := &Cli{}
		crypto, def, err := c.CryptoProv()
		assert.EqualError(t, err, "use --cfg flag to specify PKCS11 config file")
		assert.Nil(t, crypto)
		assert.Nil(t, def)

		err = (&HsmLsKeyCmd{}).Run(c)
		assert.EqualError(t, err, "use --cfg flag to specify PKCS11 config file")
	})
	t.Run("missing file", func(t *testing.T) {
		cfg := filepath.Join(t.TempDir(), "missing.yaml")
		c := &Cli{Cfg: cfg, Crypto: []string{"extra.yaml"}}
		crypto, def, err := c.CryptoProv()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to initialize crypto providers: "+cfg+", [extra.yaml]: ")
		assert.ErrorIs(t, err, fs.ErrNotExist)
		assert.Nil(t, crypto)
		assert.Nil(t, def)

		err = (&HsmKeyInfoCmd{ID: "1"}).Run(c)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to initialize crypto providers")
	})
	t.Run("invalid file", func(t *testing.T) {
		cfg := filepath.Join(t.TempDir(), "invalid.yaml")
		require.NoError(t, os.WriteFile(cfg, []byte("{"), 0600))
		c := &Cli{Cfg: cfg}
		_, _, err := c.CryptoProv()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to initialize crypto providers: "+cfg)
	})
	t.Run("inmem", func(t *testing.T) {
		c := &Cli{Cfg: "inmem"}
		crypto, def, err := c.CryptoProv()
		require.NoError(t, err)
		require.NotNil(t, crypto)
		assert.Same(t, crypto.Default(), def)

		crypto2, def2, err := c.CryptoProv()
		require.NoError(t, err)
		assert.Same(t, crypto, crypto2)
		assert.Same(t, def, def2)
	})
	t.Run("plain key", func(t *testing.T) {
		c := &Cli{Cfg: "plain", PlainKey: true}
		crypto, def, err := c.CryptoProv()
		require.NoError(t, err)
		require.NotNil(t, crypto)
		require.NotNil(t, def)
		assert.NotSame(t, crypto.Default(), def)
	})
}
