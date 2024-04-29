package cli

import (
	"bytes"
	"os"
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

func TestParse(t *testing.T) {
	var cl struct {
		Cli

		Cmd struct {
			Ptr *bool `help:"test bool ptr"`
		} `kong:"cmd"`
	}

	p := mustNew(t, &cl)
	ctx, err := p.Parse([]string{"cmd", "--ptr=false"})
	require.NoError(t, err)
	require.Equal(t, "cmd", ctx.Command())
	if assert.NotNil(t, cl.Cmd.Ptr) {
		assert.False(t, *cl.Cmd.Ptr)
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
