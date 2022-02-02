package ctl

import (
	"bytes"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteJSON(t *testing.T) {
	var cl struct {
		Version VersionFlag
	}
	cl.Version.Version = "1.2.3"
	w := bytes.NewBuffer([]byte{})

	err := WriteJSON(w, cl)
	require.NoError(t, err)

	assert.Equal(t, "{\n\t\"Version\": {\n\t\t\"Version\": \"1.2.3\"\n\t}\n}\n", w.String())
}

func TestVersionVal(t *testing.T) {
	v := VersionFlag{
		Version: "1.2.3",
	}
	assert.True(t, v.IsBool())
	assert.NoError(t, v.Decode(nil))
}

func TestBool(t *testing.T) {
	var bm boolPtrMapper
	assert.True(t, bm.IsBool())
}

func TestParse(t *testing.T) {
	var cl struct {
		Version VersionFlag
		Cmd     struct {
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

	ctx, err = p.Parse([]string{"cmd", "--ptr=1"})
	require.NoError(t, err)
	require.Equal(t, "cmd", ctx.Command())
	if assert.NotNil(t, cl.Cmd.Ptr) {
		assert.True(t, *cl.Cmd.Ptr)
	}

	ctx, err = p.Parse([]string{"cmd", "--ptr"})
	require.NoError(t, err)
	require.Equal(t, "cmd", ctx.Command())
	if assert.NotNil(t, cl.Cmd.Ptr) {
		assert.True(t, *cl.Cmd.Ptr)
	}

	_, err = p.Parse([]string{"cmd", "--ptr=invalid"})
	assert.EqualError(t, err, "--ptr: bool value must be true, 1, yes, false, 0 or no but got \"invalid\"")
}

func TestVersionFlag(t *testing.T) {
	var cl struct {
		Version VersionFlag
	}
	cl.Version.Version = "1.2.3"

	options := []kong.Option{
		kong.Name("test"),
		kong.Exit(func(int) {
			t.Helper()

		}),
		BoolPtrMapper,
	}
	parser, err := kong.New(&cl, options...)
	require.NoError(t, err)

	_, err = parser.Parse([]string{"--version"})
	require.NoError(t, err)
}

func mustNew(t *testing.T, cli interface{}, options ...kong.Option) *kong.Kong {
	t.Helper()
	options = append([]kong.Option{
		kong.Name("test"),
		kong.Exit(func(int) {
			t.Helper()
			t.Fatalf("unexpected exit()")
		}),
		BoolPtrMapper,
	}, options...)
	parser, err := kong.New(cli, options...)
	require.NoError(t, err)

	return parser
}

func Test_FileExists(t *testing.T) {
	assert.Error(t, FileExists(""))
	assert.NoError(t, FileExists("ctl.go"))

	err := FileExists("../ctl")
	require.Error(t, err)
	assert.EqualError(t, err, "not a file: ../ctl")

	err = FileExists("./a")
	assert.EqualError(t, err, "stat ./a: no such file or directory")
}

func TestWriteCert(t *testing.T) {
	w := bytes.NewBuffer([]byte{})
	WriteCert(w, []byte("key"), []byte("csr"), []byte("cert"))
	out := w.String()
	assert.Equal(t, "{\"cert\":\"cert\",\"csr\":\"csr\",\"key\":\"key\"}\n", out)
}
