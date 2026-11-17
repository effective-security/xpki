package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(t *testing.T) {
	out := bytes.NewBuffer([]byte{})
	errout := bytes.NewBuffer([]byte{})
	rc := 0
	exit := func(c int) {
		rc = c
	}

	realMain([]string{"hsm-tool", "version"}, out, errout, exit)
	assert.Equal(t, 80, rc)
	assert.Equal(t, "hsm-tool: error: unexpected argument version\n", errout.String())
	assert.Empty(t, out.String())
}

// TestMainCryptoProvError checks that a bad --cfg fails the command with
// exit status 1 and an error message, instead of a panic (XPKI-084). The
// key commands are under "hsm key".
func TestMainCryptoProvError(t *testing.T) {
	out := bytes.NewBuffer([]byte{})
	errout := bytes.NewBuffer([]byte{})
	rc := 0
	exit := func(c int) {
		rc = c
	}

	realMain([]string{"hsm-tool", "--cfg", "/nonexistent/hsm.yaml", "hsm", "key", "list"}, out, errout, exit)
	assert.Equal(t, 1, rc)
	assert.Contains(t, errout.String(), "hsm-tool: error: unable to initialize crypto providers: /nonexistent/hsm.yaml, []: ")
	assert.Empty(t, out.String())
}

// TestMainKeyCommands checks the command tree: the key commands parse under
// "hsm key", with their flags, and not directly under "hsm", where v1 had
// them.
func TestMainKeyCommands(t *testing.T) {
	const (
		exitUsage = 80
		exitError = 1
	)
	for _, tc := range []struct {
		name   string
		args   []string
		rc     int
		errout string
	}{
		{
			name:   "list",
			args:   []string{"hsm", "key", "list", "--usage", "sign", "--state", "all", "--limit", "5"},
			rc:     exitError,
			errout: "unable to initialize crypto providers",
		},
		{
			name:   "info",
			args:   []string{"hsm", "key", "info", "--tags", "id"},
			rc:     exitError,
			errout: "unable to initialize crypto providers",
		},
		{
			name:   "generate",
			args:   []string{"hsm", "key", "generate", "--algo", "ECDSA", "--size", "256", "--purpose", "sign", "--label", "l"},
			rc:     exitError,
			errout: "unable to initialize crypto providers",
		},
		{
			name:   "remove",
			args:   []string{"hsm", "key", "remove", "id"},
			rc:     exitError,
			errout: "unable to initialize crypto providers",
		},
		{
			name:   "v1 path",
			args:   []string{"hsm", "list"},
			rc:     exitUsage,
			errout: "unexpected argument list",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := bytes.NewBuffer([]byte{})
			errout := bytes.NewBuffer([]byte{})
			rc := 0
			exit := func(c int) {
				rc = c
			}
			args := append([]string{"hsm-tool", "--cfg", "/nonexistent/hsm.yaml"}, tc.args...)
			realMain(args, out, errout, exit)
			assert.Equal(t, tc.rc, rc)
			assert.Contains(t, errout.String(), tc.errout)
			assert.Empty(t, out.String())
		})
	}
}
