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
// exit status 1 and an error message, instead of a panic (XPKI-084).
func TestMainCryptoProvError(t *testing.T) {
	out := bytes.NewBuffer([]byte{})
	errout := bytes.NewBuffer([]byte{})
	rc := 0
	exit := func(c int) {
		rc = c
	}

	realMain([]string{"hsm-tool", "--cfg", "/nonexistent/hsm.yaml", "hsm", "list"}, out, errout, exit)
	assert.Equal(t, 1, rc)
	assert.Contains(t, errout.String(), "hsm-tool: error: unable to initialize crypto providers: /nonexistent/hsm.yaml, []: ")
	assert.Empty(t, out.String())
}
