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

	realMain([]string{"xpki-tool", "version"}, out, errout, exit)
	assert.Equal(t, 1, rc)
	assert.Equal(t, "xpki-tool: error: unexpected argument version\n", errout.String())
	assert.Empty(t, out.String())
}
