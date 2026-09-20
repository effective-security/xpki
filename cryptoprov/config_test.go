package cryptoprov_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const projFolder = "../.."

// SoftHSMConfig provides location for PKCS11 config
const SoftHSMConfig = "/tmp/xpki/softhsm_unittest.json"

func Test_LoadConfig(t *testing.T) {
	_, err := cryptoprov.LoadTokenConfig("missing.json")
	assert.True(t, os.IsNotExist(errors.Cause(err)), "LoadConfig with missing file should return a file doesn't exist error")

	wd, err := os.Getwd() // package dir
	require.NoError(t, err, "unable to determine current directory")

	binCfg, err := filepath.Abs(filepath.Join(wd, projFolder))
	require.NoError(t, err)

	c, err := cryptoprov.LoadTokenConfig(SoftHSMConfig)
	require.NoError(t, err, "failed to load HSM config in dir: %v", binCfg)

	assert.NotEmpty(t, c.Path())
	assert.NotEmpty(t, c.Pin())
	assert.NotEmpty(t, c.TokenLabel())
	assert.NotNil(t, c.Model())
	assert.NotNil(t, c.Manufacturer())
	assert.NotNil(t, c.TokenSerial())
	assert.NotNil(t, c.Attributes())
}

func Test_LoadTokenConfig_PinFileTrimmed(t *testing.T) {
	dir := t.TempDir()
	pinFile := filepath.Join(dir, "pin.txt")
	// trailing line endings are removed, other whitespace is part of the PIN
	require.NoError(t, os.WriteFile(pinFile, []byte(" s3 cret \r\n\n"), 0600))
	cfgFile := filepath.Join(dir, "token.yaml")
	cfg := "manufacturer: inmem\ntoken_label: unittest\npin: file:" + pinFile + "\n"
	require.NoError(t, os.WriteFile(cfgFile, []byte(cfg), 0600))

	c, err := cryptoprov.LoadTokenConfig(cfgFile)
	require.NoError(t, err)
	assert.Equal(t, " s3 cret ", c.Pin())
	assert.Equal(t, "unittest", c.TokenLabel())
}
