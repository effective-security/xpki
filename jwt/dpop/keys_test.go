package dpop_test

import (
	"os"
	"path"
	"testing"

	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeys(t *testing.T) {
	folder := path.Join(os.TempDir(), "test", "dpop-keys")
	defer func() {
		_ = os.RemoveAll(folder)
	}()

	_, _, err := dpop.LoadKey("TestKeys")
	assert.EqualError(t, err, "open TestKeys: no such file or directory")

	jk, err := dpop.GenerateKey("")
	require.NoError(t, err)

	fn, err := dpop.SaveKey(folder, jk)
	require.NoError(t, err)

	jk2, tb, err := dpop.LoadKey(fn)
	require.NoError(t, err)
	tb2, err := dpop.Thumbprint(jk2)
	require.NoError(t, err)
	assert.Equal(t, tb, tb2)
	assert.Equal(t, jk2.KeyID, tb2)
}
