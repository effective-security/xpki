package dpop_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path"
	"testing"

	"github.com/effective-security/xpki/jwt/dpop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

func TestKeys(t *testing.T) {
	folder := path.Join(os.TempDir(), "test", "dpop-keys")
	defer os.RemoveAll(folder)

	_, _, err := dpop.LoadKey("TestKeys")
	assert.EqualError(t, err, "open TestKeys: no such file or directory")

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jk := &jose.JSONWebKey{
		Key: ecKey,
	}

	fn, err := dpop.SaveKey(folder, jk)
	require.NoError(t, err)

	jk2, tb, err := dpop.LoadKey(fn)
	require.NoError(t, err)
	tb2, err := dpop.Thumbprint(jk2)
	require.NoError(t, err)
	assert.Equal(t, tb, tb2)
}
