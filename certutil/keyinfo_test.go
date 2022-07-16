package certutil_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
)

func TestKeyInfoRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	ki, err := certutil.NewKeyInfo(key)
	require.NoError(t, err)
	assert.Equal(t, "RSA", ki.Type)
	assert.Equal(t, 1024, ki.KeySize)

	ki, err = certutil.NewKeyInfo(key.Public())
	require.NoError(t, err)
	assert.Equal(t, "RSA", ki.Type)
	assert.Equal(t, 1024, ki.KeySize)
}

func TestKeyInfoKMS(t *testing.T) {
	cryptoprov.Register(awskmscrypto.ProviderName, awskmscrypto.KmsLoader)
	_, err := cryptoprov.Load("../cryptoprov/awskmscrypto/testdata/aws-dev-kms.json", nil)
	require.NoError(t, err)
	prov, err := cryptoprov.Load("../cryptoprov/awskmscrypto/testdata/aws-dev-kms.yaml", nil)
	require.NoError(t, err)

	kms := prov.Default()
	pvk, err := kms.GetKey("TestKeyInfoKMS")
	if err != nil || pvk == nil {
		pvk, err = kms.GenerateECDSAKey("TestKeyInfoKMS", elliptic.P256())
		require.NoError(t, err)
	}

	ki, err := certutil.NewKeyInfo(pvk)
	require.NoError(t, err)
	assert.Equal(t, "ECDSA", ki.Type)
	assert.Equal(t, 256, ki.KeySize)

	ki, err = certutil.NewKeyInfo(pvk.(crypto.Signer))
	require.NoError(t, err)
	assert.Equal(t, "ECDSA", ki.Type)
	assert.Equal(t, 256, ki.KeySize)
}

func TestKeyInfoECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ki, err := certutil.NewKeyInfo(key)
	require.NoError(t, err)
	assert.Equal(t, "ECDSA", ki.Type)
	assert.Equal(t, 256, ki.KeySize)

	ki, err = certutil.NewKeyInfo(key.Public())
	require.NoError(t, err)
	assert.Equal(t, "ECDSA", ki.Type)
	assert.Equal(t, 256, ki.KeySize)

	jk := &jose.JSONWebKey{
		Key: key,
	}
	ki, err = certutil.NewKeyInfo(jk)
	require.NoError(t, err)
	assert.Equal(t, "ECDSA", ki.Type)
	assert.Equal(t, 256, ki.KeySize)
}
