package cryptoprov_test

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_LoadGPGPrivateKey(t *testing.T) {
	prov := loadP11Provider(t)
	cp, err := cryptoprov.New(prov, nil)
	require.NoError(t, err)

	now := time.Now()

	t.Run("PEM key", func(t *testing.T) {
		pem, err := testca.GenerateRSAKeyInPEM(nil, 1024)
		_, err = cp.LoadGPGPrivateKey(now, pem)
		require.NoError(t, err)
	})

	t.Run("pkcs11URI", func(t *testing.T) {
		pvk, err := prov.GenerateECDSAKey("", elliptic.P256())
		require.NoError(t, err)

		keyID, _, err := prov.IdentifyKey(pvk)
		require.NoError(t, err)

		uri, _, err := prov.ExportKey(keyID)
		require.NoError(t, err)

		_, err = cp.LoadGPGPrivateKey(now, []byte(uri))
		require.NoError(t, err)
	})

	t.Run("fail", func(t *testing.T) {
		_, err = cp.LoadGPGPrivateKey(now, []byte(""))
		assert.Error(t, err)
		_, err = cp.LoadGPGPrivateKey(now, []byte("pkcs11"))
		assert.Error(t, err)
		_, err = cp.LoadGPGPrivateKey(now, []byte("pkcs11:manufacturer=test"))
		assert.Error(t, err)
		_, err = cp.LoadGPGPrivateKey(now, []byte("pkcs11:manufacturer=testprov;id=123;type=private;serial=123"))
		assert.Error(t, err)
		_, err = cp.LoadGPGPrivateKey(now, []byte("pkcs11:manufacturer=SoftHSM;id=123;type=private;serial=123"))
		assert.Error(t, err)
	})
}

func Test_LoadSigner(t *testing.T) {
	prov := loadP11Provider(t)
	cp, err := cryptoprov.New(prov, nil)
	require.NoError(t, err)

	t.Run("PEM key", func(t *testing.T) {
		pem, err := testca.GenerateRSAKeyInPEM(nil, 1024)
		require.NoError(t, err)
		_, pvk, err := cp.LoadPrivateKey(pem)
		require.NoError(t, err)
		signer := pvk.(crypto.Signer)

		digest := certutil.SHA1([]byte(prov.Manufacturer()))
		_, err = signer.Sign(rand.Reader, digest, crypto.SHA1)
		require.NoError(t, err)
	})

	t.Run("pkcs11URI", func(t *testing.T) {
		pvk, err := prov.GenerateRSAKey("", 1024, 1)
		require.NoError(t, err)

		keyID, _, err := prov.IdentifyKey(pvk)
		require.NoError(t, err)

		uri, _, err := prov.ExportKey(keyID)
		require.NoError(t, err)

		_, pvk, err = cp.LoadPrivateKey([]byte(uri))
		require.NoError(t, err)
		signer := pvk.(crypto.Signer)

		digest := certutil.SHA1([]byte(prov.Manufacturer()))
		_, err = signer.Sign(rand.Reader, digest, crypto.SHA1)
		require.NoError(t, err)
	})

	t.Run("fail", func(t *testing.T) {
		_, _, err = cp.LoadPrivateKey([]byte(""))
		assert.Error(t, err)
		_, _, err = cp.LoadPrivateKey([]byte("pkcs11"))
		assert.Error(t, err)
		_, _, err = cp.LoadPrivateKey([]byte("pkcs11:manufacturer=test"))
		assert.Error(t, err)
		_, _, err = cp.LoadPrivateKey([]byte("pkcs11:manufacturer=testprov;id=123;type=private;serial=123"))
		assert.Error(t, err)
		_, _, err = cp.LoadPrivateKey([]byte("pkcs11:manufacturer=SoftHSM;id=123;type=private;serial=123"))
		assert.Error(t, err)
	})
}

func Test_LoadTLSKeyPair(t *testing.T) {
	prov := loadP11Provider(t)
	cp, err := cryptoprov.New(prov, nil)
	require.NoError(t, err)

	tls, err := cp.LoadTLSKeyPair("testdata/test-cert.pem", "testdata/test-key.pem")
	require.NoError(t, err)
	assert.NotNil(t, tls.Certificate)
	assert.NotNil(t, tls.Leaf)
	assert.NotNil(t, tls.PrivateKey)
}
