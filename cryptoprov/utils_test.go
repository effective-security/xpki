package cryptoprov_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func Test_ParsePrivateKeyDER(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	rsaPKCS8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	ecPKCS8, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	edPKCS8, err := x509.MarshalPKCS8PrivateKey(edKey)
	require.NoError(t, err)
	ecSEC1, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)

	tcases := []struct {
		name string
		der  []byte
		exp  crypto.PrivateKey
	}{
		{"rsa_pkcs8", rsaPKCS8, rsaKey},
		{"rsa_pkcs1", x509.MarshalPKCS1PrivateKey(rsaKey), rsaKey},
		{"ecdsa_pkcs8", ecPKCS8, ecKey},
		{"ecdsa_sec1", ecSEC1, ecKey},
		{"ed25519_pkcs8", edPKCS8, edKey},
	}
	for _, tc := range tcases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := cryptoprov.ParsePrivateKeyDER(tc.der)
			require.NoError(t, err)
			require.NotNil(t, key)
			assert.True(t, key.(interface{ Equal(crypto.PrivateKey) bool }).Equal(tc.exp))
		})
	}

	t.Run("garbage", func(t *testing.T) {
		_, err := cryptoprov.ParsePrivateKeyDER([]byte("not a key"))
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "failed to parse key: "), err.Error())
		// the real x509 error must be preserved, not discarded
		assert.Contains(t, err.Error(), "x509: ")
	})
}

func Test_TLSKeyPair(t *testing.T) {
	cp, err := cryptoprov.New(inmemcrypto.NewProvider(), nil)
	require.NoError(t, err)

	rsaCert, rsaKey, err := testca.MakeSelfCertRSAPem(1)
	require.NoError(t, err)
	ecCert, ecKey, err := testca.MakeSelfCertECDSAPem(1)
	require.NoError(t, err)
	otherRSAKey, err := testca.GenerateRSAKeyInPEM(nil, 2048)
	require.NoError(t, err)

	t.Run("rsa_match", func(t *testing.T) {
		tlsCert, err := cp.TLSKeyPair(rsaCert, rsaKey)
		require.NoError(t, err)
		require.NotNil(t, tlsCert.Leaf)
		assert.Equal(t, "localhost", tlsCert.Leaf.Subject.CommonName)
		assert.NotNil(t, tlsCert.PrivateKey)
	})

	t.Run("ecdsa_match", func(t *testing.T) {
		tlsCert, err := cp.TLSKeyPair(ecCert, ecKey)
		require.NoError(t, err)
		require.NotNil(t, tlsCert.Leaf)
	})

	t.Run("mismatch_same_type", func(t *testing.T) {
		_, err := cp.TLSKeyPair(rsaCert, otherRSAKey)
		require.EqualError(t, err, "tls: private key does not match certificate public key")
	})

	t.Run("mismatch_other_type", func(t *testing.T) {
		_, err := cp.TLSKeyPair(ecCert, rsaKey)
		require.EqualError(t, err, "tls: private key does not match certificate public key")
	})

	t.Run("swapped_inputs", func(t *testing.T) {
		_, err := cp.TLSKeyPair(rsaKey, rsaCert)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PEM inputs may have been switched")
	})
}
