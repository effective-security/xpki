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
	"github.com/effective-security/xpki/cryptoprov/testprov"
	"github.com/effective-security/xpki/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_LoadSigner(t *testing.T) {
	t.Parallel()

	tp, err := testprov.Init()
	require.NoError(t, err)
	cp, err := cryptoprov.New(inmemcrypto.NewProvider(), []cryptoprov.Provider{tp})
	require.NoError(t, err)

	t.Run("PEM key", func(t *testing.T) {
		pem, err := testca.GenerateRSAKeyInPEM(nil, 1024)
		require.NoError(t, err)
		prov, pvk, err := cp.LoadPrivateKey(pem)
		require.NoError(t, err)
		assert.Nil(t, prov)
		signSHA1(t, pvk)
	})

	t.Run("pkcs11URI", func(t *testing.T) {
		pvk, err := tp.GenerateRSAKey("", 1024, 1)
		require.NoError(t, err)

		keyID, _, err := tp.IdentifyKey(pvk)
		require.NoError(t, err)

		uri, _, err := tp.ExportKey(keyID)
		require.NoError(t, err)

		prov, loaded, err := cp.LoadPrivateKey([]byte(uri))
		require.NoError(t, err)
		assert.Same(t, tp, prov)
		assert.Same(t, pvk, loaded)
		signSHA1(t, loaded)
	})

	t.Run("fail", func(t *testing.T) {
		for _, tc := range []struct {
			key string
			err string
		}{
			{key: "", err: "failed to parse key: "},
			{key: "pkcs11", err: "failed to parse key: "},
			{key: "pkcs11:manufacturer=test", err: "failed to parse key: "},
			{
				key: "pkcs11:manufacturer=testprov;id=123;type=private;serial=123",
				err: `provider not found: testprov model: : provider for "testprov" and model "" not found`,
			},
			{
				key: "pkcs11:manufacturer=SoftHSM;id=123;type=private;serial=123",
				err: `provider not found: SoftHSM model: : provider for "SoftHSM" and model "" not found`,
			},
			{
				key: "pkcs11:manufacturer=testprov;model=inmem;id=123;type=private;serial=123",
				err: "unable to get key: 123: GetKey(123): ",
			},
		} {
			_, _, err := cp.LoadPrivateKey([]byte(tc.key))
			require.Error(t, err, tc.key)
			assert.True(t, strings.HasPrefix(err.Error(), tc.err), "%s: %s", tc.key, err.Error())
		}
	})
}

func Test_LoadSigner_P11(t *testing.T) {
	prov := loadP11Provider(t)
	cp, err := cryptoprov.New(prov, nil)
	require.NoError(t, err)

	pvk, err := prov.GenerateRSAKey("", 1024, 1)
	require.NoError(t, err)

	keyID, _, err := prov.IdentifyKey(pvk)
	require.NoError(t, err)

	uri, _, err := prov.ExportKey(keyID)
	require.NoError(t, err)

	loadedProv, loaded, err := cp.LoadPrivateKey([]byte(uri))
	require.NoError(t, err)
	assert.Same(t, prov, loadedProv)
	signSHA1(t, loaded)

	_, _, err = cp.LoadPrivateKey([]byte("pkcs11:manufacturer=SoftHSM;model=" + prov.Model() + ";id=123;type=private;serial=123"))
	require.Error(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "unable to get key: 123"), err.Error())
}

// signSHA1 checks that pvk is a crypto.Signer that signs.
func signSHA1(t *testing.T, pvk crypto.PrivateKey) {
	t.Helper()
	signer, ok := pvk.(crypto.Signer)
	require.True(t, ok, "crypto.Signer not supported: %T", pvk)
	digest := certutil.SHA1([]byte("To Be Signed"))
	_, err := signer.Sign(rand.Reader, digest, crypto.SHA1)
	require.NoError(t, err)
}

func Test_LoadTLSKeyPair(t *testing.T) {
	t.Parallel()

	cp, err := cryptoprov.New(inmemcrypto.NewProvider(), nil)
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
