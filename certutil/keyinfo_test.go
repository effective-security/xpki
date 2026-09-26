package certutil_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/effective-security/xpki/certutil"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/internal/testenv"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// register providers
	_ "github.com/effective-security/xpki/cryptoprov/awskmscrypto"
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

// opaqueSigner hides the concrete key type, like an HSM or KMS signer.
type opaqueSigner struct {
	crypto.Signer
}

// opaqueDecrypter is a crypto.Decrypter that is not a crypto.Signer.
type opaqueDecrypter struct {
	crypto.Decrypter
}

// XPKI-099: KeyInfo of an opaque signer needs no KMS; the public key comes
// from Public() and the key is reported as not private.
func TestKeyInfoOpaqueKeys(t *testing.T) {
	t.Parallel()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	for _, tc := range []struct {
		name string
		key  any
		pub  crypto.PublicKey
		typ  string
		size int
		hash crypto.Hash
	}{
		{name: "rsa signer", key: opaqueSigner{rsaKey}, pub: rsaKey.Public(), typ: "RSA", size: 2048, hash: crypto.SHA256},
		{name: "rsa decrypter", key: opaqueDecrypter{rsaKey}, pub: rsaKey.Public(), typ: "RSA", size: 2048, hash: crypto.SHA256},
		{name: "p256 signer", key: opaqueSigner{p256}, pub: p256.Public(), typ: "ECDSA", size: 256, hash: crypto.SHA256},
		{name: "p384 signer", key: opaqueSigner{p384}, pub: p384.Public(), typ: "ECDSA", size: 384, hash: crypto.SHA384},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ki, err := certutil.NewKeyInfo(tc.key)
			require.NoError(t, err)
			assert.Equal(t, tc.typ, ki.Type)
			assert.Equal(t, tc.size, ki.KeySize)
			assert.Equal(t, tc.hash, ki.Hash)
			assert.False(t, ki.IsPrivate)
			assert.Equal(t, tc.key, ki.Key)
			assert.True(t, tc.pub.(interface{ Equal(crypto.PublicKey) bool }).Equal(ki.Key.(interface{ Public() crypto.PublicKey }).Public()))
		})
	}

	_, err = certutil.NewKeyInfo(opaqueSigner{edKey})
	require.EqualError(t, err, "key not supported: ed25519.PublicKey")
}

// localKMSAddr is the local-kms container that aws-dev-kms.yaml points to.
const localKMSAddr = "localhost:14556"

// TestKeyInfoKMS is an integration test: it needs local-kms (make
// start-local-kms) and may create the TestKeyInfoKMS key there.
func TestKeyInfoKMS(t *testing.T) {
	testenv.RequireTCP(t, "local-kms", localKMSAddr)
	prov, err := cryptoprov.Load("../cryptoprov/awskmscrypto/testdata/aws-dev-kms.yaml", nil)
	require.NoError(t, err)

	kms := prov.Default()
	pvk, err := kms.GetKey("TestKeyInfoKMS")
	if err != nil || pvk == nil {
		pvk, err = kms.GenerateECDSAKey("TestKeyInfoKMS", elliptic.P256())
		require.NoError(t, err)
	}
	signer, ok := pvk.(crypto.Signer)
	require.True(t, ok)

	ki, err := certutil.NewKeyInfo(pvk)
	require.NoError(t, err)
	assert.Equal(t, "ECDSA", ki.Type)
	assert.Equal(t, 256, ki.KeySize)
	assert.Equal(t, crypto.SHA256, ki.Hash)
	assert.False(t, ki.IsPrivate)
	assert.Equal(t, pvk, ki.Key)

	ki, err = certutil.NewKeyInfo(signer.Public())
	require.NoError(t, err)
	assert.Equal(t, "ECDSA", ki.Type)
	assert.Equal(t, 256, ki.KeySize)
	assert.Equal(t, signer.Public(), ki.Key)
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
