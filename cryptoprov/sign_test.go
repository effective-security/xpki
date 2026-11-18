package cryptoprov_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/cryptoprov/inmemcrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignContext checks the helpers on a provider key, which is a
// ContextSigner and ContextDecrypter, and that an ended context fails before
// the key is used.
func TestSignContext(t *testing.T) {
	t.Parallel()
	prov := inmemcrypto.NewProvider()
	key, err := prov.GenerateKey(t.Context(), &cryptoprov.GenerateKeyRequest{
		Label: "ctx",
		Type:  certutil.KeyTypeRSA,
		Size:  2048,
		Usage: cryptoprov.KeyUsageSign | cryptoprov.KeyUsageEncrypt,
	})
	require.NoError(t, err)
	signer, ok := key.(cryptoprov.ContextSigner)
	require.True(t, ok, "%T is not a ContextSigner", key)
	decrypter, ok := key.(cryptoprov.ContextDecrypter)
	require.True(t, ok, "%T is not a ContextDecrypter", key)
	pub := signer.Public().(*rsa.PublicKey)

	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	sum := sha256.Sum256([]byte("message"))

	sig, err := cryptoprov.SignContext(t.Context(), signer, rand.Reader, sum[:], crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig))
	_, err = cryptoprov.SignContext(cancelled, signer, rand.Reader, sum[:], crypto.SHA256)
	require.ErrorIs(t, err, context.Canceled)

	sig, err = cryptoprov.BindContext(t.Context(), signer).Sign(rand.Reader, sum[:], crypto.SHA256)
	require.NoError(t, err)
	require.NoError(t, rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig))
	_, err = cryptoprov.BindContext(cancelled, signer).Sign(rand.Reader, sum[:], crypto.SHA256)
	require.ErrorIs(t, err, context.Canceled)

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte("secret"), nil)
	require.NoError(t, err)
	opts := &rsa.OAEPOptions{Hash: crypto.SHA256}
	plaintext, err := cryptoprov.DecryptContext(t.Context(), decrypter, rand.Reader, ciphertext, opts)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret"), plaintext)
	_, err = cryptoprov.DecryptContext(cancelled, decrypter, rand.Reader, ciphertext, opts)
	require.ErrorIs(t, err, context.Canceled)
}
