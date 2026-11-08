package testprov

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateMLDSAKey covers generation, URI export and the signer
// contract of the non-exportable test provider.
func TestGenerateMLDSAKey(t *testing.T) {
	t.Parallel()
	p, err := Init()
	require.NoError(t, err)
	message := []byte("testprov ML-DSA message")

	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		priv, err := p.GenerateMLDSAKey("pq-"+params.String(), params)
		require.NoError(t, err)
		keyID, label, err := p.IdentifyKey(priv)
		require.NoError(t, err)
		assert.Equal(t, "pq-"+params.String(), label)

		uri, keyBytes, err := p.ExportKey(keyID)
		require.NoError(t, err)
		assert.Nil(t, keyBytes)
		assert.Equal(t, fmt.Sprintf("pkcs11:manufacturer=testprov;model=inmem;serial=20764350726;token=pq-%s;id=%s;type=private", params, keyID), uri)

		signer := priv.(crypto.Signer)
		pub := signer.Public().(*mldsa.PublicKey)
		assert.Equal(t, params, pub.Parameters())

		sig, err := signer.Sign(rand.Reader, message, nil)
		require.NoError(t, err)
		require.NoError(t, mldsa.Verify(pub, message, sig, nil))

		sig, err = signer.Sign(rand.Reader, message, &mldsa.Options{Context: "ctx"})
		require.NoError(t, err)
		require.NoError(t, mldsa.Verify(pub, message, sig, &mldsa.Options{Context: "ctx"}))

		mu, err := cryptoprov.MLDSAMu(pub, "", message)
		require.NoError(t, err)
		sig, err = signer.Sign(rand.Reader, mu, crypto.MLDSAMu)
		require.NoError(t, err)
		require.NoError(t, mldsa.Verify(pub, message, sig, nil))

		_, err = signer.Sign(rand.Reader, make([]byte, 48), crypto.SHA384)
		require.EqualError(t, err, "ML-DSA signs a message, not a digest: unsupported signer options SHA-384")

		_, err = priv.(crypto.Decrypter).Decrypt(rand.Reader, message, nil)
		require.EqualError(t, err, "crypto.Decrypter is not supported")
	}

	// a key without a label gets a generated one
	priv, err := p.GenerateMLDSAKey("", mldsa.MLDSA44())
	require.NoError(t, err)
	_, label, err := p.IdentifyKey(priv)
	require.NoError(t, err)
	assert.NotEmpty(t, label)
}

type failingMLDSAGenerator struct{}

func (failingMLDSAGenerator) GenerateKey(mldsa.Parameters) (*mldsa.PrivateKey, error) {
	return nil, errors.New("mldsa: not available")
}

func TestGenerateMLDSAKeyError(t *testing.T) {
	t.Parallel()
	p, err := Init()
	require.NoError(t, err)
	p.mldsaKeyGenerator = failingMLDSAGenerator{}
	_, err = p.GenerateMLDSAKey("label", mldsa.MLDSA87())
	require.EqualError(t, err, "parameter set ML-DSA-87: mldsa: not available")
	assert.Empty(t, p.inMemProv.keyIDToPvk)
}
