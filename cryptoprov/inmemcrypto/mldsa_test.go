package inmemcrypto

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateMLDSAKeys covers generation, lookup, PKCS#8 export and the
// signer contract for every parameter set: the message with nil, zero-hash
// and *mldsa.Options, μ with crypto.MLDSAMu, and an error for digests.
func TestGenerateMLDSAKeys(t *testing.T) {
	t.Parallel()
	message := []byte("in-memory ML-DSA message")
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			t.Parallel()
			p := NewProvider()
			priv, err := p.GenerateMLDSAKey("inmemory"+params.String(), params)
			require.NoError(t, err)

			keyID, label, err := p.IdentifyKey(priv)
			require.NoError(t, err)
			assert.Equal(t, "inmemory"+params.String(), label)

			signer, ok := priv.(crypto.Signer)
			require.True(t, ok)
			pub, ok := signer.Public().(*mldsa.PublicKey)
			require.True(t, ok, "%T", signer.Public())
			assert.Equal(t, params, pub.Parameters())

			stored, err := p.GetKey(keyID)
			require.NoError(t, err)
			assert.Same(t, priv, stored)

			uri, keyBytes, err := p.ExportKey(keyID)
			require.NoError(t, err)
			assert.Empty(t, uri)
			block, rest := pem.Decode(keyBytes)
			require.NotNil(t, block)
			assert.Empty(t, rest)
			assert.Equal(t, "PRIVATE KEY", block.Type)
			exported, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			require.NoError(t, err)
			assert.True(t, pub.Equal(exported.(*mldsa.PrivateKey).Public()))

			for name, opts := range map[string]crypto.SignerOpts{
				"nil":           nil,
				"zero hash":     crypto.Hash(0),
				"empty options": &mldsa.Options{},
			} {
				sig, err := signer.Sign(rand.Reader, message, opts)
				require.NoError(t, err, name)
				assert.Len(t, sig, params.SignatureSize(), name)
				require.NoError(t, mldsa.Verify(pub, message, sig, nil), name)
			}

			ctx := &mldsa.Options{Context: "xpki"}
			sig, err := signer.Sign(rand.Reader, message, ctx)
			require.NoError(t, err)
			require.NoError(t, mldsa.Verify(pub, message, sig, ctx))
			require.Error(t, mldsa.Verify(pub, message, sig, nil), "context is bound")

			mu, err := cryptoprov.MLDSAMu(pub, "", message)
			require.NoError(t, err)
			sig, err = signer.Sign(rand.Reader, mu, crypto.MLDSAMu)
			require.NoError(t, err)
			require.NoError(t, mldsa.Verify(pub, message, sig, nil))
			_, err = signer.Sign(rand.Reader, mu[:63], crypto.MLDSAMu)
			require.ErrorContains(t, err, "mldsa: invalid message hash length")

			_, err = signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256)
			require.EqualError(t, err, "ML-DSA signs a message, not a digest: unsupported signer options SHA-256")
			_, err = signer.Sign(rand.Reader, make([]byte, 20), crypto.SHA1)
			require.EqualError(t, err, "ML-DSA signs a message, not a digest: unsupported signer options SHA-1")
		})
	}
}

// failingMLDSAGenerator stands in for a FIPS 140-3 module build, where
// crypto/mldsa returns an error instead of a key.
type failingMLDSAGenerator struct{}

func (failingMLDSAGenerator) GenerateKey(mldsa.Parameters) (*mldsa.PrivateKey, error) {
	return nil, errors.New("mldsa: not available")
}

func TestGenerateMLDSAKeyError(t *testing.T) {
	t.Parallel()
	p := NewProvider()
	p.mldsaKeyGenerator = failingMLDSAGenerator{}
	_, err := p.GenerateMLDSAKey("label", mldsa.MLDSA65())
	require.EqualError(t, err, "unable to generate key, parameter set: ML-DSA-65: mldsa: not available")
	assert.Empty(t, p.inMemProv.keyIDToPvk)
}

// TestExportKeyUnsupportedType covers the registry holding a key type no
// generator produces: an error, not a panic.
func TestExportKeyUnsupportedType(t *testing.T) {
	t.Parallel()
	p := NewProvider()
	p.inMemProv.registerKey("odd", &provImpl{id: "odd", label: "odd", pvk: struct{}{}})
	_, _, err := p.ExportKey("odd")
	require.EqualError(t, err, "unsupported key type struct {}: odd")
	signer, err := p.GetKey("odd")
	require.NoError(t, err)
	_, err = signer.(crypto.Signer).Sign(rand.Reader, nil, nil)
	require.EqualError(t, err, "crypto.Signer is not supported")
}
