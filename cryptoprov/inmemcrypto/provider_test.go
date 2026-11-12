package inmemcrypto

import (
	"crypto"
	"crypto/rand"
	"testing"

	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_InitProvider(t *testing.T) {
	p := NewProvider()
	assert.NotNil(t, p)
	assert.NotNil(t, p.inMemProv)
	assert.NotNil(t, p.rsaKeyGenerator)
	assert.NotNil(t, p.ecdsaKeyGenerator)

	assert.Equal(t, ProviderName, p.Manufacturer())
	assert.Equal(t, "inmem", p.Model())
	assert.Equal(t, "23948570247520345", p.Serial())
}

func Test_GenerateKeys(t *testing.T) {
	p := NewProvider()
	assert.NotNil(t, p)
	assert.NotNil(t, p.inMemProv)
	assert.NotNil(t, p.rsaKeyGenerator)
	assert.NotNil(t, p.ecdsaKeyGenerator)

	priv, err := p.GenerateKey(t.Context(), &cryptoprov.GenerateKeyRequest{
		Label: "inmemoryECDSA",
		Type:  certutil.KeyTypeECDSA,
		Size:  256,
	})
	require.NoError(t, err)
	assert.NotNil(t, priv)

	keyID1, label, err := p.IdentifyKey(t.Context(), priv)
	require.NoError(t, err)
	assert.Equal(t, "inmemoryECDSA", label)

	l := len(p.inMemProv.keyIDToPvk)
	assert.Equal(t, 1, l)
	keyURI, keyBytes, err := p.ExportKey(t.Context(), keyID1)
	require.NoError(t, err)
	assert.Empty(t, keyURI)
	assert.NotNil(t, keyBytes)
	assert.Contains(t, string(keyBytes), "-----BEGIN EC PRIVATE KEY-----\n")

	s, err := p.GetKey(t.Context(), keyID1)
	require.NoError(t, err)
	si, ok := s.(*provImpl)
	assert.True(t, ok)
	assert.NotNil(t, si.Public())

	pvk, err := p.GetKey(t.Context(), keyID1)
	require.NoError(t, err)
	assert.NotNil(t, pvk)

	priv, err = p.GenerateKey(t.Context(), &cryptoprov.GenerateKeyRequest{
		Label: "inmemoryRSA",
		Type:  certutil.KeyTypeRSA,
		Size:  2048,
	})
	require.NoError(t, err)
	assert.NotNil(t, priv)

	keyID2, label, err := p.IdentifyKey(t.Context(), priv)
	require.NoError(t, err)
	assert.Equal(t, "inmemoryRSA", label)

	l = len(p.inMemProv.keyIDToPvk)
	assert.Equal(t, 2, l)

	keyURI, keyBytes, err = p.ExportKey(t.Context(), keyID2)
	require.NoError(t, err)
	assert.Empty(t, keyURI)
	assert.NotNil(t, keyBytes)
	assert.Contains(t, string(keyBytes), "-----BEGIN RSA PRIVATE KEY-----\n")

	s, err = p.GetKey(t.Context(), keyID2)
	require.NoError(t, err)
	si, ok = s.(*provImpl)
	assert.True(t, ok)
	assert.NotNil(t, si.Public())

	pvk, err = p.GetKey(t.Context(), keyID2)
	require.NoError(t, err)
	assert.NotNil(t, pvk)
}

func TestSignECDSA(t *testing.T) {
	p := NewProvider()
	assert.NotNil(t, p)
	assert.NotNil(t, p.inMemProv)
	assert.NotNil(t, p.rsaKeyGenerator)
	assert.NotNil(t, p.ecdsaKeyGenerator)

	priv, err := p.GenerateKey(t.Context(), &cryptoprov.GenerateKeyRequest{
		Label: "inmemoryECDSA",
		Type:  certutil.KeyTypeECDSA,
		Size:  256,
	})
	require.NoError(t, err)
	assert.NotNil(t, priv)

	keyID, label, err := p.IdentifyKey(t.Context(), priv)
	require.NoError(t, err)
	assert.Equal(t, "inmemoryECDSA", label)

	l := len(p.inMemProv.keyIDToPvk)
	assert.Equal(t, 1, l)
	keyURI, keyBytes, err := p.ExportKey(t.Context(), keyID)
	require.NoError(t, err)
	assert.Empty(t, keyURI)
	assert.NotNil(t, keyBytes)
	assert.Contains(t, string(keyBytes), "-----BEGIN EC PRIVATE KEY-----\n")

	signer, ok := priv.(crypto.Signer)
	require.True(t, ok)

	digest := certutil.SHA1([]byte(keyID))
	_, err = signer.Sign(rand.Reader, digest, crypto.SHA1)
	require.NoError(t, err)
}

func TestSignRSA(t *testing.T) {
	p := NewProvider()
	assert.NotNil(t, p)
	assert.NotNil(t, p.inMemProv)
	assert.NotNil(t, p.rsaKeyGenerator)
	assert.NotNil(t, p.ecdsaKeyGenerator)

	priv, err := p.GenerateKey(t.Context(), &cryptoprov.GenerateKeyRequest{
		Label: "inmemoryRSA",
		Type:  certutil.KeyTypeRSA,
		Size:  1024,
	})
	require.NoError(t, err)
	assert.NotNil(t, priv)

	keyID, label, err := p.IdentifyKey(t.Context(), priv)
	require.NoError(t, err)
	assert.Equal(t, "inmemoryRSA", label)

	l := len(p.inMemProv.keyIDToPvk)
	assert.Equal(t, 1, l)
	keyURI, keyBytes, err := p.ExportKey(t.Context(), keyID)
	require.NoError(t, err)
	assert.Empty(t, keyURI)
	assert.NotNil(t, keyBytes)
	assert.Contains(t, string(keyBytes), "-----BEGIN RSA PRIVATE KEY-----\n")

	signer, ok := priv.(crypto.Signer)
	require.True(t, ok)

	digest := certutil.SHA1([]byte(keyID))
	_, err = signer.Sign(rand.Reader, digest, crypto.SHA1)
	require.NoError(t, err)
}
