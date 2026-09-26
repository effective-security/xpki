package gcpkmscrypto_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProviderEndToEnd loads the provider through KmsLoader against the fake
// KMS and runs every KeyGenerator and KeyManager operation on the keys it
// generates, verifying each signature with the returned public key.
func TestProviderEndToEnd(t *testing.T) {
	s := newFakeKMSServer()
	addr := startFakeKMS(t, s)
	swapFactory(t, func(endpoint string) (gcpkmscrypto.KmsClient, error) {
		return gcpkmscrypto.NewKmsClient(context.Background(), endpoint, localClientOptions()...)
	})

	prov, err := gcpkmscrypto.KmsLoader(&mockTokenCfg{
		manufacturer: gcpkmscrypto.ProviderName,
		model:        "KMS",
		atts:         "Endpoint=" + addr + ",Keyring=" + testKeyring,
	})
	require.NoError(t, err)
	require.NotNil(t, prov)
	assert.Equal(t, gcpkmscrypto.ProviderName, prov.Manufacturer())
	assert.Equal(t, "KMS", prov.Model())

	mgr, ok := prov.(cryptoprov.KeyManager)
	require.True(t, ok)
	tokens, err := mgr.EnumTokens(false)
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, gcpkmscrypto.ProviderName, tokens[0].Manufacturer)
	assert.Equal(t, "KMS", tokens[0].Model)
	assert.Equal(t, mgr.CurrentSlotID(), tokens[0].SlotID)

	var keyIDs []string
	for _, tc := range []struct {
		size int
		hash crypto.Hash
	}{
		{2048, crypto.SHA256},
		{3072, crypto.SHA256},
		{4096, crypto.SHA512},
	} {
		pvk, err := prov.GenerateRSAKey("RSA*", tc.size, 1)
		require.NoError(t, err)
		keyID, label, err := prov.IdentifyKey(pvk)
		require.NoError(t, err)
		assert.Equal(t, "rsa", label)
		assert.Regexp(t, `^rsa-[a-z2-7]{8}/cryptoKeyVersions/1$`, keyID)
		keyIDs = append(keyIDs, keyID)

		uri, key, err := prov.ExportKey(keyID)
		require.NoError(t, err)
		assert.Equal(t, "pkcs11:manufacturer=GCPKMS;model=KMS;id="+keyID+";serial=1;type=private", uri)
		assert.Equal(t, uri, string(key))

		// the exported URI loads the same key version
		pkuri, err := cryptoprov.ParsePrivateKeyURI(uri)
		require.NoError(t, err)
		loaded, err := prov.GetKey(pkuri.ID())
		require.NoError(t, err)
		assert.Equal(t, keyID, loaded.(*gcpkmscrypto.Signer).KeyID())

		signer := pvk.(crypto.Signer)
		pub, ok := signer.Public().(*rsa.PublicKey)
		require.True(t, ok, "%T", signer.Public())
		assert.Equal(t, tc.size, pub.N.BitLen())
		assert.True(t, pub.Equal(loaded.(crypto.Signer).Public()))

		h := tc.hash.New()
		h.Write([]byte("digest"))
		digest := h.Sum(nil)
		sig, err := signer.Sign(rand.Reader, digest, tc.hash)
		require.NoError(t, err)
		require.NoError(t, rsa.VerifyPKCS1v15(pub, tc.hash, digest, sig))
	}

	for _, tc := range []struct {
		curve elliptic.Curve
		hash  crypto.Hash
	}{
		{elliptic.P256(), crypto.SHA256},
		{elliptic.P384(), crypto.SHA384},
	} {
		pvk, err := prov.GenerateECDSAKey("ECC", tc.curve)
		require.NoError(t, err)
		keyID, label, err := prov.IdentifyKey(pvk)
		require.NoError(t, err)
		assert.Equal(t, "ecc", label)
		keyIDs = append(keyIDs, keyID)

		loaded, err := prov.GetKey(keyID)
		require.NoError(t, err)
		signer := loaded.(crypto.Signer)
		pub, ok := signer.Public().(*ecdsa.PublicKey)
		require.True(t, ok, "%T", signer.Public())
		assert.Equal(t, tc.curve, pub.Curve)

		h := tc.hash.New()
		h.Write([]byte("digest"))
		digest := h.Sum(nil)
		sig, err := signer.Sign(rand.Reader, digest, tc.hash)
		require.NoError(t, err)
		assert.True(t, ecdsa.VerifyASN1(pub, digest, sig))

		ki, err := mgr.KeyInfo(mgr.CurrentSlotID(), keyID, true)
		require.NoError(t, err)
		assert.Equal(t, "1", ki.CurrentVersionID)
		assert.Equal(t, "ENABLED", ki.Meta["state"])
		assert.Equal(t, publicPEM(t, pub), ki.PublicKey)
	}

	keys, err := mgr.EnumKeys(mgr.CurrentSlotID(), "")
	require.NoError(t, err)
	require.Len(t, keys, len(keyIDs))
	for _, ki := range keys {
		assert.Regexp(t, `^(rsa|ecc)-[a-z2-7]{8}$`, ki.ID)
		assert.Contains(t, ki.Label, "protection=HSM,label=")
		assert.NotNil(t, ki.CreationTime)
	}

	for _, keyID := range keyIDs {
		require.NoError(t, mgr.DestroyKeyPairOnSlot(mgr.CurrentSlotID(), keyID))
		assert.Equal(t, kmspb.CryptoKeyVersion_DESTROY_SCHEDULED, s.State(t, testKeyring+"/cryptoKeys/"+keyID))
	}
	_, err = prov.GetKey(keyIDs[0])
	require.Error(t, err)

	_, err = mgr.FindKeyPairOnSlot(0, "123412", "")
	require.Error(t, err)

	closer, ok := prov.(io.Closer)
	require.True(t, ok)
	require.NoError(t, closer.Close())
	_, err = prov.GetKey(keyIDs[0])
	require.ErrorIs(t, err, gcpkmscrypto.ErrClosed)
}

//
// mockTokenCfg
//

type mockTokenCfg struct {
	manufacturer string
	model        string
	path         string
	tokenSerial  string
	tokenLabel   string
	pin          string
	atts         string
}

// Manufacturer name of the manufacturer
func (m *mockTokenCfg) Manufacturer() string {
	return m.manufacturer
}

// Model name of the device
func (m *mockTokenCfg) Model() string {
	return m.model
}

// Full path to PKCS#11 library
func (m *mockTokenCfg) Path() string {
	return m.path
}

// Token serial number
func (m *mockTokenCfg) TokenSerial() string {
	return m.tokenSerial
}

// Token label
func (m *mockTokenCfg) TokenLabel() string {
	return m.tokenLabel
}

// Pin is a secret to access the token.
// If it's prefixed with `file:`, then it will be loaded from the file.
func (m *mockTokenCfg) Pin() string {
	return m.pin
}

// Comma separated key=value pair of attributes(e.g. "ServiceName=x,UserName=y")
func (m *mockTokenCfg) Attributes() string {
	return m.atts
}
