package awskmscrypto_test

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/effective-security/x/guid"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_KmsProvider(t *testing.T) {
	os.Setenv("AWS_ACCESS_KEY_ID", "notusedbyemulator")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "notusedbyemulator")
	os.Setenv("AWS_DEFAULT_REGION", "us-west-2")
	cfg := &mockTokenCfg{
		manufacturer: awskmscrypto.ProviderName,
		model:        "KMS",
		atts:         "Endpoint=http://localhost:14556,Region=eu-west-2",
	}

	prov, err := awskmscrypto.KmsLoader(cfg)
	require.NoError(t, err)
	require.NotNil(t, prov)

	assert.Equal(t, awskmscrypto.ProviderName, prov.Manufacturer())
	assert.Equal(t, "KMS", prov.Model())

	mgr := prov.(cryptoprov.KeyManager)

	list, err := mgr.EnumTokens(false)
	require.NoError(t, err)
	require.NotEmpty(t, list)
	assert.Equal(t, awskmscrypto.ProviderName, list[0].Manufacturer)
	assert.Equal(t, "KMS", list[0].Model)

	_, err = mgr.EnumKeys(mgr.CurrentSlotID(), "")
	require.NoError(t, err)
	//require.Empty(t, keys)

	rsacases := []struct {
		size int
		hash crypto.Hash
	}{
		{2048, crypto.SHA256},
		{4096, crypto.SHA512},
	}

	for _, tc := range rsacases {
		pvk, err := prov.GenerateRSAKey(fmt.Sprintf("test_RSA_%d_%s", tc.size, guid.MustCreate()), tc.size, 1)
		require.NoError(t, err)

		keyID, _, err := prov.IdentifyKey(pvk)
		require.NoError(t, err)

		uri, _, err := prov.ExportKey(keyID)
		require.NoError(t, err)
		assert.Contains(t, uri, "pkcs11:manufacturer=")
		assert.Contains(t, uri, "model=")

		signer := pvk.(crypto.Signer)
		require.NotNil(t, signer)

		hash := tc.hash.New()
		digest := hash.Sum([]byte(`digest`))
		_, err = signer.Sign(rand.Reader, digest[:hash.Size()], tc.hash)
		require.NoError(t, err)
	}

	eccases := []struct {
		curve elliptic.Curve
		hash  crypto.Hash
	}{
		{elliptic.P256(), crypto.SHA256},
		{elliptic.P384(), crypto.SHA384},
		{elliptic.P521(), crypto.SHA512},
	}

	for _, tc := range eccases {
		pvk, err := prov.GenerateECDSAKey(fmt.Sprintf("test_ECC_%s", guid.MustCreate()), tc.curve)
		require.NoError(t, err)

		keyID, _, err := prov.IdentifyKey(pvk)
		require.NoError(t, err)

		_, err = prov.GetKey(keyID)
		require.NoError(t, err)

		signer := pvk.(crypto.Signer)
		require.NotNil(t, signer)

		hash := tc.hash.New()
		digest := hash.Sum([]byte(`digest`))
		_, err = signer.Sign(rand.Reader, digest[:hash.Size()], tc.hash)
		require.NoError(t, err)

		ki, err := mgr.KeyInfo(mgr.CurrentSlotID(), keyID, true)
		require.NoError(t, err)
		require.NotEmpty(t, ki)
	}

	keys, err := mgr.EnumKeys(mgr.CurrentSlotID(), "test_")
	require.NoError(t, err)
	require.NotEmpty(t, keys)
	for _, key := range keys {
		err = mgr.DestroyKeyPairOnSlot(mgr.CurrentSlotID(), key.ID)
		require.NoError(t, err)
	}

	_, err = mgr.FindKeyPairOnSlot(0, "123412", "")
	require.Error(t, err)
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
