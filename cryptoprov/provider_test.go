package cryptoprov_test

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"slices"
	"uuid"

	"github.com/effective-security/xpki/crypto11"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	"github.com/effective-security/xpki/cryptoprov/gcpkmscrypto"
	"github.com/effective-security/xpki/cryptoprov/inmemcrypto"
	"github.com/effective-security/xpki/cryptoprov/testprov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// closeProvider closes p when it implements Close() error, such as a
// PKCS#11 library.
func closeProvider(t *testing.T, p cryptoprov.Provider) {
	t.Helper()
	if closer, ok := p.(interface{ Close() error }); ok {
		assert.NoError(t, closer.Close())
	}
}

// loadP11Provider loads the SoftHSM token until the end of t; it skips or
// fails t as testenv.RequireFile does when the token is not configured.
func loadP11Provider(t *testing.T) cryptoprov.Provider {
	requireSoftHSM(t)
	p11, err := crypto11.ConfigureFromFile(SoftHSMConfig)
	require.NoError(t, err)
	t.Cleanup(func() { closeProvider(t, p11) })

	prov, supported := any(p11).(cryptoprov.Provider)
	require.True(t, supported)

	mgr, supported := any(p11).(cryptoprov.KeyManager)
	require.True(t, supported)
	assert.NotNil(t, mgr.EnumKeys)

	return prov
}

func TestRegistered(t *testing.T) {
	l := cryptoprov.Registered()
	require.NotEmpty(t, l)

	for _, name := range []string{
		"SoftHSM",
		inmemcrypto.ProviderName,
		awskmscrypto.ProviderName,
		gcpkmscrypto.ProviderName,
	} {
		assert.True(t, slices.Contains(l, name), "%s is not registered: %v", name, l)
	}
}

func TestInmem(t *testing.T) {
	cp, err := cryptoprov.Load("", nil)
	require.NoError(t, err)
	assert.Equal(t, inmemcrypto.ProviderName, cp.Default().Manufacturer())
}

func Test_P11(t *testing.T) {
	prov := loadP11Provider(t)

	inm, err := testprov.Init()
	require.NoError(t, err)

	cp, err := cryptoprov.New(prov, []cryptoprov.Provider{inm})
	require.NoError(t, err)

	err = cp.Add(prov)
	assert.NoError(t, err)
	err = cp.Add(prov)
	assert.NoError(t, err)

	d := cp.Default()
	assert.NotEmpty(t, d.Manufacturer())
	assert.NotNil(t, d.Model())

	_, err = cp.ByManufacturer(prov.Manufacturer(), prov.Model())
	assert.NoError(t, err)
	_, err = cp.ByManufacturer("NetHSM", "")
	assert.Error(t, err)
	assert.Equal(t, "provider for \"NetHSM\" and model \"\" not found", err.Error())

	keyURI, keyBytes, err := d.ExportKey("test")
	assert.Error(t, err)
	assert.Empty(t, keyURI)
	assert.Nil(t, keyBytes)

	t.Run("RSA-sign", func(t *testing.T) {
		rsaKeyLabel := "rsa" + uuid.NewV7().String()
		key, err := d.GenerateRSAKey(rsaKeyLabel, 1024, 1)
		require.NoError(t, err)

		keyID, keyLabel, err := d.IdentifyKey(key)
		require.NoError(t, err)
		assert.NotEmpty(t, keyID)
		assert.Equal(t, rsaKeyLabel, keyLabel)

		keyURI, keyBytes, err := d.ExportKey(keyID)
		assert.NoError(t, err)
		assert.NotEmpty(t, keyURI)
		assert.Nil(t, keyBytes)

		pvkURI, err := cryptoprov.ParsePrivateKeyURI(keyURI)
		require.NoError(t, err)
		assert.Equal(t, "SoftHSM", pvkURI.Manufacturer())
		assert.Equal(t, keyID, pvkURI.ID())

		_, pvk, err := cp.LoadPrivateKey([]byte(keyURI))
		require.NoError(t, err)

		message := []byte("To Be Signed")
		hashed := sha256.Sum256(message)

		signer, ok := pvk.(crypto.Signer)
		assert.True(t, ok, "crypto.Signer not supported")
		signature, err := signer.Sign(rand.Reader, hashed[:], crypto.SHA256)
		require.NoError(t, err)

		err = rsa.VerifyPKCS1v15(signer.Public().(*rsa.PublicKey), crypto.SHA256, hashed[:], signature)
		require.NoError(t, err)
	})

	t.Run("RSA-encrypt", func(t *testing.T) {
		rsaKeyLabel := "rsa" + uuid.NewV7().String()
		key, err := d.GenerateRSAKey(rsaKeyLabel, 1024, 2)
		require.NoError(t, err)

		keyID, keyLabel, err := d.IdentifyKey(key)
		require.NoError(t, err)
		assert.NotEmpty(t, keyID)
		assert.Equal(t, rsaKeyLabel, keyLabel)

		keyURI, keyBytes, err := d.ExportKey(keyID)
		assert.NoError(t, err)
		assert.NotEmpty(t, keyURI)
		assert.Nil(t, keyBytes)

		pvkURI, err := cryptoprov.ParsePrivateKeyURI(keyURI)
		require.NoError(t, err)
		assert.Equal(t, "SoftHSM", pvkURI.Manufacturer())
		assert.Equal(t, keyID, pvkURI.ID())

		_, pvk, err := cp.LoadPrivateKey([]byte(keyURI))
		require.NoError(t, err)

		message := []byte("To Be Encrypted")

		decryptor, ok := pvk.(crypto.Decrypter)
		assert.True(t, ok, "crypto.Decrypter not supported")

		// SoftHSM2 only implements OAEP with SHA-1/MGF1-SHA1
		encrypted, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, decryptor.Public().(*rsa.PublicKey), message, nil)
		require.NoError(t, err)

		decrypted, err := decryptor.Decrypt(rand.Reader, encrypted, &rsa.OAEPOptions{Hash: crypto.SHA1})
		require.NoError(t, err)
		assert.Equal(t, message, decrypted)
	})

	t.Run("ECDSA", func(t *testing.T) {
		ecdsaKeyLabel := "ecdsa" + uuid.NewV7().String()
		rsa, err := d.GenerateECDSAKey(ecdsaKeyLabel, elliptic.P256())
		require.NoError(t, err)

		keyID, keyLabel, err := d.IdentifyKey(rsa)
		require.NoError(t, err)
		assert.NotEmpty(t, keyID)
		assert.Equal(t, ecdsaKeyLabel, keyLabel)

		keyURI, keyBytes, err := d.ExportKey(keyID)
		assert.NoError(t, err)
		assert.NotEmpty(t, keyURI)
		assert.Nil(t, keyBytes)

		pvkURI, err := cryptoprov.ParsePrivateKeyURI(keyURI)
		require.NoError(t, err)
		assert.Equal(t, "SoftHSM", pvkURI.Manufacturer())
		assert.Equal(t, keyID, pvkURI.ID())

		_, _, err = cp.LoadPrivateKey([]byte(keyURI))
		require.NoError(t, err)
	})
}

// gcpStubClient satisfies gcpkmscrypto.KmsClient; loading a provider does
// not call the client.
type gcpStubClient struct {
	gcpkmscrypto.KmsClient
}

// TestLoad_KMSProviders loads the self-registered AWS and GCP KMS loaders by
// manufacturer from token configs, without contacting KMS: the AWS client is
// created lazily and the GCP client factory is replaced (XPKI-099).
func TestLoad_KMSProviders(t *testing.T) {
	original := gcpkmscrypto.KmsClientFactory
	t.Cleanup(func() { gcpkmscrypto.KmsClientFactory = original })
	gcpkmscrypto.KmsClientFactory = func() (gcpkmscrypto.KmsClient, error) {
		return gcpStubClient{}, nil
	}

	gcpCfg := writeTokenConfig(t, gcpkmscrypto.ProviderName, "unittest")
	cp, err := cryptoprov.Load("", []string{
		"awskmscrypto/testdata/aws-dev-kms.json",
		gcpCfg,
	})
	require.NoError(t, err)
	assert.Equal(t, inmemcrypto.ProviderName, cp.Default().Manufacturer())

	aws, err := cp.ByManufacturer(awskmscrypto.ProviderName, "14555")
	require.NoError(t, err)
	assert.IsType(t, &awskmscrypto.Provider{}, aws)

	gcp, err := cp.ByManufacturer(gcpkmscrypto.ProviderName, "unittest")
	require.NoError(t, err)
	require.IsType(t, &gcpkmscrypto.Provider{}, gcp)
	assert.Equal(t, gcpStubClient{}, gcp.(*gcpkmscrypto.Provider).KmsClient)

	// a second AWS config with the same manufacturer and model is rejected
	_, err = cryptoprov.Load("", []string{
		"awskmscrypto/testdata/aws-dev-kms.json",
		writeTokenConfig(t, awskmscrypto.ProviderName, "14555"),
	})
	assertIs(t, err, cryptoprov.ErrDuplicateProvider)
}
