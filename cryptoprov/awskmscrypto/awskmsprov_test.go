package awskmscrypto_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"

	"uuid"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/effective-security/xpki/cryptoprov"
	"github.com/effective-security/xpki/cryptoprov/awskmscrypto"
	"github.com/effective-security/xpki/internal/testenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// localKMSAddr and localKMSEndpoint are the local-kms container of
// testdata/aws-dev-kms.yaml (make start-local-kms).
const (
	localKMSAddr     = "localhost:14556"
	localKMSEndpoint = "http://" + localKMSAddr
)

// Test_KmsProvider is an integration test against local-kms (XPKI-100): it
// generates keys, checks the signatures locally, lists the keys it created
// by prefix and schedules them for deletion.
func Test_KmsProvider(t *testing.T) {
	testenv.RequireTCP(t, "local-kms", localKMSAddr)
	t.Setenv("AWS_ACCESS_KEY_ID", "notusedbyemulator")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "notusedbyemulator")
	t.Setenv("AWS_DEFAULT_REGION", "us-west-2")
	cfg := &mockTokenCfg{
		manufacturer: awskmscrypto.ProviderName,
		model:        "KMS",
		atts:         "Endpoint=" + localKMSEndpoint + ",Region=eu-west-2",
	}

	prov, err := awskmscrypto.KmsLoader(cfg)
	require.NoError(t, err)
	require.NotNil(t, prov)

	assert.Equal(t, awskmscrypto.ProviderName, prov.Manufacturer())
	assert.Equal(t, "KMS", prov.Model())

	mgr := prov.(cryptoprov.KeyManager)
	client := awskmscrypto.Client(prov.(*awskmscrypto.Provider))

	list, err := mgr.EnumTokens(false)
	require.NoError(t, err)
	require.NotEmpty(t, list)
	assert.Equal(t, awskmscrypto.ProviderName, list[0].Manufacturer)
	assert.Equal(t, "KMS", list[0].Model)

	_, err = mgr.EnumKeys(mgr.CurrentSlotID(), "")
	require.NoError(t, err)

	// every key of this run has a unique prefix, so the listing can be exact
	prefix := "test_" + uuid.NewV7().String() + "_"
	// created is every key of this run; signing is those with the prefix
	var created, signing []string
	t.Cleanup(func() {
		for _, keyID := range created {
			assert.NoError(t, mgr.DestroyKeyPairOnSlot(mgr.CurrentSlotID(), keyID))
		}
	})

	rsacases := []struct {
		size int
		hash crypto.Hash
	}{
		{2048, crypto.SHA256},
		{4096, crypto.SHA512},
	}

	for _, tc := range rsacases {
		label := fmt.Sprintf("%sRSA_%d", prefix, tc.size)
		pvk, err := prov.GenerateRSAKey(label, tc.size, 1)
		require.NoError(t, err)

		keyID, keyLabel, err := prov.IdentifyKey(pvk)
		require.NoError(t, err)
		assert.Equal(t, label, keyLabel)
		created = append(created, keyID)
		signing = append(signing, keyID)

		uri, _, err := prov.ExportKey(keyID)
		require.NoError(t, err)
		assert.Contains(t, uri, "pkcs11:manufacturer=")
		assert.Contains(t, uri, "model=")

		signer := pvk.(crypto.Signer)
		pub, ok := signer.Public().(*rsa.PublicKey)
		require.True(t, ok)
		assert.Equal(t, tc.size, pub.N.BitLen())

		digest := sum(tc.hash, "digest")
		sig, err := signer.Sign(rand.Reader, digest, tc.hash)
		require.NoError(t, err)
		require.NoError(t, rsa.VerifyPKCS1v15(pub, tc.hash, digest, sig))

		pssOpts := &rsa.PSSOptions{
			Hash:       tc.hash,
			SaltLength: rsa.PSSSaltLengthEqualsHash,
		}
		sig, err = signer.Sign(rand.Reader, digest, pssOpts)
		require.NoError(t, err)
		// KMS uses a salt of the hash length, but local-kms uses a maximal
		// salt, so the salt length is not checked here (signer_test.go does).
		require.NoError(t, rsa.VerifyPSS(pub, tc.hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}))

		// invalid options fail before any RPC
		_, err = signer.Sign(rand.Reader, digest, nil)
		require.EqualError(t, err, "signer options are required")
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
		label := fmt.Sprintf("%sECC_%s", prefix, tc.curve.Params().Name)
		pvk, err := prov.GenerateECDSAKey(label, tc.curve)
		require.NoError(t, err)

		keyID, _, err := prov.IdentifyKey(pvk)
		require.NoError(t, err)
		created = append(created, keyID)
		signing = append(signing, keyID)

		found, err := prov.GetKey(keyID)
		require.NoError(t, err)
		foundID, foundLabel, err := prov.IdentifyKey(found)
		require.NoError(t, err)
		assert.Equal(t, keyID, foundID)
		assert.Equal(t, label, foundLabel)

		signer := pvk.(crypto.Signer)
		pub, ok := signer.Public().(*ecdsa.PublicKey)
		require.True(t, ok)
		assert.Equal(t, tc.curve, pub.Curve)

		digest := sum(tc.hash, "digest")
		sig, err := signer.Sign(rand.Reader, digest, tc.hash)
		require.NoError(t, err)
		assert.True(t, ecdsa.VerifyASN1(pub, digest, sig))

		// the key supports only the algorithm of its curve
		other := crypto.SHA256
		if tc.hash == crypto.SHA256 {
			other = crypto.SHA384
		}
		_, err = signer.Sign(rand.Reader, sum(other, "digest"), other)
		require.ErrorContains(t, err, "does not support ECDSA_")

		ki, err := mgr.KeyInfo(mgr.CurrentSlotID(), keyID, true)
		require.NoError(t, err)
		assert.Equal(t, keyID, ki.ID)
		assert.Equal(t, label, ki.Label)
		assert.Contains(t, ki.PublicKey, "PUBLIC KEY")
		assert.Equal(t, "SIGN_VERIFY", ki.Meta["usage"])
	}

	// an encryption key is not generated (XPKI-031) and not returned by GetKey
	_, err = prov.GenerateRSAKey(prefix+"encrypt", 2048, 2)
	require.EqualError(t, err, "unsupported key purpose: 2, only signing keys are supported")

	encrypt, err := client.CreateKey(context.Background(), &kms.CreateKeyInput{
		KeySpec:     types.KeySpecRsa2048,
		KeyUsage:    types.KeyUsageTypeEncryptDecrypt,
		Description: aws.String(prefix + "encrypt"),
	})
	require.NoError(t, err)
	encryptID := aws.ToString(encrypt.KeyMetadata.KeyId)
	created = append(created, encryptID)
	_, err = prov.GetKey(encryptID)
	require.EqualError(t, err, fmt.Sprintf("key %s usage ENCRYPT_DECRYPT is not valid for signing", encryptID))

	// a key with another prefix is not listed
	otherPrefix := "other_" + uuid.NewV7().String()
	otherKey, err := prov.GenerateECDSAKey(otherPrefix, elliptic.P256())
	require.NoError(t, err)
	otherID, _, err := prov.IdentifyKey(otherKey)
	require.NoError(t, err)
	created = append(created, otherID)

	// the listing has exactly the signing keys of this run
	keys, err := mgr.EnumKeys(mgr.CurrentSlotID(), prefix)
	require.NoError(t, err)
	listed := make([]string, 0, len(keys))
	for _, key := range keys {
		listed = append(listed, key.ID)
		assert.True(t, strings.HasPrefix(key.Label, prefix), key.Label)
		assert.Equal(t, key.Label, key.Meta["description"])
	}
	assert.ElementsMatch(t, signing, listed, "signing keys with the prefix, without the encryption key")

	keys, err = mgr.EnumKeys(mgr.CurrentSlotID(), otherPrefix)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, otherID, keys[0].ID)

	_, err = mgr.FindKeyPairOnSlot(0, "123412", "")
	require.Error(t, err)
}

// sum returns the hash digest of msg.
func sum(hash crypto.Hash, msg string) []byte {
	h := hash.New()
	_, _ = h.Write([]byte(msg))
	return h.Sum(nil)
}
