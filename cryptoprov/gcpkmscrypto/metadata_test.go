package gcpkmscrypto_test

import (
	"crypto/elliptic"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	bareKeyID     = "bare"
	bareVersionID = bareKeyID + "/cryptoKeyVersions/1"
)

// bareKey has none of the optional metadata: no VersionTemplate, CreateTime
// or Primary.
func bareKey() *kmspb.CryptoKey {
	return &kmspb.CryptoKey{
		Name:    coverageKeyring + "/cryptoKeys/" + bareKeyID,
		Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
		Labels: map[string]string{
			"zeta":  "z",
			"label": "bare",
		},
	}
}

// bareVersion has only a name and a state.
func bareVersion() *kmspb.CryptoKeyVersion {
	return &kmspb.CryptoKeyVersion{
		Name:  coverageKeyring + "/cryptoKeys/" + bareVersionID,
		State: kmspb.CryptoKeyVersion_ENABLED,
	}
}

// TestKeyInfoMissingMetadata checks that optional metadata missing from KMS
// responses is left out instead of dereferenced (XPKI-023).
func TestKeyInfoMissingMetadata(t *testing.T) {
	t.Parallel()

	client := &fakeKMS{
		getCryptoKey: func(*kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
			return bareKey(), nil
		},
		getCryptoKeyVersion: func(*kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
			return bareVersion(), nil
		},
	}
	ki, err := newProvider(t, client).KeyInfo(0, bareVersionID, false)
	require.NoError(t, err)
	assert.Equal(t, "bare", ki.ID)
	assert.Equal(t, "1", ki.CurrentVersionID)
	assert.Equal(t, "label=bare,zeta=z", ki.Label)
	assert.Nil(t, ki.CreationTime)
	assert.Equal(t, map[string]string{
		"purpose": "ASYMMETRIC_SIGN",
		"state":   "ENABLED",
	}, ki.Meta)
}

func TestKeyInfoFullMetadata(t *testing.T) {
	t.Parallel()

	created := time.Unix(1000, 0).UTC()
	key := bareKey()
	key.CreateTime = timestamppb.New(created)
	key.VersionTemplate = &kmspb.CryptoKeyVersionTemplate{
		ProtectionLevel: kmspb.ProtectionLevel_HSM,
		Algorithm:       kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
	}
	key.Primary = &kmspb.CryptoKeyVersion{State: kmspb.CryptoKeyVersion_ENABLED}
	// the version's own algorithm and protection win over the template's
	version := enabledVersion(bareKeyID, kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384)
	version.ProtectionLevel = kmspb.ProtectionLevel_SOFTWARE
	version.State = kmspb.CryptoKeyVersion_DISABLED
	client := &fakeKMS{
		getCryptoKey: func(*kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
			return key, nil
		},
		getCryptoKeyVersion: func(*kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
			return version, nil
		},
	}
	ki, err := newProvider(t, client).KeyInfo(0, bareVersionID, false)
	require.NoError(t, err)
	assert.Equal(t, "protection=HSM,label=bare,zeta=z", ki.Label)
	assert.Equal(t, "1", ki.CurrentVersionID)
	require.NotNil(t, ki.CreationTime)
	assert.Equal(t, created, *ki.CreationTime)
	assert.Equal(t, map[string]string{
		"protection": "SOFTWARE",
		"algo":       "EC_SIGN_P384_SHA384",
		"purpose":    "ASYMMETRIC_SIGN",
		"state":      "DISABLED",
	}, ki.Meta)
}

// TestEmptyResponses checks that a nil response without an error, which a
// KMS client should never return, is an error rather than a panic.
func TestEmptyResponses(t *testing.T) {
	t.Parallel()

	noKey := func(*kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) { return nil, nil }
	noVersion := func(*kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) { return nil, nil }
	noPublic := func(*kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) { return nil, nil }
	withKey := func(*kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) { return bareKey(), nil }
	withVersion := func(*kmspb.GetCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
		return enabledVersion(bareKeyID, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256), nil
	}

	for _, tc := range []struct {
		name   string
		client *fakeKMS
		op     func(*fakeKMS) error
		err    string
	}{
		{
			name:   "GetKey key",
			client: &fakeKMS{getCryptoKey: noKey},
			op:     func(c *fakeKMS) error { _, err := newProvider(t, c).GetKey(bareVersionID); return err },
			err:    "failed to get key: empty response",
		},
		{
			name:   "GetKey version",
			client: &fakeKMS{getCryptoKey: withKey, getCryptoKeyVersion: noVersion},
			op:     func(c *fakeKMS) error { _, err := newProvider(t, c).GetKey(bareVersionID); return err },
			err:    "failed to get key version bare/cryptoKeyVersions/1: empty response",
		},
		{
			name:   "GetKey versions",
			client: &fakeKMS{getCryptoKey: withKey},
			op:     func(c *fakeKMS) error { _, err := newProvider(t, c).GetKey(bareKeyID); return err },
			err:    "failed to list versions of key bare: empty response",
		},
		{
			name:   "GetKey public",
			client: &fakeKMS{getCryptoKey: withKey, getCryptoKeyVersion: withVersion, getPublicKey: noPublic},
			op:     func(c *fakeKMS) error { _, err := newProvider(t, c).GetKey(bareVersionID); return err },
			err:    "failed to get public key: empty response",
		},
		{
			name:   "KeyInfo key",
			client: &fakeKMS{getCryptoKey: noKey},
			op:     func(c *fakeKMS) error { _, err := newProvider(t, c).KeyInfo(0, bareVersionID, false); return err },
			err:    "failed to describe key, id=bare/cryptoKeyVersions/1: empty response",
		},
		{
			name:   "KeyInfo version",
			client: &fakeKMS{getCryptoKey: withKey, getCryptoKeyVersion: noVersion},
			op:     func(c *fakeKMS) error { _, err := newProvider(t, c).KeyInfo(0, bareVersionID, false); return err },
			err:    "failed to get key version bare/cryptoKeyVersions/1: empty response",
		},
		{
			name:   "KeyInfo public",
			client: &fakeKMS{getCryptoKey: withKey, getCryptoKeyVersion: withVersion, getPublicKey: noPublic},
			op:     func(c *fakeKMS) error { _, err := newProvider(t, c).KeyInfo(0, bareVersionID, true); return err },
			err:    "failed to get public key, id=bare/cryptoKeyVersions/1: empty response",
		},
		{
			name: "GenerateECDSAKey create",
			client: &fakeKMS{createCryptoKey: func(*kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
				return nil, nil
			}},
			op: func(c *fakeKMS) error {
				_, err := newProvider(t, c).GenerateECDSAKey("label", elliptic.P256())
				return err
			},
			err: "failed to create key: empty response",
		},
		{
			name: "GenerateECDSAKey version",
			client: &fakeKMS{
				createCryptoKey: func(*kmspb.CreateCryptoKeyRequest) (*kmspb.CryptoKey, error) {
					return bareKey(), nil
				},
				getCryptoKeyVersion: noVersion,
			},
			op: func(c *fakeKMS) error {
				_, err := newProvider(t, c).GenerateECDSAKey("label", elliptic.P256())
				return err
			},
			err: "failed to get key version " + coverageKeyring + "/cryptoKeys/bare/cryptoKeyVersions/1: empty response",
		},
		{
			name:   "KeyInfo versions",
			client: &fakeKMS{getCryptoKey: withKey},
			op:     func(c *fakeKMS) error { _, err := newProvider(t, c).KeyInfo(0, bareKeyID, false); return err },
			err:    "failed to list versions of key bare: empty response",
		},
		{
			name:   "DestroyKeyPairOnSlot versions",
			client: &fakeKMS{},
			op:     func(c *fakeKMS) error { return newProvider(t, c).DestroyKeyPairOnSlot(0, bareKeyID) },
			err:    "failed to list versions of key bare: empty response",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.op(tc.client)
			require.Error(t, err)
			assert.Equal(t, tc.err, err.Error())
		})
	}

	t.Run("DestroyKeyPairOnSlot", func(t *testing.T) {
		t.Parallel()
		// a nil response confirms nothing (XPKI-123)
		client := &fakeKMS{
			destroyCryptoKeyVersion: func(*kmspb.DestroyCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
				return nil, nil
			},
		}
		err := newProvider(t, client).DestroyKeyPairOnSlot(0, bareVersionID)
		require.EqualError(t, err, "failed to schedule key deletion: bare/cryptoKeyVersions/1: empty response")
	})
}
