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

// bareKey has none of the optional metadata: no VersionTemplate, CreateTime
// or Primary.
func bareKey() *kmspb.CryptoKey {
	return &kmspb.CryptoKey{
		Name:    coverageKeyring + "/cryptoKeys/bare",
		Purpose: kmspb.CryptoKey_ASYMMETRIC_SIGN,
		Labels: map[string]string{
			"zeta":  "z",
			"label": "bare",
		},
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
	}
	ki, err := newProvider(t, client).KeyInfo(0, "bare", false)
	require.NoError(t, err)
	assert.Equal(t, "bare", ki.ID)
	assert.Equal(t, "label=bare,zeta=z", ki.Label)
	assert.Nil(t, ki.CreationTime)
	assert.Equal(t, map[string]string{"purpose": "ASYMMETRIC_SIGN"}, ki.Meta)
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
	client := &fakeKMS{
		getCryptoKey: func(*kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) {
			return key, nil
		},
	}
	ki, err := newProvider(t, client).KeyInfo(0, "bare", false)
	require.NoError(t, err)
	assert.Equal(t, "protection=HSM,label=bare,zeta=z", ki.Label)
	require.NotNil(t, ki.CreationTime)
	assert.Equal(t, created, *ki.CreationTime)
	assert.Equal(t, map[string]string{
		"protection": "HSM",
		"algo":       "EC_SIGN_P256_SHA256",
		"purpose":    "ASYMMETRIC_SIGN",
		"state":      "ENABLED",
	}, ki.Meta)
}

// TestEmptyResponses checks that a nil response without an error, which a
// KMS client should never return, is an error rather than a panic.
func TestEmptyResponses(t *testing.T) {
	t.Parallel()

	noKey := func(*kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) { return nil, nil }
	noPublic := func(*kmspb.GetPublicKeyRequest) (*kmspb.PublicKey, error) { return nil, nil }
	withKey := func(*kmspb.GetCryptoKeyRequest) (*kmspb.CryptoKey, error) { return bareKey(), nil }

	for _, tc := range []struct {
		name   string
		client *fakeKMS
		op     func(*fakeKMS) error
		err    string
	}{
		{
			name:   "GetKey key",
			client: &fakeKMS{getCryptoKey: noKey},
			op:     func(c *fakeKMS) error { _, err := newProvider(t, c).GetKey("bare"); return err },
			err:    "failed to get key: empty response",
		},
		{
			name:   "GetKey public",
			client: &fakeKMS{getCryptoKey: withKey, getPublicKey: noPublic},
			op:     func(c *fakeKMS) error { _, err := newProvider(t, c).GetKey("bare"); return err },
			err:    "failed to parse public key: invalid block type",
		},
		{
			name:   "KeyInfo key",
			client: &fakeKMS{getCryptoKey: noKey},
			op:     func(c *fakeKMS) error { _, err := newProvider(t, c).KeyInfo(0, "bare", false); return err },
			err:    "failed to describe key, id=bare: empty response",
		},
		{
			name:   "KeyInfo public",
			client: &fakeKMS{getCryptoKey: withKey, getPublicKey: noPublic},
			op:     func(c *fakeKMS) error { _, err := newProvider(t, c).KeyInfo(0, "bare", true); return err },
			err:    "failed to get public key, id=bare: empty response",
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
		// the destroy time is only logged; the request succeeded
		client := &fakeKMS{
			destroyCryptoKeyVersion: func(*kmspb.DestroyCryptoKeyVersionRequest) (*kmspb.CryptoKeyVersion, error) {
				return nil, nil
			},
		}
		assert.NoError(t, newProvider(t, client).DestroyKeyPairOnSlot(0, "bare"))
	})
}
