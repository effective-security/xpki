package gcpkmscrypto_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/cryptoprov/gcpkmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLiveKMSListKeys confirms the listing against the real service: the
// page size and the page token of KMS, and the filter forms the provider
// sends for an exact label, a label prefix and a tag ("labels.k=v",
// "labels.label:v", joined with AND), which the documentation describes. A
// filter KMS rejects fails the test with its INVALID_ARGUMENT. It passed in
// us-central1 on 2026-11-12. It creates billable HSM keys in the key
// ring of XPKI_LIVE_GCP_KMS_KEYRING and schedules their versions for
// destruction; a CryptoKey itself cannot be deleted. It is opt-in and does
// not follow XPKI_INTEGRATION.
func TestLiveKMSListKeys(t *testing.T) {
	keyring := os.Getenv(liveKMSKeyringEnv)
	if keyring == "" {
		t.Skipf("%s is not set: no real Cloud KMS to run against", liveKMSKeyringEnv)
	}
	loaded, err := gcpkmscrypto.KmsLoader(&mockTokenCfg{
		manufacturer: gcpkmscrypto.ProviderName,
		model:        "KMS",
		atts:         "Keyring=" + keyring,
	})
	require.NoError(t, err)
	provider := loaded.(*gcpkmscrypto.Provider)
	t.Cleanup(func() {
		assert.NoError(t, provider.Close())
	})
	liveListFlow(t, provider)
}

// TestLiveKMSListKeysOnFake runs the flow of TestLiveKMSListKeys on the
// in-process KMS, so that the live test is known to be right before it
// creates billable keys.
func TestLiveKMSListKeysOnFake(t *testing.T) {
	t.Parallel()
	liveListFlow(t, grpcProvider(t, newFakeKMSServer()))
}

// liveListFlow is the body of TestLiveKMSListKeys.
func liveListFlow(t *testing.T, provider *gcpkmscrypto.Provider) {
	suffix := strings.ToLower(certutil.RandomString(8))
	prefix := "xpki-live-list-" + suffix + "-"
	tags := map[string]string{"xpki-live": suffix}
	generate := func(label string, tags map[string]string) string {
		priv, err := provider.GenerateKey(t.Context(), &cryptoprov.GenerateKeyRequest{
			Label: label,
			Type:  certutil.KeyTypeECDSA,
			Size:  256,
			Tags:  tags,
		})
		require.NoError(t, err)
		keyID, _, err := provider.IdentifyKey(t.Context(), priv)
		require.NoError(t, err)
		t.Cleanup(func() {
			// the context of the test is done by now
			assert.NoError(t, provider.DestroyKey(context.Background(), keyID),
				"key %s is left in the key ring", keyID)
		})
		id, _, _ := strings.Cut(keyID, "/cryptoKeyVersions/")
		return id
	}
	first := generate(prefix+"a", tags)
	second := generate(prefix+"b", nil)

	t.Run("pages", func(t *testing.T) {
		resp, err := provider.ListKeys(t.Context(), &cryptoprov.ListKeysRequest{PageSize: 1})
		require.NoError(t, err)
		require.Len(t, resp.Keys, 1)
		assert.NotEmpty(t, resp.NextPageToken, "the key ring has at least the two keys of this test")
		assert.Empty(t, resp.Keys[0].State, "no version is read for a listing without the state")
	})

	for name, tc := range map[string]struct {
		filter cryptoprov.KeyFilter
		ids    []string
	}{
		"exact label": {
			filter: cryptoprov.KeyFilter{Label: prefix + "a"},
			ids:    []string{first},
		},
		"label prefix": {
			filter: cryptoprov.KeyFilter{LabelPrefix: prefix},
			ids:    []string{first, second},
		},
		"tag": {
			filter: cryptoprov.KeyFilter{Tags: tags},
			ids:    []string{first},
		},
		"tag and prefix": {
			filter: cryptoprov.KeyFilter{
				LabelPrefix: prefix,
				Tags:        tags,
				Usage:       cryptoprov.KeyUsageSign,
				Types:       []string{certutil.KeyTypeECDSA},
			},
			ids: []string{first},
		},
		"enabled": {
			filter: cryptoprov.KeyFilter{
				LabelPrefix: prefix,
				States:      []cryptoprov.KeyState{cryptoprov.KeyStateEnabled},
			},
			ids: []string{first, second},
		},
	} {
		t.Run(name, func(t *testing.T) {
			keys := listAll(t, provider, &cryptoprov.ListKeysRequest{
				Filter: tc.filter,
				Fields: cryptoprov.KeyFieldMetadata | cryptoprov.KeyFieldTags,
			})
			assert.ElementsMatch(t, tc.ids, listedIDs(keys))
			for _, key := range keys {
				assert.True(t, strings.HasPrefix(key.Label, prefix), key.Label)
				assert.Equal(t, certutil.KeyTypeECDSA, key.Type)
				assert.Equal(t, 256, key.Size)
				assert.Equal(t, cryptoprov.KeyUsageSign, key.Usage)
				assert.Equal(t, key.Label, key.Tags["label"])
			}
		})
	}

	t.Run("key info", func(t *testing.T) {
		info, err := provider.KeyInfo(t.Context(), first, cryptoprov.KeyFieldsAll|cryptoprov.KeyFieldPublicKey)
		require.NoError(t, err)
		assert.Equal(t, first, info.ID)
		assert.Equal(t, cryptoprov.KeyStateEnabled, info.State)
		assert.Equal(t, "1", info.CurrentVersionID)
		assert.Equal(t, suffix, info.Tags["xpki-live"])
		assert.Contains(t, info.PublicKey, "PUBLIC KEY")

		_, err = provider.KeyInfo(t.Context(), prefix+"missing", cryptoprov.KeyFieldMetadata)
		require.ErrorIs(t, err, cryptoprov.ErrKeyNotFound)
	})
}
