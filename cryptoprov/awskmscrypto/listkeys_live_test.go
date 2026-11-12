package awskmscrypto_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/cryptoprov/awskmscrypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// liveKMSTagSearchEnv, when "true", makes TestLiveKMSListKeys also run with
// the TagSearch attribute, which needs tag:GetResources and kms:TagResource.
const liveKMSTagSearchEnv = "XPKI_LIVE_AWS_KMS_TAGSEARCH"

const (
	// liveTagLag bounds the wait for the Resource Groups Tagging API to
	// list a key that was just tagged, and liveTagPoll is the pause between
	// two attempts.
	liveTagLag  = 2 * time.Minute
	liveTagPoll = 5 * time.Second

	// liveTagName is the tag of the keys of the tag search test. It must not
	// start with "xpki-", which the provider reserves for its own tags.
	liveTagName = "live-test"
)

// liveListProvider returns a provider for the real KMS of region with the
// token config attributes.
func liveListProvider(t *testing.T, region, attributes string) *awskmscrypto.Provider {
	t.Helper()
	atts := "Region=" + region
	if attributes != "" {
		atts += "," + attributes
	}
	provider, err := awskmscrypto.KmsLoader(&mockTokenCfg{
		manufacturer: awskmscrypto.ProviderName,
		model:        "KMS",
		atts:         atts,
	})
	require.NoError(t, err)
	return provider.(*awskmscrypto.Provider)
}

// liveKey creates a P-256 signing key that is scheduled for deletion when
// the test ends, and returns its id.
func liveKey(t *testing.T, provider *awskmscrypto.Provider, label string, tags map[string]string) string {
	t.Helper()
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
		ctx := context.Background()
		info, err := provider.KeyInfo(ctx, keyID, cryptoprov.KeyFieldState)
		if err == nil && info.State == cryptoprov.KeyStatePendingDeletion {
			// the test destroyed it
			return
		}
		assert.NoError(t, provider.DestroyKey(ctx, keyID),
			"key %s is left in the account", keyID)
	})
	return keyID
}

// TestLiveKMSListKeys confirms the listing against the real service (PLAN.md
// KM11): ids without a filter, the usage filter, an exact label and a label
// prefix through the aliases, the state filter and the tags of a key; with
// XPKI_LIVE_AWS_KMS_TAGSEARCH=true also a tag filter through the Resource
// Groups Tagging API and a key that only its xpki-label tag finds. It needs
// kms:CreateKey, kms:CreateAlias, kms:ListKeys, kms:ListAliases,
// kms:DescribeKey, kms:GetPublicKey, kms:ListResourceTags and
// kms:ScheduleKeyDeletion, creates billable keys and schedules them for
// deletion. It is opt-in and does not follow XPKI_INTEGRATION.
func TestLiveKMSListKeys(t *testing.T) {
	region := os.Getenv(liveKMSRegionEnv)
	if region == "" {
		t.Skipf("%s is not set: no real AWS KMS to run against", liveKMSRegionEnv)
	}
	var tagged *awskmscrypto.Provider
	if os.Getenv(liveKMSTagSearchEnv) == "true" {
		tagged = liveListProvider(t, region, "TagSearch=true")
	}
	liveListFlow(t, liveListProvider(t, region, ""), tagged)
}

// TestLiveKMSListKeysOnFake runs the flow of TestLiveKMSListKeys on the fake
// KMS and the fake tagging API, so that the live test is known to be right
// before it creates billable keys.
func TestLiveKMSListKeysOnFake(t *testing.T) {
	t.Parallel()
	client := newFakeKMS()
	liveListFlow(t, providerWith(client, nil, ""), providerWith(client, newFakeTagging(client), ""))
}

// liveListFlow is the body of TestLiveKMSListKeys. tagged is a provider of
// the same account with the TagSearch attribute, or nil to leave the
// Resource Groups Tagging API out.
func liveListFlow(t *testing.T, provider, tagged *awskmscrypto.Provider) {
	prefix := "xpki-live-list-" + strings.ToLower(certutil.RandomString(8)) + "-"
	first := liveKey(t, provider, prefix+"a", nil)
	second := liveKey(t, provider, prefix+"b", nil)

	t.Run("ids", func(t *testing.T) {
		resp, err := provider.ListKeys(t.Context(), &cryptoprov.ListKeysRequest{PageSize: 5})
		require.NoError(t, err)
		require.NotEmpty(t, resp.Keys)
		assert.LessOrEqual(t, len(resp.Keys), 5)
		for _, key := range resp.Keys {
			assert.NotEmpty(t, key.ID)
			assert.Contains(t, key.Name, ":key/"+key.ID)
			assert.Empty(t, key.PublicKey)
		}
	})

	t.Run("exact label", func(t *testing.T) {
		keys := listAll(t, provider, &cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{Label: prefix + "a"},
			Fields: cryptoprov.KeyFieldMetadata | cryptoprov.KeyFieldState,
		})
		require.Len(t, keys, 1)
		assert.Equal(t, first, keys[0].ID)
		assert.Equal(t, prefix+"a", keys[0].Label)
		assert.Equal(t, certutil.KeyTypeECDSA, keys[0].Type)
		assert.Equal(t, 256, keys[0].Size)
		assert.Equal(t, cryptoprov.KeyUsageSign, keys[0].Usage)
		assert.Equal(t, cryptoprov.KeyStateEnabled, keys[0].State)
		assert.NotNil(t, keys[0].CreationTime)
	})

	t.Run("label prefix", func(t *testing.T) {
		for _, size := range []int{1, 0} {
			keys := listAll(t, provider, &cryptoprov.ListKeysRequest{
				PageSize: size,
				Filter: cryptoprov.KeyFilter{
					LabelPrefix: prefix,
					Usage:       cryptoprov.KeyUsageSign,
					States:      []cryptoprov.KeyState{cryptoprov.KeyStateEnabled},
				},
			})
			assert.ElementsMatch(t, []string{first, second}, keyIDs(keys), "page size %d", size)
		}
	})

	t.Run("usage filter", func(t *testing.T) {
		req := &cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{
				Usage: cryptoprov.KeyUsageSign,
				Types: []string{certutil.KeyTypeECDSA},
			},
		}
		// twice: the second listing reads the immutable metadata from
		// the cache
		for range 2 {
			ids := keyIDs(listAll(t, provider, req))
			assert.Contains(t, ids, first)
			assert.Contains(t, ids, second)
		}
		assert.Positive(t, awskmscrypto.MetadataCacheLen(provider))
	})

	t.Run("key info with tags", func(t *testing.T) {
		info, err := provider.KeyInfo(t.Context(), first, cryptoprov.KeyFieldsAll|cryptoprov.KeyFieldPublicKey)
		require.NoError(t, err)
		assert.Equal(t, first, info.ID)
		assert.NotNil(t, info.Tags, "ListResourceTags")
		assert.Contains(t, info.PublicKey, "PUBLIC KEY")

		_, err = provider.KeyInfo(t.Context(), "00000000-0000-0000-0000-000000000000", cryptoprov.KeyFieldMetadata)
		require.ErrorIs(t, err, cryptoprov.ErrKeyNotFound)
	})

	t.Run("tag search", func(t *testing.T) {
		if tagged == nil {
			t.Skipf("%s is not true: the Resource Groups Tagging API is not exercised", liveKMSTagSearchEnv)
		}
		value := strings.TrimSuffix(prefix, "-")
		tags := map[string]string{liveTagName: value}
		// the second key of a label gets no alias: only its tag finds it
		aliased := liveKey(t, tagged, prefix+"t", tags)
		orphan := liveKey(t, tagged, prefix+"t", tags)

		// the tagging API lists a new key after a while
		var keys []cryptoprov.KeyInfo
		for deadline := time.Now().Add(liveTagLag); ; time.Sleep(liveTagPoll) {
			keys = listAll(t, tagged, &cryptoprov.ListKeysRequest{
				Filter: cryptoprov.KeyFilter{Tags: tags},
				Fields: cryptoprov.KeyFieldMetadata | cryptoprov.KeyFieldTags,
			})
			if len(keys) == 2 || time.Now().After(deadline) {
				break
			}
		}
		require.Len(t, keys, 2, "keys with tag %s=%s after %s", liveTagName, value, liveTagLag)
		assert.ElementsMatch(t, []string{aliased, orphan}, keyIDs(keys))
		for _, key := range keys {
			assert.Equal(t, prefix+"t", key.Label, "from the xpki-label tag")
			assert.Equal(t, certutil.KeyTypeECDSA, key.Type)
			assert.Equal(t, 256, key.Size)
			assert.Equal(t, value, key.Tags[liveTagName])
		}

		keys = listAll(t, tagged, &cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{Label: prefix + "t"},
		})
		assert.ElementsMatch(t, []string{aliased, orphan}, keyIDs(keys), "the alias and the xpki-label tag")

		// without the tagging API only the alias finds a key
		keys = listAll(t, provider, &cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{Label: prefix + "t"},
		})
		assert.Equal(t, []string{aliased}, keyIDs(keys))
	})

	t.Run("pending deletion", func(t *testing.T) {
		doomed := liveKey(t, provider, prefix+"doomed", nil)
		require.NoError(t, provider.DestroyKey(t.Context(), doomed))
		info, err := provider.KeyInfo(t.Context(), doomed, cryptoprov.KeyFieldState)
		require.NoError(t, err)
		assert.Equal(t, cryptoprov.KeyStatePendingDeletion, info.State)

		keys := listAll(t, provider, &cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{
				Label:  prefix + "doomed",
				States: []cryptoprov.KeyState{cryptoprov.KeyStateEnabled},
			},
		})
		assert.Empty(t, keys)
	})
}
