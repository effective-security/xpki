package awskmscrypto_test

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/aws/smithy-go"
	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/cryptoprov/awskmscrypto"
	"github.com/effective-security/xpki/v2/internal/provtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// barrierTimeout bounds the wait of a test hook on other calls, so a broken
// implementation fails the test instead of hanging it.
const barrierTimeout = 10 * time.Second

// v1States are the states a v1 EnumKeys listed.
var v1States = []cryptoprov.KeyState{
	cryptoprov.KeyStateEnabled,
	cryptoprov.KeyStateDisabled,
}

// keyIDs returns the ids of keys.
func keyIDs(keys []cryptoprov.KeyInfo) []string {
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		ids = append(ids, key.ID)
	}
	return ids
}

// addSigningKeys adds total P-256 signing keys labelled "key_<n>" to client
// and returns their ids in listing order.
func addSigningKeys(t testing.TB, client *fakeKMS, total int) []string {
	t.Helper()
	ids := make([]string, 0, total)
	for i := range total {
		ids = append(ids, client.mustAddKey(t, "key_"+strconv.Itoa(i), types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify))
	}
	return ids
}

// awaitBarrier waits for done to be closed and returns an error when it is
// not closed within barrierTimeout.
func awaitBarrier(done <-chan struct{}) error {
	select {
	case <-done:
		return nil
	case <-time.After(barrierTimeout):
		return errors.New("test barrier timed out")
	}
}

// listAll returns the keys of every page of req.
func listAll(t testing.TB, km cryptoprov.KeyManager, req *cryptoprov.ListKeysRequest) []cryptoprov.KeyInfo {
	t.Helper()
	keys := []cryptoprov.KeyInfo{}
	for key, err := range cryptoprov.AllKeys(t.Context(), km, req) {
		require.NoError(t, err)
		keys = append(keys, *key)
	}
	return keys
}

// providerWith returns a provider over client with the token config
// attributes, and over tagging when it is not nil.
func providerWith(client awskmscrypto.KmsClient, tagging awskmscrypto.TaggingClient, attributes string) *awskmscrypto.Provider {
	cfg := testTokenCfg()
	cfg.atts = attributes
	return awskmscrypto.NewTaggingTestProvider(cfg, client, tagging)
}

// callCounts is a snapshot of the calls of a fake client.
type callCounts map[string]int

// counts returns the calls of client so far.
func counts(client *fakeKMS) callCounts {
	client.mu.Lock()
	defer client.mu.Unlock()
	c := callCounts{}
	for name, n := range client.calls {
		c[name] = n
	}
	return c
}

// since returns the calls of client after the snapshot, without the
// methods that were not called.
func (c callCounts) since(client *fakeKMS) callCounts {
	diff := callCounts{}
	for name, n := range counts(client) {
		if d := n - c[name]; d > 0 {
			diff[name] = d
		}
	}
	return diff
}

// TestListKeysIDsOnly checks that a listing without a filter and without
// fields is ListKeys alone: one request per page, no DescribeKey, and every
// key once in listing order.
func TestListKeysIDsOnly(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	provider := newProvider(t, client)
	total := 2*awskmscrypto.ListKeysLimit + 5
	ids := addSigningKeys(t, client, total)

	before := counts(client)
	keys := listAll(t, provider, &cryptoprov.ListKeysRequest{})
	assert.Equal(t, ids, keyIDs(keys))
	assert.Equal(t, callCounts{"ListKeys": 3}, before.since(client), "the KMS maximum page by default")
	for _, key := range keys[:3] {
		assert.Equal(t, fakeArnBase+"key/"+key.ID, key.Name)
		assert.Empty(t, key.Label, "not asked for and not free")
		assert.Empty(t, key.PublicKey)
	}

	before = counts(client)
	keys = listAll(t, provider, &cryptoprov.ListKeysRequest{PageSize: 500})
	assert.Equal(t, ids, keyIDs(keys))
	assert.Equal(t, callCounts{"ListKeys": 5}, before.since(client), "one request per page of the caller")

	resp, err := provider.ListKeys(t.Context(), &cryptoprov.ListKeysRequest{PageSize: 7})
	require.NoError(t, err)
	assert.Equal(t, ids[:7], keyIDs(resp.Keys))
	assert.NotEmpty(t, resp.NextPageToken)

	t.Run("empty account", func(t *testing.T) {
		resp, err := newProvider(t, newFakeKMS()).ListKeys(t.Context(), &cryptoprov.ListKeysRequest{})
		require.NoError(t, err)
		assert.Empty(t, resp.Keys)
		assert.NotNil(t, resp.Keys)
		assert.Empty(t, resp.NextPageToken)
	})
	t.Run("truncated without marker", func(t *testing.T) {
		client := newFakeKMS()
		id := client.mustAddKey(t, "key", types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify)
		client.listKeys = func(*kms.ListKeysInput) (*kms.ListKeysOutput, error) {
			return &kms.ListKeysOutput{
				Keys:      []types.KeyListEntry{{KeyId: aws.String(id)}},
				Truncated: true,
			}, nil
		}
		resp, err := newProvider(t, client).ListKeys(t.Context(), &cryptoprov.ListKeysRequest{})
		require.EqualError(t, err, "failed to list keys: the page is truncated without a marker")
		assert.Nil(t, resp, "no partial result")
		assert.Equal(t, 1, client.CallCount("ListKeys"))
	})
}

// TestListKeysRequestCounts asserts the request counts PLAN.md gives as the
// acceptance of the listing planner, on an account of 5000 keys of which 20
// sign.
func TestListKeysRequestCounts(t *testing.T) {
	t.Parallel()

	const (
		total   = 5000
		signing = 20
		aliases = 250
	)
	client := newFakeKMS()
	var signIDs []string
	dataAliases := 0
	for i := range total {
		// the signing keys are spread over the pages
		if i%(total/signing) == 0 {
			label := "sign_" + strconv.Itoa(len(signIDs))
			id := client.mustAddKey(t, label, types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify)
			client.setAlias("alias/"+label, id)
			signIDs = append(signIDs, id)
			continue
		}
		id := client.mustAddKey(t, "data_"+strconv.Itoa(i), types.KeySpecRsa2048, types.KeyUsageTypeEncryptDecrypt)
		if dataAliases < aliases-signing {
			client.setAlias("alias/data_"+strconv.Itoa(i), id)
			dataAliases++
		}
	}
	require.Len(t, signIDs, signing)
	require.Equal(t, aliases, client.aliasCount())
	provider := newProvider(t, client)

	signFilter := cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageSign}

	before := counts(client)
	keys := listAll(t, provider, &cryptoprov.ListKeysRequest{})
	assert.Len(t, keys, total)
	assert.Equal(t, callCounts{"ListKeys": 5}, before.since(client), "ids, no filter")

	before = counts(client)
	client.peak.Store(0)
	keys = listAll(t, provider, &cryptoprov.ListKeysRequest{Filter: signFilter})
	assert.Equal(t, signIDs, keyIDs(keys))
	assert.Equal(t, callCounts{"ListKeys": 5, "DescribeKey": total}, before.since(client), "usage filter, first listing")
	assert.LessOrEqual(t, client.peak.Load(), int32(awskmscrypto.DescribeConcurrency))
	assert.Equal(t, total, awskmscrypto.MetadataCacheLen(provider))
	for _, key := range keys {
		assert.Equal(t, certutil.KeyTypeECDSA, key.Type, "free: the filter read it")
		assert.Equal(t, cryptoprov.KeyUsageSign, key.Usage)
	}

	before = counts(client)
	keys = listAll(t, provider, &cryptoprov.ListKeysRequest{Filter: signFilter})
	assert.Equal(t, signIDs, keyIDs(keys))
	assert.Equal(t, callCounts{"ListKeys": 5}, before.since(client), "the same listing again: the metadata is cached")

	before = counts(client)
	keys = listAll(t, provider, &cryptoprov.ListKeysRequest{
		Filter: signFilter,
		Fields: cryptoprov.KeyFieldMetadata,
	})
	assert.Equal(t, signIDs, keyIDs(keys))
	assert.Equal(t, callCounts{"ListKeys": 5, "DescribeKey": signing}, before.since(client), "the label is read for the returned keys")
	assert.Equal(t, "sign_0", keys[0].Label)
	assert.NotNil(t, keys[0].CreationTime)

	before = counts(client)
	keys = listAll(t, provider, &cryptoprov.ListKeysRequest{
		Filter: cryptoprov.KeyFilter{Label: "sign_7"},
		Fields: cryptoprov.KeyFieldMetadata | cryptoprov.KeyFieldState,
	})
	assert.Equal(t, []string{signIDs[7]}, keyIDs(keys))
	assert.Equal(t, callCounts{"DescribeKey": 1}, before.since(client), "an exact label is its alias")

	before = counts(client)
	keys = listAll(t, provider, &cryptoprov.ListKeysRequest{
		Filter: cryptoprov.KeyFilter{LabelPrefix: "sign_"},
	})
	assert.ElementsMatch(t, signIDs, keyIDs(keys))
	assert.Equal(t, callCounts{"ListAliases": 3, "DescribeKey": signing}, before.since(client), "a label prefix sweeps the aliases, 100 a request")

	before = counts(client)
	info, err := provider.KeyInfo(t.Context(), signIDs[3], cryptoprov.KeyFieldMetadata|cryptoprov.KeyFieldState)
	require.NoError(t, err)
	assert.Equal(t, "sign_3", info.Label)
	assert.Equal(t, callCounts{"DescribeKey": 1}, before.since(client))

	before = counts(client)
	info, err = provider.KeyInfo(t.Context(), signIDs[3], cryptoprov.KeyFieldMetadata|cryptoprov.KeyFieldState|cryptoprov.KeyFieldPublicKey)
	require.NoError(t, err)
	assert.Contains(t, info.PublicKey, "PUBLIC KEY")
	assert.Equal(t, callCounts{"DescribeKey": 1, "GetPublicKey": 1}, before.since(client))
}

// TestListKeysScan checks the filters on a listing that describes every key
// (LabelSearch=scan), which finds a key by its description as v1 did. With a
// signing usage and the enabled and disabled states it lists what v1
// EnumKeys listed (XPKI-032).
func TestListKeysScan(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	provider := providerWith(client, nil, "LabelSearch=scan")
	rsaID := client.mustAddKey(t, "test_rsa", types.KeySpecRsa2048, types.KeyUsageTypeSignVerify)
	encryptID := client.mustAddKey(t, "test_encrypt", types.KeySpecRsa2048, types.KeyUsageTypeEncryptDecrypt)
	ecID := client.mustAddKey(t, "test_ec", types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify)
	deletedID := client.mustAddKey(t, "test_deleted", types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify)
	client.setState(deletedID, types.KeyStatePendingDeletion)
	disabledID := client.mustAddKey(t, "test_disabled", types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify)
	client.setState(disabledID, types.KeyStateDisabled)
	otherID := client.mustAddKey(t, "other", types.KeySpecEccNistP384, types.KeyUsageTypeSignVerify)
	unlabelledID := client.mustAddKey(t, "", types.KeySpecEccNistP521, types.KeyUsageTypeSignVerify)
	allKeys := client.keyCount()

	v1 := func(prefix string) cryptoprov.KeyFilter {
		return cryptoprov.KeyFilter{
			Usage:       cryptoprov.KeyUsageSign,
			States:      v1States,
			LabelPrefix: prefix,
		}
	}
	cases := []struct {
		name   string
		filter cryptoprov.KeyFilter
		ids    []string
	}{
		{
			name:   "v1 listing",
			filter: v1(""),
			ids:    []string{rsaID, ecID, disabledID, otherID, unlabelledID},
		},
		{
			name:   "prefix",
			filter: v1("test_"),
			ids:    []string{rsaID, ecID, disabledID},
		},
		{
			name:   "one key",
			filter: v1("test_ec"),
			ids:    []string{ecID},
		},
		{
			name:   "encryption key is not a signing key",
			filter: v1("test_encrypt"),
			ids:    []string{},
		},
		{
			name:   "key pending deletion",
			filter: v1("test_deleted"),
			ids:    []string{},
		},
		{
			name:   "not a prefix",
			filter: v1("ther"),
			ids:    []string{},
		},
		{
			name:   "exact label",
			filter: cryptoprov.KeyFilter{Label: "other"},
			ids:    []string{otherID},
		},
		{
			name:   "no state filter keeps a key pending deletion",
			filter: cryptoprov.KeyFilter{LabelPrefix: "test_"},
			ids:    []string{rsaID, encryptID, ecID, deletedID, disabledID},
		},
		{
			name:   "pending deletion",
			filter: cryptoprov.KeyFilter{States: []cryptoprov.KeyState{cryptoprov.KeyStatePendingDeletion}},
			ids:    []string{deletedID},
		},
		{
			name:   "encryption keys",
			filter: cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageEncrypt},
			ids:    []string{encryptID},
		},
		{
			name:   "RSA keys of either usage",
			filter: cryptoprov.KeyFilter{Types: []string{certutil.KeyTypeRSA}},
			ids:    []string{rsaID, encryptID},
		},
		{
			name: "type and usage",
			filter: cryptoprov.KeyFilter{
				Types: []string{certutil.KeyTypeECDSA, certutil.KeyTypeMLDSA},
				Usage: cryptoprov.KeyUsageSign | cryptoprov.KeyUsageEncrypt,
			},
			ids: []string{ecID, deletedID, disabledID, otherID, unlabelledID},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keys := listAll(t, provider, &cryptoprov.ListKeysRequest{
				Filter: tc.filter,
				Fields: cryptoprov.KeyFieldMetadata,
			})
			assert.Equal(t, tc.ids, keyIDs(keys))
			for _, key := range keys {
				assert.Equal(t, key.Meta["description"], key.Label)
				assert.NotNil(t, key.CreationTime)
				assert.NotEmpty(t, key.Name)
				assert.Empty(t, key.PublicKey)
			}
		})
	}

	before := counts(client)
	keys := listAll(t, provider, &cryptoprov.ListKeysRequest{
		Filter: v1("test_"),
		Fields: cryptoprov.KeyFieldMetadata | cryptoprov.KeyFieldState,
	})
	require.Len(t, keys, 3)
	assert.Equal(t, "test_rsa", keys[0].Label)
	assert.Equal(t, certutil.KeyTypeRSA, keys[0].Type)
	assert.Equal(t, 2048, keys[0].Size)
	assert.Equal(t, cryptoprov.KeyUsageSign, keys[0].Usage)
	assert.Equal(t, cryptoprov.KeyStateEnabled, keys[0].State)
	assert.Equal(t, fmt.Sprintf("%v", rsaSigningAlgorithms), keys[0].Meta["algo"])
	assert.Equal(t, "SIGN_VERIFY", keys[0].Meta["usage"])
	assert.Equal(t, "RSA_2048", keys[0].Meta["spec"])
	assert.Equal(t, "test_disabled", keys[2].Label)
	assert.Equal(t, cryptoprov.KeyStateDisabled, keys[2].State)
	assert.Equal(t, "false", keys[2].Meta["enabled"])
	assert.Equal(t, "Disabled", keys[2].Meta["state"])
	// the usage filter drops the encryption key from the cache; the label
	// and the state of every other key are read again
	assert.Equal(t, callCounts{"ListKeys": 1, "DescribeKey": allKeys - 1}, before.since(client))
}

// TestListKeysLabelIndex checks that a label filter goes through the alias
// of the label and is confirmed against the description (decision K4).
func TestListKeysLabelIndex(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	provider := newProvider(t, client)
	generate := func(label string) string {
		key, err := provider.GenerateKey(t.Context(), &cryptoprov.GenerateKeyRequest{
			Label: label,
			Type:  certutil.KeyTypeECDSA,
			Size:  256,
		})
		require.NoError(t, err)
		id, _, err := provider.IdentifyKey(t.Context(), key)
		require.NoError(t, err)
		return id
	}
	caID := generate("issuer/ca 1")
	ca2ID := generate("issuer/ca 2")
	otherID := generate("other")
	// a key that has only a description: no alias points at it
	plainID := client.mustAddKey(t, "issuer/plain", types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify)
	// a second alias on a generated key, and an alias whose key has
	// another description
	client.setAlias("alias/issuer/current", caID)
	client.setAlias("alias/issuer/renamed", otherID)

	list := func(p cryptoprov.KeyManager, filter cryptoprov.KeyFilter) []string {
		return keyIDs(listAll(t, p, &cryptoprov.ListKeysRequest{
			Filter: filter,
			Fields: cryptoprov.KeyFieldMetadata,
		}))
	}

	before := counts(client)
	assert.Equal(t, []string{caID}, list(provider, cryptoprov.KeyFilter{Label: "issuer/ca 1"}))
	assert.Equal(t, callCounts{"DescribeKey": 1}, before.since(client))

	assert.Empty(t, list(provider, cryptoprov.KeyFilter{Label: "issuer/ca"}), "no such alias")
	assert.Empty(t, list(provider, cryptoprov.KeyFilter{Label: "issuer/plain"}), "a description alone is not indexed")
	assert.Empty(t, list(provider, cryptoprov.KeyFilter{Label: "issuer/renamed"}), "the alias points at a key with another label")
	assert.Empty(t, list(provider, cryptoprov.KeyFilter{Label: "issuer/ca_1"}), "the alias matches, the description does not")

	before = counts(client)
	assert.ElementsMatch(t, []string{caID, ca2ID}, list(provider, cryptoprov.KeyFilter{LabelPrefix: "issuer/"}),
		"once each: through the alias of its label")
	// issuer/ca_1, issuer/ca_2, issuer/current and issuer/renamed match
	assert.Equal(t, callCounts{"ListAliases": 1, "DescribeKey": 4}, before.since(client))

	assert.Equal(t, []string{caID}, list(provider, cryptoprov.KeyFilter{
		LabelPrefix: "issuer/",
		Label:       "issuer/ca 1",
	}), "both label conditions")

	// LabelSearch=scan finds the key that has only a description
	scan := providerWith(client, nil, "LabelSearch=scan")
	assert.Equal(t, []string{plainID}, list(scan, cryptoprov.KeyFilter{Label: "issuer/plain"}))
	assert.Equal(t, []string{caID, ca2ID, plainID}, list(scan, cryptoprov.KeyFilter{LabelPrefix: "issuer/"}))

	t.Run("alias sweep by pages", func(t *testing.T) {
		client := newFakeKMS()
		provider := newProvider(t, client)
		const total = 2*awskmscrypto.ListAliasesLimit + 30
		var ids []string
		for i := range total {
			label := fmt.Sprintf("page_%03d", i)
			id := client.mustAddKey(t, label, types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify)
			client.setAlias("alias/"+label, id)
			ids = append(ids, id)
		}
		for _, size := range []int{7, awskmscrypto.ListAliasesLimit, 0} {
			before := counts(client)
			keys := listAll(t, provider, &cryptoprov.ListKeysRequest{
				PageSize: size,
				Filter:   cryptoprov.KeyFilter{LabelPrefix: "page_"},
			})
			assert.Equal(t, ids, keyIDs(keys), "page size %d", size)
			assert.Equal(t, total, before.since(client)["DescribeKey"], "page size %d: one per matching alias", size)
		}

		// a page is filled from one ListAliases page at most
		resp, err := provider.ListKeys(t.Context(), &cryptoprov.ListKeysRequest{
			PageSize: awskmscrypto.ListAliasesLimit + 50,
			Filter:   cryptoprov.KeyFilter{LabelPrefix: "page_"},
		})
		require.NoError(t, err)
		assert.Len(t, resp.Keys, awskmscrypto.ListAliasesLimit)
		assert.NotEmpty(t, resp.NextPageToken)
	})
}

// TestListKeysTagSearch checks the Resource Groups Tagging API source: a tag
// filter is one GetResources per 100 tagged keys, the xpki tags save the
// DescribeKey of the Metadata group, and the xpki-label tag finds the keys
// whose alias could not be created.
func TestListKeysTagSearch(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	tagging := newFakeTagging(client)
	provider := providerWith(client, tagging, "")
	generate := func(label string, tags map[string]string) string {
		key, err := provider.GenerateKey(t.Context(), &cryptoprov.GenerateKeyRequest{
			Label: label,
			Type:  certutil.KeyTypeECDSA,
			Size:  384,
			Tags:  tags,
		})
		require.NoError(t, err)
		id, _, err := provider.IdentifyKey(t.Context(), key)
		require.NoError(t, err)
		return id
	}

	const tagged = awskmscrypto.ResourcesPerPage + 50
	var alphaIDs []string
	for i := range tagged {
		alphaIDs = append(alphaIDs, generate(fmt.Sprintf("alpha_%03d", i), map[string]string{"team": "alpha"}))
	}
	betaID := generate("beta_0", map[string]string{"team": "beta"})
	// tagged outside xpki: no xpki tags
	manualID := client.mustAddKey(t, "manual", types.KeySpecRsa2048, types.KeyUsageTypeSignVerify)
	client.setTags(manualID, map[string]string{"team": "alpha"})
	// untagged keys are not candidates at all
	addSigningKeys(t, client, 10)

	t.Run("generated tags", func(t *testing.T) {
		tags, err := provider.KeyInfo(t.Context(), betaID, cryptoprov.KeyFieldTags)
		require.NoError(t, err)
		assert.Equal(t, map[string]string{
			"team":                "beta",
			awskmscrypto.TagLabel: "beta_0",
			awskmscrypto.TagType:  certutil.KeyTypeECDSA,
			awskmscrypto.TagSize:  "384",
			awskmscrypto.TagUsage: "sign",
		}, tags.Tags)

		_, err = provider.GenerateKey(t.Context(), &cryptoprov.GenerateKeyRequest{
			Label: "reserved",
			Type:  certutil.KeyTypeECDSA,
			Size:  256,
			Tags:  map[string]string{"xpki-label": "mine"},
		})
		require.EqualError(t, err, `invalid tag "xpki-label": the "xpki-" prefix is reserved`)
	})

	t.Run("tag filter", func(t *testing.T) {
		before := counts(client)
		requests := len(tagging.Requests())
		keys := listAll(t, provider, &cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{Tags: map[string]string{"team": "alpha"}},
			Fields: cryptoprov.KeyFieldMetadata | cryptoprov.KeyFieldTags,
		})
		expected := append(slices.Clone(alphaIDs), manualID)
		assert.Equal(t, expected, keyIDs(keys))
		// only the key without xpki tags is described
		assert.Equal(t, callCounts{"DescribeKey": 1}, before.since(client))
		sent := tagging.Requests()[requests:]
		require.Len(t, sent, 2, "100 tagged keys a request")
		assert.Equal(t, []string{"kms:key"}, sent[0].ResourceTypeFilters)
		require.Len(t, sent[0].TagFilters, 1)
		assert.Equal(t, "team", aws.ToString(sent[0].TagFilters[0].Key))
		assert.Equal(t, []string{"alpha"}, sent[0].TagFilters[0].Values)
		assert.Equal(t, int32(awskmscrypto.ResourcesPerPage), aws.ToInt32(sent[0].ResourcesPerPage))

		first := keys[0]
		assert.Equal(t, "alpha_000", first.Label, "from the xpki-label tag")
		assert.Equal(t, certutil.KeyTypeECDSA, first.Type)
		assert.Equal(t, 384, first.Size)
		assert.Equal(t, cryptoprov.KeyUsageSign, first.Usage)
		assert.Equal(t, "alpha", first.Tags["team"])
		assert.Contains(t, first.Name, ":key/"+first.ID)
		assert.Empty(t, first.State, "not asked for")
		manual := keys[len(keys)-1]
		assert.Equal(t, "manual", manual.Label, "from its description")
		assert.Equal(t, certutil.KeyTypeRSA, manual.Type)
	})

	t.Run("tag filter with state", func(t *testing.T) {
		before := counts(client)
		keys := listAll(t, provider, &cryptoprov.ListKeysRequest{
			PageSize: 20,
			Filter: cryptoprov.KeyFilter{
				Tags:   map[string]string{"team": "beta"},
				States: []cryptoprov.KeyState{cryptoprov.KeyStateEnabled},
			},
		})
		assert.Equal(t, []string{betaID}, keyIDs(keys))
		assert.Equal(t, callCounts{"DescribeKey": 1}, before.since(client), "the state is not in a tag")
		assert.Equal(t, cryptoprov.KeyStateEnabled, keys[0].State)
	})

	t.Run("tag and type filter", func(t *testing.T) {
		before := counts(client)
		keys := listAll(t, provider, &cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{
				Tags:  map[string]string{"team": "alpha"},
				Types: []string{certutil.KeyTypeRSA},
			},
		})
		assert.Equal(t, []string{manualID}, keyIDs(keys))
		assert.Empty(t, before.since(client), "the xpki tags and the cache have every type")
	})

	t.Run("label through the tag", func(t *testing.T) {
		// the alias of the second key with a label cannot be created
		firstID := generate("shared", nil)
		secondID := generate("shared", nil)
		require.NotEqual(t, firstID, secondID)

		keys := listAll(t, provider, &cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{Label: "shared"},
		})
		assert.Equal(t, []string{firstID, secondID}, keyIDs(keys), "the alias, then the xpki-label tag, once each")

		keys = listAll(t, provider, &cryptoprov.ListKeysRequest{
			PageSize: 1,
			Filter:   cryptoprov.KeyFilter{LabelPrefix: "shar"},
		})
		assert.Equal(t, []string{firstID, secondID}, keyIDs(keys))

		// without the tagging API only the alias finds a key
		plain := newProvider(t, client)
		keys = listAll(t, plain, &cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{Label: "shared"},
		})
		assert.Equal(t, []string{firstID}, keyIDs(keys))

		// the tag only mirrors the label: the description decides
		client.setDescription(secondID, "renamed")
		keys = listAll(t, provider, &cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{Label: "shared"},
		})
		assert.Equal(t, []string{firstID}, keyIDs(keys))
	})

	t.Run("label that is not a tag value", func(t *testing.T) {
		id := generate("odd*label", nil)
		info, err := provider.KeyInfo(t.Context(), id, cryptoprov.KeyFieldTags)
		require.NoError(t, err)
		assert.NotContains(t, info.Tags, awskmscrypto.TagLabel)

		requests := len(tagging.Requests())
		keys := listAll(t, provider, &cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{Label: "odd*label"},
		})
		assert.Equal(t, []string{id}, keyIDs(keys))
		assert.Len(t, tagging.Requests(), requests, "no tag can have the label")
	})

	t.Run("without tag search", func(t *testing.T) {
		plain := newProvider(t, client)
		before := counts(client)
		keys := listAll(t, plain, &cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{Tags: map[string]string{"team": "beta"}},
		})
		assert.Equal(t, []string{betaID}, keyIDs(keys))
		calls := before.since(client)
		assert.Equal(t, 1, calls["ListKeys"])
		assert.Equal(t, client.keyCount(), calls["ListResourceTags"], "the tags of every key are read")
		assert.Zero(t, calls["DescribeKey"])
	})

	t.Run("tagging errors", func(t *testing.T) {
		failing := newFakeTagging(client)
		provider := providerWith(client, failing, "")
		req := &cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{Tags: map[string]string{"team": "alpha"}},
		}
		failing.getResources = func(*resourcegroupstaggingapi.GetResourcesInput) (*resourcegroupstaggingapi.GetResourcesOutput, error) {
			return nil, throttlingError()
		}
		_, err := provider.ListKeys(t.Context(), req)
		require.EqualError(t, err, "failed to get tagged keys: api error ThrottlingException: Rate exceeded")
		var apiErr smithy.APIError
		require.ErrorAs(t, err, &apiErr)

		failing.getResources = func(*resourcegroupstaggingapi.GetResourcesInput) (*resourcegroupstaggingapi.GetResourcesOutput, error) {
			return nil, nil
		}
		_, err = provider.ListKeys(t.Context(), req)
		require.EqualError(t, err, "failed to get tagged keys: empty response")
	})
}

// TestListKeysPageTokens checks that a token resumes inside a page of the
// source, that it is bound to the request, and that it names its source.
func TestListKeysPageTokens(t *testing.T) {
	t.Parallel()

	client := newFakeKMS()
	provider := newProvider(t, client)
	var signIDs []string
	for i := range 40 {
		if i%4 == 0 {
			signIDs = append(signIDs, client.mustAddKey(t, "sign_"+strconv.Itoa(i), types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify))
			continue
		}
		client.mustAddKey(t, "enc_"+strconv.Itoa(i), types.KeySpecRsa2048, types.KeyUsageTypeEncryptDecrypt)
	}

	req := &cryptoprov.ListKeysRequest{
		PageSize: 3,
		Filter:   cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageSign},
	}
	before := counts(client)
	var listed []string
	pages := 0
	page := *req
	for {
		resp, err := provider.ListKeys(t.Context(), &page)
		require.NoError(t, err)
		pages++
		assert.LessOrEqual(t, len(resp.Keys), 3)
		listed = append(listed, keyIDs(resp.Keys)...)
		if resp.NextPageToken == "" {
			break
		}
		page.PageToken = resp.NextPageToken
	}
	assert.Equal(t, signIDs, listed)
	assert.Equal(t, 4, pages, "ten keys by three")
	calls := before.since(client)
	assert.Equal(t, pages, calls["ListKeys"], "the page of ids is read again to resume in it")
	assert.Equal(t, 40, calls["DescribeKey"], "each key is described once over the whole listing")

	first, err := provider.ListKeys(t.Context(), req)
	require.NoError(t, err)
	require.NotEmpty(t, first.NextPageToken)

	t.Run("a page that fills early", func(t *testing.T) {
		// with a filter on usage, a page costs the candidates it examines,
		// not the whole page of ids
		client := newFakeKMS()
		ids := addSigningKeys(t, client, 500)
		provider := newProvider(t, client)
		resp, err := provider.ListKeys(t.Context(), req)
		require.NoError(t, err)
		assert.Equal(t, ids[:3], keyIDs(resp.Keys))
		assert.NotEmpty(t, resp.NextPageToken)
		assert.Equal(t, awskmscrypto.DescribeConcurrency, client.CallCount("DescribeKey"), "one chunk of candidates")

		// the next page starts where the first one stopped
		next := *req
		next.PageToken = resp.NextPageToken
		resp, err = provider.ListKeys(t.Context(), &next)
		require.NoError(t, err)
		assert.Equal(t, ids[3:6], keyIDs(resp.Keys))
		// its chunk has five keys of the first one, which are cached
		assert.Equal(t, awskmscrypto.DescribeConcurrency+3, client.CallCount("DescribeKey"))
	})
	t.Run("another filter", func(t *testing.T) {
		other := *req
		other.PageToken = first.NextPageToken
		other.Filter.Types = []string{certutil.KeyTypeRSA}
		_, err := provider.ListKeys(t.Context(), &other)
		require.ErrorIs(t, err, cryptoprov.ErrInvalidPageToken)
	})
	t.Run("another source", func(t *testing.T) {
		// the same filter is answered from another source by a provider
		// with other settings
		labelReq := &cryptoprov.ListKeysRequest{
			PageSize: 1,
			Filter:   cryptoprov.KeyFilter{LabelPrefix: "sign_"},
		}
		scan := providerWith(client, nil, "LabelSearch=scan")
		resp, err := scan.ListKeys(t.Context(), labelReq)
		require.NoError(t, err)
		require.NotEmpty(t, resp.NextPageToken)

		other := *labelReq
		other.PageToken = resp.NextPageToken
		_, err = provider.ListKeys(t.Context(), &other)
		require.ErrorIs(t, err, cryptoprov.ErrInvalidPageToken)
		require.ErrorContains(t, err, `source "keys"`)
	})
	t.Run("page that lost keys", func(t *testing.T) {
		// a token that points beyond the page ends the page, not the call
		token, err := cryptoprov.NewPageToken(req, cryptoprov.PageCursor{
			Source: "keys",
			Offset: 1000,
		})
		require.NoError(t, err)
		other := *req
		other.PageToken = token
		resp, err := provider.ListKeys(t.Context(), &other)
		require.NoError(t, err)
		assert.Empty(t, resp.Keys)
		assert.Empty(t, resp.NextPageToken)
	})
}

// TestListKeysErrors checks that a ListKeys or DescribeKey failure on any
// page and at any position fails the call, with no partial page and with
// the service error identity kept, and that a key the caller may not
// describe is left out of the listing (XPKI-033).
func TestListKeysErrors(t *testing.T) {
	t.Parallel()

	total := awskmscrypto.ListKeysLimit + 10
	accessDenied := &smithy.GenericAPIError{
		Code:    "AccessDeniedException",
		Message: "not authorized",
		Fault:   smithy.FaultClient,
	}
	// a request that describes every key
	describeAll := &cryptoprov.ListKeysRequest{Fields: cryptoprov.KeyFieldMetadata}
	// list reads every page and returns the first error
	list := func(t *testing.T, provider *awskmscrypto.Provider) ([]cryptoprov.KeyInfo, error) {
		var keys []cryptoprov.KeyInfo
		for key, err := range cryptoprov.AllKeys(t.Context(), provider, describeAll) {
			if err != nil {
				return keys, err
			}
			keys = append(keys, *key)
		}
		return keys, nil
	}

	t.Run("list", func(t *testing.T) {
		t.Parallel()
		for _, failPage := range []int{1, 2} {
			client := newFakeKMS()
			addSigningKeys(t, client, total)
			client.listErr = func(page int) error {
				if page == failPage {
					return throttlingError()
				}
				return nil
			}

			keys, err := list(t, newProvider(t, client))
			require.EqualError(t, err, "failed to list keys: api error ThrottlingException: Rate exceeded", "page %d", failPage)
			assert.Len(t, keys, (failPage-1)*awskmscrypto.ListKeysLimit, "the pages before the failure")
			var apiErr smithy.APIError
			require.ErrorAs(t, err, &apiErr)
			assert.Equal(t, "ThrottlingException", apiErr.ErrorCode())
			assert.Equal(t, (failPage-1)*awskmscrypto.ListKeysLimit, client.CallCount("DescribeKey"), "keys of the pages before the failure are described")
		}
	})

	t.Run("describe", func(t *testing.T) {
		t.Parallel()
		for _, tc := range []struct {
			name string
			// index of the failing key in the listing
			index int
			err   error
			msg   string
		}{
			{
				name:  "first key throttled",
				index: 0,
				err:   throttlingError(),
				msg:   "api error ThrottlingException: Rate exceeded",
			},
			{
				name:  "middle key timed out",
				index: 500,
				err:   &types.DependencyTimeoutException{Message: aws.String("timed out")},
				msg:   "DependencyTimeoutException: timed out",
			},
			{
				name:  "last key of page 1",
				index: awskmscrypto.ListKeysLimit - 1,
				err:   &types.KMSInternalException{Message: aws.String("internal")},
				msg:   "KMSInternalException: internal",
			},
			{
				name:  "last key",
				index: total - 1,
				err:   errors.New("connection reset"),
				msg:   "connection reset",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				t.Parallel()
				client := newFakeKMS()
				ids := addSigningKeys(t, client, total)
				failID := ids[tc.index]
				client.describeErr = func(keyID string, _ int) error {
					if keyID == failID {
						return tc.err
					}
					return nil
				}
				provider := newProvider(t, client)
				// serial calls, so the number of calls is exact
				awskmscrypto.SetDescribeConcurrency(provider, 1)

				keys, err := list(t, provider)
				require.EqualError(t, err, fmt.Sprintf("failed to describe key, id=%s, arn=%skey/%s: %s", failID, fakeArnBase, failID, tc.msg))
				failedPage := tc.index / awskmscrypto.ListKeysLimit
				assert.Len(t, keys, failedPage*awskmscrypto.ListKeysLimit, "no partial page")
				require.ErrorIs(t, err, tc.err)
				assert.Equal(t, tc.index+1, client.CallCount("DescribeKey"), "the listing stops at the failure")
			})
		}
	})

	t.Run("denied and deleted keys are not listed", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		ids := addSigningKeys(t, client, total)
		denied := []string{ids[0], ids[7], ids[awskmscrypto.ListKeysLimit]}
		gone := ids[total-1]
		client.describeErr = func(keyID string, _ int) error {
			switch {
			case slices.Contains(denied, keyID):
				return accessDenied
			case keyID == gone:
				return notFoundError(keyID)
			}
			return nil
		}

		keys, err := list(t, newProvider(t, client))
		require.NoError(t, err)
		expected := slices.DeleteFunc(slices.Clone(ids), func(id string) bool {
			return slices.Contains(denied, id) || id == gone
		})
		assert.Equal(t, expected, keyIDs(keys), "the other keys are listed in order")
		assert.Equal(t, total, client.CallCount("DescribeKey"), "every key is described")
	})

	t.Run("describe concurrent", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		ids := addSigningKeys(t, client, total)
		// the failing key waits until the ten keys before it were described,
		// so its failure is not the first event; the listing goes on meanwhile
		before := ids[:10]
		failID := ids[10]
		var described, callsAtFailure atomic.Int32
		allBefore := make(chan struct{})
		client.describeErr = func(keyID string, _ int) error {
			switch {
			case slices.Contains(before, keyID):
				if int(described.Add(1)) == len(before) {
					close(allBefore)
				}
			case keyID == failID:
				if err := awaitBarrier(allBefore); err != nil {
					return err
				}
				callsAtFailure.Store(int32(client.CallCount("DescribeKey")))
				return throttlingError()
			}
			return nil
		}
		// long enough that no slot turns over between the count and the
		// cancellation, so the bound below is exact
		client.describeDelay = 50 * time.Millisecond
		provider := newProvider(t, client)

		keys, err := list(t, provider)
		require.ErrorContains(t, err, "failed to describe key, id="+failID)
		var apiErr smithy.APIError
		require.ErrorAs(t, err, &apiErr, "the failure is reported, not the cancellation of the other calls")
		assert.Equal(t, "ThrottlingException", apiErr.ErrorCode())
		assert.Empty(t, keys)
		calls := client.CallCount("DescribeKey")
		atFailure := int(callsAtFailure.Load())
		assert.GreaterOrEqual(t, atFailure, len(before)+1)
		assert.LessOrEqual(t, calls, atFailure+awskmscrypto.DescribeConcurrency-1, "calls in flight at the failure finish, no new one starts")
	})

	t.Run("cancelled during the listing", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		addSigningKeys(t, client, 50)
		client.describeDelay = time.Minute
		ctx, cancel := context.WithCancel(t.Context())
		started := make(chan struct{})
		var once sync.Once
		client.describeErr = func(string, int) error {
			once.Do(func() { close(started) })
			return nil
		}
		go func() {
			if awaitBarrier(started) == nil {
				cancel()
			}
		}()
		_, err := newProvider(t, client).ListKeys(ctx, describeAll)
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("empty responses", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		ids := addSigningKeys(t, client, 3)
		provider := newProvider(t, client)

		client.listKeys = func(*kms.ListKeysInput) (*kms.ListKeysOutput, error) {
			return nil, nil
		}
		_, err := provider.ListKeys(t.Context(), describeAll)
		require.EqualError(t, err, "failed to list keys: empty response")
		client.listKeys = nil

		client.describeKey = func(*kms.DescribeKeyInput) (*kms.DescribeKeyOutput, error) {
			return &kms.DescribeKeyOutput{}, nil
		}
		awskmscrypto.SetDescribeConcurrency(provider, 1)
		_, err = provider.ListKeys(t.Context(), describeAll)
		require.EqualError(t, err, "failed to describe key, id="+ids[0]+": empty response")
		client.describeKey = nil

		client.listAliases = func(*kms.ListAliasesInput) (*kms.ListAliasesOutput, error) {
			return nil, nil
		}
		prefix := &cryptoprov.ListKeysRequest{Filter: cryptoprov.KeyFilter{LabelPrefix: "key_"}}
		_, err = provider.ListKeys(t.Context(), prefix)
		require.EqualError(t, err, "failed to list aliases: empty response")
		client.listAliases = func(*kms.ListAliasesInput) (*kms.ListAliasesOutput, error) {
			return nil, throttlingError()
		}
		_, err = provider.ListKeys(t.Context(), prefix)
		require.EqualError(t, err, "failed to list aliases: api error ThrottlingException: Rate exceeded")
		client.listAliases = func(*kms.ListAliasesInput) (*kms.ListAliasesOutput, error) {
			return &kms.ListAliasesOutput{Truncated: true}, nil
		}
		_, err = provider.ListKeys(t.Context(), prefix)
		require.EqualError(t, err, "failed to list aliases: the page is truncated without a marker")
	})

	t.Run("tags", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		ids := addSigningKeys(t, client, 3)
		client.setTags(ids[1], map[string]string{"team": "alpha"})
		provider := newProvider(t, client)
		req := &cryptoprov.ListKeysRequest{Fields: cryptoprov.KeyFieldTags}

		keys := listAll(t, provider, req)
		require.Len(t, keys, 3)
		assert.Empty(t, keys[0].Tags)
		assert.NotNil(t, keys[0].Tags)
		assert.Equal(t, map[string]string{"team": "alpha"}, keys[1].Tags)

		// a key whose tags the caller may not read is not listed
		client.listResourceTags = func(req *kms.ListResourceTagsInput) (*kms.ListResourceTagsOutput, error) {
			if aws.ToString(req.KeyId) == ids[0] {
				return nil, accessDenied
			}
			return &kms.ListResourceTagsOutput{}, nil
		}
		assert.Equal(t, ids[1:], keyIDs(listAll(t, provider, req)))

		client.listResourceTags = func(*kms.ListResourceTagsInput) (*kms.ListResourceTagsOutput, error) {
			return nil, throttlingError()
		}
		_, err := provider.ListKeys(t.Context(), req)
		require.ErrorContains(t, err, "failed to list tags, id=")
		client.listResourceTags = func(*kms.ListResourceTagsInput) (*kms.ListResourceTagsOutput, error) {
			return nil, nil
		}
		_, err = provider.KeyInfo(t.Context(), ids[0], cryptoprov.KeyFieldTags)
		require.EqualError(t, err, "failed to list tags, id="+ids[0]+": empty response")
		client.listResourceTags = func(*kms.ListResourceTagsInput) (*kms.ListResourceTagsOutput, error) {
			return &kms.ListResourceTagsOutput{Truncated: true}, nil
		}
		_, err = provider.KeyInfo(t.Context(), ids[0], cryptoprov.KeyFieldTags)
		require.EqualError(t, err, "failed to list tags, id="+ids[0]+": page 1 is truncated without a marker")
	})
}

// TestListKeysConcurrency checks that DescribeKey calls run concurrently,
// bounded by the configured limit, and that the order of the listing does
// not depend on the order in which they complete.
func TestListKeysConcurrency(t *testing.T) {
	t.Parallel()

	total := 100
	describeAll := &cryptoprov.ListKeysRequest{Fields: cryptoprov.KeyFieldMetadata}
	for _, concurrency := range []int{1, 3, awskmscrypto.DescribeConcurrency} {
		t.Run("concurrency="+strconv.Itoa(concurrency), func(t *testing.T) {
			t.Parallel()
			client := newFakeKMS()
			ids := addSigningKeys(t, client, total)
			// the first calls wait for each other, so they are in flight
			// together and complete after later ones started
			var arrived atomic.Int32
			allArrived := make(chan struct{})
			client.describeErr = func(_ string, call int) error {
				if call > concurrency {
					return nil
				}
				if int(arrived.Add(1)) == concurrency {
					close(allArrived)
				}
				return awaitBarrier(allArrived)
			}
			client.describeDelay = time.Millisecond
			provider := providerWith(client, nil, "DescribeConcurrency="+strconv.Itoa(concurrency))

			keys := listAll(t, provider, describeAll)
			assert.Equal(t, ids, keyIDs(keys))
			assert.Equal(t, total, client.CallCount("DescribeKey"))
			assert.Equal(t, int32(concurrency), client.peak.Load(), "peak concurrent DescribeKey calls")
		})
	}

	t.Run("zero concurrency is serial", func(t *testing.T) {
		t.Parallel()
		client := newFakeKMS()
		addSigningKeys(t, client, 2)
		client.describeDelay = time.Millisecond
		provider := newProvider(t, client)
		awskmscrypto.SetDescribeConcurrency(provider, 0)

		keys := listAll(t, provider, describeAll)
		assert.Len(t, keys, 2)
		assert.Equal(t, int32(1), client.peak.Load())
	})
}

// TestMetadataCache checks the bound of the immutable metadata cache, that
// it can be disabled, and that concurrent listings share it without a race
// and with the right result (run with -race).
func TestMetadataCache(t *testing.T) {
	t.Parallel()

	const total = 60
	newAccount := func(t *testing.T) (*fakeKMS, []string) {
		client := newFakeKMS()
		var signIDs []string
		for i := range total {
			if i%3 == 0 {
				signIDs = append(signIDs, client.mustAddKey(t, "sign_"+strconv.Itoa(i), types.KeySpecEccNistP256, types.KeyUsageTypeSignVerify))
				continue
			}
			client.mustAddKey(t, "enc_"+strconv.Itoa(i), types.KeySpecRsa2048, types.KeyUsageTypeEncryptDecrypt)
		}
		return client, signIDs
	}
	req := &cryptoprov.ListKeysRequest{
		Filter: cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageSign},
	}

	t.Run("bounded", func(t *testing.T) {
		t.Parallel()
		client, signIDs := newAccount(t)
		provider := providerWith(client, nil, "MetadataCacheSize=10")
		for range 3 {
			assert.Equal(t, signIDs, keyIDs(listAll(t, provider, req)))
			assert.Equal(t, 10, awskmscrypto.MetadataCacheLen(provider))
		}
		// at least the keys that did not fit are described again
		assert.GreaterOrEqual(t, client.CallCount("DescribeKey"), total+2*(total-10))
	})

	t.Run("disabled", func(t *testing.T) {
		t.Parallel()
		client, signIDs := newAccount(t)
		provider := providerWith(client, nil, "MetadataCacheSize=0")
		for range 2 {
			assert.Equal(t, signIDs, keyIDs(listAll(t, provider, req)))
		}
		assert.Zero(t, awskmscrypto.MetadataCacheLen(provider))
		assert.Equal(t, 2*total, client.CallCount("DescribeKey"))
	})

	t.Run("concurrent listings", func(t *testing.T) {
		t.Parallel()
		client, signIDs := newAccount(t)
		// small enough that listings evict while others read
		provider := providerWith(client, nil, "MetadataCacheSize=25")
		const listings = 16
		start := make(chan struct{})
		var wg sync.WaitGroup
		results := make([][]string, listings)
		errs := make([]error, listings)
		for i := range listings {
			wg.Go(func() {
				<-start
				page := *req
				if i%2 == 1 {
					// half of them also read the mutable fields
					page.Fields = cryptoprov.KeyFieldMetadata | cryptoprov.KeyFieldState
				}
				for key, err := range cryptoprov.AllKeys(context.Background(), provider, &page) {
					if err != nil {
						errs[i] = err
						return
					}
					results[i] = append(results[i], key.ID)
				}
			})
		}
		close(start)
		wg.Wait()
		for i := range listings {
			require.NoError(t, errs[i])
			assert.Equal(t, signIDs, results[i], "listing %d", i)
		}
		assert.LessOrEqual(t, awskmscrypto.MetadataCacheLen(provider), 25)
	})
}

// TestConformance runs the key management conformance suite on the fake
// KMS, without and with the Resource Groups Tagging API.
func TestConformance(t *testing.T) {
	t.Parallel()
	for name, tagSearch := range map[string]bool{
		"index":     false,
		"tagsearch": true,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			provtest.Run(t, provtest.Config{
				New: func(*testing.T) cryptoprov.Provider {
					client := newFakeKMS()
					if tagSearch {
						return providerWith(client, newFakeTagging(client), "")
					}
					return providerWith(client, nil, "")
				},
				Tags:  true,
				MLDSA: true,
			})
		})
	}
	t.Run("scan", func(t *testing.T) {
		t.Parallel()
		provtest.Run(t, provtest.Config{
			New: func(*testing.T) cryptoprov.Provider {
				return providerWith(newFakeKMS(), nil, "LabelSearch=scan")
			},
			Tags:  true,
			MLDSA: true,
		})
	})
}
