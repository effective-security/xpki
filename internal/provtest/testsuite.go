package provtest

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"strings"
	"testing"

	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/stretchr/testify/suite"
)

const (
	// labelPrefixBase starts the label of every key of the suite; a random
	// suffix follows, so that the suite finds its own keys in a store it
	// shares with other tests. Labels have only [a-z0-9-], which every
	// provider stores unchanged.
	labelPrefixBase = "pt"
	pageLabelBase   = "pg"
	doomedLabelBase = "pd"
	suffixLength    = 8

	// rsaKeySize is the size of the RSA keys of the suite, the smallest
	// every provider generates.
	rsaKeySize = 2048

	// pagedKeys is the number of keys the paging test lists.
	pagedKeys = 5

	// The tags of the tagged keys.
	tagTeam  = "team"
	tagEnv   = "env"
	teamA    = "alpha"
	teamB    = "beta"
	envValue = "test"
)

// pageSizes are the page sizes of the paging test; zero is the provider
// default.
var pageSizes = []int{1, 2, 3, pagedKeys, 0}

// Config describes the provider under test and what its backend can do.
type Config struct {
	// New returns the provider, which must implement cryptoprov.KeyManager.
	// The suite calls it once. The store may hold other keys and may be
	// changed by other tests while the suite runs.
	New func(t *testing.T) cryptoprov.Provider

	// Tags reports that keys can be tagged and filtered by tag. Without it
	// the suite asserts cryptoprov.ErrNotSupported for both.
	Tags bool
	// Encrypt reports that RSA encryption keys can be generated. Without it
	// the suite asserts cryptoprov.ErrNotSupported.
	Encrypt bool
	// MLDSA reports that ML-DSA keys can be generated.
	MLDSA bool
	// DestroyRemoves reports that DestroyKey removes a key at once, so that
	// it is not found afterwards. Otherwise the key stays, in a state other
	// than enabled.
	DestroyRemoves bool
	// PagingByLabel makes the paging test give its keys one label and list
	// them by that exact label instead of by a label prefix. It is for a
	// provider whose page token is an offset in the order of the keys that
	// pass the backend's own filter, in a store other tests change: only
	// the exact label keeps that order to the suite's keys.
	PagingByLabel bool
	// ListedID returns the KeyInfo.ID a listing has for the key that
	// IdentifyKey names keyID; nil when they are the same. Google Cloud KMS
	// lists the key and identifies a signer by its version.
	ListedID func(keyID string) string
}

// testKey is a key the suite generated.
type testKey struct {
	// id is the key ID from IdentifyKey and listed the ID in a listing.
	id     string
	listed string
	label  string
	req    cryptoprov.GenerateKeyRequest
	key    crypto.PrivateKey
}

// Suite is the conformance suite; use Run.
type Suite struct {
	suite.Suite

	cfg  Config
	prov cryptoprov.Provider
	km   cryptoprov.KeyManager

	// prefix is the label prefix of the keys of this run, and pageLabel
	// the label of the keys of the paging test when they share one.
	// doomedLabel is the label of the key TestDestroyKey destroys. Neither
	// has the prefix: a backend that defers the destruction keeps listing
	// that key.
	prefix      string
	pageLabel   string
	doomedLabel string
	// keys are the keys of the filter tests and paged those of the paging
	// test
	keys  []*testKey
	paged []*testKey
	// destroy has the ids of the keys to destroy when the suite ends
	destroy []string
}

// Run runs the conformance suite on the provider of cfg.
func Run(t *testing.T, cfg Config) {
	suite.Run(t, &Suite{cfg: cfg})
}

// ctx returns the context of the running test.
func (s *Suite) ctx() context.Context {
	return s.T().Context()
}

// SetupSuite creates the provider and the keys of the run.
func (s *Suite) SetupSuite() {
	s.Require().NotNil(s.cfg.New, "Config.New is required")
	s.prov = s.cfg.New(s.T())
	s.Require().NotNil(s.prov)
	km, ok := s.prov.(cryptoprov.KeyManager)
	s.Require().True(ok, "%T is not a cryptoprov.KeyManager", s.prov)
	s.km = km
	suffix := strings.ToLower(rand.Text())[:suffixLength]
	s.prefix = labelPrefixBase + suffix + "-"
	s.pageLabel = pageLabelBase + suffix
	s.doomedLabel = doomedLabelBase + suffix

	specs := []cryptoprov.GenerateKeyRequest{
		{
			Label: s.prefix + "rsa-sign",
			Type:  certutil.KeyTypeRSA,
			Size:  rsaKeySize,
			Usage: cryptoprov.KeyUsageSign,
		},
		{
			Label: s.prefix + "ec-a",
			Type:  certutil.KeyTypeECDSA,
			Size:  256,
		},
		{
			Label: s.prefix + "ec-b",
			Type:  certutil.KeyTypeECDSA,
			Size:  256,
		},
		{
			Label: s.prefix + "ec-c",
			Type:  certutil.KeyTypeECDSA,
			Size:  384,
		},
	}
	if s.cfg.Tags {
		specs[1].Tags = map[string]string{
			tagTeam: teamA,
			tagEnv:  envValue,
		}
		specs[2].Tags = map[string]string{
			tagTeam: teamB,
			tagEnv:  envValue,
		}
	}
	if s.cfg.Encrypt {
		specs = append(specs, cryptoprov.GenerateKeyRequest{
			Label: s.prefix + "rsa-enc",
			Type:  certutil.KeyTypeRSA,
			Size:  rsaKeySize,
			Usage: cryptoprov.KeyUsageEncrypt,
		})
	}
	if s.cfg.MLDSA {
		specs = append(specs, cryptoprov.GenerateKeyRequest{
			Label: s.prefix + "mldsa",
			Type:  certutil.KeyTypeMLDSA,
			Size:  cryptoprov.MLDSA65,
		})
	}
	for i := range specs {
		s.keys = append(s.keys, s.generate(&specs[i]))
	}

	if !s.cfg.PagingByLabel {
		s.paged = s.keys
		return
	}
	for range pagedKeys {
		s.paged = append(s.paged, s.generate(&cryptoprov.GenerateKeyRequest{
			Label: s.pageLabel,
			Type:  certutil.KeyTypeECDSA,
			Size:  256,
		}))
	}
}

// TearDownSuite destroys the keys of the run.
func (s *Suite) TearDownSuite() {
	if s.km == nil {
		return
	}
	// the context of the suite's test is done by now
	ctx := context.Background()
	for _, id := range s.destroy {
		if err := s.km.DestroyKey(ctx, id); err != nil {
			s.T().Logf("unable to destroy key %s: %v", id, err)
		}
	}
}

// generate creates the key of req and registers it for destruction.
func (s *Suite) generate(req *cryptoprov.GenerateKeyRequest) *testKey {
	key, err := s.prov.GenerateKey(s.ctx(), req)
	s.Require().NoError(err, "generate %s", req.Label)
	id, label, err := s.prov.IdentifyKey(s.ctx(), key)
	s.Require().NoError(err)
	s.Require().NotEmpty(id)
	s.Equal(req.Label, label)
	s.destroy = append(s.destroy, id)

	listed := id
	if s.cfg.ListedID != nil {
		listed = s.cfg.ListedID(id)
	}
	return &testKey{
		id:     id,
		listed: listed,
		label:  label,
		req:    *req,
		key:    key,
	}
}

// pagingFilter returns the filter that selects the keys of the paging test.
func (s *Suite) pagingFilter() cryptoprov.KeyFilter {
	if s.cfg.PagingByLabel {
		return cryptoprov.KeyFilter{Label: s.pageLabel}
	}
	return cryptoprov.KeyFilter{LabelPrefix: s.prefix}
}

// listedIDs returns the listing IDs of keys, sorted.
func listedIDs(keys []*testKey) []string {
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		ids = append(ids, key.listed)
	}
	slices.Sort(ids)
	return ids
}

// infoIDs returns the IDs of keys, sorted.
func infoIDs(keys []cryptoprov.KeyInfo) []string {
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		ids = append(ids, key.ID)
	}
	slices.Sort(ids)
	return ids
}

// listAll reads every page of req and returns the keys. It checks what
// holds for every page: no more keys than the page size, no public key, an
// ID in every key, and a page token that advances.
func (s *Suite) listAll(req cryptoprov.ListKeysRequest) []cryptoprov.KeyInfo {
	var keys []cryptoprov.KeyInfo
	seen := map[string]bool{}
	for {
		resp, err := s.km.ListKeys(s.ctx(), &req)
		s.Require().NoError(err)
		s.Require().NotNil(resp)
		if req.PageSize > 0 {
			s.LessOrEqual(len(resp.Keys), req.PageSize, "page is longer than the page size")
		}
		for _, key := range resp.Keys {
			s.NotEmpty(key.ID)
			s.Empty(key.PublicKey, "a listing returned a public key: %s", key.ID)
		}
		keys = append(keys, resp.Keys...)
		if resp.NextPageToken == "" {
			return keys
		}
		s.Require().False(seen[resp.NextPageToken], "page token repeats")
		seen[resp.NextPageToken] = true
		req.PageToken = resp.NextPageToken
	}
}

// TestPaging checks that a full listing returns every key once at every
// page size, by pages and through AllKeys.
func (s *Suite) TestPaging() {
	expected := listedIDs(s.paged)
	for _, size := range pageSizes {
		req := cryptoprov.ListKeysRequest{
			PageSize: size,
			Filter:   s.pagingFilter(),
		}
		s.Equal(expected, infoIDs(s.listAll(req)), "page size %d", size)

		var ids []string
		for key, err := range cryptoprov.AllKeys(s.ctx(), s.km, &req) {
			s.Require().NoError(err)
			ids = append(ids, key.ID)
		}
		slices.Sort(ids)
		s.Equal(expected, ids, "AllKeys with page size %d", size)
	}
}

// TestFilters checks every filter condition against the keys of the run.
func (s *Suite) TestFilters() {
	cases := []struct {
		name   string
		filter cryptoprov.KeyFilter
		// tags marks a case that needs a provider with tags
		tags bool
		keep func(key *testKey) bool
	}{
		{
			name: "prefix",
			keep: func(*testKey) bool { return true },
		},
		{
			name:   "usage sign",
			filter: cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageSign},
			keep: func(key *testKey) bool {
				return key.req.KeyUsage() == cryptoprov.KeyUsageSign
			},
		},
		{
			name:   "usage encrypt",
			filter: cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageEncrypt},
			keep: func(key *testKey) bool {
				return key.req.KeyUsage() == cryptoprov.KeyUsageEncrypt
			},
		},
		{
			name:   "either usage",
			filter: cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageSign | cryptoprov.KeyUsageEncrypt},
			keep:   func(*testKey) bool { return true },
		},
		{
			name:   "one type",
			filter: cryptoprov.KeyFilter{Types: []string{certutil.KeyTypeECDSA}},
			keep: func(key *testKey) bool {
				return key.req.Type == certutil.KeyTypeECDSA
			},
		},
		{
			name:   "several types",
			filter: cryptoprov.KeyFilter{Types: []string{certutil.KeyTypeRSA, certutil.KeyTypeMLDSA}},
			keep: func(key *testKey) bool {
				return key.req.Type != certutil.KeyTypeECDSA
			},
		},
		{
			name:   "exact label",
			filter: cryptoprov.KeyFilter{Label: s.prefix + "ec-b"},
			keep: func(key *testKey) bool {
				return key.label == s.prefix+"ec-b"
			},
		},
		{
			name:   "longer prefix",
			filter: cryptoprov.KeyFilter{LabelPrefix: s.prefix + "ec-"},
			keep: func(key *testKey) bool {
				return strings.HasPrefix(key.label, s.prefix+"ec-")
			},
		},
		{
			name:   "label that no key has",
			filter: cryptoprov.KeyFilter{Label: s.prefix + "ec"},
			keep:   func(*testKey) bool { return false },
		},
		{
			name:   "enabled",
			filter: cryptoprov.KeyFilter{States: []cryptoprov.KeyState{cryptoprov.KeyStateEnabled}},
			keep:   func(*testKey) bool { return true },
		},
		{
			name: "other states",
			filter: cryptoprov.KeyFilter{States: []cryptoprov.KeyState{
				cryptoprov.KeyStateDisabled,
				cryptoprov.KeyStatePendingDeletion,
				cryptoprov.KeyStateDestroyed,
			}},
			keep: func(*testKey) bool { return false },
		},
		{
			name:   "type and usage",
			filter: cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageSign, Types: []string{certutil.KeyTypeRSA}},
			keep: func(key *testKey) bool {
				return key.req.Type == certutil.KeyTypeRSA && key.req.KeyUsage() == cryptoprov.KeyUsageSign
			},
		},
		{
			name:   "one tag",
			tags:   true,
			filter: cryptoprov.KeyFilter{Tags: map[string]string{tagTeam: teamA}},
			keep: func(key *testKey) bool {
				return key.req.Tags[tagTeam] == teamA
			},
		},
		{
			name: "two tags",
			tags: true,
			filter: cryptoprov.KeyFilter{Tags: map[string]string{
				tagTeam: teamB,
				tagEnv:  envValue,
			}},
			keep: func(key *testKey) bool {
				return key.req.Tags[tagTeam] == teamB
			},
		},
		{
			name:   "shared tag",
			tags:   true,
			filter: cryptoprov.KeyFilter{Tags: map[string]string{tagEnv: envValue}},
			keep: func(key *testKey) bool {
				return key.req.Tags[tagEnv] == envValue
			},
		},
		{
			name:   "tag value that no key has",
			tags:   true,
			filter: cryptoprov.KeyFilter{Tags: map[string]string{tagTeam: "gamma"}},
			keep:   func(*testKey) bool { return false },
		},
	}
	for _, tc := range cases {
		if tc.tags && !s.cfg.Tags {
			continue
		}
		s.Run(tc.name, func() {
			filter := tc.filter
			if filter.Label == "" && filter.LabelPrefix == "" {
				// keep the listing to the keys of this run
				filter.LabelPrefix = s.prefix
			}
			var expected []*testKey
			for _, key := range s.keys {
				if tc.keep(key) {
					expected = append(expected, key)
				}
			}
			keys := s.listAll(cryptoprov.ListKeysRequest{
				// one page, so that a store other tests change cannot move
				// keys between pages
				PageSize: cryptoprov.MaxPageSize,
				Filter:   filter,
			})
			s.Equal(listedIDs(expected), infoIDs(keys))
		})
	}
}

// TestFields checks that a listing fills the groups its field mask selects.
func (s *Suite) TestFields() {
	byID := map[string]*testKey{}
	for _, key := range s.keys {
		byID[key.listed] = key
	}
	list := func(fields cryptoprov.KeyFields) []cryptoprov.KeyInfo {
		keys := s.listAll(cryptoprov.ListKeysRequest{
			PageSize: cryptoprov.MaxPageSize,
			Filter:   cryptoprov.KeyFilter{LabelPrefix: s.prefix},
			Fields:   fields,
		})
		s.Require().Len(keys, len(s.keys))
		return keys
	}

	s.Run("metadata", func() {
		for _, info := range list(cryptoprov.KeyFieldMetadata) {
			key := byID[info.ID]
			s.Require().NotNil(key, info.ID)
			s.Equal(key.label, info.Label)
			s.Equal(key.req.Type, info.Type)
			s.Equal(key.req.Size, info.Size)
			s.Equal(key.req.KeyUsage(), info.Usage, info.Label)
		}
	})
	s.Run("state", func() {
		for _, info := range list(cryptoprov.KeyFieldState) {
			s.Equal(cryptoprov.KeyStateEnabled, info.State, info.ID)
		}
	})
	s.Run("tags", func() {
		// a provider without tags ignores the group
		for _, info := range list(cryptoprov.KeyFieldTags) {
			key := byID[info.ID]
			s.Require().NotNil(key, info.ID)
			for name, value := range key.req.Tags {
				s.Equal(value, info.Tags[name], "tag %s of %s", name, info.ID)
			}
		}
	})
	s.Run("all", func() {
		list(cryptoprov.KeyFieldsAll)
	})
}

// TestPageToken checks that a page token is opaque state of one listing: it
// is rejected with another filter, another field mask, or when it is not a
// token.
func (s *Suite) TestPageToken() {
	req := cryptoprov.ListKeysRequest{
		PageSize: 1,
		Filter:   s.pagingFilter(),
	}
	resp, err := s.km.ListKeys(s.ctx(), &req)
	s.Require().NoError(err)
	s.Require().NotEmpty(resp.NextPageToken, "the first page of %d keys has a next page", len(s.paged))

	other := req
	other.PageToken = resp.NextPageToken
	other.Filter.Usage = cryptoprov.KeyUsageSign
	_, err = s.km.ListKeys(s.ctx(), &other)
	s.Require().ErrorIs(err, cryptoprov.ErrInvalidPageToken, "another filter")

	other = req
	other.PageToken = resp.NextPageToken
	other.Fields = cryptoprov.KeyFieldMetadata
	_, err = s.km.ListKeys(s.ctx(), &other)
	s.Require().ErrorIs(err, cryptoprov.ErrInvalidPageToken, "another field mask")

	for _, token := range []string{"not a token", "bm90IGEgdG9rZW4", resp.NextPageToken[1:]} {
		other = req
		other.PageToken = token
		_, err = s.km.ListKeys(s.ctx(), &other)
		s.Require().ErrorIs(err, cryptoprov.ErrInvalidPageToken, token)
	}

	// the page size is not part of the token
	other = req
	other.PageToken = resp.NextPageToken
	other.PageSize = pagedKeys
	next, err := s.km.ListKeys(s.ctx(), &other)
	s.Require().NoError(err)
	s.NotEmpty(next.Keys)
}

// TestInvalidRequests checks the requests no provider accepts.
func (s *Suite) TestInvalidRequests() {
	for name, req := range map[string]*cryptoprov.ListKeysRequest{
		"public key in a listing": {Fields: cryptoprov.KeyFieldPublicKey},
		"unknown field group":     {Fields: 1 << 20},
		"negative page size":      {PageSize: -1},
		"unknown usage":           {Filter: cryptoprov.KeyFilter{Usage: 1 << 5}},
		"unknown state":           {Filter: cryptoprov.KeyFilter{States: []cryptoprov.KeyState{"gone"}}},
		"nil":                     nil,
	} {
		_, err := s.km.ListKeys(s.ctx(), req)
		s.Error(err, name)
	}
	_, err := s.km.KeyInfo(s.ctx(), s.keys[0].id, 1<<20)
	s.Error(err, "unknown field group")

	for name, req := range map[string]*cryptoprov.GenerateKeyRequest{
		"unknown type": {Type: "DSA", Size: 2048},
		"curve":        {Type: certutil.KeyTypeECDSA, Size: 255},
		"parameter set": {
			Type: certutil.KeyTypeMLDSA,
			Size: 66,
		},
		"encrypting ECDSA key": {
			Type:  certutil.KeyTypeECDSA,
			Size:  256,
			Usage: cryptoprov.KeyUsageEncrypt,
		},
		"nil": nil,
	} {
		_, err := s.prov.GenerateKey(s.ctx(), req)
		s.Require().Error(err, name)
		s.NotErrorIs(err, cryptoprov.ErrNotSupported, name)
	}
}

// TestNotSupported checks that what the backend cannot do is an error, not
// an empty result or a key of another kind.
func (s *Suite) TestNotSupported() {
	if !s.cfg.Tags {
		_, err := s.km.ListKeys(s.ctx(), &cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{Tags: map[string]string{tagTeam: teamA}},
		})
		s.Require().ErrorIs(err, cryptoprov.ErrNotSupported, "tag filter")

		_, err = s.prov.GenerateKey(s.ctx(), &cryptoprov.GenerateKeyRequest{
			Label: s.prefix + "tagged",
			Type:  certutil.KeyTypeECDSA,
			Size:  256,
			Tags:  map[string]string{tagTeam: teamA},
		})
		s.Require().ErrorIs(err, cryptoprov.ErrNotSupported, "tagged key")
	}
	if !s.cfg.Encrypt {
		_, err := s.prov.GenerateKey(s.ctx(), &cryptoprov.GenerateKeyRequest{
			Label: s.prefix + "enc",
			Type:  certutil.KeyTypeRSA,
			Size:  rsaKeySize,
			Usage: cryptoprov.KeyUsageEncrypt,
		})
		s.Require().ErrorIs(err, cryptoprov.ErrNotSupported, "encryption key")
	}
}

// TestKeyInfo checks the description of every key, with and without its
// public key.
func (s *Suite) TestKeyInfo() {
	for _, key := range s.keys {
		info, err := s.km.KeyInfo(s.ctx(), key.id, cryptoprov.KeyFieldMetadata|cryptoprov.KeyFieldState)
		s.Require().NoError(err, key.label)
		s.Equal(key.id, info.ID)
		s.Equal(key.label, info.Label)
		s.Equal(key.req.Type, info.Type)
		s.Equal(key.req.Size, info.Size)
		s.Equal(key.req.KeyUsage(), info.Usage, key.label)
		s.Equal(cryptoprov.KeyStateEnabled, info.State)
		s.Empty(info.PublicKey, "the public key was not asked for")

		info, err = s.km.KeyInfo(s.ctx(), key.id, cryptoprov.KeyFieldPublicKey)
		s.Require().NoError(err, key.label)
		public, ok := key.key.(interface{ Public() crypto.PublicKey })
		s.Require().True(ok, "%T has no public key", key.key)
		block, _ := pem.Decode([]byte(info.PublicKey))
		s.Require().NotNil(block, "the public key of %s is not PEM: %q", key.label, info.PublicKey)
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		s.Require().NoError(err, key.label)
		equal, ok := parsed.(interface{ Equal(crypto.PublicKey) bool })
		s.Require().True(ok, "%T", parsed)
		s.True(equal.Equal(public.Public()), "the public key of %s is not the key's", key.label)
	}
	if s.cfg.Tags {
		tagged := s.keys[1]
		info, err := s.km.KeyInfo(s.ctx(), tagged.id, cryptoprov.KeyFieldTags)
		s.Require().NoError(err)
		for name, value := range tagged.req.Tags {
			s.Equal(value, info.Tags[name], name)
		}
	}
}

// TestGetKey checks that a key is loaded by its ID and exported in a form
// that names it.
func (s *Suite) TestGetKey() {
	for _, key := range s.keys {
		loaded, err := s.prov.GetKey(s.ctx(), key.id)
		s.Require().NoError(err, key.label)
		id, label, err := s.prov.IdentifyKey(s.ctx(), loaded)
		s.Require().NoError(err)
		s.Equal(key.id, id)
		s.Equal(key.label, label)

		uri, pem, err := s.prov.ExportKey(s.ctx(), key.id)
		s.Require().NoError(err, key.label)
		if uri == "" {
			s.NotEmpty(pem, "neither a URI nor a key")
			continue
		}
		parsed, err := cryptoprov.ParsePrivateKeyURI(uri)
		s.Require().NoError(err, uri)
		s.Equal(key.id, parsed.ID())
		s.Equal(s.prov.Manufacturer(), parsed.Manufacturer())
	}
}

// TestKeyNotFound checks the error for a key the provider does not have.
func (s *Suite) TestKeyNotFound() {
	missing := s.prefix + "missing"
	_, err := s.prov.GetKey(s.ctx(), missing)
	s.Require().ErrorIs(err, cryptoprov.ErrKeyNotFound, "GetKey")
	_, err = s.km.KeyInfo(s.ctx(), missing, cryptoprov.KeyFieldMetadata)
	s.Require().ErrorIs(err, cryptoprov.ErrKeyNotFound, "KeyInfo")
	err = s.km.DestroyKey(s.ctx(), missing)
	s.Require().ErrorIs(err, cryptoprov.ErrKeyNotFound, "DestroyKey")
}

// TestCancelledContext checks that a call with a cancelled context fails
// with its error and does not create a key.
func (s *Suite) TestCancelledContext() {
	ctx, cancel := context.WithCancel(s.ctx())
	cancel()

	_, err := s.km.ListKeys(ctx, &cryptoprov.ListKeysRequest{
		Filter: cryptoprov.KeyFilter{LabelPrefix: s.prefix},
	})
	s.Require().ErrorIs(err, context.Canceled, "ListKeys")
	_, err = s.km.KeyInfo(ctx, s.keys[0].id, cryptoprov.KeyFieldMetadata)
	s.Require().ErrorIs(err, context.Canceled, "KeyInfo")
	_, err = s.prov.GetKey(ctx, s.keys[0].id)
	s.Require().ErrorIs(err, context.Canceled, "GetKey")

	label := s.prefix + "cancelled"
	_, err = s.prov.GenerateKey(ctx, &cryptoprov.GenerateKeyRequest{
		Label: label,
		Type:  certutil.KeyTypeECDSA,
		Size:  256,
	})
	s.Require().ErrorIs(err, context.Canceled, "GenerateKey")
	keys := s.listAll(cryptoprov.ListKeysRequest{
		Filter: cryptoprov.KeyFilter{Label: label},
	})
	s.Empty(keys, "a key was created with a cancelled context")

	for key, err := range cryptoprov.AllKeys(ctx, s.km, &cryptoprov.ListKeysRequest{}) {
		s.Require().ErrorIs(err, context.Canceled, "AllKeys")
		s.Nil(key)
	}
}

// TestDestroyKey checks that a destroyed key is gone, or is no longer
// enabled on a backend that defers the destruction.
func (s *Suite) TestDestroyKey() {
	label := s.doomedLabel
	key, err := s.prov.GenerateKey(s.ctx(), &cryptoprov.GenerateKeyRequest{
		Label: label,
		Type:  certutil.KeyTypeECDSA,
		Size:  256,
	})
	s.Require().NoError(err)
	id, _, err := s.prov.IdentifyKey(s.ctx(), key)
	s.Require().NoError(err)

	enabled := cryptoprov.ListKeysRequest{
		Filter: cryptoprov.KeyFilter{
			Label:  label,
			States: []cryptoprov.KeyState{cryptoprov.KeyStateEnabled},
		},
	}
	s.Len(s.listAll(enabled), 1)

	s.Require().NoError(s.km.DestroyKey(s.ctx(), id))
	s.Empty(s.listAll(enabled), "a destroyed key is listed as enabled")

	info, err := s.km.KeyInfo(s.ctx(), id, cryptoprov.KeyFieldState)
	if s.cfg.DestroyRemoves {
		s.Require().ErrorIs(err, cryptoprov.ErrKeyNotFound)
		_, err = s.prov.GetKey(s.ctx(), id)
		s.Require().ErrorIs(err, cryptoprov.ErrKeyNotFound)
		return
	}
	s.Require().NoError(err)
	s.NotEqual(cryptoprov.KeyStateEnabled, info.State)
	s.NotEmpty(info.State)
}
