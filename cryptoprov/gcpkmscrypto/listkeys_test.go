package gcpkmscrypto_test

import (
	"fmt"
	"strings"
	"testing"

	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/internal/provtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// listedIDs returns the ids of keys.
func listedIDs(keys []cryptoprov.KeyInfo) []string {
	ids := make([]string, 0, len(keys))
	for _, key := range keys {
		ids = append(ids, key.ID)
	}
	return ids
}

// listAll returns the keys of every page of req.
func listAll(t *testing.T, km cryptoprov.KeyManager, req *cryptoprov.ListKeysRequest) []cryptoprov.KeyInfo {
	t.Helper()
	keys := []cryptoprov.KeyInfo{}
	for key, err := range cryptoprov.AllKeys(t.Context(), km, req) {
		require.NoError(t, err)
		keys = append(keys, *key)
	}
	return keys
}

// TestListKeysPages asserts the request counts PLAN.md gives as the
// acceptance of the listing: a listing of n keys with page size p is ⌈n/p⌉
// ListCryptoKeys requests and nothing else, and KeyInfo with the Metadata
// group is one GetCryptoKey without a version listing.
func TestListKeysPages(t *testing.T) {
	t.Parallel()

	s := newFakeKMSServer()
	provider := grpcProvider(t, s)
	const total = 25
	var ids []string
	for i := range total {
		id := fmt.Sprintf("key-%02d", i)
		s.AddKey(t, id, kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, "label-"+id)
		ids = append(ids, id)
	}

	for _, tc := range []struct {
		size     int
		requests int
	}{
		{size: 10, requests: 3},
		{size: 25, requests: 1},
		{size: 7, requests: 4},
		// the provider default page holds them all
		{size: 0, requests: 1},
	} {
		before := len(s.Calls())
		keys := listAll(t, provider, &cryptoprov.ListKeysRequest{
			PageSize: tc.size,
			Fields:   cryptoprov.KeyFieldMetadata | cryptoprov.KeyFieldTags,
		})
		assert.Equal(t, ids, listedIDs(keys), "page size %d", tc.size)
		calls := s.Calls()[before:]
		assert.Len(t, calls, tc.requests, "page size %d: %v", tc.size, calls)
		for _, call := range calls {
			assert.Equal(t, "ListCryptoKeys", call)
		}
		for _, key := range keys {
			assert.Equal(t, "label-"+key.ID, key.Label)
			assert.Equal(t, certutil.KeyTypeECDSA, key.Type)
			assert.Equal(t, 256, key.Size)
			assert.Equal(t, cryptoprov.KeyUsageSign, key.Usage)
			assert.Equal(t, testKeyring+"/cryptoKeys/"+key.ID, key.Name)
			assert.Equal(t, key.Label, key.Tags["label"])
			assert.Empty(t, key.State)
			assert.Empty(t, key.PublicKey)
		}
	}
	requests := s.ListRequests()
	assert.Equal(t, int32(10), requests[0].GetPageSize())
	assert.Empty(t, requests[0].GetPageToken())
	assert.Equal(t, "10", requests[1].GetPageToken(), "the page token of KMS is passed through")
	assert.Empty(t, requests[0].GetFilter())

	before := len(s.Calls())
	info, err := provider.KeyInfo(t.Context(), ids[3], cryptoprov.KeyFieldMetadata)
	require.NoError(t, err)
	assert.Equal(t, ids[3], info.ID)
	assert.Equal(t, "label-"+ids[3], info.Label)
	assert.Empty(t, info.State, "not asked for")
	assert.Empty(t, info.CurrentVersionID)
	assert.Equal(t, []string{"GetCryptoKey"}, s.Calls()[before:], "no version listing for the label")

	before = len(s.Calls())
	info, err = provider.KeyInfo(t.Context(), ids[3], cryptoprov.KeyFieldMetadata|cryptoprov.KeyFieldState)
	require.NoError(t, err)
	assert.Equal(t, cryptoprov.KeyStateEnabled, info.State)
	assert.Equal(t, "1", info.CurrentVersionID)
	assert.Equal(t, []string{"GetCryptoKey", "ListCryptoKeyVersions"}, s.Calls()[before:])

	t.Run("page token that is not one of KMS", func(t *testing.T) {
		req := &cryptoprov.ListKeysRequest{PageSize: 10}
		token, err := cryptoprov.NewPageToken(req, cryptoprov.PageCursor{Marker: "bogus"})
		require.NoError(t, err)
		req.PageToken = token
		_, err = provider.ListKeys(t.Context(), req)
		require.ErrorIs(t, err, cryptoprov.ErrInvalidPageToken)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "the KMS status is kept")
	})
}

// TestListKeysFilters checks every filter condition, what is sent to KMS for
// it and what is checked on the returned keys. The label conditions match
// the "label" label, sanitized as GenerateKey does (XPKI-129).
func TestListKeysFilters(t *testing.T) {
	t.Parallel()

	s := newFakeKMSServer()
	provider := grpcProvider(t, s)
	caName := s.AddKey(t, "ca-1", kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, "issuer-ca")
	s.SetLabels(t, caName, map[string]string{
		"label": "issuer-ca",
		"team":  "alpha",
		"env":   "prod",
	})
	rsaName := s.AddKey(t, "rsa-1", kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512, "issuer-rsa")
	s.SetLabels(t, rsaName, map[string]string{
		"label": "issuer-rsa",
		"team":  "beta",
		"env":   "prod",
	})
	s.AddKey(t, "pq-1", kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65, "pq")
	// "other-issuer" has the label prefix as a substring only
	s.AddKey(t, "other-1", kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, "other-issuer")
	disabledName := s.AddKey(t, "off-1", kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, "issuer-off")
	s.SetState(t, disabledName+"/cryptoKeyVersions/1", kmspb.CryptoKeyVersion_DISABLED)
	s.AddSymmetricKey(t, "sym-1", "data", kmspb.CryptoKeyVersion_ENABLED)
	s.AddSymmetricKey(t, "sym-2", "data-old", kmspb.CryptoKeyVersion_DESTROYED)
	s.AddForeignKey(t, "secp-1", kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256, "chain")

	cases := []struct {
		name   string
		filter cryptoprov.KeyFilter
		ids    []string
		// pushed is the filter KMS receives
		pushed string
		// versions reports that the listing reads key versions
		versions bool
	}{
		{
			name: "no filter",
			ids:  []string{"ca-1", "off-1", "other-1", "pq-1", "rsa-1", "secp-1", "sym-1", "sym-2"},
		},
		{
			name:   "exact label",
			filter: cryptoprov.KeyFilter{Label: "issuer-ca"},
			ids:    []string{"ca-1"},
			pushed: "labels.label=issuer-ca",
		},
		{
			name:   "label as it was requested",
			filter: cryptoprov.KeyFilter{Label: "Issuer CA"},
			ids:    []string{"ca-1"},
			pushed: "labels.label=issuer-ca",
		},
		{
			name:   "label prefix is not a substring",
			filter: cryptoprov.KeyFilter{LabelPrefix: "issuer-"},
			ids:    []string{"ca-1", "off-1", "rsa-1"},
			pushed: "labels.label:issuer-",
		},
		{
			name:   "label that no key has",
			filter: cryptoprov.KeyFilter{Label: "issuer"},
			ids:    []string{},
			pushed: "labels.label=issuer",
		},
		{
			name: "label and prefix",
			filter: cryptoprov.KeyFilter{
				Label:       "issuer-rsa",
				LabelPrefix: "issuer-",
			},
			ids:    []string{"rsa-1"},
			pushed: "labels.label=issuer-rsa",
		},
		{
			name:   "tag",
			filter: cryptoprov.KeyFilter{Tags: map[string]string{"team": "alpha"}},
			ids:    []string{"ca-1"},
			pushed: "labels.team=alpha",
		},
		{
			name: "tags and prefix",
			filter: cryptoprov.KeyFilter{
				LabelPrefix: "issuer-",
				Tags: map[string]string{
					"team": "beta",
					"env":  "prod",
				},
			},
			ids:    []string{"rsa-1"},
			pushed: "labels.label:issuer- AND labels.env=prod AND labels.team=beta",
		},
		{
			name:   "tag value that is not a plain token is checked here",
			filter: cryptoprov.KeyFilter{Tags: map[string]string{"team": "Alpha Team"}},
			ids:    []string{},
		},
		{
			name:   "signing keys",
			filter: cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageSign},
			ids:    []string{"ca-1", "off-1", "other-1", "pq-1", "rsa-1", "secp-1"},
		},
		{
			name:   "encryption keys",
			filter: cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageEncrypt},
			ids:    []string{"sym-1", "sym-2"},
		},
		{
			name:   "types",
			filter: cryptoprov.KeyFilter{Types: []string{certutil.KeyTypeRSA, certutil.KeyTypeMLDSA}},
			ids:    []string{"pq-1", "rsa-1"},
		},
		{
			name:   "ECDSA is the NIST curves",
			filter: cryptoprov.KeyFilter{Types: []string{certutil.KeyTypeECDSA}},
			ids:    []string{"ca-1", "off-1", "other-1"},
		},
		{
			name:     "enabled",
			filter:   cryptoprov.KeyFilter{States: []cryptoprov.KeyState{cryptoprov.KeyStateEnabled}},
			ids:      []string{"ca-1", "other-1", "pq-1", "rsa-1", "secp-1", "sym-1"},
			versions: true,
		},
		{
			name: "disabled or destroyed",
			filter: cryptoprov.KeyFilter{States: []cryptoprov.KeyState{
				cryptoprov.KeyStateDisabled,
				cryptoprov.KeyStateDestroyed,
			}},
			ids:      []string{"off-1", "sym-2"},
			versions: true,
		},
		{
			name: "enabled issuers",
			filter: cryptoprov.KeyFilter{
				LabelPrefix: "issuer-",
				States:      []cryptoprov.KeyState{cryptoprov.KeyStateEnabled},
			},
			ids:      []string{"ca-1", "rsa-1"},
			pushed:   "labels.label:issuer-",
			versions: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			requests := len(s.ListRequests())
			versions := s.CallCount("ListCryptoKeyVersions")
			keys := listAll(t, provider, &cryptoprov.ListKeysRequest{Filter: tc.filter})
			assert.Equal(t, tc.ids, listedIDs(keys))

			sent := s.ListRequests()[requests:]
			require.Len(t, sent, 1)
			assert.Equal(t, tc.pushed, sent[0].GetFilter())
			if tc.versions {
				assert.Greater(t, s.CallCount("ListCryptoKeyVersions"), versions)
			} else {
				assert.Equal(t, versions, s.CallCount("ListCryptoKeyVersions"), "no version is read")
			}
		})
	}

	t.Run("fields of other key families", func(t *testing.T) {
		keys := listAll(t, provider, &cryptoprov.ListKeysRequest{Fields: cryptoprov.KeyFieldsAll})
		byID := map[string]cryptoprov.KeyInfo{}
		for _, key := range keys {
			byID[key.ID] = key
		}
		assert.Empty(t, byID["sym-1"].Type, "a symmetric key has no PKI type")
		assert.Zero(t, byID["sym-1"].Size)
		assert.Equal(t, cryptoprov.KeyUsageEncrypt, byID["sym-1"].Usage)
		assert.Equal(t, cryptoprov.KeyStateEnabled, byID["sym-1"].State)
		assert.Equal(t, "1", byID["sym-1"].CurrentVersionID)
		assert.Equal(t, "GOOGLE_SYMMETRIC_ENCRYPTION", byID["sym-1"].Meta["algo"])
		assert.Equal(t, cryptoprov.KeyStateDestroyed, byID["sym-2"].State)
		assert.Empty(t, byID["secp-1"].Type, "crypto/x509 cannot use secp256k1")
		assert.Equal(t, "EC_SIGN_SECP256K1_SHA256", byID["secp-1"].Meta["algo"])
		assert.Equal(t, certutil.KeyTypeRSA, byID["rsa-1"].Type)
		assert.Equal(t, 4096, byID["rsa-1"].Size)
		assert.Equal(t, certutil.KeyTypeMLDSA, byID["pq-1"].Type)
		assert.Equal(t, cryptoprov.MLDSA65, byID["pq-1"].Size)
		assert.Equal(t, "ML-DSA-65", byID["pq-1"].Meta[cryptoprov.MetaParameterSet])
		assert.Equal(t, cryptoprov.KeyStateDisabled, byID["off-1"].State)
		assert.Equal(t, "1", byID["off-1"].CurrentVersionID)
		assert.Equal(t, cryptoprov.KeyStateEnabled, byID["ca-1"].State)
	})

	t.Run("version listing fails", func(t *testing.T) {
		broken := newFakeKMSServer()
		provider := grpcProvider(t, broken)
		name := broken.AddKey(t, "gone", kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, "gone")
		broken.FailVersionListing(name, status.Error(codes.PermissionDenied, "denied"))
		_, err := provider.ListKeys(t.Context(), &cryptoprov.ListKeysRequest{Fields: cryptoprov.KeyFieldState})
		require.ErrorContains(t, err, "failed to list versions of key gone")
		assert.Equal(t, codes.PermissionDenied, status.Code(err))

		// without the state the same listing needs no version
		resp, err := provider.ListKeys(t.Context(), &cryptoprov.ListKeysRequest{})
		require.NoError(t, err)
		assert.Len(t, resp.Keys, 1)
	})
}

// TestConformance runs the key management conformance suite on the
// in-process KMS.
func TestConformance(t *testing.T) {
	t.Parallel()
	provtest.Run(t, provtest.Config{
		New: func(t *testing.T) cryptoprov.Provider {
			return grpcProvider(t, newFakeKMSServer())
		},
		Tags:  true,
		MLDSA: true,
		ListedID: func(keyID string) string {
			id, _, _ := strings.Cut(keyID, "/cryptoKeyVersions/")
			return id
		},
	})
}

// TestGenerateKeyAlgorithmNotOffered checks that the refusal of an algorithm
// at the HSM protection level, in the shape Cloud KMS returned it for the
// ML-DSA algorithms on 2026-11-12, is cryptoprov.ErrNotSupported with the
// KMS status kept, and that another INVALID_ARGUMENT is not.
func TestGenerateKeyAlgorithmNotOffered(t *testing.T) {
	t.Parallel()

	s := newFakeKMSServer()
	provider := grpcProvider(t, s)
	refused, err := status.New(codes.InvalidArgument,
		"Algorithm PQ_SIGN_ML_DSA_65_EXTERNAL_MU is not supported for protection level: HSM").
		WithDetails(&errdetails.ErrorInfo{
			Reason: "ALGORITHM_NOT_SUPPORTED_FOR_PROTECTION_LEVEL",
			Domain: "cloudkms.googleapis.com",
			Metadata: map[string]string{
				"algorithm":        "PQ_SIGN_ML_DSA_65_EXTERNAL_MU",
				"protection_level": "HSM",
			},
		})
	require.NoError(t, err)
	s.FailCreate(refused.Err(), status.Error(codes.InvalidArgument, "invalid label"))

	req := &cryptoprov.GenerateKeyRequest{
		Label: "pq",
		Type:  certutil.KeyTypeMLDSA,
		Size:  cryptoprov.MLDSA65,
	}
	_, err = provider.GenerateKey(t.Context(), req)
	require.ErrorIs(t, err, cryptoprov.ErrNotSupported)
	require.ErrorContains(t, err, "failed to create key pq-")
	require.ErrorContains(t, err, "is not supported for protection level: HSM")
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "the KMS status is kept")

	_, err = provider.GenerateKey(t.Context(), req)
	require.ErrorContains(t, err, "invalid label")
	require.NotErrorIs(t, err, cryptoprov.ErrNotSupported)
	assert.Equal(t, 2, s.CallCount("CreateCryptoKey"))
}
