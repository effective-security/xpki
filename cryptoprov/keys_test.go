package cryptoprov_test

import (
	"context"
	"crypto/elliptic"
	"crypto/mldsa"
	stderrors "errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyUsage(t *testing.T) {
	t.Parallel()
	both := cryptoprov.KeyUsageSign | cryptoprov.KeyUsageEncrypt
	for usage, name := range map[cryptoprov.KeyUsage]string{
		0:                          "",
		cryptoprov.KeyUsageSign:    "sign",
		cryptoprov.KeyUsageEncrypt: "encrypt",
		both:                       "sign,encrypt",
	} {
		assert.Equal(t, name, usage.String())
		parsed, err := cryptoprov.ParseKeyUsage(name)
		require.NoError(t, err)
		assert.Equal(t, usage, parsed)
	}
	parsed, err := cryptoprov.ParseKeyUsage(" Encrypt , SIGN,")
	require.NoError(t, err)
	assert.Equal(t, both, parsed)
	_, err = cryptoprov.ParseKeyUsage("sign,verify")
	require.EqualError(t, err, `invalid key usage "verify": expected sign or encrypt`)

	assert.True(t, both.Has(cryptoprov.KeyUsageSign))
	assert.True(t, both.Has(both))
	assert.False(t, cryptoprov.KeyUsageSign.Has(both))
	assert.False(t, both.Has(0), "no usage is not a usage a key has")
	// the values are those of csr.KeyPurpose
	assert.Equal(t, cryptoprov.KeyUsage(1), cryptoprov.KeyUsageSign)
	assert.Equal(t, cryptoprov.KeyUsage(2), cryptoprov.KeyUsageEncrypt)
}

func TestParseKeyState(t *testing.T) {
	t.Parallel()
	for _, state := range []cryptoprov.KeyState{
		cryptoprov.KeyStateEnabled,
		cryptoprov.KeyStateDisabled,
		cryptoprov.KeyStatePendingDeletion,
		cryptoprov.KeyStateDestroyed,
		cryptoprov.KeyStateUnavailable,
	} {
		parsed, err := cryptoprov.ParseKeyState(" " + string(state) + " ")
		require.NoError(t, err)
		assert.Equal(t, state, parsed)
	}
	parsed, err := cryptoprov.ParseKeyState("Pending_Deletion")
	require.NoError(t, err)
	assert.Equal(t, cryptoprov.KeyStatePendingDeletion, parsed)
	_, err = cryptoprov.ParseKeyState("deleted")
	require.ErrorContains(t, err, `invalid key state "deleted"`)
}

func TestKeyFields(t *testing.T) {
	t.Parallel()
	all := cryptoprov.KeyFieldsAll
	assert.True(t, all.Has(cryptoprov.KeyFieldMetadata|cryptoprov.KeyFieldTags))
	assert.False(t, all.Has(cryptoprov.KeyFieldPublicKey), "a listing mask has no public key")
	assert.False(t, all.Has(0))
	require.NoError(t, (all | cryptoprov.KeyFieldPublicKey).Validate())
	require.NoError(t, cryptoprov.KeyFields(0).Validate())
	require.EqualError(t, (all | 1<<9).Validate(), "invalid key fields: unknown bits 0x200")
}

func TestKeyFilter(t *testing.T) {
	t.Parallel()
	key := &cryptoprov.KeyInfo{
		ID:    "1",
		Label: "issuer/ca",
		Type:  certutil.KeyTypeECDSA,
		Usage: cryptoprov.KeyUsageSign,
		State: cryptoprov.KeyStateEnabled,
		Tags: map[string]string{
			"team": "alpha",
			"env":  "",
		},
	}
	for _, tc := range []struct {
		name   string
		filter cryptoprov.KeyFilter
		fields cryptoprov.KeyFields
		match  bool
	}{
		{
			name:  "zero",
			match: true,
		},
		{
			name:   "usage",
			filter: cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageSign},
			fields: cryptoprov.KeyFieldMetadata,
			match:  true,
		},
		{
			name:   "either usage",
			filter: cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageSign | cryptoprov.KeyUsageEncrypt},
			fields: cryptoprov.KeyFieldMetadata,
			match:  true,
		},
		{
			name:   "other usage",
			filter: cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageEncrypt},
			fields: cryptoprov.KeyFieldMetadata,
		},
		{
			name:   "types",
			filter: cryptoprov.KeyFilter{Types: []string{certutil.KeyTypeRSA, certutil.KeyTypeECDSA}},
			fields: cryptoprov.KeyFieldMetadata,
			match:  true,
		},
		{
			name:   "other type",
			filter: cryptoprov.KeyFilter{Types: []string{certutil.KeyTypeMLDSA}},
			fields: cryptoprov.KeyFieldMetadata,
		},
		{
			name:   "label",
			filter: cryptoprov.KeyFilter{Label: "issuer/ca"},
			fields: cryptoprov.KeyFieldMetadata,
			match:  true,
		},
		{
			name:   "label is exact",
			filter: cryptoprov.KeyFilter{Label: "issuer/c"},
			fields: cryptoprov.KeyFieldMetadata,
		},
		{
			name:   "prefix",
			filter: cryptoprov.KeyFilter{LabelPrefix: "issuer/"},
			fields: cryptoprov.KeyFieldMetadata,
			match:  true,
		},
		{
			name:   "not a prefix",
			filter: cryptoprov.KeyFilter{LabelPrefix: "ca"},
			fields: cryptoprov.KeyFieldMetadata,
		},
		{
			name:   "tags",
			filter: cryptoprov.KeyFilter{Tags: map[string]string{"team": "alpha", "env": ""}},
			fields: cryptoprov.KeyFieldTags,
			match:  true,
		},
		{
			name:   "tag value",
			filter: cryptoprov.KeyFilter{Tags: map[string]string{"team": "beta"}},
			fields: cryptoprov.KeyFieldTags,
		},
		{
			name:   "missing tag is not an empty one",
			filter: cryptoprov.KeyFilter{Tags: map[string]string{"owner": ""}},
			fields: cryptoprov.KeyFieldTags,
		},
		{
			name:   "states",
			filter: cryptoprov.KeyFilter{States: []cryptoprov.KeyState{cryptoprov.KeyStateDisabled, cryptoprov.KeyStateEnabled}},
			fields: cryptoprov.KeyFieldState,
			match:  true,
		},
		{
			name:   "other state",
			filter: cryptoprov.KeyFilter{States: []cryptoprov.KeyState{cryptoprov.KeyStateDestroyed}},
			fields: cryptoprov.KeyFieldState,
		},
		{
			name: "every condition",
			filter: cryptoprov.KeyFilter{
				Usage:       cryptoprov.KeyUsageSign,
				Types:       []string{certutil.KeyTypeECDSA},
				Label:       "issuer/ca",
				LabelPrefix: "iss",
				Tags:        map[string]string{"team": "alpha"},
				States:      []cryptoprov.KeyState{cryptoprov.KeyStateEnabled},
			},
			fields: cryptoprov.KeyFieldsAll,
			match:  true,
		},
		{
			name: "one condition fails",
			filter: cryptoprov.KeyFilter{
				Usage: cryptoprov.KeyUsageSign,
				Types: []string{certutil.KeyTypeECDSA},
				Label: "issuer/other",
			},
			fields: cryptoprov.KeyFieldMetadata,
		},
	} {
		assert.Equal(t, tc.match, tc.filter.Match(key), tc.name)
		assert.Equal(t, tc.fields, tc.filter.Fields(), tc.name)
		assert.Equal(t, tc.name == "zero", tc.filter.IsZero(), tc.name)
	}
}

func TestListKeysRequest(t *testing.T) {
	t.Parallel()
	valid := &cryptoprov.ListKeysRequest{
		PageSize: 10,
		Filter: cryptoprov.KeyFilter{
			Usage:  cryptoprov.KeyUsageSign,
			Types:  []string{certutil.KeyTypeRSA, "SLH-DSA"},
			Tags:   map[string]string{"team": "alpha"},
			States: []cryptoprov.KeyState{cryptoprov.KeyStateEnabled},
		},
		Fields: cryptoprov.KeyFieldsAll,
	}
	require.NoError(t, valid.Validate())
	require.NoError(t, (&cryptoprov.ListKeysRequest{}).Validate())

	var nilReq *cryptoprov.ListKeysRequest
	for name, tc := range map[string]struct {
		req *cryptoprov.ListKeysRequest
		msg string
	}{
		"nil": {
			req: nilReq,
			msg: "invalid list keys request: nil",
		},
		"page size": {
			req: &cryptoprov.ListKeysRequest{PageSize: -1},
			msg: "invalid page size: -1",
		},
		"public key": {
			req: &cryptoprov.ListKeysRequest{Fields: cryptoprov.KeyFieldMetadata | cryptoprov.KeyFieldPublicKey},
			msg: "invalid key fields: a listing does not return public keys, use KeyInfo",
		},
		"fields": {
			req: &cryptoprov.ListKeysRequest{Fields: 1 << 8},
			msg: "invalid key fields: unknown bits 0x100",
		},
		"usage": {
			req: &cryptoprov.ListKeysRequest{Filter: cryptoprov.KeyFilter{Usage: 4}},
			msg: "invalid key usage filter: unknown bits 0x4",
		},
		"type": {
			req: &cryptoprov.ListKeysRequest{Filter: cryptoprov.KeyFilter{Types: []string{""}}},
			msg: "invalid key type filter: empty type",
		},
		"state": {
			req: &cryptoprov.ListKeysRequest{Filter: cryptoprov.KeyFilter{States: []cryptoprov.KeyState{"on"}}},
			msg: `invalid key state filter "on": expected one of [enabled disabled pending_deletion destroyed unavailable]`,
		},
		"tag": {
			req: &cryptoprov.ListKeysRequest{Filter: cryptoprov.KeyFilter{Tags: map[string]string{"": "x"}}},
			msg: "invalid tag filter: empty tag name",
		},
	} {
		require.EqualError(t, tc.req.Validate(), tc.msg, name)
	}

	assert.Equal(t, 10, valid.Limit(50))
	assert.Equal(t, 50, (&cryptoprov.ListKeysRequest{}).Limit(50))
	assert.Equal(t, cryptoprov.DefaultPageSize, (&cryptoprov.ListKeysRequest{}).Limit(0))
	assert.Equal(t, cryptoprov.MaxPageSize, (&cryptoprov.ListKeysRequest{PageSize: 5000}).Limit(50))
	assert.Equal(t, cryptoprov.MaxPageSize, (&cryptoprov.ListKeysRequest{}).Limit(5000))
}

func TestPageKeys(t *testing.T) {
	t.Parallel()
	const total = 25
	keys := make([]cryptoprov.KeyInfo, total)
	for i := range keys {
		keys[i] = cryptoprov.KeyInfo{
			ID:    strconv.Itoa(i),
			Label: fmt.Sprintf("key-%02d", i),
			Usage: cryptoprov.KeyUsageSign,
		}
		if i%5 == 0 {
			keys[i].Usage = cryptoprov.KeyUsageEncrypt
		}
	}
	collect := func(req cryptoprov.ListKeysRequest) (ids []string, pages int) {
		for {
			resp, err := cryptoprov.PageKeys(&req, keys)
			require.NoError(t, err)
			require.NotNil(t, resp.Keys)
			pages++
			for _, key := range resp.Keys {
				ids = append(ids, key.ID)
			}
			if resp.NextPageToken == "" {
				return ids, pages
			}
			req.PageToken = resp.NextPageToken
		}
	}

	ids, pages := collect(cryptoprov.ListKeysRequest{PageSize: 10})
	assert.Len(t, ids, total)
	assert.Equal(t, 3, pages)

	ids, pages = collect(cryptoprov.ListKeysRequest{})
	assert.Len(t, ids, total)
	assert.Equal(t, 1, pages, "the default page holds them all")

	// exactly a page: no token for an empty next one
	ids, pages = collect(cryptoprov.ListKeysRequest{PageSize: total})
	assert.Len(t, ids, total)
	assert.Equal(t, 1, pages)

	ids, pages = collect(cryptoprov.ListKeysRequest{
		PageSize: 2,
		Filter:   cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageEncrypt},
	})
	assert.Equal(t, []string{"0", "5", "10", "15", "20"}, ids)
	assert.Equal(t, 3, pages)

	ids, _ = collect(cryptoprov.ListKeysRequest{Filter: cryptoprov.KeyFilter{Label: "none"}})
	assert.Empty(t, ids)

	req := cryptoprov.ListKeysRequest{PageSize: 10}
	first, err := cryptoprov.PageKeys(&req, keys)
	require.NoError(t, err)
	require.NotEmpty(t, first.NextPageToken)

	// the token belongs to the filter and the fields, not to the page size
	other := req
	other.PageToken = first.NextPageToken
	other.PageSize = 3
	next, err := cryptoprov.PageKeys(&other, keys)
	require.NoError(t, err)
	assert.Equal(t, "10", next.Keys[0].ID)

	other.Filter.LabelPrefix = "key-"
	_, err = cryptoprov.PageKeys(&other, keys)
	require.ErrorIs(t, err, cryptoprov.ErrInvalidPageToken)
	require.EqualError(t, err, "issued for another request: invalid page token")

	other = req
	other.PageToken = first.NextPageToken
	other.Fields = cryptoprov.KeyFieldTags
	_, err = cryptoprov.PageKeys(&other, keys)
	require.ErrorIs(t, err, cryptoprov.ErrInvalidPageToken)

	other = req
	other.PageToken = "?"
	_, err = cryptoprov.PageKeys(&other, keys)
	require.ErrorIs(t, err, cryptoprov.ErrInvalidPageToken)

	// a token beyond the keys ends the listing; a negative one is invalid
	other = req
	other.PageToken, err = cryptoprov.NewPageToken(&other, cryptoprov.PageCursor{Offset: 1000})
	require.NoError(t, err)
	next, err = cryptoprov.PageKeys(&other, keys)
	require.NoError(t, err)
	assert.Empty(t, next.Keys)
	assert.Empty(t, next.NextPageToken)

	other.PageToken, err = cryptoprov.NewPageToken(&other, cryptoprov.PageCursor{Offset: -1})
	require.NoError(t, err)
	_, err = cryptoprov.PageKeys(&other, keys)
	require.ErrorIs(t, err, cryptoprov.ErrInvalidPageToken)
	require.ErrorContains(t, err, "negative offset -1")

	_, err = cryptoprov.PageKeys(&cryptoprov.ListKeysRequest{PageSize: -1}, keys)
	require.EqualError(t, err, "invalid page size: -1")

	// the order of the types and the states is not part of the binding
	a := cryptoprov.ListKeysRequest{Filter: cryptoprov.KeyFilter{
		Types:  []string{"RSA", "ECDSA"},
		States: []cryptoprov.KeyState{cryptoprov.KeyStateEnabled, cryptoprov.KeyStateDisabled},
	}}
	b := cryptoprov.ListKeysRequest{Filter: cryptoprov.KeyFilter{
		Types:  []string{"ECDSA", "RSA"},
		States: []cryptoprov.KeyState{cryptoprov.KeyStateDisabled, cryptoprov.KeyStateEnabled},
	}}
	b.PageToken, err = cryptoprov.NewPageToken(&a, cryptoprov.PageCursor{
		Source: "s",
		Marker: "m",
		Offset: 3,
	})
	require.NoError(t, err)
	cursor, err := cryptoprov.ParsePageToken(&b)
	require.NoError(t, err)
	assert.Equal(t, cryptoprov.PageCursor{Source: "s", Marker: "m", Offset: 3}, cursor)
	assert.Equal(t, []string{"ECDSA", "RSA"}, b.Filter.Types, "the request is not reordered")
}

// pagedManager is a KeyManager whose ListKeys returns the pages in turn; the
// page token is the index of the next page.
type pagedManager struct {
	cryptoprov.KeyManager
	pages []*cryptoprov.ListKeysResponse
	errAt int
	calls int
}

func (m *pagedManager) ListKeys(_ context.Context, req *cryptoprov.ListKeysRequest) (*cryptoprov.ListKeysResponse, error) {
	m.calls++
	index := 0
	if req.PageToken != "" {
		index, _ = strconv.Atoi(req.PageToken)
	}
	if m.errAt > 0 && index == m.errAt {
		return nil, errors.New("backend failed")
	}
	return m.pages[index], nil
}

func TestAllKeys(t *testing.T) {
	t.Parallel()
	page := func(next string, ids ...string) *cryptoprov.ListKeysResponse {
		resp := &cryptoprov.ListKeysResponse{NextPageToken: next}
		for _, id := range ids {
			resp.Keys = append(resp.Keys, cryptoprov.KeyInfo{ID: id})
		}
		return resp
	}
	collect := func(ctx context.Context, km cryptoprov.KeyManager, req *cryptoprov.ListKeysRequest) (ids []string, err error) {
		for key, kerr := range cryptoprov.AllKeys(ctx, km, req) {
			if kerr != nil {
				assert.Nil(t, key)
				return ids, kerr
			}
			ids = append(ids, key.ID)
		}
		return ids, nil
	}

	t.Run("an empty page is not the end", func(t *testing.T) {
		km := &pagedManager{pages: []*cryptoprov.ListKeysResponse{
			page("1", "a", "b"),
			page("2"),
			page("", "c"),
		}}
		req := &cryptoprov.ListKeysRequest{PageSize: 2}
		ids, err := collect(t.Context(), km, req)
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b", "c"}, ids)
		assert.Equal(t, 3, km.calls)
		assert.Empty(t, req.PageToken, "the request is not modified")
	})
	t.Run("starts at the page token", func(t *testing.T) {
		km := &pagedManager{pages: []*cryptoprov.ListKeysResponse{
			page("1", "a"),
			page("", "b"),
		}}
		ids, err := collect(t.Context(), km, &cryptoprov.ListKeysRequest{PageToken: "1"})
		require.NoError(t, err)
		assert.Equal(t, []string{"b"}, ids)
	})
	t.Run("error after a page", func(t *testing.T) {
		km := &pagedManager{
			pages: []*cryptoprov.ListKeysResponse{page("1", "a"), nil},
			errAt: 1,
		}
		ids, err := collect(t.Context(), km, &cryptoprov.ListKeysRequest{})
		require.EqualError(t, err, "backend failed")
		assert.Equal(t, []string{"a"}, ids)
	})
	t.Run("stops when the caller does", func(t *testing.T) {
		km := &pagedManager{pages: []*cryptoprov.ListKeysResponse{
			page("1", "a", "b"),
			page("", "c"),
		}}
		for key, err := range cryptoprov.AllKeys(t.Context(), km, &cryptoprov.ListKeysRequest{}) {
			require.NoError(t, err)
			assert.Equal(t, "a", key.ID)
			break
		}
		assert.Equal(t, 1, km.calls, "the next page is not read")
	})
	t.Run("provider errors", func(t *testing.T) {
		_, err := collect(t.Context(), &pagedManager{pages: []*cryptoprov.ListKeysResponse{nil}}, &cryptoprov.ListKeysRequest{})
		require.EqualError(t, err, "provider returned no page")

		// a token that does not advance would loop forever
		km := &pagedManager{pages: []*cryptoprov.ListKeysResponse{page("1"), page("1")}}
		_, err = collect(t.Context(), km, &cryptoprov.ListKeysRequest{})
		require.EqualError(t, err, "provider returned the page token of the request")
		assert.Equal(t, 2, km.calls)

		_, err = collect(t.Context(), km, nil)
		require.EqualError(t, err, "invalid list keys request: nil")
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		km := &pagedManager{pages: []*cryptoprov.ListKeysResponse{page("")}}
		_, err := collect(ctx, km, &cryptoprov.ListKeysRequest{})
		require.ErrorIs(t, err, context.Canceled)
		assert.Zero(t, km.calls)
	})
}

func TestGenerateKeyRequest(t *testing.T) {
	t.Parallel()
	for _, req := range []*cryptoprov.GenerateKeyRequest{
		{Type: certutil.KeyTypeRSA, Size: 2048},
		{Type: certutil.KeyTypeRSA, Size: 3072, Usage: cryptoprov.KeyUsageEncrypt},
		{Type: certutil.KeyTypeRSA, Size: 4096, Usage: cryptoprov.KeyUsageSign | cryptoprov.KeyUsageEncrypt},
		{Type: certutil.KeyTypeECDSA, Size: 256, Usage: cryptoprov.KeyUsageSign},
		{Type: certutil.KeyTypeECDSA, Size: 384},
		{Type: certutil.KeyTypeECDSA, Size: 521, Tags: map[string]string{"team": "alpha"}},
		{Type: certutil.KeyTypeMLDSA, Size: cryptoprov.MLDSA44},
		{Type: certutil.KeyTypeMLDSA, Size: cryptoprov.MLDSA87, Label: "pq"},
	} {
		require.NoError(t, req.Validate(), "%s %d", req.Type, req.Size)
	}
	assert.Equal(t, cryptoprov.KeyUsageSign, (&cryptoprov.GenerateKeyRequest{}).KeyUsage(), "no usage is a signing key")
	assert.Equal(t, cryptoprov.KeyUsageEncrypt, (&cryptoprov.GenerateKeyRequest{Usage: cryptoprov.KeyUsageEncrypt}).KeyUsage())

	var nilReq *cryptoprov.GenerateKeyRequest
	for name, tc := range map[string]struct {
		req *cryptoprov.GenerateKeyRequest
		msg string
	}{
		"nil": {
			req: nilReq,
			msg: "invalid generate key request: nil",
		},
		"type": {
			req: &cryptoprov.GenerateKeyRequest{Type: "rsa", Size: 2048},
			msg: `invalid key type "rsa": expected RSA, ECDSA or ML-DSA`,
		},
		"RSA size": {
			req: &cryptoprov.GenerateKeyRequest{Type: certutil.KeyTypeRSA},
			msg: "invalid RSA key size: 0",
		},
		"curve": {
			req: &cryptoprov.GenerateKeyRequest{Type: certutil.KeyTypeECDSA, Size: 224},
			msg: "invalid ECDSA curve size (expected 256, 384 or 521): 224",
		},
		"parameter set": {
			req: &cryptoprov.GenerateKeyRequest{Type: certutil.KeyTypeMLDSA, Size: 2},
			msg: "invalid ML-DSA parameter set (expected 44, 65 or 87): 2",
		},
		"usage": {
			req: &cryptoprov.GenerateKeyRequest{Type: certutil.KeyTypeRSA, Size: 2048, Usage: 8},
			msg: "invalid key usage: unknown bits 0x8",
		},
		"ECDSA does not encrypt": {
			req: &cryptoprov.GenerateKeyRequest{Type: certutil.KeyTypeECDSA, Size: 256, Usage: cryptoprov.KeyUsageEncrypt},
			msg: `invalid key usage "encrypt": a ECDSA key is a signing key`,
		},
		"ML-DSA does not encrypt": {
			req: &cryptoprov.GenerateKeyRequest{Type: certutil.KeyTypeMLDSA, Size: 65, Usage: cryptoprov.KeyUsageSign | cryptoprov.KeyUsageEncrypt},
			msg: `invalid key usage "sign,encrypt": a ML-DSA key is a signing key`,
		},
		"tag": {
			req: &cryptoprov.GenerateKeyRequest{Type: certutil.KeyTypeRSA, Size: 2048, Tags: map[string]string{"": "x"}},
			msg: "invalid tags: empty tag name",
		},
	} {
		require.EqualError(t, tc.req.Validate(), tc.msg, name)
	}
}

func TestKeySizes(t *testing.T) {
	t.Parallel()
	for size, curve := range map[int]elliptic.Curve{
		256: elliptic.P256(),
		384: elliptic.P384(),
		521: elliptic.P521(),
	} {
		got, err := cryptoprov.ECDSACurve(size)
		require.NoError(t, err)
		assert.Equal(t, curve, got)
	}
	_, err := cryptoprov.ECDSACurve(224)
	require.EqualError(t, err, "invalid ECDSA curve size (expected 256, 384 or 521): 224")

	for size, params := range map[int]mldsa.Parameters{
		cryptoprov.MLDSA44: mldsa.MLDSA44(),
		cryptoprov.MLDSA65: mldsa.MLDSA65(),
		cryptoprov.MLDSA87: mldsa.MLDSA87(),
	} {
		assert.Equal(t, size, cryptoprov.MLDSASize(params))
		got, err := cryptoprov.MLDSAParameters(size)
		require.NoError(t, err)
		assert.Equal(t, params, got)
	}
	assert.Zero(t, cryptoprov.MLDSASize(mldsa.Parameters{}))
}

// causeError is a backend error a caller looks for with errors.As.
type causeError struct{ code int }

func (e *causeError) Error() string { return "backend code " + strconv.Itoa(e.code) }

func TestMarkError(t *testing.T) {
	t.Parallel()
	require.NoError(t, cryptoprov.MarkError(nil, cryptoprov.ErrKeyNotFound))

	backend := errors.WithMessage(&causeError{code: 404}, "failed to describe key")
	err := cryptoprov.MarkError(backend, cryptoprov.ErrKeyNotFound)
	require.EqualError(t, err, "failed to describe key: backend code 404", "the message is the backend's")

	// with the standard library and with cockroachdb/errors, also when the
	// error is wrapped again
	wrapped := errors.WithMessage(err, "list")
	for _, e := range []error{err, wrapped} {
		assert.True(t, stderrors.Is(e, cryptoprov.ErrKeyNotFound))
		assert.True(t, errors.Is(e, cryptoprov.ErrKeyNotFound))
		assert.False(t, stderrors.Is(e, cryptoprov.ErrNotSupported))
		var cause *causeError
		require.True(t, stderrors.As(e, &cause))
		assert.Equal(t, 404, cause.code)
	}
}
