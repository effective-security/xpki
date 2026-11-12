package crypto11

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"uuid"

	"github.com/effective-security/xpki/v2/certutil"
	"github.com/effective-security/xpki/v2/cryptoprov"
	"github.com/effective-security/xpki/v2/internal/provtest"
	"github.com/miekg/pkcs11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRSAKeySize is the size of the RSA keys of the listing tests: small,
// since their generation is not what is tested.
const testRSAKeySize = 1024

// labelsOf returns the labels of keys, in listing order.
func labelsOf(keys []cryptoprov.KeyInfo) []string {
	labels := make([]string, 0, len(keys))
	for _, key := range keys {
		labels = append(labels, key.Label)
	}
	return labels
}

// TestConformance runs the key management conformance suite on the SoftHSM
// token. Other tests change the token while it runs, so its paging test
// lists by an exact label, which the token evaluates.
func TestConformance(t *testing.T) {
	requireP11(t)
	t.Parallel()
	provtest.Run(t, provtest.Config{
		New: func(*testing.T) cryptoprov.Provider {
			return p11lib
		},
		Encrypt:        true,
		DestroyRemoves: true,
		PagingByLabel:  true,
	})
}

// TestListKeysOnToken checks the listing on the SoftHSM token: the search
// template of each filter, the conditions checked on the candidates, the
// fields, the page tokens, and that attributes are read for the keys of the
// page only and no session is left open. Not parallel: it sets the
// keyAttributesRead hook and counts sessions.
func TestListKeysOnToken(t *testing.T) {
	requireP11(t)
	ctx := t.Context()
	lib := p11lib
	prefix := "lk" + uuid.NewV7().String()[24:] + "-"

	generate := func(label, keyType string, size int, usage cryptoprov.KeyUsage) string {
		key, err := lib.GenerateKey(ctx, &cryptoprov.GenerateKeyRequest{
			Label: label,
			Type:  keyType,
			Size:  size,
			Usage: usage,
		})
		require.NoError(t, err, label)
		id, _, err := lib.IdentifyKey(ctx, key)
		require.NoError(t, err)
		t.Cleanup(func() {
			assert.NoError(t, lib.DestroyKey(context.Background(), id))
		})
		return id
	}
	generate(prefix+"rsa-sign", certutil.KeyTypeRSA, testRSAKeySize, cryptoprov.KeyUsageSign)
	generate(prefix+"rsa-enc", certutil.KeyTypeRSA, testRSAKeySize, cryptoprov.KeyUsageEncrypt)
	generate(prefix+"rsa-both", certutil.KeyTypeRSA, testRSAKeySize, cryptoprov.KeyUsageSign|cryptoprov.KeyUsageEncrypt)
	generate(prefix+"ec-256", certutil.KeyTypeECDSA, 256, 0)
	generate(prefix+"ec-384", certutil.KeyTypeECDSA, 384, 0)
	const same = 3
	for range same {
		generate(prefix+"same", certutil.KeyTypeECDSA, 256, 0)
	}

	var reads atomic.Int32
	keyAttributesRead = func() { reads.Add(1) }
	t.Cleanup(func() { keyAttributesRead = func() {} })

	list := func(req cryptoprov.ListKeysRequest) []cryptoprov.KeyInfo {
		var keys []cryptoprov.KeyInfo
		for {
			resp, err := lib.ListKeys(ctx, &req)
			require.NoError(t, err)
			if req.PageSize > 0 {
				assert.LessOrEqual(t, len(resp.Keys), req.PageSize)
			}
			keys = append(keys, resp.Keys...)
			if resp.NextPageToken == "" {
				return keys
			}
			req.PageToken = resp.NextPageToken
		}
	}
	// withPrefix keeps a listing to the keys of this test, in one call
	withPrefix := func(filter cryptoprov.KeyFilter) cryptoprov.ListKeysRequest {
		filter.LabelPrefix = prefix
		return cryptoprov.ListKeysRequest{
			PageSize: cryptoprov.MaxPageSize,
			Filter:   filter,
			Fields:   cryptoprov.KeyFieldMetadata,
		}
	}

	t.Run("exact label is the search template", func(t *testing.T) {
		tokenInfo, err := lib.Ctx.GetTokenInfo(lib.Slot.id)
		require.NoError(t, err)
		sessions := tokenInfo.SessionCount

		for _, size := range []int{1, 2, same, 0} {
			reads.Store(0)
			keys := list(cryptoprov.ListKeysRequest{
				PageSize: size,
				Filter:   cryptoprov.KeyFilter{Label: prefix + "same"},
			})
			require.Len(t, keys, same, "page size %d", size)
			ids := map[string]bool{}
			for _, key := range keys {
				ids[key.ID] = true
				assert.Equal(t, prefix+"same", key.Label)
				assert.Equal(t, certutil.KeyTypeECDSA, key.Type, "free: read with the ID")
				assert.Zero(t, key.Size, "not asked for")
				assert.Empty(t, key.PublicKey)
			}
			assert.Len(t, ids, same, "every key once")
			assert.Equal(t, int32(same), reads.Load(), "attributes are read for the returned keys only")
		}

		tokenInfo, err = lib.Ctx.GetTokenInfo(lib.Slot.id)
		require.NoError(t, err)
		assert.Equal(t, sessions, tokenInfo.SessionCount, "the listing closed its session")
	})

	t.Run("filters", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			filter cryptoprov.KeyFilter
			labels []string
		}{
			{
				name:   "prefix",
				labels: []string{"ec-256", "ec-384", "rsa-both", "rsa-enc", "rsa-sign", "same", "same", "same"},
			},
			{
				name:   "sign",
				filter: cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageSign},
				labels: []string{"ec-256", "ec-384", "rsa-both", "rsa-sign", "same", "same", "same"},
			},
			{
				name:   "encrypt",
				filter: cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageEncrypt},
				labels: []string{"rsa-both", "rsa-enc"},
			},
			{
				name:   "either usage",
				filter: cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageSign | cryptoprov.KeyUsageEncrypt},
				labels: []string{"ec-256", "ec-384", "rsa-both", "rsa-enc", "rsa-sign", "same", "same", "same"},
			},
			{
				name:   "one type",
				filter: cryptoprov.KeyFilter{Types: []string{certutil.KeyTypeRSA}},
				labels: []string{"rsa-both", "rsa-enc", "rsa-sign"},
			},
			{
				name:   "the same type twice",
				filter: cryptoprov.KeyFilter{Types: []string{certutil.KeyTypeRSA, certutil.KeyTypeRSA}},
				labels: []string{"rsa-both", "rsa-enc", "rsa-sign"},
			},
			{
				name:   "several types",
				filter: cryptoprov.KeyFilter{Types: []string{certutil.KeyTypeRSA, certutil.KeyTypeECDSA}},
				labels: []string{"ec-256", "ec-384", "rsa-both", "rsa-enc", "rsa-sign", "same", "same", "same"},
			},
			{
				name:   "types without a key",
				filter: cryptoprov.KeyFilter{Types: []string{certutil.KeyTypeMLDSA, "DSA"}},
				labels: []string{},
			},
			{
				name:   "type PKCS#11 does not have",
				filter: cryptoprov.KeyFilter{Types: []string{"DSA"}},
				labels: []string{},
			},
			{
				name: "type and usage",
				filter: cryptoprov.KeyFilter{
					Types: []string{certutil.KeyTypeRSA},
					Usage: cryptoprov.KeyUsageSign,
				},
				labels: []string{"rsa-both", "rsa-sign"},
			},
			{
				name:   "enabled",
				filter: cryptoprov.KeyFilter{States: []cryptoprov.KeyState{cryptoprov.KeyStateEnabled, cryptoprov.KeyStateDisabled}},
				labels: []string{"ec-256", "ec-384", "rsa-both", "rsa-enc", "rsa-sign", "same", "same", "same"},
			},
			{
				name:   "no key is disabled",
				filter: cryptoprov.KeyFilter{States: []cryptoprov.KeyState{cryptoprov.KeyStateDisabled}},
				labels: []string{},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				keys := list(withPrefix(tc.filter))
				labels := labelsOf(keys)
				for i := range labels {
					labels[i] = labels[i][len(prefix):]
				}
				assert.ElementsMatch(t, tc.labels, labels)
				for _, key := range keys {
					assert.Equal(t, cryptoprov.KeyStateEnabled, key.State)
					assert.Equal(t, "Private key", key.Class)
					assert.NotZero(t, key.Usage, key.Label)
					assert.Empty(t, key.Tags)
					assert.Empty(t, key.Name)
				}
			})
		}
	})

	t.Run("fields", func(t *testing.T) {
		byLabel := map[string]cryptoprov.KeyInfo{}
		for _, key := range list(withPrefix(cryptoprov.KeyFilter{})) {
			byLabel[key.Label[len(prefix):]] = key
		}
		for label, expected := range map[string]struct {
			keyType string
			size    int
			usage   cryptoprov.KeyUsage
		}{
			"rsa-sign": {
				keyType: certutil.KeyTypeRSA,
				size:    testRSAKeySize,
				usage:   cryptoprov.KeyUsageSign,
			},
			"rsa-both": {
				keyType: certutil.KeyTypeRSA,
				size:    testRSAKeySize,
				usage:   cryptoprov.KeyUsageSign | cryptoprov.KeyUsageEncrypt,
			},
			"ec-256": {
				keyType: certutil.KeyTypeECDSA,
				size:    256,
				usage:   cryptoprov.KeyUsageSign,
			},
			"ec-384": {
				keyType: certutil.KeyTypeECDSA,
				size:    384,
				usage:   cryptoprov.KeyUsageSign,
			},
		} {
			key := byLabel[label]
			assert.Equal(t, expected.keyType, key.Type, label)
			assert.Equal(t, expected.size, key.Size, label)
			assert.True(t, key.Usage.Has(expected.usage), "%s: usage %s", label, key.Usage)
		}
		assert.True(t, byLabel["rsa-enc"].Usage.Has(cryptoprov.KeyUsageEncrypt))

		// KeyInfo reads the same description
		info, err := lib.KeyInfo(ctx, byLabel["ec-384"].ID, cryptoprov.KeyFieldsAll)
		require.NoError(t, err)
		assert.Equal(t, byLabel["ec-384"], *info)
	})

	t.Run("page tokens", func(t *testing.T) {
		// a label prefix is checked on the candidates: the token is an
		// offset in the private keys of the token
		req := withPrefix(cryptoprov.KeyFilter{})
		req.PageSize = 2
		resp, err := lib.ListKeys(ctx, &req)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(resp.Keys), 2)

		other := cryptoprov.ListKeysRequest{
			PageSize: 1,
			Filter:   cryptoprov.KeyFilter{Label: prefix + "same"},
		}
		first, err := lib.ListKeys(ctx, &other)
		require.NoError(t, err)
		require.NotEmpty(t, first.NextPageToken)
		other.PageToken = first.NextPageToken
		other.Filter.Label = prefix + "ec-256"
		_, err = lib.ListKeys(ctx, &other)
		require.ErrorIs(t, err, cryptoprov.ErrInvalidPageToken)

		// an offset beyond the search ends the listing
		beyond := cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{Label: prefix + "same"},
		}
		beyond.PageToken, err = cryptoprov.NewPageToken(&beyond, cryptoprov.PageCursor{Offset: 100})
		require.NoError(t, err)
		resp, err = lib.ListKeys(ctx, &beyond)
		require.NoError(t, err)
		assert.Empty(t, resp.Keys)
		assert.Empty(t, resp.NextPageToken)
	})

	t.Run("not supported and invalid", func(t *testing.T) {
		_, err := lib.ListKeys(ctx, &cryptoprov.ListKeysRequest{
			Filter: cryptoprov.KeyFilter{Tags: map[string]string{"team": "alpha"}},
		})
		require.ErrorIs(t, err, cryptoprov.ErrNotSupported)

		_, err = lib.GenerateKey(ctx, &cryptoprov.GenerateKeyRequest{
			Label: prefix + "tagged",
			Type:  certutil.KeyTypeECDSA,
			Size:  256,
			Tags:  map[string]string{"team": "alpha"},
		})
		require.ErrorIs(t, err, cryptoprov.ErrNotSupported)

		_, err = lib.ListKeys(ctx, &cryptoprov.ListKeysRequest{Fields: cryptoprov.KeyFieldPublicKey})
		require.Error(t, err)

		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		_, err = lib.ListKeys(cancelled, &cryptoprov.ListKeysRequest{})
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("another slot", func(t *testing.T) {
		tokens, err := lib.ListTokens(ctx)
		require.NoError(t, err)
		for _, token := range tokens {
			km, err := lib.Token(token.SlotID)
			require.NoError(t, err)
			// a public session on another token sees no private key of it
			_, err = km.ListKeys(ctx, &cryptoprov.ListKeysRequest{PageSize: 1})
			require.NoError(t, err, "slot %d", token.SlotID)
		}
	})
}

// TestKeySearch checks the search template of a filter without a token.
func TestKeySearch(t *testing.T) {
	t.Parallel()

	attribute := func(s *keySearch, attributeType uint) *pkcs11.Attribute {
		for _, a := range s.template {
			if a.Type == attributeType {
				return a
			}
		}
		return nil
	}

	s, ok := newKeySearch(&cryptoprov.KeyFilter{})
	require.True(t, ok)
	require.Len(t, s.template, 1)
	assert.Equal(t, uint(pkcs11.CKA_CLASS), s.template[0].Type)
	assert.False(t, s.filtersCandidates())

	s, ok = newKeySearch(&cryptoprov.KeyFilter{
		Label: "ca",
		Types: []string{certutil.KeyTypeMLDSA},
		Usage: cryptoprov.KeyUsageSign,
	})
	require.True(t, ok)
	assert.Equal(t, []byte("ca"), attribute(s, pkcs11.CKA_LABEL).Value)
	keyType, err := bytesToUlong(attribute(s, pkcs11.CKA_KEY_TYPE).Value)
	require.NoError(t, err)
	assert.Equal(t, uint(ckkMLDSA), keyType)
	assert.Equal(t, []byte{1}, attribute(s, pkcs11.CKA_SIGN).Value)
	assert.Nil(t, attribute(s, pkcs11.CKA_DECRYPT))
	assert.False(t, s.filtersCandidates(), "the token evaluates the whole filter")

	s, ok = newKeySearch(&cryptoprov.KeyFilter{Usage: cryptoprov.KeyUsageEncrypt})
	require.True(t, ok)
	assert.Equal(t, []byte{1}, attribute(s, pkcs11.CKA_DECRYPT).Value)

	s, ok = newKeySearch(&cryptoprov.KeyFilter{
		LabelPrefix: "ca",
		Types:       []string{certutil.KeyTypeRSA, certutil.KeyTypeECDSA},
		Usage:       cryptoprov.KeyUsageSign | cryptoprov.KeyUsageEncrypt,
	})
	require.True(t, ok)
	assert.Len(t, s.template, 1, "the class only")
	assert.True(t, s.filtersCandidates())
	assert.True(t, s.match(&cryptoprov.KeyInfo{
		Label: "ca-1",
		Type:  certutil.KeyTypeECDSA,
		Usage: cryptoprov.KeyUsageSign,
	}))
	assert.False(t, s.match(&cryptoprov.KeyInfo{
		Label: "other",
		Type:  certutil.KeyTypeECDSA,
		Usage: cryptoprov.KeyUsageSign,
	}))
	assert.False(t, s.match(&cryptoprov.KeyInfo{
		Label: "ca-1",
		Type:  certutil.KeyTypeMLDSA,
		Usage: cryptoprov.KeyUsageSign,
	}))
	assert.False(t, s.match(&cryptoprov.KeyInfo{
		Label: "ca-1",
		Type:  certutil.KeyTypeRSA,
	}))

	_, ok = newKeySearch(&cryptoprov.KeyFilter{States: []cryptoprov.KeyState{cryptoprov.KeyStateDestroyed}})
	assert.False(t, ok)
	_, ok = newKeySearch(&cryptoprov.KeyFilter{Types: []string{"DSA"}})
	assert.False(t, ok)
}

// TestWithSessionCtx_BoundsTheWait checks the context-aware borrow: a
// borrower at the session limit waits no longer than its context, a context
// that is already done borrows nothing, and the pool keeps working.
func TestWithSessionCtx_BoundsTheWait(t *testing.T) {
	t.Parallel()
	lib, sessions := newFakeLib(1)
	release := make(chan struct{})
	_, held := holdSession(t, lib, testSlot, release)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	ran := false
	err := lib.withSessionCtx(ctx, testSlot, func(pkcs11.SessionHandle) error {
		ran = true
		return nil
	})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorContains(t, err, "wait for a session on slot")
	assert.False(t, ran)

	cancelled, cancelNow := context.WithCancel(t.Context())
	cancelNow()
	close(release)
	require.NoError(t, <-held)
	err = lib.withSessionCtx(cancelled, testSlot, func(pkcs11.SessionHandle) error {
		ran = true
		return nil
	})
	require.ErrorIs(t, err, context.Canceled, "an idle session is not borrowed for a context that is done")
	assert.False(t, ran)

	// the session is still usable
	require.NoError(t, lib.withSessionCtx(t.Context(), testSlot, func(pkcs11.SessionHandle) error {
		ran = true
		return nil
	}))
	assert.True(t, ran)
	opened, _, live, maxLive := sessions.counts()
	assert.Equal(t, 1, opened)
	assert.Equal(t, 1, live)
	assert.Equal(t, 1, maxLive)
	require.NoError(t, lib.Close())
}

// TestWithSessionCtx_CancelDoesNotLoseWakeups runs borrowers that give up
// against borrowers that wait, on a pool of two sessions: a cancelled
// waiter must pass on the wake-up it consumed, so every patient borrower
// gets a session (run with -race).
func TestWithSessionCtx_CancelDoesNotLoseWakeups(t *testing.T) {
	t.Parallel()
	const (
		maxSessions = 2
		borrowers   = 64
	)
	lib, sessions := newFakeLib(maxSessions)
	var (
		wg        sync.WaitGroup
		completed atomic.Int32
		gaveUp    atomic.Int32
	)
	start := make(chan struct{})
	for i := range borrowers {
		wg.Go(func() {
			<-start
			ctx := t.Context()
			if i%2 == 1 {
				// impatient: gives up while the pool is busy
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Millisecond)
				defer cancel()
			}
			err := lib.withSessionCtx(ctx, testSlot, func(pkcs11.SessionHandle) error {
				time.Sleep(2 * time.Millisecond)
				return nil
			})
			switch {
			case err == nil:
				completed.Add(1)
			case i%2 == 1 && assert.ErrorIs(t, err, context.DeadlineExceeded):
				gaveUp.Add(1)
			default:
				assert.NoError(t, err, "a patient borrower failed")
			}
		})
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	close(start)
	select {
	case <-done:
	case <-time.After(testDeadline):
		require.FailNow(t, "borrowers are stuck: a wake-up was lost")
	}
	assert.Equal(t, int32(borrowers), completed.Load()+gaveUp.Load())
	assert.GreaterOrEqual(t, completed.Load(), int32(borrowers/2), "every patient borrower completed")
	_, _, _, maxLive := sessions.counts()
	assert.LessOrEqual(t, maxLive, maxSessions)
	require.NoError(t, lib.Close())
}
