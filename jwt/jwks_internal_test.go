package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/effective-security/xpki/v2/csr"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoteKeySetRotationCooldown checks that a key published during the
// refresh cooldown becomes usable once the cooldown ends (XPKI-070).
func TestRemoteKeySetRotationCooldown(t *testing.T) {
	t.Parallel()
	oldKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	var (
		mu   sync.Mutex
		keys = []jose.JSONWebKey{{Key: &oldKey.PublicKey, KeyID: "old"}}
		hits atomic.Int32
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		mu.Lock()
		body, err := json.Marshal(jose.JSONWebKeySet{Keys: keys})
		mu.Unlock()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	var clock atomic.Int64
	clock.Store(time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC).UnixNano())
	advance := func(d time.Duration) { clock.Add(int64(d)) }

	ctx := context.Background()
	ks := NewRemoteKeySet(ctx, srv.URL)
	ks.now = func() time.Time { return time.Unix(0, clock.Load()) }

	_, err = ks.GetKeyForAlgorithm(ctx, "old", algES256)
	require.NoError(t, err)

	mu.Lock()
	keys = append(keys, jose.JSONWebKey{Key: &newKey.PublicKey, KeyID: "new"})
	mu.Unlock()

	// Inside the cooldown the new kid is refused without a fetch.
	advance(DefaultJWKSRefreshCooldown - time.Nanosecond)
	_, err = ks.GetKeyForAlgorithm(ctx, "new", algES256)
	require.EqualError(t, err, `kid="new": key not found`)
	assert.ErrorIs(t, err, ErrKeyNotFound)
	assert.Equal(t, int32(1), hits.Load())

	// Known keys keep working from the cache meanwhile.
	key, err := ks.GetKeyForAlgorithm(ctx, "old", algES256)
	require.NoError(t, err)
	assert.Equal(t, &oldKey.PublicKey, key)

	// Once the cooldown has passed, one fetch picks up the rotated key.
	advance(time.Nanosecond)
	key, err = ks.GetKeyForAlgorithm(ctx, "new", algES256)
	require.NoError(t, err)
	assert.Equal(t, &newKey.PublicKey, key)
	assert.Equal(t, int32(2), hits.Load())

	// The successful fetch starts a new cooldown.
	_, err = ks.GetKeyForAlgorithm(ctx, "other", algES256)
	require.EqualError(t, err, `kid="other": key not found`)
	assert.Equal(t, int32(2), hits.Load())
}

func TestRemoteKeySetOptions(t *testing.T) {
	t.Parallel()
	ks := NewRemoteKeySet(context.Background(), "https://example.invalid/jwks")
	assert.Equal(t, DefaultJWKSRefreshCooldown, ks.cooldown)
	assert.Equal(t, DefaultJWKSFetchTimeout, ks.fetchTimeout)
	assert.Equal(t, int64(DefaultJWKSMaxResponseSize), ks.maxResponseSize)
	require.NotNil(t, ks.client)
	assert.Equal(t, DefaultJWKSFetchTimeout, ks.client.Timeout)

	ks = NewRemoteKeySet(context.Background(), "https://example.invalid/jwks",
		WithRefreshCooldown(-time.Second),
		WithFetchTimeout(0),
		WithMaxResponseSize(-1),
	)
	assert.Zero(t, ks.cooldown)
	assert.Equal(t, DefaultJWKSFetchTimeout, ks.fetchTimeout)
	assert.Equal(t, int64(DefaultJWKSMaxResponseSize), ks.maxResponseSize)

	ks = NewRemoteKeySet(context.Background(), "https://example.invalid/jwks",
		WithRefreshCooldown(time.Minute),
		WithFetchTimeout(3*time.Second),
		WithMaxResponseSize(4096),
	)
	assert.Equal(t, time.Minute, ks.cooldown)
	assert.Equal(t, 3*time.Second, ks.fetchTimeout)
	assert.Equal(t, int64(4096), ks.maxResponseSize)
	assert.Equal(t, 3*time.Second, ks.client.Timeout)
}

// keySetSettings are the options a RemoteKeySet was created with.
type keySetSettings struct {
	cooldown        time.Duration
	fetchTimeout    time.Duration
	maxResponseSize int64
	minTTL          time.Duration
	maxTTL          time.Duration
	staleIfError    time.Duration
}

func settingsOf(r *RemoteKeySet) keySetSettings {
	return keySetSettings{
		cooldown:        r.cooldown,
		fetchTimeout:    r.fetchTimeout,
		maxResponseSize: r.maxResponseSize,
		minTTL:          r.minTTL,
		maxTTL:          r.maxTTL,
		staleIfError:    r.staleIfError,
	}
}

var defaultKeySetSettings = keySetSettings{
	cooldown:        DefaultJWKSRefreshCooldown,
	fetchTimeout:    DefaultJWKSFetchTimeout,
	maxResponseSize: DefaultJWKSMaxResponseSize,
	minTTL:          DefaultJWKSMinCacheTTL,
	maxTTL:          DefaultJWKSMaxCacheTTL,
	staleIfError:    DefaultJWKSStaleIfError,
}

func TestRemoteKeySetCacheOptions(t *testing.T) {
	t.Parallel()
	const jwksURL = "https://example.invalid/jwks"
	ctx := context.Background()

	ks := NewRemoteKeySet(ctx, jwksURL)
	assert.Equal(t, defaultKeySetSettings, settingsOf(ks))

	ks = NewRemoteKeySet(ctx, jwksURL,
		WithMinCacheTTL(0),
		WithMaxCacheTTL(-time.Second),
		WithStaleIfError(-time.Second),
	)
	want := defaultKeySetSettings
	want.staleIfError = 0
	assert.Equal(t, want, settingsOf(ks))

	ks = NewRemoteKeySet(ctx, jwksURL,
		WithMinCacheTTL(time.Minute),
		WithMaxCacheTTL(10*time.Minute),
		WithStaleIfError(time.Hour),
	)
	want = defaultKeySetSettings
	want.minTTL, want.maxTTL, want.staleIfError = time.Minute, 10*time.Minute, time.Hour
	assert.Equal(t, want, settingsOf(ks))

	// A minimum above the maximum is lowered to it, in any option order.
	ks = NewRemoteKeySet(ctx, jwksURL, WithMaxCacheTTL(2*time.Minute), WithMinCacheTTL(time.Hour))
	assert.Equal(t, 2*time.Minute, ks.minTTL)
	assert.Equal(t, 2*time.Minute, ks.maxTTL)
}

// TestParserConfigJWKSClient checks that NewParser applies
// ParserConfig.JWKSClient to its RemoteKeySet.
func TestParserConfigJWKSClient(t *testing.T) {
	t.Parallel()
	remote := func(t *testing.T, cfg *ParserConfig) *RemoteKeySet {
		t.Helper()
		p, err := NewParser(cfg)
		require.NoError(t, err)
		ks, ok := p.(*parser).verifier.(*RemoteKeySet)
		require.True(t, ok, "verifier is %T", p.(*parser).verifier)
		return ks
	}

	t.Run("yaml", func(t *testing.T) {
		t.Parallel()
		cfg, err := LoadParserConfig("testdata/oidc_parser_jwks_client.yaml")
		require.NoError(t, err)
		ks := remote(t, cfg)
		assert.Equal(t, keySetSettings{
			cooldown:        0,
			fetchTimeout:    3 * time.Second,
			maxResponseSize: 4096,
			minTTL:          time.Minute,
			maxTTL:          10 * time.Minute,
			staleIfError:    0,
		}, settingsOf(ks))
		assert.Equal(t, 3*time.Second, ks.client.Timeout)
	})

	t.Run("json with absent fields", func(t *testing.T) {
		t.Parallel()
		var cfg ParserConfig
		err := json.Unmarshal([]byte(`{
			"jwks_uri": "https://example.invalid/jwks",
			"jwks_client": {"fetch_timeout": "3s", "min_cache_ttl": 60, "stale_if_error": "2h"}
		}`), &cfg)
		require.NoError(t, err)
		require.NotNil(t, cfg.JWKSClient)
		assert.Nil(t, cfg.JWKSClient.RefreshCooldown)
		want := defaultKeySetSettings
		want.fetchTimeout, want.minTTL, want.staleIfError = 3*time.Second, time.Minute, 2*time.Hour
		assert.Equal(t, want, settingsOf(remote(t, &cfg)))
	})

	t.Run("no jwks_client", func(t *testing.T) {
		t.Parallel()
		ks := remote(t, &ParserConfig{JWKSURI: "https://example.invalid/jwks"})
		assert.Equal(t, defaultKeySetSettings, settingsOf(ks))
	})

	t.Run("negative values", func(t *testing.T) {
		t.Parallel()
		negative := csr.Duration(-time.Second)
		ks := remote(t, &ParserConfig{
			JWKSURI: "https://example.invalid/jwks",
			JWKSClient: &RemoteKeySetConfig{
				RefreshCooldown: &negative,
				FetchTimeout:    negative,
				MaxResponseSize: -1,
				MinCacheTTL:     negative,
				MaxCacheTTL:     negative,
				StaleIfError:    &negative,
			},
		})
		want := defaultKeySetSettings
		want.cooldown, want.staleIfError = 0, 0
		assert.Equal(t, want, settingsOf(ks))
	})

	t.Run("nil config", func(t *testing.T) {
		t.Parallel()
		var cfg *RemoteKeySetConfig
		assert.Nil(t, cfg.Options())
	})
}

// TestRemoteKeySetStaleSnapshotSharesFetch covers a lookup that read the cache
// before a fetch published and took the lock after the fetch freed its
// inflight slot: it must reuse that fetch's result, even with cooldown 0.
func TestRemoteKeySetStaleSnapshotSharesFetch(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	body, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "a"}}})
	require.NoError(t, err)

	var (
		hits   atomic.Int32
		failed atomic.Bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if failed.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	ctx := context.Background()
	ks := NewRemoteKeySet(ctx, srv.URL, WithRefreshCooldown(0))

	stale := ks.keysFromCache(time.Now()).fetches
	_, err = ks.GetKey(ctx, "a")
	require.NoError(t, err)
	require.Equal(t, int32(1), hits.Load())

	keys, err := ks.keysFromRemote(ctx, stale)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "a", keys[0].KeyID)
	assert.Equal(t, int32(1), hits.Load(), "stale snapshot must not start another fetch")

	// A current snapshot still refetches with cooldown 0.
	current := ks.keysFromCache(time.Now()).fetches
	failed.Store(true)
	_, err = ks.keysFromRemote(ctx, current)
	require.EqualError(t, err, "get keys failed: 502 Bad Gateway")
	assert.Equal(t, int32(2), hits.Load())

	// A snapshot older than a failed fetch shares that failure.
	_, err = ks.keysFromRemote(ctx, current)
	require.EqualError(t, err, "get keys failed: 502 Bad Gateway")
	assert.Equal(t, int32(2), hits.Load())
}
