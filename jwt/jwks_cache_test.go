package jwt_test

import (
	"cmp"
	"context"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/effective-security/xpki/v2/jwt"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	algES256 = "ES256"
	// expiredAt is the expiry of keys fetched at testClockStart with the
	// default maximum lifetime.
	expiredAt = "2026-11-18T01:00:00Z"
	// serverDown is the error of a fetch from a jwksServer answering 500.
	serverDown = "get keys failed: 500 Internal Server Error"
)

var testClockStart = time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)

// testClock is a manual clock for RemoteKeySet.SetClock.
type testClock struct{ ns atomic.Int64 }

func newTestClock() *testClock {
	c := &testClock{}
	c.ns.Store(testClockStart.UnixNano())
	return c
}

func (c *testClock) now() time.Time { return time.Unix(0, c.ns.Load()).UTC() }

func (c *testClock) advance(d time.Duration) { c.ns.Add(int64(d)) }

// httpDate formats t as an HTTP date, for the Date and Expires headers.
func httpDate(t time.Time) string { return t.UTC().Format(http.TimeFormat) }

func newClockedKeySet(srv *jwksServer, clock *testClock, opts ...jwt.RemoteKeySetOption) *jwt.RemoteKeySet {
	ks := jwt.NewRemoteKeySet(context.Background(), srv.URL, opts...)
	ks.SetClock(clock.now)
	return ks
}

// waitFetches waits until n fetches of ks have completed.
func waitFetches(t *testing.T, ks *jwt.RemoteKeySet, n uint64) {
	t.Helper()
	require.Eventually(t, func() bool { return ks.Fetches() == n }, 5*time.Second, time.Millisecond)
}

func TestRemoteKeySetCacheTTL(t *testing.T) {
	t.Parallel()
	k := newJWKSTestKeys(t)
	keyA := jose.JSONWebKey{Key: &k.p256.PublicKey, KeyID: "a"}

	tests := []struct {
		name         string
		cacheControl string
		// date is the response Date, testClockStart when zero; expires is
		// the Expires header, none when zero.
		date    time.Time
		expires time.Time
		opts    []jwt.RemoteKeySetOption
		ttl     time.Duration
	}{
		{
			name: "no header",
			ttl:  jwt.DefaultJWKSMaxCacheTTL,
		},
		{
			name:         "max-age",
			cacheControl: "public, max-age=600",
			ttl:          10 * time.Minute,
		},
		{
			name:         "max-age less the apparent age",
			cacheControl: "max-age=3600",
			date:         testClockStart.Add(-50 * time.Minute),
			ttl:          10 * time.Minute,
		},
		{
			name:    "Expires already passed by its Date",
			date:    testClockStart.Add(-time.Hour),
			expires: testClockStart.Add(-30 * time.Minute),
			ttl:     jwt.DefaultJWKSMinCacheTTL,
		},
		{
			name:         "below the minimum",
			cacheControl: "max-age=60",
			ttl:          jwt.DefaultJWKSMinCacheTTL,
		},
		{
			name:         "no-cache",
			cacheControl: "no-cache",
			ttl:          jwt.DefaultJWKSMinCacheTTL,
		},
		{
			name:         "above the maximum",
			cacheControl: "max-age=21065",
			ttl:          jwt.DefaultJWKSMaxCacheTTL,
		},
		{
			name:         "custom bounds",
			cacheControl: "max-age=90",
			opts: []jwt.RemoteKeySetOption{
				jwt.WithMinCacheTTL(time.Minute),
				jwt.WithMaxCacheTTL(2 * time.Minute),
			},
			ttl: 90 * time.Second,
		},
		{
			name: "custom maximum without header",
			opts: []jwt.RemoteKeySetOption{jwt.WithMaxCacheTTL(2 * time.Minute)},
			ttl:  2 * time.Minute,
		},
		{
			name:         "minimum above the maximum",
			cacheControl: "no-store",
			opts:         []jwt.RemoteKeySetOption{jwt.WithMinCacheTTL(2 * time.Hour)},
			ttl:          jwt.DefaultJWKSMaxCacheTTL,
		},
		{
			name:         "never shorter than the cooldown",
			cacheControl: "no-cache",
			opts:         []jwt.RemoteKeySetOption{jwt.WithRefreshCooldown(10 * time.Minute)},
			ttl:          10 * time.Minute,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := newJWKSServer(t, keyA)
			srv.setHeader("Date", httpDate(cmp.Or(tc.date, testClockStart)))
			if tc.cacheControl != "" {
				srv.setHeader("Cache-Control", tc.cacheControl)
			}
			if !tc.expires.IsZero() {
				srv.setHeader("Expires", httpDate(tc.expires))
			}
			ks := newClockedKeySet(srv, newTestClock(), tc.opts...)
			_, err := ks.GetKey(context.Background(), "a")
			require.NoError(t, err)
			assert.Equal(t, tc.ttl, ks.CacheTTL())
		})
	}
}

// TestRemoteKeySetRefreshAhead covers roadmap item 5: a lookup in the last
// quarter of the cache lifetime refreshes in the background without waiting
// for the endpoint, after which a key added to the document is found without
// a miss and a removed key is no longer accepted.
func TestRemoteKeySetRefreshAhead(t *testing.T) {
	t.Parallel()
	k := newJWKSTestKeys(t)
	ctx := context.Background()
	srv := newJWKSServer(t, jose.JSONWebKey{Key: &k.rsa.PublicKey, KeyID: "a"})
	clock := newTestClock()
	ks := newClockedKeySet(srv, clock)

	_, err := ks.GetKey(ctx, "a")
	require.NoError(t, err)

	// The endpoint rotates a out and b in, and stalls until gate is closed.
	srv.setKeys(t, jose.JSONWebKey{Key: &k.p256.PublicKey, KeyID: "b"})
	gate := make(chan struct{})
	srv.setGate(gate)

	// Before the last quarter, the cached document is used as is. A lookup
	// that starts a refresh sets the inflight request before it returns, so
	// Inflight is a deterministic check.
	clock.advance(jwt.DefaultJWKSMaxCacheTTL*3/4 - time.Second)
	key, err := ks.GetKey(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, &k.rsa.PublicKey, key)
	assert.False(t, ks.Inflight(), "refresh started before the last quarter")
	assert.Equal(t, int32(1), srv.hits.Load())

	// In the last quarter, a lookup starts a refresh and does not wait for it.
	clock.advance(time.Second)
	key, err = ks.GetKey(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, &k.rsa.PublicKey, key)
	assert.True(t, ks.Inflight())
	require.Eventually(t, func() bool { return srv.hits.Load() == 2 }, 5*time.Second, time.Millisecond)

	// Lookups during the refresh use the cache and send no other request.
	key, err = ks.GetKey(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, &k.rsa.PublicKey, key)
	assert.Equal(t, int32(2), srv.hits.Load())
	assert.Equal(t, int32(1), srv.maxActive.Load())

	close(gate)
	waitFetches(t, ks, 2)

	key, err = ks.GetKeyForAlgorithm(ctx, "b", algES256)
	require.NoError(t, err)
	assert.Equal(t, &k.p256.PublicKey, key)
	_, err = ks.GetKey(ctx, "a")
	require.EqualError(t, err, `kid="a": key not found`)
	assert.ErrorIs(t, err, jwt.ErrKeyNotFound)
	assert.Equal(t, int32(2), srv.hits.Load())
	assert.Equal(t, jwt.DefaultJWKSMaxCacheTTL, ks.CacheTTL())
}

// TestRemoteKeySetExpiredKeysWaitForRefresh checks that a lookup after the
// expiry, with no lookup in the last quarter, waits for the new document
// rather than accepting a key that was removed from it.
func TestRemoteKeySetExpiredKeysWaitForRefresh(t *testing.T) {
	t.Parallel()
	k := newJWKSTestKeys(t)
	ctx := context.Background()
	srv := newJWKSServer(t, jose.JSONWebKey{Key: &k.rsa.PublicKey, KeyID: "a"})
	srv.setHeader("Cache-Control", "max-age=600")
	srv.setHeader("Date", httpDate(testClockStart))
	clock := newTestClock()
	ks := newClockedKeySet(srv, clock)

	_, err := ks.GetKey(ctx, "a")
	require.NoError(t, err)

	srv.setKeys(t, jose.JSONWebKey{Key: &k.p256.PublicKey, KeyID: "b"})
	clock.advance(10 * time.Minute)
	key, err := ks.GetKey(ctx, "a")
	require.EqualError(t, err, `kid="a": key not found`)
	assert.ErrorIs(t, err, jwt.ErrKeyNotFound)
	assert.Nil(t, key)
	assert.Equal(t, int32(2), srv.hits.Load())

	key, err = ks.GetKeyForAlgorithm(ctx, "b", algES256)
	require.NoError(t, err)
	assert.Equal(t, &k.p256.PublicKey, key)
	assert.Equal(t, int32(2), srv.hits.Load())
}

// TestRemoteKeySetEarlyFailureGrantsNoGrace checks that a fetch that failed
// early in the lifetime, for a kid that is not cached, does not let a lookup
// after the expiry use the expired keys without waiting: a key removed from
// the document in the meantime is refused.
func TestRemoteKeySetEarlyFailureGrantsNoGrace(t *testing.T) {
	t.Parallel()
	k := newJWKSTestKeys(t)
	ctx := context.Background()
	srv := newJWKSServer(t, jose.JSONWebKey{Key: &k.rsa.PublicKey, KeyID: "a"})
	clock := newTestClock()
	ks := newClockedKeySet(srv, clock)

	_, err := ks.GetKey(ctx, "a")
	require.NoError(t, err)

	srv.setBody(http.StatusInternalServerError, nil)
	clock.advance(time.Minute)
	_, err = ks.GetKey(ctx, "x")
	require.EqualError(t, err, "unable to fetch JWKS key: "+serverDown)
	assert.Equal(t, int32(2), srv.hits.Load())

	srv.setKeys(t, jose.JSONWebKey{Key: &k.p256.PublicKey, KeyID: "b"})
	clock.advance(jwt.DefaultJWKSMaxCacheTTL)
	key, err := ks.GetKey(ctx, "a")
	require.EqualError(t, err, `kid="a": key not found`)
	assert.Nil(t, key)
	assert.Equal(t, int32(3), srv.hits.Load())
}

// TestRemoteKeySetStaleIfError checks that expired keys stay in use while
// refreshes fail, for the grace period only.
func TestRemoteKeySetStaleIfError(t *testing.T) {
	t.Parallel()
	k := newJWKSTestKeys(t)
	ctx := context.Background()
	keyA := jose.JSONWebKey{Key: &k.rsa.PublicKey, KeyID: "a"}
	srv := newJWKSServer(t, keyA)
	clock := newTestClock()
	ks := newClockedKeySet(srv, clock)

	_, err := ks.GetKey(ctx, "a")
	require.NoError(t, err)
	srv.setBody(http.StatusInternalServerError, []byte("down"))

	// The keys expire and the refresh the lookup waits for fails: the
	// lookup still gets its key.
	clock.advance(jwt.DefaultJWKSMaxCacheTTL)
	key, err := ks.GetKey(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, &k.rsa.PublicKey, key)
	assert.Equal(t, int32(2), srv.hits.Load())

	// Inside the cooldown, lookups use the expired keys without a fetch.
	clock.advance(jwt.DefaultJWKSRefreshCooldown - time.Nanosecond)
	key, err = ks.GetKey(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, &k.rsa.PublicKey, key)
	assert.Equal(t, int32(2), srv.hits.Load())

	// After it, a lookup still uses them and retries in the background.
	clock.advance(time.Nanosecond)
	key, err = ks.GetKey(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, &k.rsa.PublicKey, key)
	waitFetches(t, ks, 3)
	assert.Equal(t, int32(3), srv.hits.Load())

	// A kid that is not cached reports the failure.
	_, err = ks.GetKey(ctx, "x")
	require.EqualError(t, err, "unable to fetch JWKS key: JWKS refresh throttled after failure: "+serverDown)

	// At the end of the grace period, the lookup fails with the fetch error.
	clock.advance(jwt.DefaultJWKSStaleIfError - jwt.DefaultJWKSRefreshCooldown)
	key, err = ks.GetKey(ctx, "a")
	require.EqualError(t, err, "unable to fetch JWKS key: JWKS keys expired at "+expiredAt+": "+serverDown)
	assert.Nil(t, key)
	assert.Equal(t, int32(4), srv.hits.Load())
	_, err = ks.GetKey(ctx, "a")
	require.EqualError(t, err, "unable to fetch JWKS key: JWKS refresh throttled after failure: JWKS keys expired at "+expiredAt+": "+serverDown)
	assert.Equal(t, int32(4), srv.hits.Load())

	// A recovered endpoint is used once the cooldown has passed.
	srv.setKeys(t, keyA)
	clock.advance(jwt.DefaultJWKSRefreshCooldown)
	key, err = ks.GetKey(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, &k.rsa.PublicKey, key)
	assert.Equal(t, int32(5), srv.hits.Load())
	assert.Equal(t, jwt.DefaultJWKSMaxCacheTTL, ks.CacheTTL())
}

func TestRemoteKeySetStaleIfErrorDisabled(t *testing.T) {
	t.Parallel()
	k := newJWKSTestKeys(t)
	ctx := context.Background()
	srv := newJWKSServer(t, jose.JSONWebKey{Key: &k.rsa.PublicKey, KeyID: "a"})
	clock := newTestClock()
	ks := newClockedKeySet(srv, clock, jwt.WithStaleIfError(0))

	_, err := ks.GetKey(ctx, "a")
	require.NoError(t, err)
	srv.setBody(http.StatusInternalServerError, nil)

	// A refresh ahead fails, and the keys stay in use until they expire.
	clock.advance(jwt.DefaultJWKSMaxCacheTTL - time.Nanosecond)
	_, err = ks.GetKey(ctx, "a")
	require.NoError(t, err)
	waitFetches(t, ks, 2)

	clock.advance(time.Nanosecond)
	key, err := ks.GetKey(ctx, "a")
	require.EqualError(t, err, "unable to fetch JWKS key: JWKS refresh throttled after failure: JWKS keys expired at "+expiredAt+": "+serverDown)
	assert.Nil(t, key)
	assert.Equal(t, int32(2), srv.hits.Load())

	clock.advance(jwt.DefaultJWKSRefreshCooldown)
	_, err = ks.GetKey(ctx, "a")
	require.EqualError(t, err, "unable to fetch JWKS key: JWKS keys expired at "+expiredAt+": "+serverDown)
	assert.Equal(t, int32(3), srv.hits.Load())
}

// TestRemoteKeySetRefreshAheadFailure checks that after a failed refresh
// ahead, a lookup after the expiry uses the keys without waiting, even for
// an endpoint that stalls.
func TestRemoteKeySetRefreshAheadFailure(t *testing.T) {
	t.Parallel()
	k := newJWKSTestKeys(t)
	ctx := context.Background()
	srv := newJWKSServer(t, jose.JSONWebKey{Key: &k.rsa.PublicKey, KeyID: "a"})
	clock := newTestClock()
	ks := newClockedKeySet(srv, clock)

	_, err := ks.GetKey(ctx, "a")
	require.NoError(t, err)
	srv.setBody(http.StatusInternalServerError, nil)

	clock.advance(jwt.DefaultJWKSMaxCacheTTL * 3 / 4)
	_, err = ks.GetKey(ctx, "a")
	require.NoError(t, err)
	waitFetches(t, ks, 2)

	gate := make(chan struct{})
	srv.setGate(gate)
	clock.advance(jwt.DefaultJWKSMaxCacheTTL / 4)
	key, err := ks.GetKey(ctx, "a")
	require.NoError(t, err)
	assert.Equal(t, &k.rsa.PublicKey, key)
	require.Eventually(t, func() bool { return srv.hits.Load() == 3 }, 5*time.Second, time.Millisecond)
	assert.True(t, ks.Inflight())

	close(gate)
	waitFetches(t, ks, 3)
}

// TestRemoteKeySetCacheConcurrent overlaps lookups with clock advances that
// cross the refresh and expiry points, key rotation and endpoint failures,
// so the race detector sees background refreshes and the expiry state.
func TestRemoteKeySetCacheConcurrent(t *testing.T) {
	t.Parallel()
	k := newJWKSTestKeys(t)
	ctx := context.Background()
	keys := []jose.JSONWebKey{
		{Key: &k.rsa.PublicKey, KeyID: "k0"},
		{Key: &k.rsa2.PublicKey, KeyID: "k1"},
		{Key: &k.p256.PublicKey, KeyID: "k2"},
		{Key: &k.p384.PublicKey, KeyID: "k3"},
	}
	srv := newJWKSServer(t, keys...)
	clock := newTestClock()
	ks := newClockedKeySet(srv, clock, jwt.WithStaleIfError(time.Hour))
	// Cache the keys at the start clock: a first fetch that finished after the
	// last clock step would stay fresh to the end.
	_, err := ks.GetKey(ctx, keys[0].KeyID)
	require.NoError(t, err)

	const (
		workers = 8
		lookups = 100
		steps   = 40
	)
	var (
		start = make(chan struct{})
		// advanced is set after the last clock step. Each worker looks up at
		// least `lookups` times and until it has seen advanced, so its last
		// lookup sees the final clock, past every expiry, and the run cannot
		// end with the first fetch only.
		advanced atomic.Bool
		wg       sync.WaitGroup
	)
	for w := range workers {
		wg.Go(func() {
			<-start
			for i := 0; ; i++ {
				last := advanced.Load()
				_, _ = ks.GetKey(ctx, keys[(w+i)%len(keys)].KeyID)
				if last && i >= lookups {
					return
				}
			}
		})
	}
	wg.Go(func() {
		<-start
		for i := range steps {
			clock.advance(20 * time.Minute)
			if i%3 == 0 {
				srv.setBody(http.StatusInternalServerError, nil)
			} else {
				srv.setKeys(t, keys[:1+i%len(keys)]...)
			}
		}
		advanced.Store(true)
	})
	close(start)
	wg.Wait()
	require.Eventually(t, func() bool { return !ks.Inflight() }, 5*time.Second, time.Millisecond)
	assert.Greater(t, srv.hits.Load(), int32(1), "no refresh overlapped the lookups")
	assert.Equal(t, int32(1), srv.maxActive.Load(), "fetches must not overlap")

	// Past any grace period, the next lookup fetches the current document.
	srv.setKeys(t, keys...)
	clock.advance(jwt.DefaultJWKSMaxCacheTTL + time.Hour)
	for _, want := range keys {
		key, err := ks.GetKey(ctx, want.KeyID)
		require.NoError(t, err, "kid "+strconv.Quote(want.KeyID))
		assert.Equal(t, want.Key, key)
	}
}
