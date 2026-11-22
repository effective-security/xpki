package dpop_test

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/effective-security/xpki/v2/jwt/dpop"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeStore is a ReplayStore shared by several caches, as a Redis server is
// shared by several instances. A key is gone at the instant its time to live
// ends. Its clock is now, dpop.TimeNowFn by default.
type fakeStore struct {
	lock    sync.Mutex
	now     func() time.Time
	entries map[string]time.Time
	keys    []string
	ttls    []time.Duration
	ctxs    []context.Context
	err     error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		now:     func() time.Time { return dpop.TimeNowFn() },
		entries: map[string]time.Time{},
	}
}

func (s *fakeStore) SetIfAbsent(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.err != nil {
		return false, s.err
	}
	s.keys = append(s.keys, key)
	s.ttls = append(s.ttls, ttl)
	s.ctxs = append(s.ctxs, ctx)
	now := s.now()
	if expiry, ok := s.entries[key]; ok && now.Before(expiry) {
		return false, nil
	}
	s.entries[key] = now.Add(ttl)
	return true, nil
}

func newSharedCache(t testing.TB, store dpop.ReplayStore, cfg dpop.SharedReplayCacheConfig) *dpop.SharedReplayCache {
	t.Helper()
	c, err := dpop.NewSharedReplayCache(store, cfg)
	require.NoError(t, err)
	return c
}

func TestNewSharedReplayCache(t *testing.T) {
	t.Parallel()

	c, err := dpop.NewSharedReplayCache(nil, dpop.SharedReplayCacheConfig{})
	assert.EqualError(t, err, "dpop: replay store is required")
	assert.Nil(t, c)

	c, err = dpop.NewSharedReplayCache(dpop.ReplayStoreFunc(nil), dpop.SharedReplayCacheConfig{})
	assert.EqualError(t, err, "dpop: replay store is required")
	assert.Nil(t, c)

	c, err = dpop.NewSharedReplayCache(newFakeStore(), dpop.SharedReplayCacheConfig{ClockSkew: -time.Second})
	assert.EqualError(t, err, "dpop: invalid replay clock skew: -1s")
	assert.Nil(t, c)

	// a cache not created by NewSharedReplayCache rejects instead of panicking
	var nilCache *dpop.SharedReplayCache
	for _, c := range []*dpop.SharedReplayCache{{}, nilCache} {
		err = c.Add(context.Background(), "k", time.Now().Add(time.Minute))
		assert.EqualError(t, err, "dpop: replay cache is not initialized")
	}
}

func TestSharedReplayCache_Add(t *testing.T) {
	t.Parallel()
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "request")
	expiresAt := time.Now().Add(time.Hour)

	t.Run("defaults", func(t *testing.T) {
		t.Parallel()
		store := newFakeStore()
		c := newSharedCache(t, store, dpop.SharedReplayCacheConfig{})
		require.NoError(t, c.Add(ctx, "k", expiresAt))

		err := c.Add(ctx, "k", expiresAt)
		assert.ErrorIs(t, err, dpop.ErrReplay)
		assert.EqualError(t, err, "dpop: proof replayed")

		require.Len(t, store.keys, 2)
		assert.Equal(t, dpop.DefaultReplayKeyPrefix+"k", store.keys[0])
		assert.Equal(t, "dpop:jti:k", store.keys[0])
		// an hour plus the default clock skew, less the time spent since
		// expiresAt was taken
		assert.InDelta(t, time.Hour+dpop.DefaultReplayClockSkew, store.ttls[0], float64(time.Second))
		assert.Equal(t, "request", store.ctxs[0].Value(ctxKey{}), "the context reaches the store")
	})

	t.Run("prefix", func(t *testing.T) {
		t.Parallel()
		store := newFakeStore()
		c := newSharedCache(t, store, dpop.SharedReplayCacheConfig{KeyPrefix: "api/"})
		require.NoError(t, c.Add(ctx, "k", expiresAt))
		assert.Equal(t, []string{"api/k"}, store.keys)
	})

	t.Run("store error fails closed", func(t *testing.T) {
		t.Parallel()
		boom := errors.New("connection refused")
		store := newFakeStore()
		store.err = boom
		c := newSharedCache(t, store, dpop.SharedReplayCacheConfig{})
		err := c.Add(ctx, "k", expiresAt)
		assert.ErrorIs(t, err, boom)
		assert.False(t, errors.Is(err, dpop.ErrReplay))
		assert.EqualError(t, err, "dpop: unable to record proof: connection refused")
	})

	t.Run("ReplayStoreFunc", func(t *testing.T) {
		t.Parallel()
		var got []string
		store := dpop.ReplayStoreFunc(func(_ context.Context, key string, _ time.Duration) (bool, error) {
			got = append(got, key)
			return len(got) == 1, nil
		})
		c := newSharedCache(t, store, dpop.SharedReplayCacheConfig{})
		require.NoError(t, c.Add(ctx, "k", expiresAt))
		assert.ErrorIs(t, c.Add(ctx, "k", expiresAt), dpop.ErrReplay)
		assert.Equal(t, []string{"dpop:jti:k", "dpop:jti:k"}, got)
	})
}

// TestSharedReplayCache_TTL is not parallel: it replaces dpop.TimeNowFn.
func TestSharedReplayCache_TTL(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	restore := dpop.TimeNowFn
	dpop.TimeNowFn = func() time.Time { return now }
	t.Cleanup(func() { dpop.TimeNowFn = restore })
	ctx := context.Background()

	for _, tc := range []struct {
		name      string
		clockSkew time.Duration
		expiresAt time.Time
		ttl       time.Duration
	}{
		{
			// the deadline is inclusive: one nanosecond more, rounded up
			name:      "default clock skew",
			expiresAt: now.Add(dpop.DefaultExpiration),
			ttl:       dpop.DefaultExpiration + time.Minute + time.Millisecond,
		},
		{
			name:      "rounded up to the millisecond",
			clockSkew: time.Nanosecond,
			expiresAt: now.Add(1500 * time.Microsecond),
			ttl:       2 * time.Millisecond,
		},
		{
			name:      "a whole millisecond gets one more",
			clockSkew: time.Millisecond,
			expiresAt: now.Add(time.Second),
			ttl:       time.Second + 2*time.Millisecond,
		},
		{
			name:      "one nanosecond short of a whole millisecond",
			clockSkew: time.Millisecond - time.Nanosecond,
			expiresAt: now.Add(time.Second),
			ttl:       time.Second + time.Millisecond,
		},
		{
			name:      "at the expiry instant",
			clockSkew: time.Nanosecond,
			expiresAt: now,
			ttl:       time.Millisecond,
		},
		{
			name:      "already expired",
			clockSkew: time.Second,
			expiresAt: now.Add(-time.Hour),
			ttl:       time.Millisecond,
		},
		{
			// the sum would wrap around to a negative, then 1 ms
			name:      "huge clock skew saturates",
			clockSkew: time.Duration(math.MaxInt64),
			expiresAt: now.Add(time.Minute),
			ttl:       time.Duration(math.MaxInt64).Truncate(time.Millisecond),
		},
		{
			name:      "far-future expiry saturates",
			clockSkew: time.Minute,
			expiresAt: now.Add(time.Duration(math.MaxInt64)),
			ttl:       time.Duration(math.MaxInt64).Truncate(time.Millisecond),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newFakeStore()
			c := newSharedCache(t, store, dpop.SharedReplayCacheConfig{ClockSkew: tc.clockSkew})
			require.NoError(t, c.Add(ctx, "k", tc.expiresAt))
			assert.Equal(t, []time.Duration{tc.ttl}, store.ttls)
		})
	}

	// the key outlives the last instant at which the verifier accepts the
	// proof by the clock skew, that instant included, and expires within the
	// millisecond after it
	store := newFakeStore()
	c := newSharedCache(t, store, dpop.SharedReplayCacheConfig{ClockSkew: time.Second})
	expiresAt := now.Add(time.Minute)
	require.NoError(t, c.Add(ctx, "k", expiresAt))
	now = expiresAt.Add(time.Second)
	assert.ErrorIs(t, c.Add(ctx, "k", now.Add(time.Minute)), dpop.ErrReplay)
	now = expiresAt.Add(time.Second + time.Millisecond)
	require.NoError(t, c.Add(ctx, "k", now.Add(time.Minute)))
}

// TestSharedReplayCache_ClockSkewBoundary is not parallel: it replaces
// dpop.TimeNowFn. The clocks of the store and of the first instance are
// right; the second instance runs exactly ClockSkew behind, so it accepts
// the proof until the store's clock reads the last accepted instant plus
// ClockSkew, and must still see the replay then.
func TestSharedReplayCache_ClockSkewBoundary(t *testing.T) {
	const clockSkew = time.Minute
	// whole seconds, so that iat is exactly storeNow
	storeNow := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	instanceNow := storeNow
	restore := dpop.TimeNowFn
	dpop.TimeNowFn = func() time.Time { return instanceNow }
	t.Cleanup(func() { dpop.TimeNowFn = restore })

	store := newFakeStore()
	store.now = func() time.Time { return storeNow }
	cfg := dpop.SharedReplayCacheConfig{ClockSkew: clockSkew}
	first := dpop.VerifyConfig{ReplayCache: newSharedCache(t, store, cfg)}
	second := dpop.VerifyConfig{ReplayCache: newSharedCache(t, store, cfg)}
	proof := signProof(t, jose.ES256, newECKey(t), map[string]any{"iat": storeNow.Unix()})

	_, err := dpop.VerifyClaims(first, proof, testMethod, testHTU)
	require.NoError(t, err)

	// the last instant at which the second instance accepts the proof
	storeNow = storeNow.Add(dpop.DefaultExpiration + clockSkew)
	instanceNow = storeNow.Add(-clockSkew)
	_, err = dpop.VerifyClaims(second, proof, testMethod, testHTU)
	assert.ErrorIs(t, err, dpop.ErrReplay)

	// one nanosecond later the instance rejects the proof itself
	instanceNow = instanceNow.Add(time.Nanosecond)
	_, err = dpop.VerifyClaims(second, proof, testMethod, testHTU)
	assert.ErrorContains(t, err, "dpop: iat claim expired")
}

// TestSharedReplayCache_Instances verifies one proof on two server instances
// whose caches share a store: the second instance sees a replay.
func TestSharedReplayCache_Instances(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	first := dpop.VerifyConfig{ReplayCache: newSharedCache(t, store, dpop.SharedReplayCacheConfig{})}
	second := dpop.VerifyConfig{ReplayCache: newSharedCache(t, store, dpop.SharedReplayCacheConfig{})}
	proof := signProof(t, jose.ES256, newECKey(t), nil)

	_, err := dpop.VerifyClaims(first, proof, testMethod, testHTU)
	require.NoError(t, err)
	_, err = dpop.VerifyClaims(second, proof, testMethod, testHTU)
	assert.ErrorIs(t, err, dpop.ErrReplay)
	assert.EqualError(t, err, "dpop: proof rejected: dpop: proof replayed")

	// the key is the prefix and a fixed-length hash of thumbprint and jti,
	// kept through iat + DefaultExpiration plus the clock skew
	require.Len(t, store.keys, 2)
	assert.Len(t, store.keys[0], len(dpop.DefaultReplayKeyPrefix)+43)
	assert.LessOrEqual(t, store.ttls[0], dpop.DefaultExpiration+dpop.DefaultReplayClockSkew+time.Millisecond)
	assert.Greater(t, store.ttls[0], dpop.DefaultExpiration)
}

// TestSharedReplayCache_Concurrent releases simultaneous verifications of
// one proof on two instances and requires exactly one to be accepted; run
// it with -race.
func TestSharedReplayCache_Concurrent(t *testing.T) {
	t.Parallel()
	const workers = 32
	store := newFakeStore()
	instances := []dpop.VerifyConfig{
		{ReplayCache: newSharedCache(t, store, dpop.SharedReplayCacheConfig{})},
		{ReplayCache: newSharedCache(t, store, dpop.SharedReplayCacheConfig{})},
	}
	proof := signProof(t, jose.ES256, newECKey(t), nil)

	var accepted, replayed atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range workers {
		cfg := instances[i%len(instances)]
		wg.Go(func() {
			<-start
			_, err := dpop.VerifyClaims(cfg, proof, testMethod, testHTU)
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, dpop.ErrReplay):
				replayed.Add(1)
			default:
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), accepted.Load())
	assert.Equal(t, int32(workers-1), replayed.Load())
}
