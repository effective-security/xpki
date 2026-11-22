package dpop

import (
	"cmp"
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"math"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
)

// DefaultReplayCacheSize is the capacity used by NewMemoryReplayCache when
// the requested size is not positive. Size the cache as peak accepted proofs
// per second times the acceptance window (DefaultExpiration plus
// jwt.DefaultTimeSkew).
const DefaultReplayCacheSize = 100000

const (
	// DefaultReplayKeyPrefix is the prefix SharedReplayCache puts before
	// every key it stores when SharedReplayCacheConfig.KeyPrefix is empty.
	DefaultReplayKeyPrefix = "dpop:jti:"
	// DefaultReplayClockSkew is how long SharedReplayCache keeps a key
	// beyond the expiry the verifier asked for when
	// SharedReplayCacheConfig.ClockSkew is zero. It covers the clock
	// differences between the instances that share the store.
	DefaultReplayClockSkew = time.Minute
	// minReplayTTL is the shortest time to live SharedReplayCache asks the
	// store for: Redis expiries have millisecond precision.
	minReplayTTL = time.Millisecond
	// maxReplayTTL is the longest time to live SharedReplayCache asks the
	// store for, low enough that rounding it up cannot overflow.
	maxReplayTTL = time.Duration(math.MaxInt64) - minReplayTTL
	// inclusiveTTL is added to the time to live so that the key outlives the
	// inclusive deadline: a store may drop a key at the instant its time to
	// live ends, when an instance ClockSkew behind still accepts the proof.
	inclusiveTTL = time.Nanosecond
)

var (
	// ErrReplay is returned when a proof with the same key and jti was
	// already accepted within its acceptance window.
	ErrReplay = errors.New("dpop: proof replayed")
	// ErrReplayCacheFull is returned by MemoryReplayCache when every entry
	// is still unexpired. The proof is rejected (fail closed).
	ErrReplayCacheFull = errors.New("dpop: replay cache is full")
)

// ReplayCache records accepted DPoP proofs so that VerifyClaims can reject a
// second use of the same proof (RFC 9449 §11.1). Implementations must be safe
// for concurrent use; a shared store (for example Redis SET NX with an
// expiry) is needed when several server instances accept proofs for the same
// resource.
type ReplayCache interface {
	// Add atomically records key through expiresAt (inclusive: the verifier
	// still accepts a proof at that instant). It returns an error
	// wrapping ErrReplay when key is already recorded and not expired, and
	// any other error when the key cannot be recorded; VerifyClaims rejects
	// the proof in both cases. Of concurrent Add calls for the same key,
	// exactly one may succeed.
	Add(ctx context.Context, key string, expiresAt time.Time) error
}

// replayKey returns the fixed-length replay cache key for a proof: jti is
// scoped by the proof key thumbprint so that unrelated clients cannot
// collide, and hashed so that the retained size does not depend on the
// caller-controlled jti length.
func replayKey(thumbprint, jti string) string {
	h := sha256.New()
	h.Write([]byte(thumbprint))
	h.Write([]byte{0})
	h.Write([]byte(jti))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// MemoryReplayCache is a bounded, process-local ReplayCache. Expired entries
// are evicted before a new key is admitted; when the cache is still full the
// new proof is rejected with ErrReplayCacheFull. Failing closed means a
// client that can mint valid proofs (at a token endpoint, any client) can
// fill the cache and have other proofs rejected for up to the acceptance
// window; size it for peak load and rate-limit proof sources. It uses
// TimeNowFn as its clock.
type MemoryReplayCache struct {
	lock    sync.Mutex
	max     int
	entries map[string]time.Time
	expiry  expiryHeap
}

// NewMemoryReplayCache returns a MemoryReplayCache holding at most maxEntries
// unexpired proofs, or DefaultReplayCacheSize when maxEntries is not positive.
func NewMemoryReplayCache(maxEntries int) *MemoryReplayCache {
	if maxEntries <= 0 {
		maxEntries = DefaultReplayCacheSize
	}
	return &MemoryReplayCache{
		max:     maxEntries,
		entries: make(map[string]time.Time),
	}
}

// Add records key until expiresAt; see ReplayCache.
func (c *MemoryReplayCache) Add(_ context.Context, key string, expiresAt time.Time) error {
	now := TimeNowFn()

	c.lock.Lock()
	defer c.lock.Unlock()

	// after eviction every retained entry is unexpired
	c.evictExpired(now)
	if _, ok := c.entries[key]; ok {
		return errors.WithStack(ErrReplay)
	}
	if len(c.entries) >= c.max {
		return errors.WithStack(ErrReplayCacheFull)
	}
	c.entries[key] = expiresAt
	heap.Push(&c.expiry, expiryItem{key: key, expiresAt: expiresAt})
	return nil
}

// Len returns the number of retained entries, including entries that have
// expired but were not evicted yet.
func (c *MemoryReplayCache) Len() int {
	c.lock.Lock()
	defer c.lock.Unlock()
	return len(c.entries)
}

// evictExpired removes entries whose expiry is before now; an entry is kept
// at its expiry instant, which the verifier still accepts. Each retained key
// has exactly one heap item, so the heap is bounded by max as well.
func (c *MemoryReplayCache) evictExpired(now time.Time) {
	for len(c.expiry) > 0 && now.After(c.expiry[0].expiresAt) {
		item := heap.Pop(&c.expiry).(expiryItem)
		delete(c.entries, item.key)
	}
}

// ReplayStore is the one operation SharedReplayCache needs from a store that
// several server instances share.
type ReplayStore interface {
	// SetIfAbsent stores key with a time to live of ttl when key is absent
	// or expired, and reports whether it stored it. Of concurrent calls for
	// the same key, from any instance, at most one may return true. The
	// store must keep the key for at least ttl: one with a coarser expiry
	// rounds ttl up, and a Redis that evicts keys under memory pressure
	// (a maxmemory-policy other than noeviction) lets replays through, so
	// use noeviction, which makes a full store an error and rejects the
	// proof, or a dedicated instance. With Redis it is SET key value NX PX
	// ttl, which go-redis offers as SetNX.
	SetIfAbsent(ctx context.Context, key string, ttl time.Duration) (bool, error)
}

// ReplayStoreFunc adapts a function to ReplayStore.
type ReplayStoreFunc func(ctx context.Context, key string, ttl time.Duration) (bool, error)

// SetIfAbsent calls f.
func (f ReplayStoreFunc) SetIfAbsent(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	return f(ctx, key, ttl)
}

// SharedReplayCacheConfig configures NewSharedReplayCache.
type SharedReplayCacheConfig struct {
	// KeyPrefix is put before every key, to keep the entries apart from
	// other data in the store; empty means DefaultReplayKeyPrefix. Servers
	// that accept proofs for different resources may share one prefix: the
	// key is scoped by the proof key thumbprint and jti, not the resource.
	KeyPrefix string
	// ClockSkew is added to the time to live of every key, so that an
	// instance whose clock is behind still finds the key while it accepts
	// the proof; zero means DefaultReplayClockSkew. It must not be negative.
	ClockSkew time.Duration
}

// SharedReplayCache is a ReplayCache over a ReplayStore, for servers that run
// several instances: a proof accepted by one instance is a replay for all of
// them. Each Add is one SetIfAbsent with a relative time to live, from
// TimeNowFn to expiresAt, which the store counts on its own clock: the clock
// of the store does not matter, and the clocks of the instances need to
// agree within ClockSkew. A store error rejects the proof (fail closed).
type SharedReplayCache struct {
	store     ReplayStore
	prefix    string
	clockSkew time.Duration
}

// NewSharedReplayCache returns a SharedReplayCache that records proofs in
// store. A go-redis client fits ReplayStore with ReplayStoreFunc:
//
//	store := dpop.ReplayStoreFunc(func(ctx context.Context, key string, ttl time.Duration) (bool, error) {
//		return rdb.SetNX(ctx, key, 1, ttl).Result()
//	})
func NewSharedReplayCache(store ReplayStore, cfg SharedReplayCacheConfig) (*SharedReplayCache, error) {
	if f, ok := store.(ReplayStoreFunc); store == nil || (ok && f == nil) {
		return nil, errors.New("dpop: replay store is required")
	}
	if cfg.ClockSkew < 0 {
		return nil, errors.Errorf("dpop: invalid replay clock skew: %s", cfg.ClockSkew)
	}
	return &SharedReplayCache{
		store:     store,
		prefix:    cmp.Or(cfg.KeyPrefix, DefaultReplayKeyPrefix),
		clockSkew: cmp.Or(cfg.ClockSkew, DefaultReplayClockSkew),
	}, nil
}

// Add records key through expiresAt plus the clock skew, inclusive; see
// ReplayCache. The time to live is one nanosecond longer than that, rounded
// up to the millisecond, and at least one millisecond.
func (c *SharedReplayCache) Add(ctx context.Context, key string, expiresAt time.Time) error {
	if c == nil || c.store == nil {
		return errors.New("dpop: replay cache is not initialized")
	}
	// saturate instead of wrapping around to a short time to live
	ttl := min(expiresAt.Sub(TimeNowFn()), maxReplayTTL-c.clockSkew-inclusiveTTL) + c.clockSkew + inclusiveTTL
	if rem := ttl % minReplayTTL; rem > 0 {
		ttl += minReplayTTL - rem
	}
	ttl = max(ttl, minReplayTTL)
	stored, err := c.store.SetIfAbsent(ctx, c.prefix+key, ttl)
	if err != nil {
		return errors.WithMessage(err, "dpop: unable to record proof")
	}
	if !stored {
		return errors.WithStack(ErrReplay)
	}
	return nil
}

type expiryItem struct {
	key       string
	expiresAt time.Time
}

// expiryHeap is a min-heap of entries ordered by expiry.
type expiryHeap []expiryItem

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].expiresAt.Before(h[j].expiresAt) }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *expiryHeap) Push(x any) { *h = append(*h, x.(expiryItem)) }

func (h *expiryHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}
