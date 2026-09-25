package dpop

import (
	"container/heap"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
)

// DefaultReplayCacheSize is the capacity used by NewMemoryReplayCache when
// the requested size is not positive. Size the cache as peak accepted proofs
// per second times the acceptance window (DefaultExpiration plus
// jwt.DefaultTimeSkew).
const DefaultReplayCacheSize = 100000

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
