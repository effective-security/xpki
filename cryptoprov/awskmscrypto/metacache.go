package awskmscrypto

import (
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// immutableMeta is the part of a key's metadata that KMS never changes after
// CreateKey: a listing filters on it and reports it without describing the
// key again. The description, the state and the tags can change and are not
// part of it.
type immutableMeta struct {
	arn     string
	spec    types.KeySpec
	usage   types.KeyUsageType
	origin  types.OriginType
	manager types.KeyManagerType
	created *time.Time
}

// immutableOf returns the immutable part of meta.
func immutableOf(meta *types.KeyMetadata) *immutableMeta {
	return &immutableMeta{
		arn:     aws.ToString(meta.Arn),
		spec:    meta.KeySpec,
		usage:   meta.KeyUsage,
		origin:  meta.Origin,
		manager: meta.KeyManager,
		created: meta.CreationDate,
	}
}

// metadataCache keeps the immutable metadata of the keys a provider has
// described, by key id, for the lifetime of the provider. It is bounded:
// when it is full, an arbitrary entry makes room for a new one, which costs
// a later listing one DescribeKey. It is safe for concurrent use; the
// entries are never modified once stored. A nil cache stores nothing.
type metadataCache struct {
	mu      sync.RWMutex
	max     int
	entries map[string]*immutableMeta
}

// newMetadataCache returns a cache of at most size entries, or nil, which
// disables caching, when size is not positive.
func newMetadataCache(size int) *metadataCache {
	if size <= 0 {
		return nil
	}
	return &metadataCache{
		max:     size,
		entries: make(map[string]*immutableMeta),
	}
}

// get returns the immutable metadata of the key keyID, or nil.
func (c *metadataCache) get(keyID string) *immutableMeta {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.entries[keyID]
}

// put records the immutable metadata of the key keyID.
func (c *metadataCache) put(keyID string, meta *immutableMeta) {
	if c == nil || keyID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.entries[keyID]; !ok && len(c.entries) >= c.max {
		for evicted := range c.entries {
			delete(c.entries, evicted)
			break
		}
	}
	c.entries[keyID] = meta
}

// len returns the number of cached keys.
func (c *metadataCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
