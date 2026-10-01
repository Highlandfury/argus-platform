package metrics

import (
	"sync"
	"time"
)

// MatrixCache is the small in-process LRU behind the GET /v1/metrics/query
// convenience form (docs/08 §13.5: 15–60 s TTL, ETag/If-None-Match). Entries
// store the rendered response body so a cache hit is byte-identical to the
// original 200; the ETag is the body hash. The cache is single-process by
// design (same posture as the Phase-1 idempotency cache); invalidation is
// unnecessary because time moves forward.
type MatrixCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[string]matrixCacheEntry
	order   []string
}

type matrixCacheEntry struct {
	body    []byte
	etag    string
	expires time.Time
}

// MatrixCacheTTL is the documented cache TTL (in the canonical 15–60 s band).
const MatrixCacheTTL = 30 * time.Second

// MatrixCacheMaxEntries bounds the LRU size.
const MatrixCacheMaxEntries = 256

// NewMatrixCache creates the GET cache. Zero or negative values fall back to
// the documented defaults.
func NewMatrixCache(ttl time.Duration, maxEntries int) *MatrixCache {
	if ttl <= 0 {
		ttl = MatrixCacheTTL
	}
	if maxEntries <= 0 {
		maxEntries = MatrixCacheMaxEntries
	}
	return &MatrixCache{ttl: ttl, max: maxEntries, entries: make(map[string]matrixCacheEntry)}
}

// Get returns the cached body and ETag when the key is present and unexpired.
func (c *MatrixCache) Get(key string) (body []byte, etag string, ok bool) {
	if c == nil || key == "" {
		return nil, "", false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, found := c.entries[key]
	if !found {
		return nil, "", false
	}
	if time.Now().After(entry.expires) {
		delete(c.entries, key)
		return nil, "", false
	}
	return append([]byte(nil), entry.body...), entry.etag, true
}

// Put stores one rendered response, evicting the oldest entry when full.
func (c *MatrixCache) Put(key string, body []byte, etag string) {
	if c == nil || key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists {
		for len(c.order) >= c.max && len(c.order) > 0 {
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.entries, oldest)
		}
		c.order = append(c.order, key)
	}
	c.entries[key] = matrixCacheEntry{
		body:    append([]byte(nil), body...),
		etag:    etag,
		expires: time.Now().Add(c.ttl),
	}
}
