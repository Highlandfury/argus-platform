package httpx

import (
	"sync"
	"time"
)

// IdempotencyCache stores completed response payloads keyed by a caller-supplied
// Idempotency-Key so transport-level retries of non-idempotent creates return
// the original result instead of minting duplicates (SPEC §13). In-memory and
// single-process by design in Phase 1; entries expire after ttl and the cache
// is bounded.
type IdempotencyCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	entries map[string]idempotencyEntry
	order   []string
}

type idempotencyEntry struct {
	status  int
	body    []byte
	expires time.Time
}

// NewIdempotencyCache creates a cache; zero/negative values fall back to the
// documented defaults (24 h, 4096 entries).
func NewIdempotencyCache(ttl time.Duration, maxEntries int) *IdempotencyCache {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	return &IdempotencyCache{ttl: ttl, max: maxEntries, entries: make(map[string]idempotencyEntry)}
}

// Get returns the stored response when key was seen and has not expired.
// Nil receivers and empty keys never match.
func (c *IdempotencyCache) Get(key string) (status int, body []byte, ok bool) {
	if c == nil || key == "" {
		return 0, nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, found := c.entries[key]
	if !found {
		return 0, nil, false
	}
	if time.Now().After(entry.expires) {
		delete(c.entries, key)
		return 0, nil, false
	}
	return entry.status, append([]byte(nil), entry.body...), true
}

// Put stores a completed response, evicting the oldest entry when full.
func (c *IdempotencyCache) Put(key string, status int, body []byte) {
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
	c.entries[key] = idempotencyEntry{
		status:  status,
		body:    append([]byte(nil), body...),
		expires: time.Now().Add(c.ttl),
	}
}
