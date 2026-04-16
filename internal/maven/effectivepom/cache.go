package effectivepom

import (
	"sync"
	"time"
)

// cachedPOM stores a parsed POM result with its insertion time for TTL eviction.
type cachedPOM struct {
	result    *pomResult
	insertedAt time.Time
}

// pomCache is a simple LRU-ish cache for parent POM results, keyed by GAV
// coordinates. It uses a map with a size cap — when the cap is reached, the
// oldest entry is evicted. Thread-safe via sync.RWMutex.
//
// Why not a proper LRU list: parent POMs are immutable per GAV release, so
// access-order tracking adds complexity without meaningful benefit. A simple
// map with size cap + TTL is sufficient for the expected working set (typically
// 500–2000 entries for enterprise repos).
type pomCache struct {
	mu       sync.RWMutex
	entries  map[string]*cachedPOM
	maxSize  int
	ttl      time.Duration
}

// newPOMCache creates a cache with the given size cap and TTL.
func newPOMCache(maxSize int, ttl time.Duration) *pomCache {
	if maxSize <= 0 {
		maxSize = 4096
	}
	return &pomCache{
		entries: make(map[string]*cachedPOM, maxSize),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// get returns the cached POM result for the given coordinates, or nil if not
// found or expired.
func (c *pomCache) get(coords Coords) *pomResult {
	key := coords.String()
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Since(entry.insertedAt) > c.ttl {
		// Expired — remove and return miss.
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil
	}
	return entry.result
}

// put stores a POM result in the cache. If the cache is at capacity, it evicts
// the oldest entry (by insertion time).
func (c *pomCache) put(coords Coords, result *pomResult) {
	key := coords.String()
	c.mu.Lock()
	defer c.mu.Unlock()

	// If already present, just update.
	if _, ok := c.entries[key]; ok {
		c.entries[key] = &cachedPOM{result: result, insertedAt: time.Now()}
		return
	}

	// Evict oldest if at capacity.
	if len(c.entries) >= c.maxSize {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, v := range c.entries {
			if first || v.insertedAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.insertedAt
				first = false
			}
		}
		if oldestKey != "" {
			delete(c.entries, oldestKey)
		}
	}

	c.entries[key] = &cachedPOM{result: result, insertedAt: time.Now()}
}
