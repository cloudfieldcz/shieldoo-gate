package ai

import (
	"sync"
	"time"
)

// BaselineEntry is the pre-computed CRITICAL+HIGH baseline for a single
// Component over the active baseline window. RefreshedAt is the wall-clock
// time the entry was last (re)written by the recompute scheduler.
type BaselineEntry struct {
	Mean        float64
	Stddev      float64
	Samples     int
	RefreshedAt time.Time
}

// BaselineCache is a thread-safe in-memory map of componentID → BaselineEntry,
// keyed for sub-microsecond reads. Entries are populated by the daily
// baseline_recompute scheduler; AnomalyDetector consults the cache before
// falling back to the live SQL path.
//
// Cache misses (or entries older than MaxAge) are not errors — the detector
// simply runs its existing per-Evaluate aggregation, so the cache is purely
// an optimization and is safe to disable.
type BaselineCache struct {
	mu      sync.RWMutex
	entries map[int64]BaselineEntry
	maxAge  time.Duration
}

// NewBaselineCache creates an empty cache. maxAge bounds how stale an entry may
// be before Get treats it as a miss; a typical value is 25h (slightly longer
// than the 24h scheduler tick to absorb scheduler skew).
func NewBaselineCache(maxAge time.Duration) *BaselineCache {
	if maxAge <= 0 {
		maxAge = 25 * time.Hour
	}
	return &BaselineCache{
		entries: make(map[int64]BaselineEntry),
		maxAge:  maxAge,
	}
}

// Get returns the cached entry and ok=true when it is fresh; otherwise ok=false.
func (c *BaselineCache) Get(componentID int64) (BaselineEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[componentID]
	if !ok {
		return BaselineEntry{}, false
	}
	if c.maxAge > 0 && time.Since(e.RefreshedAt) > c.maxAge {
		return BaselineEntry{}, false
	}
	return e, true
}

// Set inserts or updates an entry, stamping RefreshedAt to now.
func (c *BaselineCache) Set(componentID int64, mean, stddev float64, samples int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[componentID] = BaselineEntry{
		Mean:        mean,
		Stddev:      stddev,
		Samples:     samples,
		RefreshedAt: time.Now().UTC(),
	}
}

// Len returns the number of cached entries (useful for metrics + tests).
func (c *BaselineCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
