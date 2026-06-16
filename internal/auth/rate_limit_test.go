package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// Per-dimension overrides should apply on top of the default rate.
func TestRateLimiter_DimensionOverride_AppliesIndependently(t *testing.T) {
	rl := NewRateLimiter(100, 10).
		WithDimensionLimit("scan-upload", 100, 10).
		WithDimensionLimit("ai-draft", 0.001, 1) // basically one and done

	// AI draft has burst=1 so the second call should be throttled.
	assert.True(t, rl.allowDim("ai-draft", "ai-draft:k"))
	assert.False(t, rl.allowDim("ai-draft", "ai-draft:k"), "second call within burst window must be denied")

	// scan-upload at burst=10 should still allow several calls.
	for i := 0; i < 5; i++ {
		assert.True(t, rl.allowDim("scan-upload", "scan-upload:k"), "call %d should be allowed", i)
	}
}

// Different bucket keys (e.g. per-component) must not share token state.
func TestRateLimiter_DistinctKeysHaveSeparateBuckets(t *testing.T) {
	rl := NewRateLimiter(100, 10).
		WithDimensionLimit("ignore", 0.001, 1)

	assert.True(t, rl.allowDim("ignore", "ignore:tokA:cmp1"))
	assert.False(t, rl.allowDim("ignore", "ignore:tokA:cmp1"), "same key must be throttled")
	assert.True(t, rl.allowDim("ignore", "ignore:tokA:cmp2"), "different component should have its own bucket")
	assert.True(t, rl.allowDim("ignore", "ignore:tokB:cmp1"), "different token should have its own bucket")
}

// Without an override, the dimension falls back to the default rate.
func TestRateLimiter_FallsBackToDefault(t *testing.T) {
	rl := NewRateLimiter(0.001, 1) // default rate is severe
	assert.True(t, rl.allowDim("uncovered", "uncovered:k"))
	assert.False(t, rl.allowDim("uncovered", "uncovered:k"))
}

// nil receiver must be inert (this matches Allow's semantics for "limiter disabled").
func TestRateLimiter_NilIsInert(t *testing.T) {
	var rl *RateLimiter
	for i := 0; i < 100; i++ {
		assert.True(t, rl.Allow("anything"))
	}
}

// Idle buckets must be reclaimed by sweep so a flood of distinct keys cannot grow
// the map without bound.
func TestRateLimiter_Sweep_EvictsIdleBuckets(t *testing.T) {
	rl := NewRateLimiter(100, 10)
	defer rl.Stop()

	base := time.Unix(1_700_000_000, 0)
	rl.idleTTL = time.Minute
	rl.now = func() time.Time { return base }

	rl.allowDim("d", "d:old")
	// Advance well past the idle TTL, then touch a second key.
	rl.now = func() time.Time { return base.Add(5 * time.Minute) }
	rl.allowDim("d", "d:fresh")

	rl.sweep()

	rl.mu.Lock()
	_, oldPresent := rl.buckets["d:old"]
	_, freshPresent := rl.buckets["d:fresh"]
	rl.mu.Unlock()
	assert.False(t, oldPresent, "idle bucket should be evicted")
	assert.True(t, freshPresent, "recently-seen bucket must be retained")
}

// The hard cap bounds memory: inserting beyond maxBuckets evicts the oldest entry.
func TestRateLimiter_MaxBuckets_EvictsOldest(t *testing.T) {
	rl := NewRateLimiter(100, 10)
	defer rl.Stop()

	base := time.Unix(1_700_000_000, 0)
	rl.maxBuckets = 2
	rl.now = func() time.Time { return base }
	rl.allowDim("d", "d:a") // oldest
	rl.now = func() time.Time { return base.Add(time.Second) }
	rl.allowDim("d", "d:b")
	rl.now = func() time.Time { return base.Add(2 * time.Second) }
	rl.allowDim("d", "d:c") // triggers eviction of the oldest (d:a)

	rl.mu.Lock()
	defer rl.mu.Unlock()
	assert.LessOrEqual(t, len(rl.buckets), 2, "bucket count must stay at the cap")
	_, aPresent := rl.buckets["d:a"]
	assert.False(t, aPresent, "oldest bucket must be evicted at the cap")
}

// The anonymous fallback key must be the bare IP, not ip:port — otherwise a single
// host trivially evades per-IP limiting and inflates the bucket map.
func TestClientIPKey_StripsPort(t *testing.T) {
	assert.Equal(t, "203.0.113.7", clientIPKey("203.0.113.7:54321"))
	assert.Equal(t, "2001:db8::1", clientIPKey("[2001:db8::1]:443"))
	assert.Equal(t, "no-port", clientIPKey("no-port"))
}
