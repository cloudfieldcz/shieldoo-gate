package auth

import (
	"testing"

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
