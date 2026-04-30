package versiondiff

import (
	"testing"
	"time"
)

func TestBreaker_Disabled(t *testing.T) {
	b := newConsecutiveFailureBreaker(0, time.Second)
	if !b.allow(time.Now()) {
		t.Fatalf("nil breaker should allow")
	}
	b.recordFailure(time.Now()) // no-op, no panic
}

func TestBreaker_OpensAfterThreshold(t *testing.T) {
	b := newConsecutiveFailureBreaker(3, time.Minute)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !b.allow(now) {
			t.Fatalf("call %d should be allowed before opening", i)
		}
		b.recordFailure(now)
	}
	if b.allow(now) {
		t.Fatalf("breaker should be open after 3 failures")
	}
}

func TestBreaker_HalfOpenAfterCooldown(t *testing.T) {
	b := newConsecutiveFailureBreaker(2, 10*time.Millisecond)
	now := time.Now()
	b.recordFailure(now)
	b.recordFailure(now)
	if b.allow(now) {
		t.Fatalf("breaker should be open")
	}
	// Cooldown elapsed
	later := now.Add(50 * time.Millisecond)
	if !b.allow(later) {
		t.Fatalf("breaker should half-open after cooldown")
	}
}

func TestBreaker_SuccessResetsCount(t *testing.T) {
	b := newConsecutiveFailureBreaker(3, time.Minute)
	now := time.Now()
	b.recordFailure(now)
	b.recordFailure(now)
	b.recordSuccess()
	b.recordFailure(now)
	if !b.allow(now) {
		t.Fatalf("after success-reset, single failure should not open")
	}
}
