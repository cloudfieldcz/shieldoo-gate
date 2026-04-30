package versiondiff

import (
	"testing"
)

func TestPackageRateLimiter_DisabledAllowsAll(t *testing.T) {
	l := newPackageRateLimiter(0)
	for i := 0; i < 100; i++ {
		if !l.allow("foo") {
			t.Fatalf("disabled limiter must always allow")
		}
	}
}

func TestPackageRateLimiter_BurstAndExhaust(t *testing.T) {
	l := newPackageRateLimiter(3) // 3 per hour, burst 3
	for i := 0; i < 3; i++ {
		if !l.allow("foo") {
			t.Fatalf("call %d: should be allowed", i)
		}
	}
	if l.allow("foo") {
		t.Fatalf("4th call must be denied within burst window")
	}
	// Different package — independent budget.
	if !l.allow("bar") {
		t.Fatalf("bar should be allowed (separate bucket)")
	}
}
