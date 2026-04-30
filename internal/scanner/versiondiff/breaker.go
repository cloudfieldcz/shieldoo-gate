package versiondiff

import (
	"sync"
	"time"
)

// consecutiveFailureBreaker opens after N consecutive bridge errors and stays
// open for `cooldown`. Any successful scan resets the count.
type consecutiveFailureBreaker struct {
	threshold int
	cooldown  time.Duration

	mu     sync.Mutex
	count  int
	openAt time.Time
}

func newConsecutiveFailureBreaker(threshold int, cooldown time.Duration) *consecutiveFailureBreaker {
	if threshold <= 0 {
		return nil
	}
	return &consecutiveFailureBreaker{threshold: threshold, cooldown: cooldown}
}

// allow returns true if the breaker is closed (or the cooldown has elapsed).
func (b *consecutiveFailureBreaker) allow(now time.Time) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openAt.IsZero() {
		return true
	}
	if now.Sub(b.openAt) >= b.cooldown {
		// Cooldown elapsed — half-open: reset and allow one probe call.
		b.openAt = time.Time{}
		b.count = 0
		return true
	}
	return false
}

// recordSuccess closes the breaker (resets failure count).
func (b *consecutiveFailureBreaker) recordSuccess() {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.count = 0
	b.openAt = time.Time{}
	b.mu.Unlock()
}

// recordFailure increments the count; opens the breaker if threshold is reached.
func (b *consecutiveFailureBreaker) recordFailure(now time.Time) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.count++
	if b.count >= b.threshold && b.openAt.IsZero() {
		b.openAt = now
	}
}
