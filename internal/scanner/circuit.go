package scanner

import (
	"sync"
	"time"
)

// scanCircuit is a per-scanner circuit breaker. After `threshold` consecutive
// failures it opens for `cooldown`, during which scanOne short-circuits with an
// overload error instead of hammering an unhealthy scanner.
type scanCircuit struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	failures  int
	openUntil time.Time
}

func newScanCircuit(threshold int, cooldown time.Duration) *scanCircuit {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = time.Minute
	}
	return &scanCircuit{threshold: threshold, cooldown: cooldown}
}

func (c *scanCircuit) isOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Before(c.openUntil)
}

func (c *scanCircuit) recordSuccess() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures = 0
	c.openUntil = time.Time{}
}

func (c *scanCircuit) recordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures++
	if c.failures >= c.threshold {
		c.openUntil = time.Now().Add(c.cooldown)
	}
}
