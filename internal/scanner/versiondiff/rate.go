package versiondiff

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// packageRateLimiter caps the number of LLM calls per package name per hour.
// Lazy-init per package; never deletes entries (a long-running process
// accumulates entries proportional to scanned package count, which is bounded
// in practice — historical data shows ~5000 unique names over months).
type packageRateLimiter struct {
	limit float64 // events per second
	burst int
	mu    sync.Mutex
	mp    map[string]*rate.Limiter
}

// newPackageRateLimiter — perHour is the long-run rate; 0 disables limiting.
// burst is set equal to perHour so a fresh package gets its full hourly budget
// up-front (avoids the limiter delaying the first call unnecessarily).
func newPackageRateLimiter(perHour int) *packageRateLimiter {
	if perHour <= 0 {
		return nil
	}
	return &packageRateLimiter{
		limit: float64(perHour) / 3600.0,
		burst: perHour,
		mp:    make(map[string]*rate.Limiter),
	}
}

// allow returns true if the caller may proceed with an LLM call now.
// Returns true unconditionally if the limiter is nil (disabled).
func (p *packageRateLimiter) allow(name string) bool {
	if p == nil {
		return true
	}
	p.mu.Lock()
	lim, ok := p.mp[name]
	if !ok {
		lim = rate.NewLimiter(rate.Limit(p.limit), p.burst)
		p.mp[name] = lim
	}
	p.mu.Unlock()
	return lim.AllowN(time.Now(), 1)
}
