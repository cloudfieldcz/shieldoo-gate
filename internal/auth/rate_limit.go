package auth

import (
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"
)

// Bucket-eviction defaults. Buckets idle longer than defaultIdleTTL are reclaimed
// by the janitor; the map is also hard-capped at defaultMaxBuckets to bound memory
// under adversarial load (e.g. spoofed source identities). Evicting an idle bucket
// is safe: a bucket untouched for longer than its refill window has refilled to full,
// so recreating it on the next request is equivalent to keeping it.
const (
	defaultIdleTTL    = 10 * time.Minute
	defaultMaxBuckets = 50_000
	janitorInterval   = time.Minute
)

// dimensionLimit overrides the default rate / burst for a specific bucket
// dimension (e.g. "ai-draft" deserves a tighter limit than "scan-upload").
type dimensionLimit struct {
	limit rate.Limit
	burst int
}

// bucket is a token-bucket limiter plus the last time it was consulted, used for
// idle eviction.
type bucket struct {
	lim      *rate.Limiter
	lastSeen time.Time
}

// RateLimiter holds per-key token-bucket limiters with optional per-dimension
// overrides. Bucket keys are namespaced by dimension so the same scope key can
// have independent buckets for, say, "scan-upload" vs "ignore-create".
//
// The buckets map is bounded: a background janitor evicts idle buckets and the map
// is hard-capped, so a flood of distinct keys cannot exhaust memory.
type RateLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*bucket
	limit      rate.Limit
	burst      int
	overrides  map[string]dimensionLimit
	idleTTL    time.Duration
	maxBuckets int
	now        func() time.Time // injectable clock for tests
	stop       chan struct{}
	stopOnce   sync.Once
}

// NewRateLimiter constructs a rate limiter with the supplied tokens-per-second + burst.
// A background janitor goroutine is started to evict idle buckets; call Stop to end it.
func NewRateLimiter(perSecond float64, burst int) *RateLimiter {
	if perSecond <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = 1
	}
	r := &RateLimiter{
		buckets:    make(map[string]*bucket),
		limit:      rate.Limit(perSecond),
		burst:      burst,
		overrides:  map[string]dimensionLimit{},
		idleTTL:    defaultIdleTTL,
		maxBuckets: defaultMaxBuckets,
		now:        time.Now,
		stop:       make(chan struct{}),
	}
	go r.janitorLoop()
	return r
}

// WithDimensionLimit registers a per-dimension override. perSecond≤0 is rejected
// (the dimension keeps the default). Chainable.
func (r *RateLimiter) WithDimensionLimit(dimension string, perSecond float64, burst int) *RateLimiter {
	if r == nil || perSecond <= 0 {
		return r
	}
	if burst <= 0 {
		burst = 1
	}
	r.mu.Lock()
	r.overrides[dimension] = dimensionLimit{limit: rate.Limit(perSecond), burst: burst}
	r.mu.Unlock()
	return r
}

// Stop ends the janitor goroutine. Safe to call multiple times and on a nil receiver.
func (r *RateLimiter) Stop() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() { close(r.stop) })
}

// janitorLoop periodically sweeps idle buckets.
func (r *RateLimiter) janitorLoop() {
	ticker := time.NewTicker(janitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			r.sweep()
		case <-r.stop:
			return
		}
	}
}

// sweep removes buckets that have been idle longer than idleTTL.
func (r *RateLimiter) sweep() {
	cutoff := r.now().Add(-r.idleTTL)
	r.mu.Lock()
	for k, b := range r.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(r.buckets, k)
		}
	}
	r.mu.Unlock()
}

// evictOldestLocked drops the single least-recently-seen bucket. Caller holds r.mu.
// Used as a backstop when the map hits maxBuckets between janitor runs; the oldest
// bucket is the least active and thus the safest to reclaim.
func (r *RateLimiter) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, b := range r.buckets {
		if first || b.lastSeen.Before(oldest) {
			oldestKey, oldest, first = k, b.lastSeen, false
		}
	}
	if !first {
		delete(r.buckets, oldestKey)
	}
}

// limitFor returns (limit, burst) for the given dimension, falling back to the
// default when no override is registered.
func (r *RateLimiter) limitFor(dimension string) (rate.Limit, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if dl, ok := r.overrides[dimension]; ok {
		return dl.limit, dl.burst
	}
	return r.limit, r.burst
}

// allowDim returns true when the bucket for key has a token, sized to the
// limit registered for dimension.
func (r *RateLimiter) allowDim(dimension, key string) bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	b, ok := r.buckets[key]
	if !ok {
		if len(r.buckets) >= r.maxBuckets {
			r.evictOldestLocked()
		}
		dl, hasOverride := r.overrides[dimension]
		var lim *rate.Limiter
		if hasOverride {
			lim = rate.NewLimiter(dl.limit, dl.burst)
		} else {
			lim = rate.NewLimiter(r.limit, r.burst)
		}
		b = &bucket{lim: lim}
		r.buckets[key] = b
	}
	b.lastSeen = r.now()
	allowed := b.lim.Allow()
	r.mu.Unlock()
	return allowed
}

// Allow returns true when the bucket for key has a token available. Uses the
// default rate (no dimension namespacing). Retained for compatibility — prefer
// allowDim through Middleware/MiddlewareByPath.
func (r *RateLimiter) Allow(key string) bool {
	return r.allowDim("", key)
}

// Middleware returns an http middleware that 429s requests whose bucket is empty.
// The bucket key is derived from the request context's ScopeKey (PAT hash, OIDC email,
// or the client IP). Pass distinct dimension to scope the limiter to a specific endpoint
// (e.g. "scan-upload", "ignore-create"). Per-dimension limits override the default
// rate when registered via WithDimensionLimit.
func (r *RateLimiter) Middleware(dimension string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if r == nil {
				next.ServeHTTP(w, req)
				return
			}
			id := ScopeKeyFromContext(req.Context())
			if id == "" {
				id = clientIPKey(req.RemoteAddr)
			}
			key := dimension + ":" + id
			if !r.allowDim(dimension, key) {
				writeRateLimited(w)
				return
			}
			next.ServeHTTP(w, req)
		})
	}
}

// MiddlewareByPath returns an http middleware that adds a chi URL parameter to
// the bucket key, producing a per-(scope_key, resource) bucket. Use for
// endpoints where the rate should not just apply per token but also per
// resource — e.g. ignore-create on a specific component.
func (r *RateLimiter) MiddlewareByPath(dimension, pathParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if r == nil {
				next.ServeHTTP(w, req)
				return
			}
			id := ScopeKeyFromContext(req.Context())
			if id == "" {
				id = clientIPKey(req.RemoteAddr)
			}
			pv := chi.URLParam(req, pathParam)
			key := dimension + ":" + id + ":" + pv
			if !r.allowDim(dimension, key) {
				writeRateLimited(w)
				return
			}
			next.ServeHTTP(w, req)
		})
	}
}

// clientIPKey normalizes a request RemoteAddr ("ip:port") to just the IP so that
// anonymous rate-limit buckets are keyed per host, not per ephemeral source port
// (which would let a single host create unbounded buckets and evade limiting).
func clientIPKey(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}

func writeRateLimited(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
}
