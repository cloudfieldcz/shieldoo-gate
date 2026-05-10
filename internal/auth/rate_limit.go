package auth

import (
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
	"golang.org/x/time/rate"
)

// dimensionLimit overrides the default rate / burst for a specific bucket
// dimension (e.g. "ai-draft" deserves a tighter limit than "scan-upload").
type dimensionLimit struct {
	limit rate.Limit
	burst int
}

// RateLimiter holds per-key token-bucket limiters with optional per-dimension
// overrides. Bucket keys are namespaced by dimension so the same scope key can
// have independent buckets for, say, "scan-upload" vs "ignore-create".
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*rate.Limiter
	limit    rate.Limit
	burst    int
	overrides map[string]dimensionLimit
}

// NewRateLimiter constructs a rate limiter with the supplied tokens-per-second + burst.
func NewRateLimiter(perSecond float64, burst int) *RateLimiter {
	if perSecond <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = 1
	}
	return &RateLimiter{
		buckets:   make(map[string]*rate.Limiter),
		limit:     rate.Limit(perSecond),
		burst:     burst,
		overrides: map[string]dimensionLimit{},
	}
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
	l, ok := r.buckets[key]
	if !ok {
		dl, hasOverride := r.overrides[dimension]
		if hasOverride {
			l = rate.NewLimiter(dl.limit, dl.burst)
		} else {
			l = rate.NewLimiter(r.limit, r.burst)
		}
		r.buckets[key] = l
	}
	r.mu.Unlock()
	return l.Allow()
}

// Allow returns true when the bucket for key has a token available. Uses the
// default rate (no dimension namespacing). Retained for compatibility — prefer
// allowDim through Middleware/MiddlewareByPath.
func (r *RateLimiter) Allow(key string) bool {
	return r.allowDim("", key)
}

// Middleware returns an http middleware that 429s requests whose bucket is empty.
// The bucket key is derived from the request context's ScopeKey (PAT hash, OIDC email,
// or "anonymous"). Pass distinct dimension to scope the limiter to a specific endpoint
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
				id = req.RemoteAddr
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
				id = req.RemoteAddr
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

func writeRateLimited(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "60")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
}
