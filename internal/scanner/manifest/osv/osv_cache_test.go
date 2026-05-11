package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// hydrate caches /v1/vulns/{id} for cacheTTL. A second call within the
// TTL window for the same vuln must hit the cache, not the network.
// Pre-Phase 3 the cache was read but never written, producing N+1 GETs
// at scan time — meaningful only for image SBOMs (10× more CVE hits).
func TestHydrate_CacheHit_NoSecondNetworkFetch(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "CVE-2024-12345",
			"severity": []map[string]string{{"type": "CVSS_V3", "score": "9.8"}},
			"affected": []map[string]any{
				{
					"package": map[string]string{"name": "openssl", "ecosystem": "Alpine"},
					"ranges": []map[string]any{
						{"type": "ECOSYSTEM", "events": []map[string]string{{"fixed": "3.0.13-r0"}}},
					},
				},
			},
		})
	}))
	defer srv.Close()

	s := New(Config{APIURL: srv.URL, Timeout: 2 * time.Second, CacheTTL: 5 * time.Minute})
	ctx := context.Background()

	_, fixed := s.hydrate(ctx, "CVE-2024-12345", "openssl", "Alpine")
	_, fixed2 := s.hydrate(ctx, "CVE-2024-12345", "openssl", "Alpine")

	if got := atomic.LoadInt64(&hits); got != 1 {
		t.Errorf("expected 1 network fetch on cache hit, got %d", got)
	}
	if fixed != "3.0.13-r0" || fixed2 != "3.0.13-r0" {
		t.Errorf("fixed=%q fixed2=%q, want both 3.0.13-r0", fixed, fixed2)
	}
}

// hydrate must respect cacheTTL: an entry past its TTL must be re-fetched.
func TestHydrate_CacheExpiry_RefetchesAfterTTL(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":       "CVE-2024-99999",
			"severity": []map[string]string{{"type": "CVSS_V3", "score": "7.5"}},
		})
	}))
	defer srv.Close()

	s := New(Config{APIURL: srv.URL, Timeout: 2 * time.Second, CacheTTL: 10 * time.Millisecond})
	ctx := context.Background()

	_, _ = s.hydrate(ctx, "CVE-2024-99999", "x", "y")
	time.Sleep(25 * time.Millisecond)
	_, _ = s.hydrate(ctx, "CVE-2024-99999", "x", "y")

	if got := atomic.LoadInt64(&hits); got != 2 {
		t.Errorf("expected 2 network fetches (cache expired), got %d", got)
	}
}
