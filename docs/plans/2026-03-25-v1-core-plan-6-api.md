# Shieldoo Gate v1.0 Core — Phase 6: REST API + Prometheus Metrics

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the admin REST API with all endpoints for artifact management, statistics, threat feed, health checks, and Prometheus metrics.

**Architecture:** Chi router serves JSON REST API on the admin port (8080). Endpoints operate against SQLite via sqlx. Rescan endpoint invokes the scanner engine. Prometheus metrics use `client_golang` for standard counters/gauges/histograms. The OpenAPI spec documents the API contract.

**Tech Stack:** Go 1.25+, chi/v5, sqlx, `prometheus/client_golang`, testify

**Index:** [`plan-index.md`](./2026-03-25-v1-core-plan-index.md)

---

### Task 1: API Server Setup + Health Endpoint

**Files:**
- Create: `internal/api/server.go`
- Create: `internal/api/health.go`
- Test: `internal/api/health_test.go`

- [ ] **Step 1: Write tests**

```go
// internal/api/health_test.go
package api

import (
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/cloudfieldcz/shieldoo-gate/internal/config"
    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestHealthEndpoint_ReturnsOK(t *testing.T) {
    db, err := config.InitDB(":memory:")
    require.NoError(t, err)
    defer db.Close()

    engine := scanner.NewEngine(nil, 30*time.Second)
    server := NewServer(db, nil, engine, nil)

    req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
    w := httptest.NewRecorder()
    server.Routes().ServeHTTP(w, req)

    assert.Equal(t, http.StatusOK, w.Code)

    var resp map[string]interface{}
    json.NewDecoder(w.Body).Decode(&resp)
    assert.Equal(t, "ok", resp["status"])
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/ -v -run TestHealth`
Expected: FAIL

- [ ] **Step 3: Implement server and health endpoint**

```go
// internal/api/server.go
package api

import (
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "github.com/jmoiron/sqlx"
    "github.com/prometheus/client_golang/prometheus/promhttp"

    "github.com/cloudfieldcz/shieldoo-gate/internal/cache"
    "github.com/cloudfieldcz/shieldoo-gate/internal/policy"
    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

type Server struct {
    db           *sqlx.DB
    cache        cache.CacheStore
    scanEngine   *scanner.Engine
    policyEngine *policy.Engine
}

func NewServer(db *sqlx.DB, cache cache.CacheStore, scanEngine *scanner.Engine, policyEngine *policy.Engine) *Server {
    return &Server{
        db:           db,
        cache:        cache,
        scanEngine:   scanEngine,
        policyEngine: policyEngine,
    }
}

func (s *Server) Routes() chi.Router {
    r := chi.NewRouter()
    r.Use(middleware.Recoverer)
    r.Use(middleware.RealIP)

    r.Route("/api/v1", func(r chi.Router) {
        // Health
        r.Get("/health", s.handleHealth)

        // Artifacts
        r.Get("/artifacts", s.handleListArtifacts)
        r.Get("/artifacts/{id}", s.handleGetArtifact)
        r.Get("/artifacts/{id}/scan-results", s.handleGetScanResults)
        r.Post("/artifacts/{id}/rescan", s.handleRescan)
        r.Post("/artifacts/{id}/quarantine", s.handleQuarantine)
        r.Post("/artifacts/{id}/release", s.handleRelease)

        // Statistics
        r.Get("/stats/summary", s.handleStatsSummary)
        r.Get("/stats/blocked", s.handleStatsBlocked)

        // Threat feed
        r.Get("/feed", s.handleGetFeed)
        r.Post("/feed/refresh", s.handleRefreshFeed)
    })

    // Prometheus metrics
    r.Handle("/metrics", promhttp.Handler())

    return r
}
```

```go
// internal/api/health.go
package api

import (
    "encoding/json"
    "net/http"
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
    health := map[string]interface{}{
        "status": "ok",
    }

    // Check scanner health
    if s.scanEngine != nil {
        scannerHealth := s.scanEngine.HealthCheck(r.Context())
        scanners := make(map[string]string)
        allHealthy := true
        for name, err := range scannerHealth {
            if err != nil {
                scanners[name] = err.Error()
                allHealthy = false
            } else {
                scanners[name] = "healthy"
            }
        }
        health["scanners"] = scanners
        if !allHealthy {
            health["status"] = "degraded"
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(health)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/api/ -v -run TestHealth`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/api/server.go internal/api/health.go internal/api/health_test.go
git commit -m "feat(api): add REST API server setup with health endpoint and Prometheus metrics"
```

---

### Task 2: Artifact Endpoints

**Files:**
- Create: `internal/api/artifacts.go`
- Test: `internal/api/artifacts_test.go`

Endpoints:
- `GET /api/v1/artifacts` — list with pagination (`?page=1&per_page=50`)
- `GET /api/v1/artifacts/{id}` — detail with scan history
- `GET /api/v1/artifacts/{id}/scan-results` — scan result history
- `POST /api/v1/artifacts/{id}/rescan` — trigger manual rescan
- `POST /api/v1/artifacts/{id}/quarantine` — manual quarantine
- `POST /api/v1/artifacts/{id}/release` — release from quarantine

- [ ] **Step 1: Write tests**

Test list endpoint with pagination, get detail, quarantine/release flow, rescan trigger. Use in-memory SQLite with test data.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/api/ -v -run TestArtifact`
Expected: FAIL

- [ ] **Step 3: Implement artifact endpoints**

Key implementation details:
- List: `SELECT * FROM artifacts ORDER BY cached_at DESC LIMIT ? OFFSET ?`
- Detail: Join `artifacts` + `artifact_status` + latest `scan_results`
- Rescan: Re-run scanner engine on cached artifact, update status
- Quarantine: Set `artifact_status.status = 'QUARANTINED'`, write audit log
- Release: Set status back to `'CLEAN'`, set `released_at`, write audit log

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/api/ -v -run TestArtifact`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/api/artifacts.go internal/api/artifacts_test.go
git commit -m "feat(api): add artifact CRUD, rescan, quarantine, and release endpoints"
```

---

### Task 3: Statistics Endpoints

**Files:**
- Create: `internal/api/stats.go`
- Test: `internal/api/stats_test.go`

Endpoints:
- `GET /api/v1/stats/summary` — traffic summary (counts by event type for last 24h, 7d, 30d)
- `GET /api/v1/stats/blocked` — blocked artifacts history

- [ ] **Step 1: Write tests**

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement statistics endpoints**

Query audit_log for aggregate counts grouped by event_type and time windows.

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add internal/api/stats.go internal/api/stats_test.go
git commit -m "feat(api): add statistics summary and blocked artifacts endpoints"
```

---

### Task 4: Threat Feed Endpoints

**Files:**
- Create: `internal/api/feed.go`
- Test: `internal/api/feed_test.go`

Endpoints:
- `GET /api/v1/feed` — view local copy of community feed
- `POST /api/v1/feed/refresh` — force feed refresh

- [ ] **Step 1: Write tests**

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement feed endpoints**

GET lists entries from `threat_feed` table. POST invokes the threat feed client's `Refresh()` method.

- [ ] **Step 4: Run tests to verify they pass**

- [ ] **Step 5: Commit**

```bash
git add internal/api/feed.go internal/api/feed_test.go
git commit -m "feat(api): add threat feed view and refresh endpoints"
```

---

### Task 5: Prometheus Metrics Registration

**Files:**
- Create: `internal/api/metrics.go`

Register Prometheus metrics from `docs/initial-analyse.md` section 10:

```
shieldoo_gate_requests_total{ecosystem, action}
shieldoo_gate_scan_duration_seconds{scanner}
shieldoo_gate_cache_size_bytes{ecosystem}
shieldoo_gate_cache_hits_total{ecosystem}
shieldoo_gate_cache_misses_total{ecosystem}
shieldoo_gate_blocked_total{ecosystem, reason}
shieldoo_gate_quarantined_total{ecosystem}
shieldoo_gate_scanner_errors_total{scanner}
```

- [ ] **Step 1: Implement metrics registration**

```go
// internal/api/metrics.go
package api

import "github.com/prometheus/client_golang/prometheus"

var (
    RequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "shieldoo_gate_requests_total",
        Help: "Total requests by ecosystem and action",
    }, []string{"ecosystem", "action"})

    ScanDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
        Name:    "shieldoo_gate_scan_duration_seconds",
        Help:    "Scan duration by scanner",
        Buckets: prometheus.DefBuckets,
    }, []string{"scanner"})

    CacheSizeBytes = prometheus.NewGaugeVec(prometheus.GaugeOpts{
        Name: "shieldoo_gate_cache_size_bytes",
        Help: "Cache size in bytes by ecosystem",
    }, []string{"ecosystem"})

    CacheHitsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "shieldoo_gate_cache_hits_total",
        Help: "Cache hits by ecosystem",
    }, []string{"ecosystem"})

    CacheMissesTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "shieldoo_gate_cache_misses_total",
        Help: "Cache misses by ecosystem",
    }, []string{"ecosystem"})

    BlockedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "shieldoo_gate_blocked_total",
        Help: "Blocked artifacts by ecosystem and reason",
    }, []string{"ecosystem", "reason"})

    QuarantinedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "shieldoo_gate_quarantined_total",
        Help: "Quarantined artifacts by ecosystem",
    }, []string{"ecosystem"})

    ScannerErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
        Name: "shieldoo_gate_scanner_errors_total",
        Help: "Scanner errors by scanner name",
    }, []string{"scanner"})
)

func init() {
    prometheus.MustRegister(
        RequestsTotal, ScanDuration, CacheSizeBytes,
        CacheHitsTotal, CacheMissesTotal, BlockedTotal,
        QuarantinedTotal, ScannerErrorsTotal,
    )
}
```

- [ ] **Step 2: Verify metrics endpoint works**

Run: `go test ./internal/api/ -v`
Expected: All PASS (metrics registered without collision).

- [ ] **Step 3: Commit**

```bash
git add internal/api/metrics.go
git commit -m "feat(api): register Prometheus metrics for requests, scans, cache, blocks"
```

---

### Task 6: OpenAPI Specification

**Files:**
- Create: `docs/api/openapi.yaml`

- [ ] **Step 1: Write OpenAPI 3.1 spec**

Document all endpoints with request/response schemas matching the implementation. Reference the endpoint list from `docs/initial-analyse.md` section 10.

- [ ] **Step 2: Commit**

```bash
git add docs/api/openapi.yaml
git commit -m "docs(api): add OpenAPI 3.1 specification for REST API"
```

---

### Task 7: Verify All Phase 6 Tests Pass

- [ ] **Step 1: Run all API tests**

Run: `go test ./internal/api/... -v -race`
Expected: All PASS.

- [ ] **Step 2: Run vet**

Run: `go vet ./internal/api/...`
Expected: No issues.
