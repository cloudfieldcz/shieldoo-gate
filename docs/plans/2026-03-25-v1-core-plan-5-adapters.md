# Shieldoo Gate v1.0 Core — Phase 5: Protocol Adapters (PyPI, npm, Docker, NuGet)

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement all four protocol adapters as HTTP handlers that transparently proxy their native protocol, integrating cache checks, scanning, policy evaluation, and audit logging.

**Architecture:** Each adapter implements `adapter.Adapter` (which embeds `http.Handler`). The shared flow is: parse request → check cache (including `artifact_status`) → on miss: download from upstream → scan → evaluate policy → cache write (if allowed) → serve or block. Adapters share a common base for DB operations and audit logging but implement protocol-specific request/response handling. Package names and versions are validated with a whitelist character pattern to prevent path traversal.

**Tech Stack:** Go 1.23+, chi/v5 (routing), `net/http` (upstream proxying), `google/go-containerregistry` (Docker), sqlx, testify

**Index:** [`plan-index.md`](./2026-03-25-v1-core-plan-index.md)

---

### Task 1: Adapter Base (Shared Logic)

**Files:**
- Create: `internal/adapter/base.go`
- Test: `internal/adapter/base_test.go`

Shared adapter logic: DB operations (artifact insert, status check, audit log write), input validation, common error responses.

- [ ] **Step 1: Write tests for input validation and artifact status check**

```go
// internal/adapter/base_test.go
package adapter

import (
    "testing"

    "github.com/stretchr/testify/assert"
)

func TestValidatePackageName_Valid(t *testing.T) {
    valid := []string{"requests", "my-package", "my_package", "pkg.util", "MyPkg123"}
    for _, name := range valid {
        assert.NoError(t, ValidatePackageName(name), "expected %q to be valid", name)
    }
}

func TestValidatePackageName_Invalid(t *testing.T) {
    invalid := []string{"../etc/passwd", "pkg/../bad", "pkg;rm -rf", ""}
    for _, name := range invalid {
        assert.Error(t, ValidatePackageName(name), "expected %q to be invalid", name)
    }
}

func TestValidateVersion_Valid(t *testing.T) {
    valid := []string{"1.0.0", "2.31.0", "1.0.0-beta.1", "0.1.17"}
    for _, v := range valid {
        assert.NoError(t, ValidateVersion(v), "expected %q to be valid", v)
    }
}

func TestValidateVersion_Invalid(t *testing.T) {
    invalid := []string{"../bad", "1.0;cmd", ""}
    for _, v := range invalid {
        assert.Error(t, ValidateVersion(v), "expected %q to be invalid", v)
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adapter/ -v -run TestValidate`
Expected: FAIL

- [ ] **Step 3: Implement base adapter logic**

```go
// internal/adapter/base.go
package adapter

import (
    "encoding/json"
    "fmt"
    "net/http"
    "regexp"
    "time"

    "github.com/cloudfieldcz/shieldoo-gate/internal/model"
    "github.com/jmoiron/sqlx"
)

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)
var versionPattern = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)

func ValidatePackageName(name string) error {
    if name == "" || !namePattern.MatchString(name) {
        return fmt.Errorf("invalid package name: %q", name)
    }
    return nil
}

func ValidateVersion(version string) error {
    if version == "" || !versionPattern.MatchString(version) {
        return fmt.Errorf("invalid version: %q", version)
    }
    return nil
}

type ErrorResponse struct {
    Error     string `json:"error"`
    Artifact  string `json:"artifact,omitempty"`
    Reason    string `json:"reason,omitempty"`
    DetailsURL string `json:"details_url,omitempty"`
}

func WriteJSONError(w http.ResponseWriter, status int, resp ErrorResponse) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(resp)
}

// WriteAuditLog inserts an audit log entry. Designed to be called asynchronously.
func WriteAuditLog(db *sqlx.DB, entry model.AuditEntry) error {
    _, err := db.Exec(`
        INSERT INTO audit_log (ts, event_type, artifact_id, client_ip, user_agent, reason, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
        time.Now().UTC(), string(entry.EventType), entry.ArtifactID,
        entry.ClientIP, entry.UserAgent, entry.Reason, entry.MetadataJSON,
    )
    return err
}

// GetArtifactStatus checks if an artifact is cached and returns its status.
// Returns nil, nil if not found.
func GetArtifactStatus(db *sqlx.DB, artifactID string) (*model.ArtifactStatus, error) {
    var status model.ArtifactStatus
    err := db.Get(&status, "SELECT * FROM artifact_status WHERE artifact_id = ?", artifactID)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, nil
        }
        return nil, fmt.Errorf("adapter: checking artifact status: %w", err)
    }
    return &status, nil
}

// InsertScanResults writes scan results to the scan_results table and updates artifact_status.last_scan_id.
func InsertScanResults(db *sqlx.DB, artifactID string, results []scanner.ScanResult) error {
    for _, r := range results {
        findingsJSON, _ := json.Marshal(r.Findings)
        res, err := db.Exec(`
            INSERT INTO scan_results (artifact_id, scanned_at, scanner_name, scanner_version, verdict, confidence, findings_json, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            artifactID, r.ScannedAt, r.ScannerID, "", string(r.Verdict), r.Confidence,
            string(findingsJSON), r.Duration.Milliseconds(),
        )
        if err != nil {
            return fmt.Errorf("adapter: inserting scan result: %w", err)
        }
        lastID, _ := res.LastInsertId()
        db.Exec("UPDATE artifact_status SET last_scan_id = ? WHERE artifact_id = ?", lastID, artifactID)
    }
    return nil
}

// InsertArtifact inserts artifact + status records in a transaction.
func InsertArtifact(db *sqlx.DB, artifact model.Artifact, status model.ArtifactStatus) error {
    tx, err := db.Beginx()
    if err != nil {
        return fmt.Errorf("adapter: beginning transaction: %w", err)
    }
    defer tx.Rollback()

    _, err = tx.Exec(`
        INSERT OR REPLACE INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        artifact.ID(), artifact.Ecosystem, artifact.Name, artifact.Version,
        artifact.UpstreamURL, artifact.SHA256, artifact.SizeBytes,
        artifact.CachedAt, artifact.LastAccessedAt, artifact.StoragePath,
    )
    if err != nil {
        return fmt.Errorf("adapter: inserting artifact: %w", err)
    }

    _, err = tx.Exec(`
        INSERT OR REPLACE INTO artifact_status (artifact_id, status, quarantine_reason, quarantined_at, released_at, rescan_due_at, last_scan_id)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
        status.ArtifactID, string(status.Status), status.QuarantineReason,
        status.QuarantinedAt, status.ReleasedAt, status.RescanDueAt, status.LastScanID,
    )
    if err != nil {
        return fmt.Errorf("adapter: inserting artifact_status: %w", err)
    }

    return tx.Commit()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/adapter/ -v -run TestValidate`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/base.go internal/adapter/base_test.go
git commit -m "feat(adapter): add shared base logic for input validation, DB ops, audit logging"
```

---

### Task 2: PyPI Adapter (PEP 503 / PEP 691)

**Files:**
- Create: `internal/adapter/pypi/pypi.go`
- Test: `internal/adapter/pypi/pypi_test.go`

Routes from `docs/initial-analyse.md` section 5.2:
- `GET /simple/` → package index (proxied from upstream)
- `GET /simple/{package}/` → package file list (proxied, URLs rewritten)
- `GET /packages/{path}` → download artifact (triggers scan on cache miss)

- [ ] **Step 1: Write tests**

```go
// internal/adapter/pypi/pypi_test.go
package pypi

import (
    "context"
    "io"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
    "github.com/cloudfieldcz/shieldoo-gate/internal/config"
    "github.com/cloudfieldcz/shieldoo-gate/internal/policy"
    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func setupTestPyPI(t *testing.T, upstreamHandler http.HandlerFunc) (*PyPIAdapter, *httptest.Server) {
    t.Helper()
    upstream := httptest.NewServer(upstreamHandler)
    t.Cleanup(upstream.Close)

    db, err := config.InitDB(":memory:")
    require.NoError(t, err)
    t.Cleanup(func() { db.Close() })

    cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
    require.NoError(t, err)

    scanEngine := scanner.NewEngine(nil, 30*time.Second) // no scanners for unit tests
    policyEngine := policy.NewEngine(policy.EngineConfig{
        BlockIfVerdict:      "MALICIOUS",
        QuarantineIfVerdict: "SUSPICIOUS",
        MinimumConfidence:   0.7,
    })

    adapter := NewPyPIAdapter(db, cacheStore, scanEngine, policyEngine, upstream.URL)
    return adapter, upstream
}

func TestPyPIAdapter_SimpleIndex_ProxiesUpstream(t *testing.T) {
    adapter, _ := setupTestPyPI(t, func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html")
        w.Write([]byte(`<html><body><a href="/simple/requests/">requests</a></body></html>`))
    })

    req := httptest.NewRequest(http.MethodGet, "/simple/", nil)
    w := httptest.NewRecorder()
    adapter.ServeHTTP(w, req)

    assert.Equal(t, http.StatusOK, w.Code)
    assert.Contains(t, w.Body.String(), "requests")
}

func TestPyPIAdapter_Ecosystem(t *testing.T) {
    adapter, _ := setupTestPyPI(t, nil)
    assert.Equal(t, scanner.EcosystemPyPI, adapter.Ecosystem())
}

// Compile-time interface check
var _ adapter.Adapter = (*PyPIAdapter)(nil)
```

Note: `adapter.Adapter` import needs to reference the interface package. The test above verifies basic proxying. Full integration tests (with scanning) are in Phase 8.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adapter/pypi/ -v`
Expected: FAIL

- [ ] **Step 3: Implement PyPI adapter**

The implementation should:
1. Route `/simple/` and `/simple/{package}/` as proxy pass-through to upstream (rewrite download URLs)
2. Route `/packages/{path}` as the artifact download endpoint with full scan pipeline
3. Use chi router for sub-routing within the adapter

```go
// internal/adapter/pypi/pypi.go
package pypi

import (
    "context"
    "crypto/sha256"
    "fmt"
    "io"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/jmoiron/sqlx"
    "github.com/rs/zerolog/log"

    "github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
    "github.com/cloudfieldcz/shieldoo-gate/internal/cache"
    "github.com/cloudfieldcz/shieldoo-gate/internal/model"
    "github.com/cloudfieldcz/shieldoo-gate/internal/policy"
    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

type PyPIAdapter struct {
    db           *sqlx.DB
    cache        cache.CacheStore
    scanEngine   *scanner.Engine
    policyEngine *policy.Engine
    upstreamURL  string
    httpClient   *http.Client
    router       chi.Router
}

func NewPyPIAdapter(db *sqlx.DB, cache cache.CacheStore, scanEngine *scanner.Engine, policyEngine *policy.Engine, upstreamURL string) *PyPIAdapter {
    a := &PyPIAdapter{
        db:           db,
        cache:        cache,
        scanEngine:   scanEngine,
        policyEngine: policyEngine,
        upstreamURL:  strings.TrimRight(upstreamURL, "/"),
        httpClient:   &http.Client{Timeout: 60 * time.Second},
    }

    r := chi.NewRouter()
    r.Get("/simple/", a.handleIndex)
    r.Get("/simple/{package}/", a.handlePackage)
    r.Get("/packages/*", a.handleDownload)
    a.router = r
    return a
}

func (a *PyPIAdapter) Ecosystem() scanner.Ecosystem { return scanner.EcosystemPyPI }

func (a *PyPIAdapter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    a.router.ServeHTTP(w, r)
}

func (a *PyPIAdapter) HealthCheck(ctx context.Context) error {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.upstreamURL+"/simple/", nil)
    if err != nil {
        return fmt.Errorf("pypi: creating health check request: %w", err)
    }
    resp, err := a.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("pypi: upstream health check: %w", err)
    }
    resp.Body.Close()
    return nil
}

func (a *PyPIAdapter) handleIndex(w http.ResponseWriter, r *http.Request) {
    a.proxyUpstream(w, r, "/simple/")
}

func (a *PyPIAdapter) handlePackage(w http.ResponseWriter, r *http.Request) {
    pkg := chi.URLParam(r, "package")
    if err := adapter.ValidatePackageName(pkg); err != nil {
        adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: err.Error()})
        return
    }
    a.proxyUpstream(w, r, fmt.Sprintf("/simple/%s/", pkg))
}

func (a *PyPIAdapter) handleDownload(w http.ResponseWriter, r *http.Request) {
    path := chi.URLParam(r, "*")
    // Extract package name and version from path (e.g., "requests/2.31.0/requests-2.31.0.tar.gz")
    parts := strings.SplitN(path, "/", 3)
    if len(parts) < 3 {
        adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: "invalid download path"})
        return
    }
    pkgName, version, filename := parts[0], parts[1], parts[2]

    if err := adapter.ValidatePackageName(pkgName); err != nil {
        adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: err.Error()})
        return
    }
    if err := adapter.ValidateVersion(version); err != nil {
        adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{Error: err.Error()})
        return
    }

    artifactID := fmt.Sprintf("pypi:%s:%s", pkgName, version)

    // Check artifact_status in DB
    status, err := adapter.GetArtifactStatus(a.db, artifactID)
    if err != nil {
        log.Error().Err(err).Str("artifact", artifactID).Msg("pypi: checking artifact status")
    }

    if status != nil {
        // Quarantined artifacts are NEVER served — security invariant #1
        if status.Status == model.StatusQuarantined {
            adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
                Error:    "artifact_quarantined",
                Artifact: artifactID,
                Reason:   status.QuarantineReason,
            })
            go adapter.WriteAuditLog(a.db, model.AuditEntry{
                EventType: model.EventBlocked, ArtifactID: artifactID,
                ClientIP: r.RemoteAddr, UserAgent: r.UserAgent(), Reason: "quarantined",
            })
            return
        }

        // Check cache + TTL
        cachePath, err := a.cache.Get(r.Context(), artifactID)
        if err == nil {
            // Check TTL — if cached_at + TTL < now, treat as cache miss (re-download + re-scan)
            var cachedAt time.Time
            a.db.Get(&cachedAt, "SELECT cached_at FROM artifacts WHERE id = ?", artifactID)
            ttl := 168 * time.Hour // 7 days default for PyPI; should come from config
            if !cachedAt.IsZero() && time.Since(cachedAt) > ttl {
                // TTL expired — treat as cache miss, fall through to download+scan
            } else {
                // Cache hit — serve directly
                go adapter.WriteAuditLog(a.db, model.AuditEntry{
                    EventType: model.EventServed, ArtifactID: artifactID,
                    ClientIP: r.RemoteAddr, UserAgent: r.UserAgent(),
                })
                a.db.Exec("UPDATE artifacts SET last_accessed_at = ? WHERE id = ?", time.Now().UTC(), artifactID)
                http.ServeFile(w, r, cachePath)
                return
            }
        }
    }

    // Cache miss — download from upstream, scan, evaluate, serve/block
    a.downloadScanServe(w, r, pkgName, version, filename, artifactID)
}

func (a *PyPIAdapter) downloadScanServe(w http.ResponseWriter, r *http.Request, pkgName, version, filename, artifactID string) {
    // Download from upstream to temp file
    upstreamURL := fmt.Sprintf("%s/packages/%s/%s/%s", a.upstreamURL, pkgName, version, filename)
    tmpFile, fileSize, fileSHA256, err := a.downloadToTemp(r.Context(), upstreamURL)
    if err != nil {
        log.Error().Err(err).Str("url", upstreamURL).Msg("pypi: downloading from upstream")
        adapter.WriteJSONError(w, http.StatusBadGateway, adapter.ErrorResponse{Error: "upstream_error", Reason: err.Error()})
        return
    }
    defer os.Remove(tmpFile)

    // Scan
    artifact := scanner.Artifact{
        ID:          artifactID,
        Ecosystem:   scanner.EcosystemPyPI,
        Name:        pkgName,
        Version:     version,
        LocalPath:   tmpFile,
        SHA256:      fileSHA256,
        SizeBytes:   fileSize,
        UpstreamURL: upstreamURL,
    }

    scanResults, err := a.scanEngine.ScanAll(r.Context(), artifact)
    if err != nil {
        log.Error().Err(err).Str("artifact", artifactID).Msg("pypi: scanning artifact")
    }

    // Evaluate policy
    policyResult, err := a.policyEngine.Evaluate(r.Context(), artifact, scanResults)
    if err != nil {
        log.Error().Err(err).Str("artifact", artifactID).Msg("pypi: evaluating policy")
    }

    now := time.Now().UTC()
    modelArtifact := model.Artifact{
        Ecosystem: "pypi", Name: pkgName, Version: version,
        UpstreamURL: upstreamURL, SHA256: fileSHA256, SizeBytes: fileSize,
        CachedAt: now, LastAccessedAt: now, StoragePath: "",
    }

    // Write scan results to DB (important: this persists scan history for the API)
    if err := adapter.InsertScanResults(a.db, artifactID, scanResults); err != nil {
        log.Error().Err(err).Str("artifact", artifactID).Msg("pypi: writing scan results")
    }

    switch policyResult.Action {
    case policy.ActionBlock:
        adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
            Error: "artifact_blocked", Artifact: artifactID, Reason: policyResult.Reason,
        })
        go adapter.WriteAuditLog(a.db, model.AuditEntry{
            EventType: model.EventBlocked, ArtifactID: artifactID,
            ClientIP: r.RemoteAddr, UserAgent: r.UserAgent(), Reason: policyResult.Reason,
        })

    case policy.ActionQuarantine:
        artStatus := model.ArtifactStatus{
            ArtifactID: artifactID, Status: model.StatusQuarantined,
            QuarantineReason: policyResult.Reason, QuarantinedAt: &now,
        }
        adapter.InsertArtifact(a.db, modelArtifact, artStatus)
        a.cache.Put(r.Context(), artifact, tmpFile) // store but don't serve
        adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
            Error: "artifact_quarantined", Artifact: artifactID, Reason: policyResult.Reason,
        })
        go adapter.WriteAuditLog(a.db, model.AuditEntry{
            EventType: model.EventQuarantined, ArtifactID: artifactID,
            ClientIP: r.RemoteAddr, UserAgent: r.UserAgent(), Reason: policyResult.Reason,
        })

    case policy.ActionWarn:
        artStatus := model.ArtifactStatus{ArtifactID: artifactID, Status: model.StatusClean}
        adapter.InsertArtifact(a.db, modelArtifact, artStatus)
        a.cache.Put(r.Context(), artifact, tmpFile)
        w.Header().Set("X-Shieldoo-Warning", policyResult.Reason)
        go adapter.WriteAuditLog(a.db, model.AuditEntry{
            EventType: model.EventServed, ArtifactID: artifactID,
            ClientIP: r.RemoteAddr, UserAgent: r.UserAgent(), Reason: "warned: " + policyResult.Reason,
        })
        http.ServeFile(w, r, tmpFile)

    default: // ActionAllow
        artStatus := model.ArtifactStatus{ArtifactID: artifactID, Status: model.StatusClean}
        adapter.InsertArtifact(a.db, modelArtifact, artStatus)
        a.cache.Put(r.Context(), artifact, tmpFile)
        go adapter.WriteAuditLog(a.db, model.AuditEntry{
            EventType: model.EventServed, ArtifactID: artifactID,
            ClientIP: r.RemoteAddr, UserAgent: r.UserAgent(),
        })
        http.ServeFile(w, r, tmpFile)
    }
}

func (a *PyPIAdapter) downloadToTemp(ctx context.Context, url string) (path string, size int64, sha string, err error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return "", 0, "", fmt.Errorf("creating request: %w", err)
    }

    resp, err := a.httpClient.Do(req)
    if err != nil {
        return "", 0, "", fmt.Errorf("downloading: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return "", 0, "", fmt.Errorf("upstream returned status %d", resp.StatusCode)
    }

    tmpFile, err := os.CreateTemp("", "shieldoo-pypi-*.tmp")
    if err != nil {
        return "", 0, "", fmt.Errorf("creating temp file: %w", err)
    }

    h := sha256.New()
    written, err := io.Copy(io.MultiWriter(tmpFile, h), resp.Body)
    if err != nil {
        tmpFile.Close()
        os.Remove(tmpFile.Name())
        return "", 0, "", fmt.Errorf("writing artifact: %w", err)
    }
    tmpFile.Close()

    return tmpFile.Name(), written, fmt.Sprintf("%x", h.Sum(nil)), nil
}

func (a *PyPIAdapter) proxyUpstream(w http.ResponseWriter, r *http.Request, path string) {
    req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, a.upstreamURL+path, nil)
    if err != nil {
        adapter.WriteJSONError(w, http.StatusInternalServerError, adapter.ErrorResponse{Error: err.Error()})
        return
    }

    // Forward Accept header for PEP 691 JSON API support
    if accept := r.Header.Get("Accept"); accept != "" {
        req.Header.Set("Accept", accept)
    }

    resp, err := a.httpClient.Do(req)
    if err != nil {
        adapter.WriteJSONError(w, http.StatusBadGateway, adapter.ErrorResponse{Error: "upstream_error"})
        return
    }
    defer resp.Body.Close()

    for k, vv := range resp.Header {
        for _, v := range vv {
            w.Header().Add(k, v)
        }
    }
    w.WriteHeader(resp.StatusCode)
    io.Copy(w, resp.Body)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/adapter/pypi/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/pypi/
git commit -m "feat(pypi): implement PEP 503/691 proxy adapter with scan pipeline"
```

---

### Task 3: npm Adapter

**Files:**
- Create: `internal/adapter/npm/npm.go`
- Test: `internal/adapter/npm/npm_test.go`

Routes from `docs/initial-analyse.md` section 5.3:
- `GET /{package}` → package metadata (proxied)
- `GET /{package}/{version}` → version metadata (proxied)
- `GET /{package}/-/{tarball}` → download tarball (triggers scan)

Follow the same pattern as PyPI adapter. The npm adapter is structurally similar — proxy metadata requests, intercept tarball downloads for scanning.

- [ ] **Step 1: Write tests**

Tests should mirror PyPI adapter tests: verify metadata proxying, tarball interception, ecosystem type. Use the same `setupTest` pattern.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adapter/npm/ -v`
Expected: FAIL

- [ ] **Step 3: Implement npm adapter**

Same structure as PyPI adapter but with npm-specific URL patterns and metadata format (JSON). Tarball download path is `/{package}/-/{tarball-filename}`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/adapter/npm/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/npm/
git commit -m "feat(npm): implement npm Registry API proxy adapter with scan pipeline"
```

---

### Task 4: Docker/OCI Adapter

**Files:**
- Create: `internal/adapter/docker/docker.go`
- Test: `internal/adapter/docker/docker_test.go`

Routes from `docs/initial-analyse.md` section 5.1:
- `GET /v2/` → version check
- `GET /v2/{name}/manifests/{ref}` → pull manifest (triggers scan if not cached)
- `GET /v2/{name}/blobs/{digest}` → pull layer blob

v1.0 scope: read-only pull proxy for single-arch images and manifest lists. No push support. Uses `google/go-containerregistry` library.

- [ ] **Step 1: Write tests**

Test version check endpoint (`/v2/`), manifest proxying, blob serving. Use mock HTTP upstream.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adapter/docker/ -v`
Expected: FAIL

- [ ] **Step 3: Implement Docker adapter**

Add dependency:
```bash
go get github.com/google/go-containerregistry@latest
```

The Docker adapter is the most complex. Key considerations:
- `/v2/` must return `200 OK` with `Docker-Distribution-API-Version: registry/2.0`
- Manifest requests trigger scanning of the entire image
- Blob requests serve individual layers from cache
- Use `go-containerregistry` for upstream communication

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/adapter/docker/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/docker/
git commit -m "feat(docker): implement OCI Distribution Spec read-only pull proxy adapter"
```

---

### Task 5: NuGet V3 Adapter

**Files:**
- Create: `internal/adapter/nuget/nuget.go`
- Test: `internal/adapter/nuget/nuget_test.go`

Routes from `docs/initial-analyse.md` section 5.4:
- `GET /v3/index.json` → service index
- `GET /v3/registration/{id}/index` → package metadata
- `GET /v3-flatcontainer/{id}/{v}` → download .nupkg (triggers scan)

- [ ] **Step 1: Write tests**

Test service index endpoint, package metadata proxying, nupkg download with scan pipeline.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adapter/nuget/ -v`
Expected: FAIL

- [ ] **Step 3: Implement NuGet adapter**

The NuGet service index (`/v3/index.json`) must be rewritten to point download URLs to the proxy. Same scan pipeline pattern as PyPI/npm for `.nupkg` downloads.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/adapter/nuget/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/nuget/
git commit -m "feat(nuget): implement NuGet V3 API proxy adapter with scan pipeline"
```

---

### Task 6: Verify All Phase 5 Tests Pass

- [ ] **Step 1: Run all adapter tests**

Run: `go test ./internal/adapter/... -v -race`
Expected: All PASS.

- [ ] **Step 2: Run vet**

Run: `go vet ./internal/adapter/...`
Expected: No issues.
