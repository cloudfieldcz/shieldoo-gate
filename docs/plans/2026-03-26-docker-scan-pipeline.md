# Shieldoo Gate — Phase 5a: Docker Adapter Scan Pipeline

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add scan-on-pull pipeline to the Docker/OCI adapter so that manifest pulls trigger image scanning via Trivy before the image is served to the client.

**Context:** The Docker adapter (Phase 5, Task 4) was implemented as a pure pass-through proxy. The original plan-5 specified "Manifest requests trigger scanning of the entire image" but this was not implemented. The Trivy scanner already supports `EcosystemDocker` with `trivy image --input`. This plan closes the gap.

**Security invariant:** This is a **security finding** — without scanning, the Docker adapter forwards potentially malicious images to clients without any inspection.

**Architecture:** On manifest pull, the adapter must:
1. Pull the full image (manifest + layers) to a local OCI tarball using `go-containerregistry`
2. Run Trivy scan on the tarball (`trivy image --input <path>`)
3. Evaluate policy on scan results
4. Cache the image layers if clean
5. Serve or block based on policy decision

**Tech Stack:** Go 1.25+, `google/go-containerregistry` (already in go.mod), `internal/scanner` (Trivy already supports Docker), chi/v5, sqlx, testify

**Index:** [`plan-index.md`](./2026-03-25-v1-core-plan-index.md)

---

### Task 1: Add scan engine to DockerAdapter struct

**Files:**
- Modify: `internal/adapter/docker/docker.go`

- [ ] **Step 1: Update DockerAdapter to accept and store a `*scanner.Engine`**

The constructor `NewDockerAdapter` currently takes `(db, cacheStore, policyEngine, upstreamURL)`. Add `scanEngine *scanner.Engine` parameter.

```go
type DockerAdapter struct {
    db          *sqlx.DB
    cache       cache.CacheStore
    scanEngine  *scanner.Engine  // NEW
    policyEng   *policy.Engine
    upstreamURL string
    router      http.Handler
    httpClient  *http.Client
}
```

- [ ] **Step 2: Update all call sites of `NewDockerAdapter`**

Find and update `cmd/shieldoo-gate/main.go` and `internal/adapter/docker/docker_test.go` to pass `scanEngine`.

- [ ] **Step 3: Compile and verify tests still pass**

Run: `go build ./... && go test ./internal/adapter/docker/ -v`

- [ ] **Step 4: Commit**

```bash
git commit -m "refactor(docker): add scan engine to DockerAdapter constructor"
```

---

### Task 2: Implement manifest pull with image download + scan

**Files:**
- Modify: `internal/adapter/docker/docker.go`
- Modify: `internal/adapter/docker/docker_test.go`

This is the core task. On a manifest request:
1. Check if image is already in cache with clean status → serve cached manifest
2. If not cached or status unknown: pull image to OCI tarball using `go-containerregistry`
3. Scan tarball with Trivy via `scanEngine.ScanAll()`
4. Evaluate policy
5. If clean: cache and serve manifest. If blocked/quarantined: return 403.

- [ ] **Step 1: Write test for manifest pull with scan pipeline**

```go
func TestDockerAdapter_ManifestPull_TriggersScanning(t *testing.T) {
    // Mock upstream that serves a valid manifest JSON
    // Verify that after pull, audit log contains a SCANNED entry
    // Verify response includes the manifest content
}

func TestDockerAdapter_ManifestPull_QuarantinedImage_Returns403(t *testing.T) {
    // Pre-insert a quarantined artifact_status for the image
    // Verify 403 response
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adapter/docker/ -v -run TestDockerAdapter_ManifestPull`
Expected: FAIL

- [ ] **Step 3: Implement image download to OCI tarball**

Use `go-containerregistry` to pull image to a local tarball:

```go
import (
    "github.com/google/go-containerregistry/pkg/crane"
    "github.com/google/go-containerregistry/pkg/v1/tarball"
)

func (a *DockerAdapter) pullImageToTarball(ctx context.Context, name, ref string) (string, int64, string, error) {
    // Use crane to pull the image
    fullRef := a.upstreamURL + "/" + name + ":" + ref
    img, err := crane.Pull(fullRef)
    // Save to temp tarball
    tmpFile, _ := os.CreateTemp("", "shieldoo-docker-*.tar")
    tarball.Write(ref, img, tmpFile)
    // Compute SHA256
    // Return (path, size, sha256, error)
}
```

- [ ] **Step 4: Implement scan pipeline in manifest handler**

Replace the current pass-through `proxyUpstream` call in the manifest branch with:
1. Check cache + artifact_status (fail closed on DB error, per security fix)
2. Acquire per-artifact lock (`adapter.ArtifactLocker`)
3. Pull image to tarball
4. Build `scanner.Artifact` with `Ecosystem: EcosystemDocker`
5. Call `scanEngine.ScanAll()`
6. Call `policyEngine.Evaluate()`
7. Based on policy: cache + serve manifest, or block with 403
8. Write audit log

Note: Blob requests (`/blobs/`) can remain as pass-through since they serve individual layers — the scanning happens on manifest pull which triggers full image analysis.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/adapter/docker/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git commit -m "feat(docker): add scan-on-pull pipeline for manifest requests via Trivy"
```

---

### Task 3: Add audit logging to Docker adapter

**Files:**
- Modify: `internal/adapter/docker/docker.go`

- [ ] **Step 1: Add audit log entries for Docker operations**

- SERVED: when a clean image is served (from cache or after scan)
- BLOCKED: when a malicious/quarantined image is rejected
- SCANNED: after scan completes (with scan result metadata)

Use `adapter.WriteAuditLog()` consistent with PyPI/npm/NuGet adapters.

- [ ] **Step 2: Add `X-Shieldoo-Scanned: true/false` response header**

So Docker clients and CI systems can verify that pulled images were actually scanned.

- [ ] **Step 3: Commit**

```bash
git commit -m "feat(docker): add audit logging and scan status headers"
```

---

### Task 4: Update tests and verify integration

**Files:**
- Modify: `internal/adapter/docker/docker_test.go`

- [ ] **Step 1: Update existing tests for new constructor signature**

- [ ] **Step 2: Add test for blob pass-through (no scanning)**

Verify that `/v2/{name}/blobs/{digest}` requests are proxied without triggering the scan pipeline.

- [ ] **Step 3: Run all adapter tests**

Run: `go test ./internal/adapter/... -v -race`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git commit -m "test(docker): update tests for scan pipeline integration"
```

---

### Notes

- The `go-containerregistry` library is already in `go.mod` — no new dependencies needed
- Trivy scanner already handles `EcosystemDocker` with `trivy image --input <tarball>`
- Blob requests remain pass-through — scanning at manifest level covers the full image
- Performance: first pull will be slower (download + scan + re-serve). Subsequent pulls from cache are fast.
- Image layers are large — ensure `downloadToTemp` size limits (2 GB per layer, as set in security fixes) are appropriate for Docker images. May need to increase or make configurable.
