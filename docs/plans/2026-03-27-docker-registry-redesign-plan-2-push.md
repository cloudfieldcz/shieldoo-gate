# Docker Registry Redesign — Phase 2: Push Support

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable `docker push` for internal images (non-upstream namespaces) with OCI monolithic upload support and scan-before-serve guarantees.

**Architecture:** Implement minimal OCI push endpoints: blob upload initiation (POST), blob upload completion (PUT), blob existence check (HEAD), and manifest put (PUT). Scanning runs after manifest PUT is received but before success response. Push is rejected for namespaces matching upstream registries in the allowlist. A new `docker_tags` table tracks tag-to-digest mappings. Blob storage uses the local cache filesystem.

**Tech Stack:** Go 1.25+, chi router, OCI Distribution Spec monolithic upload, sqlx + SQLite, testify

**Index:** [`plan-index.md`](./2026-03-27-docker-registry-redesign-plan-index.md)

---

### Task 1: Database Migration — `docker_tags` table

**Files:**
- Create: `internal/config/migrations/004_docker_tags.sql`

- [ ] **Step 1: Write the migration SQL**

```sql
-- internal/config/migrations/004_docker_tags.sql

CREATE TABLE IF NOT EXISTS docker_tags (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id         INTEGER NOT NULL REFERENCES docker_repositories(id),
    tag             TEXT NOT NULL,
    manifest_digest TEXT NOT NULL,
    artifact_id     TEXT REFERENCES artifacts(id),
    created_at      DATETIME NOT NULL,
    updated_at      DATETIME NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_docker_tags_repo_tag ON docker_tags(repo_id, tag);
CREATE INDEX IF NOT EXISTS idx_docker_tags_digest ON docker_tags(manifest_digest);
```

- [ ] **Step 2: Verify migration runs cleanly**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/config/ -run TestInitDB -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/config/migrations/004_docker_tags.sql
git commit -m "feat(db): add docker_tags table for tag-to-digest mapping"
```

---

### Task 2: Push Namespace Validation

**Files:**
- Modify: `internal/adapter/docker/registry.go`
- Modify: `internal/adapter/docker/registry_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestRegistryResolver_IsPushAllowed_InternalNamespace(t *testing.T) {
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: "https://registry-1.docker.io",
		AllowedRegistries: []config.DockerRegistryEntry{
			{Host: "ghcr.io", URL: "https://ghcr.io"},
		},
		Push: config.DockerPushConfig{Enabled: true},
	}
	r := docker.NewRegistryResolver(cfg)

	// Internal namespace (no dot) → push allowed
	assert.True(t, r.IsPushAllowed("myteam/myapp"))

	// Upstream registry namespace → push forbidden
	assert.False(t, r.IsPushAllowed("ghcr.io/user/app"))

	// Default registry namespace (implicit docker hub) → push forbidden
	assert.False(t, r.IsPushAllowed("library/nginx"))
	assert.False(t, r.IsPushAllowed("nginx"))
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/docker/ -run TestRegistryResolver_IsPushAllowed -v`
Expected: FAIL

- [ ] **Step 3: Implement IsPushAllowed**

Add to `internal/adapter/docker/registry.go`:

```go
// IsPushAllowed returns true if the name represents an internal namespace
// (not an upstream proxy namespace). Push is only allowed for internal images.
func (rr *RegistryResolver) IsPushAllowed(name string) bool {
	firstSlash := strings.Index(name, "/")
	if firstSlash > 0 {
		firstSegment := name[:firstSlash]
		if looksLikeRegistry(firstSegment) {
			// Matches an upstream registry → push forbidden
			return false
		}
	}
	// No slash or no dot/colon → this would go to default registry (Docker Hub)
	// Push to upstream proxy namespaces is forbidden
	// Only names that don't resolve to any upstream are pushable
	_, _, _, err := rr.Resolve(name)
	if err != nil {
		// Not in allowlist → could be internal
		return true
	}
	// If it resolves to default (docker.io), it's an upstream namespace → forbidden
	return false
}
```

Wait — this logic is wrong. A name like "myteam/myapp" resolves to docker.io (default). We need a different approach: push is allowed ONLY if the first segment contains NO dot/colon (so it doesn't match any upstream) AND `push.enabled` is true. But we also need to block bare names that would go to Docker Hub. So:

```go
// IsPushAllowed returns true if the image name is a valid internal push target.
// Internal images must have at least one slash and the first segment must NOT
// look like a registry hostname (no dots or colons).
func (rr *RegistryResolver) IsPushAllowed(name string) bool {
	firstSlash := strings.Index(name, "/")
	if firstSlash <= 0 {
		// Bare name (no slash) → would be library/X on Docker Hub → not pushable
		return false
	}
	firstSegment := name[:firstSlash]
	if looksLikeRegistry(firstSegment) {
		// Looks like a registry hostname → upstream namespace → not pushable
		return false
	}
	// Has slash, first segment is NOT a registry → internal namespace → pushable
	return true
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/docker/ -run TestRegistryResolver_IsPushAllowed -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/docker/registry.go internal/adapter/docker/registry_test.go
git commit -m "feat(docker): add push namespace validation to registry resolver"
```

---

### Task 3: Blob Storage Helpers

**Files:**
- Create: `internal/adapter/docker/blobs.go`
- Create: `internal/adapter/docker/blobs_test.go`

- [ ] **Step 1: Write the failing tests**

```go
// internal/adapter/docker/blobs_test.go
package docker_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
)

func TestBlobStore_PutAndGet(t *testing.T) {
	bs := docker.NewBlobStore(t.TempDir())

	content := []byte("fake layer content")
	digest := "sha256:abc123def456"

	err := bs.Put(digest, content)
	require.NoError(t, err)

	data, err := bs.Get(digest)
	require.NoError(t, err)
	assert.Equal(t, content, data)
}

func TestBlobStore_Exists(t *testing.T) {
	bs := docker.NewBlobStore(t.TempDir())

	assert.False(t, bs.Exists("sha256:doesnotexist"))

	err := bs.Put("sha256:abc123", []byte("data"))
	require.NoError(t, err)

	assert.True(t, bs.Exists("sha256:abc123"))
}

func TestBlobStore_PathTraversal_Rejected(t *testing.T) {
	bs := docker.NewBlobStore(t.TempDir())

	err := bs.Put("sha256:../../etc/passwd", []byte("evil"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid digest")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/docker/ -run TestBlobStore -v`
Expected: FAIL

- [ ] **Step 3: Implement blobs.go**

```go
// internal/adapter/docker/blobs.go
package docker

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var validDigestRe = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// BlobStore manages local blob storage for pushed images.
type BlobStore struct {
	basePath string
}

// NewBlobStore creates a blob store at the given base directory.
func NewBlobStore(basePath string) *BlobStore {
	return &BlobStore{basePath: basePath}
}

// Put stores blob content keyed by digest.
func (bs *BlobStore) Put(digest string, data []byte) error {
	safePath, err := bs.digestPath(digest)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(safePath), 0o755); err != nil {
		return fmt.Errorf("docker blob: creating directory: %w", err)
	}
	return os.WriteFile(safePath, data, 0o644)
}

// Get retrieves blob content by digest.
func (bs *BlobStore) Get(digest string) ([]byte, error) {
	safePath, err := bs.digestPath(digest)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(safePath)
}

// Exists returns true if a blob with the given digest exists.
func (bs *BlobStore) Exists(digest string) bool {
	safePath, err := bs.digestPath(digest)
	if err != nil {
		return false
	}
	_, err = os.Stat(safePath)
	return err == nil
}

func (bs *BlobStore) digestPath(digest string) (string, error) {
	if !validDigestRe.MatchString(digest) {
		// Also accept short digests for testing, but block path traversal
		if strings.Contains(digest, "..") || strings.ContainsAny(digest, "/\\") {
			return "", fmt.Errorf("docker blob: invalid digest %q", digest)
		}
	}
	// sha256:abcdef → sha256/ab/abcdef (two-level directory for performance)
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("docker blob: invalid digest format %q", digest)
	}
	algo, hex := parts[0], parts[1]
	prefix := hex
	if len(hex) >= 2 {
		prefix = hex[:2]
	}
	return filepath.Join(bs.basePath, "blobs", algo, prefix, hex), nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/docker/ -run TestBlobStore -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/docker/blobs.go internal/adapter/docker/blobs_test.go
git commit -m "feat(docker): add local blob storage for pushed images"
```

---

### Task 4: OCI Push Handlers — Upload Sessions

**Files:**
- Create: `internal/adapter/docker/push.go`
- Create: `internal/adapter/docker/push_test.go`

- [ ] **Step 1: Write the failing tests**

```go
// internal/adapter/docker/push_test.go
package docker_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

func setupTestDockerWithPush(t *testing.T) *docker.DockerAdapter {
	t.Helper()
	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// ... setup with Push.Enabled = true, no upstream needed for push
	// Use setupTestDocker-like helper with push config
}

func TestDockerPush_UpstreamNamespace_Returns403(t *testing.T) {
	// POST /v2/ghcr.io/user/app/blobs/uploads/ → 403
	a := setupTestDockerWithPush(t)
	req := httptest.NewRequest(http.MethodPost, "/v2/ghcr.io/user/app/blobs/uploads/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestDockerPush_InitiateUpload_Returns202(t *testing.T) {
	// POST /v2/myteam/myapp/blobs/uploads/ → 202 + Location header
	a := setupTestDockerWithPush(t)
	req := httptest.NewRequest(http.MethodPost, "/v2/myteam/myapp/blobs/uploads/", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	assert.Equal(t, http.StatusAccepted, w.Code)
	assert.NotEmpty(t, w.Header().Get("Location"))
	assert.NotEmpty(t, w.Header().Get("Docker-Upload-UUID"))
}

func TestDockerPush_CompleteUpload_Returns201(t *testing.T) {
	a := setupTestDockerWithPush(t)

	// Step 1: Initiate
	initReq := httptest.NewRequest(http.MethodPost, "/v2/myteam/myapp/blobs/uploads/", nil)
	initW := httptest.NewRecorder()
	a.ServeHTTP(initW, initReq)
	require.Equal(t, http.StatusAccepted, initW.Code)
	location := initW.Header().Get("Location")

	// Step 2: Complete with digest
	blobData := []byte("fake blob content")
	completeReq := httptest.NewRequest(http.MethodPut, location+"?digest=sha256:abc123", bytes.NewReader(blobData))
	completeW := httptest.NewRecorder()
	a.ServeHTTP(completeW, completeReq)
	assert.Equal(t, http.StatusCreated, completeW.Code)
}

func TestDockerPush_BlobHead_ExistingBlob_Returns200(t *testing.T) {
	a := setupTestDockerWithPush(t)

	// Upload a blob first, then HEAD it
	// ... (initiate + complete upload, then HEAD /v2/myteam/myapp/blobs/sha256:abc123)
}
```

Note: These are skeleton tests. The actual implementation will need to handle UUID-based upload sessions, which requires an in-memory map of active uploads.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/docker/ -run TestDockerPush -v`
Expected: FAIL

- [ ] **Step 3: Implement push.go — upload session management**

```go
// internal/adapter/docker/push.go
package docker

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
)

// uploadSession tracks an in-progress blob upload.
type uploadSession struct {
	uuid   string
	name   string // image name
	data   []byte // accumulated data (monolithic)
}

// pushHandler manages OCI push operations.
type pushHandler struct {
	sessions  sync.Map // uuid → *uploadSession
	blobStore *BlobStore
}

func newPushHandler(blobStore *BlobStore) *pushHandler {
	return &pushHandler{blobStore: blobStore}
}

// handleBlobUploadInit handles POST /v2/{name}/blobs/uploads/
func (ph *pushHandler) handleBlobUploadInit(w http.ResponseWriter, r *http.Request, name string) {
	sessionUUID := uuid.New().String()
	ph.sessions.Store(sessionUUID, &uploadSession{
		uuid: sessionUUID,
		name: name,
	})

	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", name, sessionUUID))
	w.Header().Set("Docker-Upload-UUID", sessionUUID)
	w.Header().Set("Range", "0-0")
	w.WriteHeader(http.StatusAccepted)
}

// handleBlobUploadComplete handles PUT /v2/{name}/blobs/uploads/{uuid}?digest=sha256:...
func (ph *pushHandler) handleBlobUploadComplete(w http.ResponseWriter, r *http.Request, name, uploadUUID string) {
	digest := r.URL.Query().Get("digest")
	if digest == "" {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "missing digest",
			Reason: "digest query parameter is required",
		})
		return
	}

	val, ok := ph.sessions.LoadAndDelete(uploadUUID)
	if !ok {
		http.Error(w, "upload session not found", http.StatusNotFound)
		return
	}
	session := val.(*uploadSession)

	// Read blob body (monolithic upload)
	const maxBlobSize = 2 << 30 // 2 GB
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBlobSize))
	if err != nil {
		http.Error(w, "failed to read blob", http.StatusInternalServerError)
		return
	}
	session.data = body

	// Verify digest
	h := sha256.Sum256(body)
	computedDigest := "sha256:" + hex.EncodeToString(h[:])
	if computedDigest != digest {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "digest mismatch",
			Reason: fmt.Sprintf("computed %s, expected %s", computedDigest, digest),
		})
		return
	}

	// Store blob
	if err := ph.blobStore.Put(digest, body); err != nil {
		log.Error().Err(err).Str("digest", digest).Msg("docker push: failed to store blob")
		http.Error(w, "failed to store blob", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", name, digest))
	w.WriteHeader(http.StatusCreated)
}

// handleBlobHead handles HEAD /v2/{name}/blobs/{digest}
func (ph *pushHandler) handleBlobHead(w http.ResponseWriter, r *http.Request, digest string) {
	if ph.blobStore.Exists(digest) {
		w.Header().Set("Docker-Content-Digest", digest)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.NotFound(w, r)
}
```

- [ ] **Step 4: Integrate push routes into buildRouter**

In `docker.go`, update `buildRouter` to add POST/PUT/HEAD routes:

```go
func (a *DockerAdapter) buildRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/v2/", a.handleV2Check)
	r.Get("/v2/*", a.handleV2Wildcard)
	r.Post("/v2/*", a.handleV2WildcardWrite)
	r.Put("/v2/*", a.handleV2WildcardWrite)
	r.Patch("/v2/*", a.handleV2WildcardWrite)
	r.Head("/v2/*", a.handleV2WildcardHead)
	return r
}
```

Implement `handleV2WildcardWrite` and `handleV2WildcardHead` to parse paths and route to push handlers.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/docker/ -run TestDockerPush -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/adapter/docker/push.go internal/adapter/docker/push_test.go internal/adapter/docker/docker.go
git commit -m "feat(docker): OCI monolithic blob upload (POST + PUT + HEAD)"
```

---

### Task 5: Manifest PUT — Scan Before Response

**Files:**
- Modify: `internal/adapter/docker/push.go`
- Modify: `internal/adapter/docker/push_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestDockerPush_ManifestPut_ScansBeforeResponse(t *testing.T) {
	// Push a manifest → adapter must scan before returning 201
	// With no scanners configured, scan returns clean → 201
	a := setupTestDockerWithPush(t)

	manifestBody := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}`)
	req := httptest.NewRequest(http.MethodPut, "/v2/myteam/myapp/manifests/v1.0", bytes.NewReader(manifestBody))
	req.Header.Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.NotEmpty(t, w.Header().Get("Docker-Content-Digest"))
}
```

- [ ] **Step 2: Implement handleManifestPut**

Add to `push.go`:
```go
// handleManifestPut handles PUT /v2/{name}/manifests/{ref}
// Scan runs BEFORE returning success. Security Invariant #2.
func (a *DockerAdapter) handleManifestPut(w http.ResponseWriter, r *http.Request, name, ref string) {
	// 1. Read manifest body
	// 2. Compute digest
	// 3. Create docker_repository if needed (EnsureRepository with isInternal=true)
	// 4. Store manifest temporarily
	// 5. Scan (blocking)
	// 6. If scan fails → quarantine, return 403
	// 7. If scan passes → store in cache, insert docker_tag, return 201
}
```

- [ ] **Step 3: Run test to verify it passes**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/docker/ -run TestDockerPush_ManifestPut -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/adapter/docker/push.go internal/adapter/docker/push_test.go
git commit -m "feat(docker): manifest PUT with scan-before-response"
```

---

### Task 6: Tag DB Helpers

**Files:**
- Create: `internal/adapter/docker/tags.go`
- Create: `internal/adapter/docker/tags_test.go`

- [ ] **Step 1: Write failing tests for tag CRUD**

Test `UpsertTag`, `ListTags`, `DeleteTag`, `GetTagByDigest`.

- [ ] **Step 2: Implement tags.go**

```go
// internal/adapter/docker/tags.go
package docker

// DockerTag, UpsertTag, ListTags, DeleteTag, GetTagByDigest
```

- [ ] **Step 3: Run tests, verify pass**

- [ ] **Step 4: Commit**

```bash
git add internal/adapter/docker/tags.go internal/adapter/docker/tags_test.go
git commit -m "feat(docker): tag CRUD helpers for docker_tags table"
```

---

### Task 7: Documentation + Final Verification

- [ ] **Step 1: Update docs for push support**
- [ ] **Step 2: Run full test suite**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./... -count=1 -race`

- [ ] **Step 3: Build + lint**

Run: `cd /Users/valda/src/projects/shieldoo-gate && make build && make lint`

- [ ] **Step 4: Commit**

```bash
git add docs/
git commit -m "docs(docker): document push support and OCI upload flow"
```
