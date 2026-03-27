# Docker Registry Redesign — Phase 4a: Tag Management API

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** REST API endpoints for managing Docker repositories and tags, including manual tagging, tag movement (with re-scan trigger), tag deletion, and manual sync trigger.

**Architecture:** New handler file in `internal/api/` registers endpoints under `/api/v1/docker/`. Handlers call the DB helpers from `internal/adapter/docker/` (repos.go, tags.go). Tag movement triggers a re-scan of the target digest. Follows existing API patterns (chi router, JSON responses, structured errors).

**Tech Stack:** Go 1.25+, chi router, sqlx + SQLite, testify

**Index:** [`plan-index.md`](./2026-03-27-docker-registry-redesign-plan-index.md)

---

### Task 1: API Handler — List Repositories

**Files:**
- Create: `internal/api/docker_handlers.go`
- Create: `internal/api/docker_handlers_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/api/docker_handlers_test.go
func TestDockerAPI_ListRepositories_ReturnsJSON(t *testing.T) {
	// Setup: DB with 2 repos
	// GET /api/v1/docker/repositories → 200 + JSON array
}

func TestDockerAPI_ListRepositories_FilterByRegistry(t *testing.T) {
	// GET /api/v1/docker/repositories?registry=ghcr.io → filtered results
}
```

- [ ] **Step 2: Implement handler**

```go
// internal/api/docker_handlers.go
package api

// GET /api/v1/docker/repositories
func (s *Server) handleListDockerRepositories(w http.ResponseWriter, r *http.Request) {
	registry := r.URL.Query().Get("registry")
	repos, err := docker.ListRepositories(s.db, registry)
	// ... JSON response
}
```

- [ ] **Step 3: Register route in api server**

Add to the existing `Routes()` method in `internal/api/server.go`.

- [ ] **Step 4: Run tests, verify pass**
- [ ] **Step 5: Commit**

```bash
git add internal/api/docker_handlers.go internal/api/docker_handlers_test.go internal/api/server.go
git commit -m "feat(api): GET /api/v1/docker/repositories endpoint"
```

---

### Task 2: API Handler — List Tags for Repository

**Files:**
- Modify: `internal/api/docker_handlers.go`
- Modify: `internal/api/docker_handlers_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestDockerAPI_ListTags_ReturnsTagsForRepo(t *testing.T) {
	// GET /api/v1/docker/repositories/{id}/tags → 200 + JSON array of tags
}
```

- [ ] **Step 2: Implement handler**

```go
// GET /api/v1/docker/repositories/{id}/tags
func (s *Server) handleListDockerTags(w http.ResponseWriter, r *http.Request) {
	repoID := chi.URLParam(r, "id")
	tags, err := docker.ListTags(s.db, repoID)
	// ... JSON response
}
```

- [ ] **Step 3: Run tests, verify pass**
- [ ] **Step 4: Commit**

```bash
git add internal/api/docker_handlers.go internal/api/docker_handlers_test.go
git commit -m "feat(api): GET /api/v1/docker/repositories/{id}/tags endpoint"
```

---

### Task 3: API Handler — Create/Move Tag (with re-scan)

**Files:**
- Modify: `internal/api/docker_handlers.go`
- Modify: `internal/api/docker_handlers_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestDockerAPI_CreateTag_Returns201(t *testing.T) {
	// POST /api/v1/docker/repositories/{id}/tags
	// Body: {"tag": "v1.0", "manifest_digest": "sha256:abc123"}
	// → 201 Created
}

func TestDockerAPI_MoveTag_TriggersRescan(t *testing.T) {
	// POST with existing tag but new digest → should trigger re-scan
	// Audit log entry for tag movement
}
```

- [ ] **Step 2: Implement handler**

```go
// POST /api/v1/docker/repositories/{id}/tags
func (s *Server) handleCreateDockerTag(w http.ResponseWriter, r *http.Request) {
	// 1. Parse request body
	// 2. Upsert tag
	// 3. If tag moved (different digest), trigger re-scan
	// 4. Write audit log
	// 5. Return 201
}
```

- [ ] **Step 3: Run tests, verify pass**
- [ ] **Step 4: Commit**

```bash
git add internal/api/docker_handlers.go internal/api/docker_handlers_test.go
git commit -m "feat(api): POST /api/v1/docker/repositories/{id}/tags with re-scan"
```

---

### Task 4: API Handler — Delete Tag

**Files:**
- Modify: `internal/api/docker_handlers.go`
- Modify: `internal/api/docker_handlers_test.go`

- [ ] **Step 1: Write test + implement**

```go
// DELETE /api/v1/docker/repositories/{id}/tags/{tag}
// → 204 No Content (artifact NOT deleted, only tag mapping)
```

- [ ] **Step 2: Run tests, verify pass**
- [ ] **Step 3: Commit**

```bash
git add internal/api/docker_handlers.go internal/api/docker_handlers_test.go
git commit -m "feat(api): DELETE /api/v1/docker/repositories/{id}/tags/{tag}"
```

---

### Task 5: API Handler — Manual Sync Trigger

**Files:**
- Modify: `internal/api/docker_handlers.go`
- Modify: `internal/api/docker_handlers_test.go`

- [ ] **Step 1: Write test + implement**

```go
// POST /api/v1/docker/sync/{id}
// → 202 Accepted (sync queued)
```

The handler triggers `SyncService.SyncRepository` in a goroutine.

- [ ] **Step 2: Run tests, verify pass**
- [ ] **Step 3: Commit**

```bash
git add internal/api/docker_handlers.go internal/api/docker_handlers_test.go
git commit -m "feat(api): POST /api/v1/docker/sync/{id} manual trigger"
```

---

### Task 6: API Handler — List Allowed Registries

**Files:**
- Modify: `internal/api/docker_handlers.go`

- [ ] **Step 1: Write test + implement**

```go
// GET /api/v1/docker/registries → returns allowed_registries from config
```

- [ ] **Step 2: Run tests, verify pass**
- [ ] **Step 3: Commit**

```bash
git add internal/api/docker_handlers.go internal/api/docker_handlers_test.go
git commit -m "feat(api): GET /api/v1/docker/registries endpoint"
```

---

### Task 7: Documentation + Final Verification

- [ ] **Step 1: Update API docs / OpenAPI spec**

Update `docs/api/openapi.yaml` with new endpoints.

- [ ] **Step 2: Run full test suite**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./... -count=1 -race`

- [ ] **Step 3: Build + lint**

Run: `cd /Users/valda/src/projects/shieldoo-gate && make build && make lint`

- [ ] **Step 4: Commit**

```bash
git add docs/
git commit -m "docs(api): document Docker management API endpoints"
```
