# SHA256 Integrity Gate — Phase 2: Delete Artifact API + E2E Tests

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add DELETE /api/v1/artifacts/{id} endpoint (purges cache + DB) and comprehensive e2e shell tests for integrity verification.

**Architecture:** New API handler deletes artifact from DB (artifacts, artifact_status, scan_results) and cache in a single transaction + cache.Delete(). E2E tests run in PostgreSQL pass (Run 2) where test-runner can manipulate DB via psql.

**Tech Stack:** Go (chi router), PostgreSQL (psql client in test-runner), shell scripts

**Index:** [`plan-index.md`](./2026-04-10-sha256-integrity-gate-plan-index.md)

---

## File Structure

| Action | Path | Purpose |
|--------|------|---------|
| Modify | `internal/api/artifacts.go` | Add `handleDeleteArtifact` handler |
| Modify | `internal/api/server.go` | Register DELETE route |
| Create | `internal/api/artifacts_delete_test.go` | Unit test for delete handler |
| Modify | `docs/api/openapi.yaml` | Document DELETE endpoint |
| Modify | `tests/e2e-shell/Dockerfile.test-runner` | Add postgresql-client |
| Modify | `tests/e2e-shell/helpers.sh` | Add `db_exec` helper for SQL manipulation |
| Create | `tests/e2e-shell/test_integrity.sh` | E2E integrity tests |
| Modify | `tests/e2e-shell/run_all.sh` | Source test_integrity.sh |

---

### Task 1: DELETE /api/v1/artifacts/{id} endpoint

**Files:**
- Modify: `internal/api/artifacts.go`
- Modify: `internal/api/server.go`

- [ ] **Step 1: Add handler**

Append to `internal/api/artifacts.go`:

```go
// handleDeleteArtifact handles DELETE /api/v1/artifacts/{id}.
// Purges the artifact from cache and DB (artifacts, artifact_status, scan_results).
// This is the only resolution for integrity violations.
func (s *Server) handleDeleteArtifact(w http.ResponseWriter, r *http.Request) {
	id := artifactID(r)

	// 1. Delete from cache first (non-fatal if not found).
	if err := s.cache.Delete(r.Context(), id); err != nil {
		log.Warn().Err(err).Str("artifact", id).Msg("delete: cache delete failed (may already be evicted)")
	}

	// 2. Delete from DB in transaction.
	tx, err := s.db.BeginTxx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin transaction")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	// Check artifact exists.
	var exists int
	if err := tx.QueryRowxContext(r.Context(), `SELECT COUNT(*) FROM artifacts WHERE id = ?`, id).Scan(&exists); err != nil || exists == 0 {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}

	// Delete scan_results, artifact_status, artifacts (in FK order).
	_, _ = tx.ExecContext(r.Context(), `DELETE FROM scan_results WHERE artifact_id = ?`, id)
	_, _ = tx.ExecContext(r.Context(), `DELETE FROM artifact_status WHERE artifact_id = ?`, id)
	_, err = tx.ExecContext(r.Context(), `DELETE FROM artifacts WHERE id = ?`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete artifact")
		return
	}

	// Audit log (inside transaction).
	userEmail := userEmailFromRequest(r)
	_, _ = tx.ExecContext(r.Context(),
		`INSERT INTO audit_log (ts, event_type, artifact_id, reason, user_email)
		 VALUES (?, ?, ?, ?, ?)`,
		time.Now().UTC(), "ARTIFACT_DELETED", id, "admin deletion", userEmail)

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit deletion")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":   "deleted",
		"artifact": id,
	})
}
```

- [ ] **Step 2: Register route in server.go**

In the `Routes()` method, in the artifacts route group, add:

```go
r.Delete("/{id}", s.handleDeleteArtifact)
```

The `{id}` pattern should match the existing GET and POST patterns for artifacts.

- [ ] **Step 3: Verify build**

Run: `make build`

- [ ] **Step 4: Commit**

```bash
git add internal/api/artifacts.go internal/api/server.go
git commit -m "feat(api): add DELETE /api/v1/artifacts/{id} endpoint

Purges artifact from cache and DB (scan_results, artifact_status, artifacts).
This is the only resolution for SHA256 integrity violations."
```

---

### Task 2: Unit test for delete handler

**Files:**
- Create: `internal/api/artifacts_delete_test.go`

- [ ] **Step 1: Write test**

Follow existing test patterns in `internal/api/` (check `testhelper_test.go` for setup).

Test cases:
- Delete existing artifact → 200, DB rows removed, cache.Delete called
- Delete non-existent artifact → 404
- Verify audit log entry written

- [ ] **Step 2: Run tests**

Run: `go test ./internal/api/ -run TestDeleteArtifact -v`

- [ ] **Step 3: Commit**

```bash
git add internal/api/artifacts_delete_test.go
git commit -m "test(api): add unit tests for DELETE artifact endpoint"
```

---

### Task 3: Update OpenAPI spec

**Files:**
- Modify: `docs/api/openapi.yaml`

- [ ] **Step 1: Add DELETE endpoint**

Add under `/api/v1/artifacts/{id}`:

```yaml
    delete:
      summary: Delete artifact
      description: >
        Permanently removes an artifact from cache and database.
        Deletes all associated scan results and status records.
        This is the only resolution for SHA256 integrity violations.
      operationId: deleteArtifact
      tags: [Artifacts]
      parameters:
        - $ref: '#/components/parameters/ArtifactID'
      responses:
        '200':
          description: Artifact deleted
          content:
            application/json:
              schema:
                type: object
                properties:
                  status:
                    type: string
                    example: deleted
                  artifact:
                    type: string
                    example: "npm:lodash:4.17.21"
        '404':
          $ref: '#/components/responses/NotFound'
```

Also add `INTEGRITY_VIOLATION` and `ARTIFACT_DELETED` to the EventType enum if it exists.

- [ ] **Step 2: Commit**

```bash
git add docs/api/openapi.yaml
git commit -m "docs(api): add DELETE /api/v1/artifacts/{id} to OpenAPI spec"
```

---

### Task 4: Add postgresql-client to test-runner + db_exec helper

**Files:**
- Modify: `tests/e2e-shell/Dockerfile.test-runner`
- Modify: `tests/e2e-shell/helpers.sh`

- [ ] **Step 1: Add postgresql-client to Dockerfile**

In the "Base utilities" `apt-get install` block, add `postgresql-client-16` (or `postgresql-client`):

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates=20240203 \
        curl=8.5.0-2ubuntu10.* \
        file=1:5.45-3build1 \
        jq=1.7.1-* \
        postgresql-client \
        unzip=6.0-28ubuntu4.* \
        git=1:2.43.0-1ubuntu7.* \
    && rm -rf /var/lib/apt/lists/*
```

Note: `postgresql-client` (without version pin) is acceptable here since this is a test-only container and the specific version doesn't affect test behavior. Pin if CI requires it.

- [ ] **Step 2: Add db_exec helper to helpers.sh**

Append to `helpers.sh`:

```bash
# ---------------------------------------------------------------------------
# Database access (for integrity e2e tests)
# ---------------------------------------------------------------------------
# db_exec runs SQL against the test database.
# Only works in PostgreSQL passes (Run 2/3). Returns 1 in SQLite passes.
db_exec() {
    local sql="$1"
    if [ "${SGW_DATABASE_BACKEND:-sqlite}" = "postgres" ]; then
        PGPASSWORD=shieldoo_e2e_pass psql -h postgres -U shieldoo -d shieldoo_e2e -tAc "$sql" 2>/dev/null
    else
        return 1
    fi
}

# db_available returns 0 if the test-runner can manipulate the DB directly.
db_available() {
    [ "${SGW_DATABASE_BACKEND:-sqlite}" = "postgres" ] && db_exec "SELECT 1" >/dev/null 2>&1
}
```

- [ ] **Step 3: Pass SGW_DATABASE_BACKEND to test-runner in auth overlay**

In `docker-compose.e2e.auth.yml`, add to test-runner environment:

```yaml
  test-runner:
    environment:
      SGW_DATABASE_BACKEND: "postgres"
```

Do the same in `docker-compose.e2e.azurite.yml`.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e-shell/Dockerfile.test-runner tests/e2e-shell/helpers.sh \
  tests/e2e-shell/docker-compose.e2e.auth.yml tests/e2e-shell/docker-compose.e2e.azurite.yml
git commit -m "chore(e2e): add postgresql-client to test-runner for DB manipulation"
```

---

### Task 5: E2E integrity shell tests

**Files:**
- Create: `tests/e2e-shell/test_integrity.sh`
- Modify: `tests/e2e-shell/run_all.sh`

- [ ] **Step 1: Write test_integrity.sh**

```bash
#!/usr/bin/env bash
# test_integrity.sh — E2E tests for SHA256 integrity verification
#
# These tests require direct database access (PostgreSQL passes only).
# They are automatically skipped in SQLite passes.

# ---------------------------------------------------------------------------
# Scenario 1: Download clean package → tamper SHA256 in DB → re-download → 403
# ---------------------------------------------------------------------------
test_integrity_cache_tamper_npm() {
    if ! db_available; then
        log_skip "integrity_cache_tamper_npm" "requires PostgreSQL (Run 2/3)"
        return
    fi

    local desc="integrity: cache tamper → 403 on re-download (npm)"

    # 1. Install a clean npm package (populates cache + DB).
    local pkg="is-number"
    local ver="7.0.0"
    local tarball_url
    tarball_url="${E2E_NPM_URL}/${pkg}/-/${pkg}-${ver}.tgz"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
    if [ "$http_code" != "200" ]; then
        log_fail "$desc" "initial download failed (HTTP $http_code)"
        return
    fi

    local artifact_id="npm:${pkg}:${ver}"

    # 2. Verify artifact is CLEAN in DB.
    local status
    status=$(db_exec "SELECT status FROM artifact_status WHERE artifact_id = '${artifact_id}'")
    if [ "$status" != "CLEAN" ]; then
        log_fail "$desc" "expected CLEAN status after download, got: $status"
        return
    fi

    # 3. Tamper SHA256 in DB.
    db_exec "UPDATE artifacts SET sha256 = '0000000000000000000000000000000000000000000000000000000000000000' WHERE id = '${artifact_id}'"

    # 4. Re-download — should get 403 (integrity violation).
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
    assert_eq "$http_code" "403" "$desc — re-download after SHA256 tamper"

    # 5. Verify artifact was auto-quarantined.
    status=$(db_exec "SELECT status FROM artifact_status WHERE artifact_id = '${artifact_id}'")
    assert_eq "$status" "QUARANTINED" "$desc — auto-quarantine after integrity violation"

    # 6. Verify INTEGRITY_VIOLATION audit event.
    local event
    event=$(db_exec "SELECT event_type FROM audit_log WHERE artifact_id = '${artifact_id}' ORDER BY id DESC LIMIT 1")
    assert_eq "$event" "INTEGRITY_VIOLATION" "$desc — audit log event"

    # 7. Cleanup: delete artifact so it doesn't affect other tests.
    curl -s -X DELETE "${E2E_CURL_AUTH[@]}" "${E2E_ADMIN_URL}/api/v1/artifacts/${artifact_id}" > /dev/null

    log_pass "$desc"
}

# ---------------------------------------------------------------------------
# Scenario 2: Download → quarantine → override → re-download OK →
#             tamper SHA256 → rescan → verify quarantine
# ---------------------------------------------------------------------------
test_integrity_quarantine_override_rescan() {
    if ! db_available; then
        log_skip "integrity_quarantine_override_rescan" "requires PostgreSQL (Run 2/3)"
        return
    fi

    local desc="integrity: quarantine → override → tamper → rescan → re-quarantine"

    # 1. Download a clean npm package.
    local pkg="is-odd"
    local ver="3.0.1"
    local tarball_url="${E2E_NPM_URL}/${pkg}/-/${pkg}-${ver}.tgz"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
    if [ "$http_code" != "200" ]; then
        log_fail "$desc" "initial download failed (HTTP $http_code)"
        return
    fi

    local artifact_id="npm:${pkg}:${ver}"

    # 2. Quarantine via API.
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" \
        -X POST "${E2E_ADMIN_URL}/api/v1/artifacts/${artifact_id}/quarantine" \
        -H "Content-Type: application/json" \
        -d '{"reason":"integrity e2e test"}')
    assert_eq "$http_code" "200" "$desc — quarantine API"

    # 3. Verify download is blocked (403).
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
    assert_eq "$http_code" "403" "$desc — blocked while quarantined"

    # 4. Release via override API.
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" \
        -X POST "${E2E_ADMIN_URL}/api/v1/artifacts/${artifact_id}/override" \
        -H "Content-Type: application/json" \
        -d '{"reason":"integrity e2e test release"}')
    assert_eq "$http_code" "201" "$desc — override/release API"

    # 5. Verify download works again (200).
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
    assert_eq "$http_code" "200" "$desc — download after release"

    # 6. Tamper SHA256 in DB.
    db_exec "UPDATE artifacts SET sha256 = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' WHERE id = '${artifact_id}'"

    # 7. Trigger rescan.
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" \
        -X POST "${E2E_ADMIN_URL}/api/v1/artifacts/${artifact_id}/rescan")
    assert_eq "$http_code" "202" "$desc — rescan API"

    # 8. Wait for rescan scheduler to process.
    sleep 5

    # 9. Verify artifact is quarantined again (integrity violation during rescan).
    local status
    status=$(db_exec "SELECT status FROM artifact_status WHERE artifact_id = '${artifact_id}'")
    assert_eq "$status" "QUARANTINED" "$desc — re-quarantined after tampered rescan"

    # 10. Verify INTEGRITY_VIOLATION audit event from rescan.
    local event
    event=$(db_exec "SELECT event_type FROM audit_log WHERE artifact_id = '${artifact_id}' AND event_type = 'INTEGRITY_VIOLATION' ORDER BY id DESC LIMIT 1")
    assert_eq "$event" "INTEGRITY_VIOLATION" "$desc — rescan integrity violation audit"

    # 11. Cleanup: delete artifact.
    curl -s -X DELETE "${E2E_CURL_AUTH[@]}" "${E2E_ADMIN_URL}/api/v1/artifacts/${artifact_id}" > /dev/null

    log_pass "$desc"
}

# ---------------------------------------------------------------------------
# Scenario 3: After integrity violation → delete artifact → re-fetch → OK
# ---------------------------------------------------------------------------
test_integrity_delete_and_refetch() {
    if ! db_available; then
        log_skip "integrity_delete_and_refetch" "requires PostgreSQL (Run 2/3)"
        return
    fi

    local desc="integrity: delete after violation → fresh re-fetch succeeds"

    # 1. Download a clean package.
    local pkg="picomatch"
    local ver="4.0.2"
    local tarball_url="${E2E_NPM_URL}/${pkg}/-/${pkg}-${ver}.tgz"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
    if [ "$http_code" != "200" ]; then
        log_fail "$desc" "initial download failed (HTTP $http_code)"
        return
    fi

    local artifact_id="npm:${pkg}:${ver}"

    # 2. Tamper SHA256 → triggers quarantine on next access.
    db_exec "UPDATE artifacts SET sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE id = '${artifact_id}'"

    # 3. Re-download → 403 (integrity violation).
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
    assert_eq "$http_code" "403" "$desc — blocked after tamper"

    # 4. Delete artifact via API.
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" \
        -X DELETE "${E2E_ADMIN_URL}/api/v1/artifacts/${artifact_id}")
    assert_eq "$http_code" "200" "$desc — delete API"

    # 5. Re-fetch — should download fresh from upstream, scan, and serve (200).
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
    assert_eq "$http_code" "200" "$desc — fresh download after delete"

    # 6. Verify artifact is CLEAN again.
    local status
    status=$(db_exec "SELECT status FROM artifact_status WHERE artifact_id = '${artifact_id}'")
    assert_eq "$status" "CLEAN" "$desc — clean after re-fetch"

    log_pass "$desc"
}

# ---------------------------------------------------------------------------
# Run all integrity tests
# ---------------------------------------------------------------------------
test_integrity_cache_tamper_npm
test_integrity_quarantine_override_rescan
test_integrity_delete_and_refetch
```

- [ ] **Step 2: Source test_integrity.sh in run_all.sh**

Add to `run_all.sh` after the other test sources:

```bash
source ./test_integrity.sh
```

- [ ] **Step 3: Run e2e tests**

Run: `make test-e2e-containerized`
Expected: All integrity tests PASS in Run 2/3, SKIP in Run 1

- [ ] **Step 4: Iterate until all pass**

If any test fails, debug and fix. Repeat `make test-e2e-containerized` until green.

- [ ] **Step 5: Commit**

```bash
git add tests/e2e-shell/test_integrity.sh tests/e2e-shell/run_all.sh
git commit -m "test(e2e): add SHA256 integrity verification end-to-end tests

Three scenarios:
1. Cache tamper → 403 on re-download
2. Quarantine → override → tamper → rescan → re-quarantine
3. Delete after violation → fresh re-fetch succeeds"
```
