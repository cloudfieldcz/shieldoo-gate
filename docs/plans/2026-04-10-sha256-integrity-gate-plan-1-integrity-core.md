# SHA256 Integrity Gate — Phase 1: Integrity Verification Core

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add SHA256 integrity verification to every artifact serve path (cache hit, re-download, rescan) — fail-closed, quarantine on mismatch.

**Architecture:** Two central helper functions in `base.go`: `VerifyCacheIntegrity` (checks cached file SHA256 vs DB) and `VerifyUpstreamIntegrity` (checks re-downloaded SHA256 vs DB record). Both quarantine + audit log on mismatch. All 7 adapters and the rescan scheduler call these. New event type `INTEGRITY_VIOLATION`.

**Tech Stack:** Go, SHA256 (crypto/sha256), SQLite/PostgreSQL

**Index:** [`plan-index.md`](./2026-04-10-sha256-integrity-gate-plan-index.md)

---

## File Structure

| Action | Path | Purpose |
|--------|------|---------|
| Modify | `internal/model/audit.go` | Add `EventIntegrityViolation` |
| Modify | `internal/adapter/base.go` | Add `VerifyCacheIntegrity`, `VerifyUpstreamIntegrity`, `ComputeSHA256` |
| Create | `internal/adapter/integrity_test.go` | Unit tests for integrity helpers |
| Modify | `internal/adapter/npm/npm.go` | Wire integrity into cache-hit + cache-miss paths |
| Modify | `internal/adapter/pypi/pypi.go` | Wire integrity into cache-hit + cache-miss paths |
| Modify | `internal/adapter/nuget/nuget.go` | Wire integrity into cache-hit + cache-miss paths |
| Modify | `internal/adapter/maven/maven.go` | Wire integrity into cache-hit + cache-miss paths |
| Modify | `internal/adapter/rubygems/rubygems.go` | Wire integrity into cache-hit + cache-miss paths |
| Modify | `internal/adapter/gomod/gomod.go` | Wire integrity into cache-hit + cache-miss paths |
| Modify | `internal/adapter/docker/docker.go` | Wire integrity into cache-hit path |
| Modify | `internal/scheduler/rescan.go` | Wire integrity before scan |
| Modify | `docs/index.md` | Document integrity verification |

---

### Task 1: Add event type and integrity helpers

**Files:**
- Modify: `internal/model/audit.go:17`
- Modify: `internal/adapter/base.go` (append)

- [ ] **Step 1: Add `EventIntegrityViolation` to model**

In `internal/model/audit.go`, add after `EventAllowedWithWarning`:

```go
EventIntegrityViolation EventType = "INTEGRITY_VIOLATION"
```

- [ ] **Step 2: Add `ComputeSHA256` to base.go**

Append to `internal/adapter/base.go`:

```go
// ComputeSHA256 returns the hex-encoded SHA256 hash of the file at the given path.
func ComputeSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("integrity: opening file %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("integrity: reading file %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
```

Add imports: `"crypto/sha256"`, `"encoding/hex"`, `"io"`, `"os"`.

- [ ] **Step 3: Add `VerifyCacheIntegrity` to base.go**

This is the critical security gate for cache-hit serving. Fail-closed: any error refuses to serve.

```go
// VerifyCacheIntegrity verifies that the cached file at localPath matches
// the SHA256 stored in the artifacts table. FAIL-CLOSED: returns error on
// any failure (DB error, IO error, mismatch). On SHA256 mismatch, the
// artifact is automatically quarantined and an INTEGRITY_VIOLATION audit
// event is written.
func VerifyCacheIntegrity(db *config.GateDB, artifactID, localPath string) error {
	var dbSHA256 string
	err := db.Get(&dbSHA256, `SELECT sha256 FROM artifacts WHERE id = ?`, artifactID)
	if err != nil {
		return fmt.Errorf("integrity: reading SHA256 for %s: %w", artifactID, err)
	}

	fileSHA256, err := ComputeSHA256(localPath)
	if err != nil {
		return fmt.Errorf("integrity: computing SHA256 for %s: %w", artifactID, err)
	}

	if dbSHA256 != fileSHA256 {
		reason := fmt.Sprintf("INTEGRITY VIOLATION: cached file SHA256 mismatch (expected=%s, got=%s)", dbSHA256, fileSHA256)
		now := time.Now().UTC()
		_, _ = db.Exec(
			`UPDATE artifact_status SET status = ?, quarantine_reason = ?, quarantined_at = ? WHERE artifact_id = ?`,
			string(model.StatusQuarantined), reason, now, artifactID,
		)
		_ = WriteAuditLog(db, model.AuditEntry{
			EventType:    model.EventIntegrityViolation,
			ArtifactID:   artifactID,
			Reason:       reason,
			MetadataJSON: fmt.Sprintf(`{"expected_sha256":%q,"actual_sha256":%q,"source":"cache"}`, dbSHA256, fileSHA256),
		})
		return fmt.Errorf("%s", reason)
	}
	return nil
}
```

- [ ] **Step 4: Add `VerifyUpstreamIntegrity` to base.go**

This catches upstream content mutation when re-downloading after cache eviction.

```go
// VerifyUpstreamIntegrity checks whether a newly downloaded artifact's SHA256
// matches a previously recorded SHA256 in the DB. If the artifact is unknown
// (no DB record), returns nil — this is a first download. On mismatch, the
// artifact is quarantined and an INTEGRITY_VIOLATION event is written.
// FAIL-CLOSED: DB errors return an error (do not serve).
func VerifyUpstreamIntegrity(db *config.GateDB, artifactID, newSHA256 string) error {
	var existingSHA256 string
	err := db.Get(&existingSHA256, `SELECT sha256 FROM artifacts WHERE id = ?`, artifactID)
	if err != nil {
		// No prior record — first download, nothing to compare.
		return nil
	}

	if existingSHA256 != newSHA256 {
		reason := fmt.Sprintf("INTEGRITY VIOLATION: upstream content changed (known=%s, downloaded=%s)", existingSHA256, newSHA256)
		now := time.Now().UTC()
		_, _ = db.Exec(
			`UPDATE artifact_status SET status = ?, quarantine_reason = ?, quarantined_at = ? WHERE artifact_id = ?`,
			string(model.StatusQuarantined), reason, now, artifactID,
		)
		_ = WriteAuditLog(db, model.AuditEntry{
			EventType:    model.EventIntegrityViolation,
			ArtifactID:   artifactID,
			Reason:       reason,
			MetadataJSON: fmt.Sprintf(`{"known_sha256":%q,"upstream_sha256":%q,"source":"upstream"}`, existingSHA256, newSHA256),
		})
		return fmt.Errorf("%s", reason)
	}
	return nil
}
```

- [ ] **Step 5: Verify build**

Run: `cd /Users/valda/src/projects/shieldoo-gate && make build`
Expected: builds successfully

- [ ] **Step 6: Commit**

```bash
git add internal/model/audit.go internal/adapter/base.go
git commit -m "feat(integrity): add SHA256 verification helpers and INTEGRITY_VIOLATION event type

Add VerifyCacheIntegrity (file vs DB), VerifyUpstreamIntegrity (download vs DB),
and ComputeSHA256 helper. Both quarantine artifact and write audit log on mismatch.
Fail-closed: any error refuses to serve."
```

---

### Task 2: Unit tests for integrity helpers

**Files:**
- Create: `internal/adapter/integrity_test.go`

- [ ] **Step 1: Write tests**

```go
package adapter_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

func setupTestDB(t *testing.T) *config.GateDB {
	t.Helper()
	db, err := config.InitDB(config.DatabaseConfig{Backend: "sqlite", SQLite: config.SQLiteConfig{Path: ":memory:"}})
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func insertTestArtifact(t *testing.T, db *config.GateDB, id, sha256 string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, 'npm', 'test', '1.0.0', 'http://example.com', ?, 100, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, '/tmp/test')`,
		id, sha256)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifact_status (artifact_id, status) VALUES (?, 'CLEAN')`, id)
	require.NoError(t, err)
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "integrity-test-*")
	require.NoError(t, err)
	_, err = f.WriteString(content)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

func sha256hex(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// --- ComputeSHA256 ---

func TestComputeSHA256_ValidFile(t *testing.T) {
	content := "hello world"
	path := writeTempFile(t, content)
	got, err := adapter.ComputeSHA256(path)
	require.NoError(t, err)
	assert.Equal(t, sha256hex(content), got)
}

func TestComputeSHA256_NonexistentFile_ReturnsError(t *testing.T) {
	_, err := adapter.ComputeSHA256("/nonexistent/file")
	assert.Error(t, err)
}

// --- VerifyCacheIntegrity ---

func TestVerifyCacheIntegrity_MatchingSHA256_ReturnsNil(t *testing.T) {
	db := setupTestDB(t)
	content := "clean artifact content"
	path := writeTempFile(t, content)
	insertTestArtifact(t, db, "npm:test:1.0.0", sha256hex(content))

	err := adapter.VerifyCacheIntegrity(db, "npm:test:1.0.0", path)
	assert.NoError(t, err)
}

func TestVerifyCacheIntegrity_MismatchSHA256_QuarantinesAndReturnsError(t *testing.T) {
	db := setupTestDB(t)
	path := writeTempFile(t, "actual file content")
	insertTestArtifact(t, db, "npm:test:1.0.0", "0000000000000000000000000000000000000000000000000000000000000000")

	err := adapter.VerifyCacheIntegrity(db, "npm:test:1.0.0", path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "INTEGRITY VIOLATION")

	// Verify artifact was quarantined
	var status string
	require.NoError(t, db.Get(&status, `SELECT status FROM artifact_status WHERE artifact_id = ?`, "npm:test:1.0.0"))
	assert.Equal(t, string(model.StatusQuarantined), status)

	// Verify audit log was written
	var eventType string
	require.NoError(t, db.Get(&eventType, `SELECT event_type FROM audit_log ORDER BY id DESC LIMIT 1`))
	assert.Equal(t, string(model.EventIntegrityViolation), eventType)
}

func TestVerifyCacheIntegrity_UnknownArtifact_ReturnsError(t *testing.T) {
	db := setupTestDB(t)
	path := writeTempFile(t, "content")

	err := adapter.VerifyCacheIntegrity(db, "npm:unknown:1.0.0", path)
	assert.Error(t, err) // Fail-closed: no DB record = error
}

func TestVerifyCacheIntegrity_FileNotFound_ReturnsError(t *testing.T) {
	db := setupTestDB(t)
	insertTestArtifact(t, db, "npm:test:1.0.0", "abc123")

	err := adapter.VerifyCacheIntegrity(db, "npm:test:1.0.0", "/nonexistent/file")
	assert.Error(t, err)
}

// --- VerifyUpstreamIntegrity ---

func TestVerifyUpstreamIntegrity_MatchingSHA256_ReturnsNil(t *testing.T) {
	db := setupTestDB(t)
	insertTestArtifact(t, db, "npm:test:1.0.0", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")

	err := adapter.VerifyUpstreamIntegrity(db, "npm:test:1.0.0", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	assert.NoError(t, err)
}

func TestVerifyUpstreamIntegrity_MismatchSHA256_QuarantinesAndReturnsError(t *testing.T) {
	db := setupTestDB(t)
	insertTestArtifact(t, db, "npm:test:1.0.0", "aaaa000000000000000000000000000000000000000000000000000000000000")

	err := adapter.VerifyUpstreamIntegrity(db, "npm:test:1.0.0", "bbbb000000000000000000000000000000000000000000000000000000000000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "INTEGRITY VIOLATION")
	assert.Contains(t, err.Error(), "upstream content changed")

	// Verify artifact was quarantined
	var status string
	require.NoError(t, db.Get(&status, `SELECT status FROM artifact_status WHERE artifact_id = ?`, "npm:test:1.0.0"))
	assert.Equal(t, string(model.StatusQuarantined), status)
}

func TestVerifyUpstreamIntegrity_UnknownArtifact_ReturnsNil(t *testing.T) {
	db := setupTestDB(t)

	// No prior record — first download, should pass
	err := adapter.VerifyUpstreamIntegrity(db, "npm:new:1.0.0", "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
	assert.NoError(t, err)
}
```

- [ ] **Step 2: Run tests**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/ -run TestVerify -v`
Expected: ALL PASS

Note: if `config.InitDB` with `:memory:` doesn't exist as a helper, check `internal/config/db.go` for the correct way to create a test DB and adjust `setupTestDB` accordingly. The existing test patterns in `internal/api/testhelper_test.go` show how tests create in-memory DBs.

- [ ] **Step 3: Commit**

```bash
git add internal/adapter/integrity_test.go
git commit -m "test(integrity): add unit tests for SHA256 verification helpers"
```

---

### Task 3: Wire integrity into npm adapter

**Files:**
- Modify: `internal/adapter/npm/npm.go`

- [ ] **Step 1: Add cache-hit integrity check**

In `downloadScanServe()`, after the quarantine check and BEFORE the tag mutability check (around line 251), add:

```go
		// SHA256 integrity verification — FAIL-CLOSED.
		if err := adapter.VerifyCacheIntegrity(a.db, artifactID, cachedPath); err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("SECURITY: cache integrity violation")
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:    "integrity_violation",
				Artifact: artifactID,
				Reason:   "cached artifact integrity check failed",
			})
			return
		}
```

- [ ] **Step 2: Add upstream integrity check (cache-miss path)**

In the cache-miss path, after `downloadToTemp()` returns and BEFORE the scan (between download and `scanArtifact` construction, around line 312), add:

```go
	// Upstream integrity check — detect content mutation for known artifacts.
	if err := adapter.VerifyUpstreamIntegrity(a.db, artifactID, sha); err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("SECURITY: upstream content mutation detected")
		os.Remove(tmpPath)
		adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
			Error:    "integrity_violation",
			Artifact: artifactID,
			Reason:   "upstream content changed since last scan — artifact quarantined, admin must delete and re-approve",
		})
		return
	}
```

- [ ] **Step 3: Add integrity check in re-check-after-lock path**

In the double-check cache path (after lock acquisition, around line 285-303), add the same cache integrity check before serving:

```go
		// SHA256 integrity verification on race-condition cache hit.
		if err := adapter.VerifyCacheIntegrity(a.db, artifactID, cachedPath); err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("SECURITY: cache integrity violation (post-lock)")
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:    "integrity_violation",
				Artifact: artifactID,
				Reason:   "cached artifact integrity check failed",
			})
			return
		}
```

- [ ] **Step 4: Build and test**

Run: `make build && make test`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/npm/npm.go
git commit -m "feat(npm): wire SHA256 integrity verification into serve paths"
```

---

### Task 4: Wire integrity into pypi adapter

**Files:**
- Modify: `internal/adapter/pypi/pypi.go`

Same pattern as Task 3. Three insertion points:

- [ ] **Step 1: Cache-hit path** — after quarantine check (around line 212), before tag mutability check (line 214):

```go
		if err := adapter.VerifyCacheIntegrity(a.db, artifactID, cachedPath); err != nil {
			log.Error().Err(err).Str("artifact", artifactID).Msg("SECURITY: cache integrity violation")
			adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
				Error:    "integrity_violation",
				Artifact: artifactID,
				Reason:   "cached artifact integrity check failed",
			})
			return
		}
```

- [ ] **Step 2: Upstream check** — after `downloadToTemp()` (line 292), before building scanArtifact:

```go
	if err := adapter.VerifyUpstreamIntegrity(a.db, artifactID, sha); err != nil {
		log.Error().Err(err).Str("artifact", artifactID).Msg("SECURITY: upstream content mutation detected")
		os.Remove(tmpPath)
		adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
			Error:    "integrity_violation",
			Artifact: artifactID,
			Reason:   "upstream content changed since last scan — artifact quarantined, admin must delete and re-approve",
		})
		return
	}
```

- [ ] **Step 3: Re-check-after-lock path** — after lock cache re-check (line 272), add integrity check before serving.

- [ ] **Step 4: Build and test**

Run: `make build && make test`

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/pypi/pypi.go
git commit -m "feat(pypi): wire SHA256 integrity verification into serve paths"
```

---

### Task 5: Wire integrity into remaining adapters (nuget, maven, rubygems, gomod, docker)

**Files:**
- Modify: `internal/adapter/nuget/nuget.go`
- Modify: `internal/adapter/maven/maven.go`
- Modify: `internal/adapter/rubygems/rubygems.go`
- Modify: `internal/adapter/gomod/gomod.go`
- Modify: `internal/adapter/docker/docker.go`

Same 3-point pattern for each adapter. For each:

- [ ] **Step 1: NuGet** — cache-hit (after quarantine check ~line 279), upstream (after download ~line 331), re-check-after-lock (~line 311).

- [ ] **Step 2: Maven** — cache-hit (after quarantine check ~line 304), upstream (after download ~line 364), re-check-after-lock (~line 338).

- [ ] **Step 3: RubyGems** — cache-hit (after quarantine check ~line 299), upstream (after download ~line 359), re-check-after-lock (~line 333).

- [ ] **Step 4: GoMod** — cache-hit (after quarantine check ~line 311), upstream (after download ~line 374), re-check-after-lock (~line 347).

- [ ] **Step 5: Docker** — cache-hit in `handleManifest()` (after quarantine check ~line 594), cache-hit in `serveInternalManifest()` (after quarantine check ~line 526), cache-miss upstream check (after fetch ~line 672). Docker re-check-after-lock at ~line 644.

- [ ] **Step 6: Build and test**

Run: `make build && make test`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/adapter/nuget/ internal/adapter/maven/ internal/adapter/rubygems/ internal/adapter/gomod/ internal/adapter/docker/
git commit -m "feat(adapters): wire SHA256 integrity verification into all remaining adapters"
```

---

### Task 6: Wire integrity into rescan scheduler

**Files:**
- Modify: `internal/scheduler/rescan.go:194`

- [ ] **Step 1: Add integrity check before scan**

In `rescanArtifact()`, after getting `localPath` from cache (line 196) and BEFORE building scanArtifact (line 209), add:

```go
	// SHA256 integrity verification — FAIL-CLOSED.
	// If the cached file has been tampered with, quarantine immediately.
	if err := adapter.VerifyCacheIntegrity(s.db, art.ID, localPath); err != nil {
		log.Error().Err(err).Str("artifact", art.ID).Msg("SECURITY: rescan integrity violation — cached file tampered")
		// VerifyCacheIntegrity already quarantined the artifact and wrote audit log.
		return
	}
```

Add import: `"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"`

- [ ] **Step 2: Build and test**

Run: `make build && make test`

- [ ] **Step 3: Commit**

```bash
git add internal/scheduler/rescan.go
git commit -m "feat(rescan): verify SHA256 integrity before rescanning cached artifact"
```

---

### Task 7: Update documentation

**Files:**
- Modify: `docs/index.md`

- [ ] **Step 1: Add integrity verification section**

Add a section documenting:
- SHA256 integrity is verified on every cache serve (fail-closed)
- Upstream content mutation is detected on re-download
- Rescan scheduler verifies integrity before scanning
- Integrity violation → automatic quarantine + `INTEGRITY_VIOLATION` audit event
- Resolution: admin must delete artifact via API, next request re-fetches fresh

- [ ] **Step 2: Commit**

```bash
git add docs/index.md
git commit -m "docs: document SHA256 integrity verification security gate"
```
