# Version-Diff AI Rebuild — Phase 9: Retention + cleanup

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cap unbounded growth of `version_diff_results` by adding a retention task that deletes CLEAN rows older than 90 days. Add a `scanner_version` column (migration 025) so future UI can distinguish v1.x heuristic rows from v2.0+ AI rows. Optionally seed it for new rows in [`internal/scanner/versiondiff/scanner.go`](../../internal/scanner/versiondiff/scanner.go) (defaults to `'2.0.0'` for new inserts).

**Architecture:** A retention helper in `internal/scheduler/version_diff_retention.go` (or a small file under `internal/api/` — wherever the existing rescan scheduler lives). The repo currently has [`internal/scheduler/rescan.go`](../../internal/scheduler/rescan.go) — we put our cleanup ticker there to follow the same pattern. The 90-day SUSPICIOUS retention is intentionally **not** auto-deleted — those rows are evidence and stay forever (until manually pruned).

**Tech Stack:** Go (existing scheduler patterns), one new migration file (postgres + sqlite parity).

**Index:** [`plan-index.md`](./2026-04-30-version-diff-ai-rebuild-plan-index.md)

---

## Context for executor

The repo already has a scheduler package ([`internal/scheduler/`](../../internal/scheduler/)) used by the rescan job. We add a sibling retention loop. It runs daily, deletes rows where `verdict='CLEAN'` AND `diff_at < now() - 90 days`, and logs the deletion count.

Migration 025 adds the `scanner_version` column — small enough to ship as a separate file rather than coupling to migration 024 (which already does a lot of work). Old heuristic rows have `scanner_version = NULL`; new rows from the AI scanner write `'2.0.0'`. UI filtering can then `WHERE scanner_version >= '2'`.

---

### Task 1: Migration 025 — `scanner_version` column

**Files:**
- Create: `internal/config/migrations/postgres/025_version_diff_scanner_version.sql`
- Create: `internal/config/migrations/sqlite/025_version_diff_scanner_version.sql`

- [ ] **Step 1: Write the Postgres migration**

Create [internal/config/migrations/postgres/025_version_diff_scanner_version.sql](../../internal/config/migrations/postgres/025_version_diff_scanner_version.sql):

```sql
-- Migration 025: tag rows with the version of the version-diff scanner that
-- produced them. Old heuristic rows remain NULL; v2.0+ rows write '2.0.0'.
-- Also adds a (verdict, diff_at) index used by the retention DELETE query.
ALTER TABLE version_diff_results
    ADD COLUMN scanner_version TEXT;

CREATE INDEX IF NOT EXISTS idx_version_diff_scanner_version
    ON version_diff_results(scanner_version);

-- Used by RunVersionDiffRetention: DELETE WHERE verdict='CLEAN' AND diff_at < ?
CREATE INDEX IF NOT EXISTS idx_version_diff_verdict_diff_at
    ON version_diff_results(verdict, diff_at);
```

- [ ] **Step 2: Write the SQLite migration**

Create [internal/config/migrations/sqlite/025_version_diff_scanner_version.sql](../../internal/config/migrations/sqlite/025_version_diff_scanner_version.sql):

```sql
ALTER TABLE version_diff_results
    ADD COLUMN scanner_version TEXT;

CREATE INDEX IF NOT EXISTS idx_version_diff_scanner_version
    ON version_diff_results(scanner_version);

CREATE INDEX IF NOT EXISTS idx_version_diff_verdict_diff_at
    ON version_diff_results(verdict, diff_at);
```

- [ ] **Step 3: Add a Go test**

Append to [internal/config/migration_024_test.go](../../internal/config/migration_024_test.go) (or a new `migration_025_test.go`):

```go
func TestMigration025_AddsScannerVersionColumn(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	type col struct {
		Name string `db:"name"`
	}
	var cols []col
	require.NoError(t, db.Select(&cols, "PRAGMA table_info(version_diff_results)"))
	found := false
	for _, c := range cols {
		if c.Name == "scanner_version" {
			found = true
			break
		}
	}
	require.True(t, found, "scanner_version column missing")
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/config/ -v -run "TestMigration02[45]"
```

Expected: PASS.

(No commit yet.)

---

### Task 2: Persist `scanner_version` in new rows

**Files:**
- Modify: [internal/scanner/versiondiff/scanner.go](../../internal/scanner/versiondiff/scanner.go) (the `persistRow` helper from Phase 6b)

- [ ] **Step 1: Update the INSERT to include `scanner_version`**

In [internal/scanner/versiondiff/scanner.go](../../internal/scanner/versiondiff/scanner.go), modify `persistRow` to add the column. Update the `INSERT INTO version_diff_results (...)` and `VALUES (...)` clauses:

```go
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO version_diff_results
		 (artifact_id, previous_artifact, diff_at,
		  files_added, files_modified, files_removed,
		  size_ratio, max_entropy_delta,
		  verdict, findings_json,
		  ai_verdict, ai_confidence, ai_explanation, ai_model_used, ai_prompt_version,
		  ai_tokens_used, previous_version, scanner_version)
		 VALUES (?, ?, ?,
		         ?, ?, ?,
		         NULL, NULL,
		         ?, '[]',
		         ?, ?, ?, ?, ?,
		         ?, ?, ?)
		 ON CONFLICT (artifact_id, previous_artifact, ai_model_used, ai_prompt_version) DO NOTHING`,
		artifact.ID, prevID, time.Now().UTC(),
		resp.FilesAdded, resp.FilesModified, resp.FilesRemoved,
		string(mp.finalVerdict),
		strings.ToUpper(resp.Verdict), resp.Confidence, truncate(resp.Explanation, 500),
		model, prompt,
		resp.TokensUsed, prevVersion, scannerVersion,
	)
```

The constant `scannerVersion = "2.0.0"` is already defined at the top of the file.

- [ ] **Step 2: Add a test that verifies the column is populated**

Append to [internal/scanner/versiondiff/scanner_test.go](../../internal/scanner/versiondiff/scanner_test.go):

```go
func TestScan_PersistsScannerVersionColumn(t *testing.T) {
	prevContent := []byte("p")
	prevSHA := sha256Hex(prevContent)
	mb := &mockBridge{
		scanFn: func(_ context.Context, _ *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
			return &pb.DiffScanResponse{Verdict: "CLEAN", Confidence: 0.6, ModelUsed: "gpt-5.4-mini"}, nil
		},
	}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:sv:0.9": prevContent})
	seedArtifactPair(t, db, "pypi", "sv",
		"pypi:sv:1.0", "1.0", "n",
		"pypi:sv:0.9", "0.9", prevSHA, true)

	s, _ := NewVersionDiffScanner(db, cs, defaultCfg(sock))
	defer s.Close()
	_, _ = s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:sv:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "sv", Version: "1.0", SHA256: "n",
	})

	var got string
	require.NoError(t, db.Get(&got,
		"SELECT scanner_version FROM version_diff_results WHERE artifact_id = ?", "pypi:sv:1.0"))
	assert.Equal(t, "2.0.0", got)
}
```

- [ ] **Step 3: Run**

```bash
go test ./internal/scanner/versiondiff/ -v -run TestScan_PersistsScannerVersionColumn
make test
```

Expected: PASS.

(No commit yet.)

---

### Task 3: Retention cleanup task

**Files:**
- Create: `internal/scheduler/version_diff_retention.go`
- Create: `internal/scheduler/version_diff_retention_test.go`

The existing scheduler in [internal/scheduler/rescan.go](../../internal/scheduler/rescan.go) shows the in-package idiom (a `Run(ctx context.Context)` function or a struct with a `Start` method). Match whichever pattern is in use.

- [ ] **Step 1: Match the existing struct-based scheduler pattern**

The existing [internal/scheduler/rescan.go](../../internal/scheduler/rescan.go)
uses a struct (`RescanScheduler`) with `New…(...)` + `Start()` + `Stop()` +
internal `run(ctx)`. The retention task follows the same shape.

- [ ] **Step 2: Write the retention scheduler**

Create [internal/scheduler/version_diff_retention.go](../../internal/scheduler/version_diff_retention.go):

```go
package scheduler

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

// VersionDiffRetentionDays is the maximum age (days) for CLEAN rows in
// version_diff_results. SUSPICIOUS+ rows are preserved indefinitely as audit
// evidence. Hard-coded for now; can be config-driven later if needed.
const VersionDiffRetentionDays = 90

// VersionDiffRetentionScheduler runs a daily DELETE of CLEAN rows older than
// VersionDiffRetentionDays. Mirrors the RescanScheduler shape.
type VersionDiffRetentionScheduler struct {
	db     *config.GateDB
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewVersionDiffRetentionScheduler returns a scheduler ready to Start.
func NewVersionDiffRetentionScheduler(db *config.GateDB) *VersionDiffRetentionScheduler {
	return &VersionDiffRetentionScheduler{db: db}
}

// Start launches the background goroutine: an immediate run, then every 24 h.
func (s *VersionDiffRetentionScheduler) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.runOnce(ctx)
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.runOnce(ctx)
			}
		}
	}()
	log.Info().
		Int("retention_days", VersionDiffRetentionDays).
		Msg("version-diff retention scheduler started")
}

// Stop cancels the background goroutine and waits for it to exit.
func (s *VersionDiffRetentionScheduler) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.wg.Wait()
}

// runOnce executes a single retention pass. Public so tests can drive it directly.
func (s *VersionDiffRetentionScheduler) runOnce(ctx context.Context) {
	cutoff := time.Now().UTC().Add(-VersionDiffRetentionDays * 24 * time.Hour)
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM version_diff_results
		  WHERE verdict = 'CLEAN' AND diff_at < ?`,
		cutoff,
	)
	if err != nil {
		log.Warn().Err(err).Msg("version-diff retention: delete failed")
		return
	}
	rows, _ := res.RowsAffected()
	log.Info().Int64("rows_deleted", rows).Time("cutoff", cutoff).
		Msg("version-diff retention: pruned CLEAN rows")
}
```

- [ ] **Step 3: Write the test**

Create [internal/scheduler/version_diff_retention_test.go](../../internal/scheduler/version_diff_retention_test.go):

```go
package scheduler

import (
	"context"
	"strconv"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/stretchr/testify/require"
)

func TestVersionDiffRetention_DeletesOldClean_KeepsSuspiciousAndRecent(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	// Seed minimal artifacts to satisfy FK.
	_, err = db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, 'pypi', 'foo', '1.0', '', '', 0, datetime('now'), datetime('now'), '')`,
		"art-new",
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, 'pypi', 'foo', '0.9', '', '', 0, datetime('now', '-200 days'), datetime('now', '-200 days'), '')`,
		"art-old",
	)
	require.NoError(t, err)

	// 1 row CLEAN + ancient (deletes), 1 SUSPICIOUS + ancient (kept), 1 CLEAN + recent (kept).
	insert := func(verdict string, daysAgo int) {
		_, err := db.Exec(
			`INSERT INTO version_diff_results
			 (artifact_id, previous_artifact, diff_at, verdict, findings_json,
			  ai_verdict, ai_confidence, ai_model_used, ai_prompt_version, ai_tokens_used)
			 VALUES (?, ?, datetime('now', ?), ?, '[]', ?, 0.5, 'gpt-5.4-mini', 'p' || ?, 100)`,
			"art-new", "art-old", "-"+strconv.Itoa(daysAgo)+" days", verdict, verdict, daysAgo,
		)
		require.NoError(t, err)
	}
	insert("CLEAN", 100)      // ancient CLEAN — should be deleted
	insert("SUSPICIOUS", 200) // ancient SUSPICIOUS — keep
	insert("CLEAN", 30)       // recent CLEAN — keep

	NewVersionDiffRetentionScheduler(db).runOnce(context.Background())

	var n int
	require.NoError(t, db.Get(&n, "SELECT COUNT(*) FROM version_diff_results"))
	require.Equal(t, 2, n, "expected one CLEAN deletion")

	var verdicts []string
	require.NoError(t, db.Select(&verdicts, "SELECT verdict FROM version_diff_results ORDER BY verdict"))
	require.Equal(t, []string{"CLEAN", "SUSPICIOUS"}, verdicts)
}
```

- [ ] **Step 4: Run**

```bash
go test ./internal/scheduler/ -v -run TestRunVersionDiffRetention
```

Expected: PASS.

(No commit yet.)

---

### Task 4: Wire the retention task into `main.go`

**Files:**
- Modify: [cmd/shieldoo-gate/main.go](../../cmd/shieldoo-gate/main.go) (after `scanEngine` init or near where the rescan scheduler starts)

- [ ] **Step 1: Find where rescan starts**

```bash
grep -n "rescan\|RescanScheduler\|StartRescan\|scheduler\." cmd/shieldoo-gate/main.go | head -10
```

Identify the call site where the existing scheduler is started (it should be a `go scheduler.Start...(ctx, ...)` line or similar).

- [ ] **Step 2: Add the retention task next to it**

In `cmd/shieldoo-gate/main.go`, after the rescan scheduler is started and **only if** `cfg.Scanners.VersionDiff.Enabled`, add:

```go
	if cfg.Scanners.VersionDiff.Enabled {
		vdiffRetention := scheduler.NewVersionDiffRetentionScheduler(db)
		vdiffRetention.Start()
		defer vdiffRetention.Stop()
		log.Info().Msg("version-diff retention scheduler started (90-day CLEAN row cleanup)")
	}
```

The `db` variable is already in scope at this point in main.go.

- [ ] **Step 3: Build + lint**

```bash
make build && make lint
```

Expected: clean.

- [ ] **Step 4: Run all tests**

```bash
make test
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/migrations/postgres/025_version_diff_scanner_version.sql \
        internal/config/migrations/sqlite/025_version_diff_scanner_version.sql \
        internal/config/migration_024_test.go \
        internal/scanner/versiondiff/scanner.go \
        internal/scanner/versiondiff/scanner_test.go \
        internal/scheduler/version_diff_retention.go \
        internal/scheduler/version_diff_retention_test.go \
        cmd/shieldoo-gate/main.go
git commit -m "feat(version-diff): scanner_version column, retention index, 90-day CLEAN row cleanup"
```

---

### Task 5: Daily cost circuit breaker — explicit deferral note

The `DailyCostLimitUSD` config field is introduced in Phase 6a but the
hard-stop circuit breaker that auto-disables the scanner on overrun is
deliberately deferred. To avoid operator confusion (a config field that
appears load-bearing but isn't), update [config.example.yaml](../../config.example.yaml)
in this commit:

```yaml
    daily_cost_limit_usd: 5.0   # ADVISORY in v2.0 — current implementation
                                 # records spend in version_diff_results.ai_tokens_used
                                 # but does not auto-disable on exceed. Hard cap will
                                 # arrive in a follow-up. Use Prometheus alerting on
                                 # token-usage queries (see docs/scanners/version-diff.md)
                                 # for now.
```

Same comment in [docs/scanners/version-diff.md](../../docs/scanners/version-diff.md).
Add a follow-up tracker entry (TODO.md or `docs/plans/follow-ups.md`):
"Wire daily_cost_limit_usd hard cap (v2.1)".

---

## Verification — phase-end

```bash
# Migrations applied automatically on next startup
ls internal/config/migrations/postgres/025_version_diff_scanner_version.sql \
   internal/config/migrations/sqlite/025_version_diff_scanner_version.sql

# Tests green
make test

# Retention runs in main.go
grep "StartVersionDiffRetention" cmd/shieldoo-gate/main.go
```

## What this phase ships

- Migration 025 (Postgres + SQLite parity) adding `scanner_version` column.
- Scanner persists `scanner_version = "2.0.0"` on every new row.
- A daily retention task that prunes CLEAN rows older than 90 days while preserving SUSPICIOUS+ rows for audit.
- Unit tests covering the migration, the persistence, and the retention semantics.

## What this phase deliberately does NOT ship

- UI filtering of v1.x vs v2.0 rows (out of scope — separate UI task).
- Configurable retention window (hard-coded 90 days; can be config-driven if operators ask).
- Daily cost circuit breaker (deferred from Phase 6b — could ship here if the executor wants to fold it in).

## Risks during this phase

- **Retention runs at startup** — if a deploy crashes after starting and before the daily ticker fires, the prune still runs once. Acceptable.
- **Concurrent INSERTs during DELETE** — Postgres MVCC handles this without locks. SQLite uses WAL mode so the delete acquires a brief write lock; in our scale (≤ tens of writes/min) the contention is invisible.
- **Schema drift between SUSPICIOUS rows older than 90 days and v2.0+ writes:** retention deliberately keeps SUSPICIOUS rows forever. After multiple model+prompt revisions, you may have SUSPICIOUS rows pinned to legacy `ai_model_used` / `ai_prompt_version` values that no longer match what the bridge is producing. This is intentional — they are audit evidence — but operators querying historical FP rate must filter by `ai_prompt_version` to get apples-to-apples comparisons.
