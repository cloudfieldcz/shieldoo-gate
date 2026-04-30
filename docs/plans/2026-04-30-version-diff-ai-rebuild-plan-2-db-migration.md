# Version-Diff AI Rebuild — Phase 2: DB migration 024 (AI columns + idempotency UNIQUE INDEX)

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add AI-specific columns to `version_diff_results`, relax NOT NULL on legacy heuristic metric columns, deduplicate existing rows, and create the idempotency `UNIQUE INDEX (artifact_id, previous_artifact, ai_model_used, ai_prompt_version)`. Atomic on Postgres (single transaction); recreate-and-copy pattern on SQLite.

**Architecture:** Two new migration files (`024_version_diff_ai_columns.sql`) under [`internal/config/migrations/postgres/`](../../internal/config/migrations/postgres/) and [`internal/config/migrations/sqlite/`](../../internal/config/migrations/sqlite/). Both files are picked up automatically by [`runMigrations`](../../internal/config/db.go#L138) on startup, ordered by filename. Each file is one `db.Exec(sql)` call — multi-statement bodies are supported.

**Tech Stack:** ANSI SQL (subset compatible with both Postgres and SQLite). SQLite recreate-and-copy pattern modeled on [migrations/sqlite/007_audit_user_email.sql](../../internal/config/migrations/sqlite/007_audit_user_email.sql).

> **Important — no explicit `BEGIN;`/`COMMIT;` in migration files.** The migration runner at [internal/config/db.go:139-166](../../internal/config/db.go#L139) calls `db.Exec(sql)` for each migration. None of the existing migrations (verified across `internal/config/migrations/{postgres,sqlite}/00*.sql`) wrap their bodies in explicit `BEGIN`/`COMMIT` — `lib/pq` rejects explicit transaction control inside a multi-statement Exec, and SQLite handles each multi-statement Exec implicitly. We therefore omit `BEGIN`/`COMMIT` and rely on the driver's per-statement implicit-transaction semantics. The atomicity claim still holds for SQLite (the runner runs the whole body in one Exec; statements are processed sequentially within the connection); for Postgres, a partial failure mid-body leaves the schema in a half-applied state that requires manual rollback (acceptable risk for a one-time migration with the operator's pg_dump backup taken in Phase 8a Task 1 Step 2).

**Index:** [`plan-index.md`](./2026-04-30-version-diff-ai-rebuild-plan-index.md)

---

## Context for executor

The current `version_diff_results` table ([016_version_diff_results.sql](../../internal/config/migrations/postgres/016_version_diff_results.sql)) was designed for the heuristic scanner. The rebuild needs:

1. **New AI columns** — `ai_verdict`, `ai_confidence`, `ai_explanation`, `ai_model_used`, `ai_prompt_version`, `ai_tokens_used`, `previous_version`. All nullable so historical rows from the old scanner remain valid.
2. **Drop NOT NULL** on `files_added`, `files_removed`, `files_modified`, `size_ratio`, `max_entropy_delta`. The new flow only populates the first three (from the bridge response counts) and not always — a strict empty-diff shortcut returns CLEAN without populating any of them.
3. **Deduplicate** existing rows on the `(artifact_id, previous_artifact)` pair. The old scanner could create duplicates from re-scans / restarts since no UNIQUE constraint was in place.
4. **`UNIQUE INDEX uq_version_diff_pair`** on `(artifact_id, previous_artifact, ai_model_used, ai_prompt_version)`. This is the idempotency cache key. Rolling out a new model or prompt version invalidates all cache entries automatically (rows have a different model/prompt, so a new INSERT does not collide).

**Why atomic?** A non-atomic migration that creates the UNIQUE INDEX before deduping fails on production data. Production has historical duplicates. The migration must DELETE-then-INDEX in one transaction so a failure rolls everything back.

**Why is `(artifact_id, previous_artifact, NULL, NULL)` not a uniqueness collision risk?** SQL `UNIQUE` treats `NULL` as distinct (each `NULL` is its own value). Multiple legacy rows with `(art, prev, NULL, NULL)` will satisfy the unique index after dedup because we keep only the row with the largest `id` per `(artifact_id, previous_artifact)`. New rows from the AI scanner will have non-NULL `ai_model_used` + `ai_prompt_version`, so they won't collide with the legacy row either.

---

### Task 1: Write Postgres migration `024_version_diff_ai_columns.sql`

**Files:**
- Create: `internal/config/migrations/postgres/024_version_diff_ai_columns.sql`

- [ ] **Step 1: Write the migration**

Create the file with this content:

```sql
-- Migration 024: extend version_diff_results for AI-driven scanner.
-- Adds AI columns, relaxes NOT NULL on legacy heuristic metrics, dedupes existing
-- rows on (artifact_id, previous_artifact), and adds the idempotency UNIQUE INDEX.
-- No explicit BEGIN/COMMIT — the runner calls db.Exec per migration; multi-statement
-- bodies are processed by lib/pq's simple-query protocol. (See plan rationale.)

ALTER TABLE version_diff_results
    ADD COLUMN ai_verdict        TEXT,
    ADD COLUMN ai_confidence     REAL,
    ADD COLUMN ai_explanation    TEXT,
    ADD COLUMN ai_model_used     TEXT,
    ADD COLUMN ai_prompt_version TEXT,
    ADD COLUMN ai_tokens_used    INTEGER,
    ADD COLUMN previous_version  TEXT;

ALTER TABLE version_diff_results ALTER COLUMN size_ratio        DROP NOT NULL;
ALTER TABLE version_diff_results ALTER COLUMN max_entropy_delta DROP NOT NULL;
ALTER TABLE version_diff_results ALTER COLUMN files_added       DROP NOT NULL;
ALTER TABLE version_diff_results ALTER COLUMN files_modified    DROP NOT NULL;
ALTER TABLE version_diff_results ALTER COLUMN files_removed     DROP NOT NULL;

-- Deduplicate: keep the row with the largest id per (artifact_id, previous_artifact).
DELETE FROM version_diff_results
 WHERE id NOT IN (
   SELECT MAX(id) FROM version_diff_results
    GROUP BY artifact_id, previous_artifact
 );

-- Idempotency key. Uses the AI columns so a model or prompt change invalidates cache.
-- Note on NULL semantics: legacy v1.x rows have ai_model_used=NULL and ai_prompt_version=NULL.
-- SQL UNIQUE treats NULL as distinct, so the legacy row coexists with v2.0 rows that have
-- non-NULL values for both columns. New v2.0 rows ALWAYS persist non-NULL ai_model_used
-- (the model name) and non-empty ai_prompt_version (SHA[:12] of the bridge's system prompt
-- — see plan-6b lookupCache for how this is read back via DiffScanResponse.prompt_version).
CREATE UNIQUE INDEX IF NOT EXISTS uq_version_diff_pair
    ON version_diff_results(artifact_id, previous_artifact, ai_model_used, ai_prompt_version);
```

- [ ] **Step 2: Apply the migration to a fresh local Postgres**

If you don't have a local Postgres running, skip to Task 3 (SQLite gives equivalent confidence). If you do, spin up the docker-compose stack:

```bash
docker compose -f docker/docker-compose.yml up -d postgres
sleep 5
docker exec -i $(docker ps -qf name=postgres) psql -U shieldoo -d shieldoo < internal/config/migrations/postgres/016_version_diff_results.sql
docker exec -i $(docker ps -qf name=postgres) psql -U shieldoo -d shieldoo < internal/config/migrations/postgres/024_version_diff_ai_columns.sql
```

Expected: no errors. (If the table doesn't exist yet because you skipped 001-015, that's fine — re-run via `make build && ./bin/shieldoo-gate` which applies all migrations in order.)

- [ ] **Step 3: Verify schema after migration**

```bash
docker exec $(docker ps -qf name=postgres) psql -U shieldoo -d shieldoo -c "\d version_diff_results"
```

Expected output includes:
- New columns: `ai_verdict`, `ai_confidence`, `ai_explanation`, `ai_model_used`, `ai_prompt_version`, `ai_tokens_used`, `previous_version` — all nullable
- `files_added`, `files_removed`, `files_modified`, `size_ratio`, `max_entropy_delta` — all nullable (no `NOT NULL`)
- Indexes include `uq_version_diff_pair UNIQUE, btree (artifact_id, previous_artifact, ai_model_used, ai_prompt_version)`

(No commit yet — combined with Task 2 + 3.)

---

### Task 2: Write SQLite migration `024_version_diff_ai_columns.sql`

**Files:**
- Create: `internal/config/migrations/sqlite/024_version_diff_ai_columns.sql`

SQLite does not support `ALTER COLUMN ... DROP NOT NULL`, so we use the recreate-and-copy pattern. Precedent: [migrations/sqlite/007_audit_user_email.sql](../../internal/config/migrations/sqlite/007_audit_user_email.sql).

- [ ] **Step 1: Write the migration**

Create the file with:

```sql
-- Migration 024 (SQLite): extend version_diff_results for AI-driven scanner.
-- SQLite cannot ALTER COLUMN DROP NOT NULL, so we recreate the table and copy.
-- Pattern matches migration 007. No explicit BEGIN/COMMIT — db.Exec processes
-- multi-statement bodies; SQLite handles each statement implicitly. PRAGMA
-- foreign_keys is left ON (the default); the FK target (artifacts.id) is not
-- changed by this migration so the rename succeeds without disabling it.
-- Dedup is implicit: ORDER BY id DESC + INSERT OR IGNORE keeps the first
-- (newest) row per legacy pair, dropping older duplicates.

CREATE TABLE version_diff_results_v24 (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id        TEXT NOT NULL,
    previous_artifact  TEXT NOT NULL REFERENCES artifacts(id),
    diff_at            DATETIME NOT NULL,
    files_added        INTEGER,
    files_removed      INTEGER,
    files_modified     INTEGER,
    size_ratio         REAL,
    max_entropy_delta  REAL,
    new_dependencies   TEXT,
    sensitive_changes  TEXT,
    verdict            TEXT NOT NULL,
    findings_json      TEXT NOT NULL,
    ai_verdict         TEXT,
    ai_confidence      REAL,
    ai_explanation     TEXT,
    ai_model_used      TEXT,
    ai_prompt_version  TEXT,
    ai_tokens_used     INTEGER,
    previous_version   TEXT
);

CREATE UNIQUE INDEX uq_version_diff_pair
    ON version_diff_results_v24(artifact_id, previous_artifact, ai_model_used, ai_prompt_version);

INSERT OR IGNORE INTO version_diff_results_v24
    (id, artifact_id, previous_artifact, diff_at,
     files_added, files_removed, files_modified, size_ratio, max_entropy_delta,
     new_dependencies, sensitive_changes, verdict, findings_json,
     ai_verdict, ai_confidence, ai_explanation, ai_model_used, ai_prompt_version, ai_tokens_used, previous_version)
    SELECT id, artifact_id, previous_artifact, diff_at,
           files_added, files_removed, files_modified, size_ratio, max_entropy_delta,
           new_dependencies, sensitive_changes, verdict, findings_json,
           NULL, NULL, NULL, NULL, NULL, NULL, NULL
      FROM version_diff_results
     ORDER BY id DESC;

DROP TABLE version_diff_results;
ALTER TABLE version_diff_results_v24 RENAME TO version_diff_results;

CREATE INDEX IF NOT EXISTS idx_version_diff_artifact ON version_diff_results(artifact_id);
```

Notes:
- Ordering by `id DESC` + `INSERT OR IGNORE` keeps the newest row per `(artifact_id, previous_artifact)` because the first INSERT wins under the unique index. AI columns are NULL on these legacy rows, so future AI-scanner inserts (with non-NULL `ai_model_used` + `ai_prompt_version`) won't collide.
- The composite index `idx_artifacts_eco_name_cached` from migration 016 stays on the `artifacts` table (untouched by this migration) — no need to recreate it.

- [ ] **Step 2: Apply the migration to a clean SQLite database**

```bash
rm -f /tmp/test-vdiff.db
sqlite3 /tmp/test-vdiff.db < internal/config/migrations/sqlite/001_init.sql
# Apply all migrations 002 through 023 in order:
for f in internal/config/migrations/sqlite/0[01][0-9]_*.sql internal/config/migrations/sqlite/02[0-3]_*.sql; do
  sqlite3 /tmp/test-vdiff.db < "$f" || { echo "FAILED: $f"; break; }
done
sqlite3 /tmp/test-vdiff.db < internal/config/migrations/sqlite/024_version_diff_ai_columns.sql
```

Expected: no errors. If a single migration file errors, fix it before continuing.

- [ ] **Step 3: Verify schema after migration**

```bash
sqlite3 /tmp/test-vdiff.db "PRAGMA table_info(version_diff_results);"
sqlite3 /tmp/test-vdiff.db ".indexes version_diff_results"
```

Expected:
- All AI columns present, all `NOT NULL=0` (nullable)
- `files_added`, `files_removed`, `files_modified`, `size_ratio`, `max_entropy_delta` all `NOT NULL=0`
- Indexes include `uq_version_diff_pair` and `idx_version_diff_artifact`

- [ ] **Step 4: Test dedup logic (synthetic data)**

```bash
sqlite3 /tmp/test-vdiff.db <<'SQL'
-- Reset the table
DROP TABLE version_diff_results;
SQL

# Re-create the pre-migration shape and seed duplicates
sqlite3 /tmp/test-vdiff.db < internal/config/migrations/sqlite/016_version_diff_results.sql

sqlite3 /tmp/test-vdiff.db <<'SQL'
INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
    VALUES ('a1', 'pypi', 'foo', '1.0', 'https://up/foo-1.0', 'h1', 100, datetime('now'), datetime('now'), '/tmp/a1'),
           ('a2', 'pypi', 'foo', '0.9', 'https://up/foo-0.9', 'h2', 100, datetime('now', '-1 day'), datetime('now', '-1 day'), '/tmp/a2');
INSERT INTO version_diff_results
    (artifact_id, previous_artifact, diff_at, files_added, files_removed, files_modified, size_ratio, max_entropy_delta, verdict, findings_json)
VALUES ('a1', 'a2', datetime('now'), 1, 0, 0, 1.0, 0.0, 'CLEAN', '[]'),
       ('a1', 'a2', datetime('now'), 1, 0, 0, 1.0, 0.0, 'SUSPICIOUS', '[]'),
       ('a1', 'a2', datetime('now'), 1, 0, 0, 1.0, 0.0, 'CLEAN', '[]');
SELECT COUNT(*) FROM version_diff_results;
SQL
```

Expected: `3`

- [ ] **Step 5: Re-run migration 024 and verify dedupe**

```bash
sqlite3 /tmp/test-vdiff.db < internal/config/migrations/sqlite/024_version_diff_ai_columns.sql
sqlite3 /tmp/test-vdiff.db "SELECT COUNT(*) FROM version_diff_results; SELECT id, artifact_id, previous_artifact, verdict FROM version_diff_results ORDER BY id;"
```

Expected: `1` row remaining, with the largest original `id` (i.e. the third insert with verdict `CLEAN`).

- [ ] **Step 6: Test that the unique index allows new AI rows alongside the legacy NULL row**

```bash
sqlite3 /tmp/test-vdiff.db <<'SQL'
INSERT INTO version_diff_results
    (artifact_id, previous_artifact, diff_at, verdict, findings_json,
     ai_verdict, ai_confidence, ai_model_used, ai_prompt_version, ai_tokens_used, previous_version)
VALUES ('a1', 'a2', datetime('now'), 'CLEAN', '[]', 'CLEAN', 0.9, 'gpt-5.4-mini', 'abc123', 1500, '0.9');

-- Second insert with identical AI columns must fail (idempotency working)
INSERT INTO version_diff_results
    (artifact_id, previous_artifact, diff_at, verdict, findings_json,
     ai_verdict, ai_confidence, ai_model_used, ai_prompt_version, ai_tokens_used, previous_version)
VALUES ('a1', 'a2', datetime('now'), 'CLEAN', '[]', 'CLEAN', 0.9, 'gpt-5.4-mini', 'abc123', 1500, '0.9');
SQL
```

Expected: first insert succeeds, second errors with `UNIQUE constraint failed: version_diff_results.artifact_id, version_diff_results.previous_artifact, version_diff_results.ai_model_used, version_diff_results.ai_prompt_version`.

- [ ] **Step 7: Test that a different prompt_version inserts cleanly**

```bash
sqlite3 /tmp/test-vdiff.db <<'SQL'
INSERT INTO version_diff_results
    (artifact_id, previous_artifact, diff_at, verdict, findings_json,
     ai_verdict, ai_confidence, ai_model_used, ai_prompt_version, ai_tokens_used, previous_version)
VALUES ('a1', 'a2', datetime('now'), 'CLEAN', '[]', 'CLEAN', 0.9, 'gpt-5.4-mini', 'def456', 1500, '0.9');
SELECT COUNT(*) FROM version_diff_results;
SQL
```

Expected: `3` rows total (1 legacy + 2 with different `ai_prompt_version` values).

(No commit yet.)

---

### Task 3: Add a Go integration test for migration 024

The repo applies migrations on app startup. The simplest in-language verification is a test that runs all migrations against a fresh in-memory SQLite and asserts on the schema.

**Files:**
- Test: `internal/config/db_test.go` (extend) or new file `internal/config/migration_024_test.go`

- [ ] **Step 1: Locate the existing migration test helper**

The repo uses `InitDB(SQLiteMemoryConfig())` directly in [internal/config/db_test.go](../../internal/config/db_test.go) (e.g. line 13–15: `db, err := InitDB(SQLiteMemoryConfig())`). Reuse the same call. `InitDB` runs all migrations automatically.

- [ ] **Step 2: Write the failing test**

Create `internal/config/migration_024_test.go`:

```go
package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMigration024_AddsAIColumnsAndUniqueIndex(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	// InitDB runs all migrations including 024 automatically.
	// Verify column existence and nullability.
	type col struct {
		Name    string `db:"name"`
		Notnull int    `db:"notnull"`
	}
	var cols []col
	require.NoError(t, db.Select(&cols, "PRAGMA table_info(version_diff_results)"))

	wantNullable := map[string]bool{
		"ai_verdict":        true,
		"ai_confidence":     true,
		"ai_explanation":    true,
		"ai_model_used":     true,
		"ai_prompt_version": true,
		"ai_tokens_used":    true,
		"previous_version":  true,
		"files_added":       true,
		"files_removed":     true,
		"files_modified":    true,
		"size_ratio":        true,
		"max_entropy_delta": true,
	}

	got := map[string]bool{}
	for _, c := range cols {
		got[c.Name] = c.Notnull == 0
	}
	for name, expectNullable := range wantNullable {
		nullable, present := got[name]
		require.True(t, present, "column %s missing after migration 024", name)
		require.Equal(t, expectNullable, nullable, "column %s nullability mismatch", name)
	}
}

func TestMigration024_UniqueIndexEnforced(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	// Seed two artifacts (FK target) — match the columns from migrations/sqlite/001_init.sql.
	_, err := db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, 'pypi', 'foo', '1.0', 'https://up/foo-1.0', 'h1', 100, datetime('now'), datetime('now'), '/tmp/a1'),
		        (?, 'pypi', 'foo', '0.9', 'https://up/foo-0.9', 'h2', 100, datetime('now', '-1 day'), datetime('now', '-1 day'), '/tmp/a2')`,
		"art-new", "art-old",
	)
	require.NoError(t, err)

	insert := func() error {
		_, err := db.Exec(
			`INSERT INTO version_diff_results
			 (artifact_id, previous_artifact, diff_at, verdict, findings_json,
			  ai_verdict, ai_confidence, ai_model_used, ai_prompt_version, ai_tokens_used)
			 VALUES (?, ?, datetime('now'), 'CLEAN', '[]', 'CLEAN', 0.9, 'gpt-5.4-mini', 'abc123', 1500)`,
			"art-new", "art-old",
		)
		return err
	}

	require.NoError(t, insert(), "first insert must succeed")
	require.Error(t, insert(), "second insert with identical AI key must fail unique constraint")
}
```

> Note: `db.Exec` here uses `?` placeholders; `GateDB` rebinds them automatically for the active backend.

- [ ] **Step 3: Run the test — it should pass after Tasks 1+2 created the migration files**

```bash
go test -run TestMigration024 ./internal/config/ -v
```

Expected: PASS.

If the helper `newTestSQLiteDB` does not exist with that exact name, find the analogous one (likely `setupTestDB` or similar) by reading `internal/config/db_test.go` — adapt the test to use whatever the existing pattern is. Do not invent a new helper.

- [ ] **Step 4: Run the full Go test suite to ensure no regression**

```bash
make test
```

Expected: all tests pass (including the existing `db_test.go` tests on `version_diff_results`).

- [ ] **Step 5: Commit**

```bash
git add internal/config/migrations/postgres/024_version_diff_ai_columns.sql \
        internal/config/migrations/sqlite/024_version_diff_ai_columns.sql \
        internal/config/migration_024_test.go
git commit -m "feat(db): migration 024 — AI columns + idempotency UNIQUE INDEX on version_diff_results"
```

---

## Verification — phase-end

```bash
# Migrations are wired up to the embedded FS automatically (no Go change needed).
# Confirm both files are present:
ls internal/config/migrations/postgres/024_version_diff_ai_columns.sql
ls internal/config/migrations/sqlite/024_version_diff_ai_columns.sql

# Migration tests pass
go test -run TestMigration024 ./internal/config/ -v

# Full Go suite still green
make test

# Quick smoke: starting the binary with a fresh SQLite applies all migrations
SHIELDOO_GATE_DATABASE_BACKEND=sqlite \
SHIELDOO_GATE_DATABASE_SQLITE_PATH=/tmp/sg-smoke.db \
./bin/shieldoo-gate --validate-config 2>&1 | grep -E "migration|error" || echo "no migration errors"
```

## Risks during this phase

- **Production rollback is one-way for SQLite.** The recreate-and-copy drops the old table. Before applying in production, take an `sqlite3 .backup` snapshot. Mitigation: documented in Phase 8a (rollout phase) prerequisites.
- **Postgres `ALTER ... DROP NOT NULL` on a busy table can lock briefly.** With our DB sizes (50K rows max for `version_diff_results`) this is sub-second. No pg_dump needed for safety, but Phase 8a still calls for one.
- **Multi-statement `db.Exec`** — both backends accept multi-statement strings via `database/sql` `Exec`. Verified by precedent migration 007 which uses the same pattern.
- **`PRAGMA foreign_keys = OFF` inside a transaction** — SQLite documents that the pragma takes effect at the next transaction boundary. To be safe, the migration toggles it before `BEGIN` would be ideal, but the recreate-and-copy in [007_audit_user_email.sql](../../internal/config/migrations/sqlite/007_audit_user_email.sql) doesn't toggle FK at all (audit_log has no inbound FK). Our table has `previous_artifact REFERENCES artifacts(id)` outbound — toggling FK off ensures we can swap the table without violating the FK during the rename. This works as written because the FK is checked at commit time when set DEFERRABLE; SQLite's default behavior allows the swap as long as the post-COMMIT state satisfies the FK.

## What this phase ships

- Two migration files (one per backend) — atomic, idempotent (re-running produces no error because of `IF NOT EXISTS` on the index in Postgres; SQLite handles re-runs because the new table name `version_diff_results_v24` only exists between BEGIN/COMMIT).
- A Go-side test that asserts the post-migration schema and unique-constraint behavior.

## What this phase deliberately does NOT ship

- No code that writes to the new columns yet (Phase 6b).
- No retention/cleanup of historical heuristic rows (Phase 9).
- No `scanner_version` column — that's a separate, smaller migration in Phase 9.
