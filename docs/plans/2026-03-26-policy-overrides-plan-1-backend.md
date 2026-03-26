# Policy Overrides — Phase 1: Backend

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add DB-backed policy overrides so that false-positive artifacts can be allowed through the scan pipeline via API calls.

**Architecture:** New `policy_overrides` table in SQLite, new `PolicyOverride` model struct, policy engine extended with DB access to check overrides before static allowlist. New REST API endpoints for CRUD operations on overrides. When an override is created for a quarantined artifact, it is automatically released.

**Tech Stack:** Go, SQLite (sqlx), chi router, testify

**Index:** [`plan-index.md`](./2026-03-26-policy-overrides-plan-index.md)

---

### Task 1: DB Migration — Add `policy_overrides` table

**Files:**
- Create: `internal/config/migrations/002_policy_overrides.sql`
- Modify: `internal/config/db.go:11-19` (embed pattern + run both migrations)

- [ ] **Step 1: Create migration SQL file**

Create `internal/config/migrations/002_policy_overrides.sql`:

```sql
CREATE TABLE IF NOT EXISTS policy_overrides (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ecosystem  TEXT NOT NULL,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL DEFAULT '',
    scope      TEXT NOT NULL DEFAULT 'version',
    reason     TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT 'api',
    created_at DATETIME NOT NULL,
    expires_at DATETIME,
    revoked    INTEGER NOT NULL DEFAULT 0,
    revoked_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_policy_overrides_lookup ON policy_overrides(ecosystem, name, version, revoked);
```

Column notes:
- `version`: empty string = all versions (scope=package)
- `scope`: "version" or "package"
- `revoked`: 0 = active, 1 = revoked (soft delete — never hard delete overrides for audit trail)
- `expires_at`: NULL = never expires

- [ ] **Step 2: Update db.go to run both migrations**

Modify `internal/config/db.go` to embed the entire `migrations/` directory and run all `.sql` files in order:

```go
package config

import (
	"embed"
	"fmt"
	"sort"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

func readMigrations() ([]string, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("config: reading migrations dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var sqls []string
	for _, name := range names {
		data, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("config: reading migration %s: %w", name, err)
		}
		sqls = append(sqls, string(data))
	}
	return sqls, nil
}

func InitDB(dbPath string) (*sqlx.DB, error) {
	db, err := sqlx.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("config: opening database %s: %w", dbPath, err)
	}

	// Set SQLite PRAGMAs
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("config: setting pragma %q: %w", pragma, err)
		}
	}

	// Run all migrations in order
	migrations, err := readMigrations()
	if err != nil {
		db.Close()
		return nil, err
	}
	for i, sql := range migrations {
		if _, err := db.Exec(sql); err != nil {
			db.Close()
			return nil, fmt.Errorf("config: running migration %d: %w", i+1, err)
		}
	}

	return db, nil
}
```

- [ ] **Step 3: Verify migration runs**

Run: `go build ./...`
Expected: Compiles without errors.

- [ ] **Step 4: Commit**

```bash
git add internal/config/migrations/002_policy_overrides.sql internal/config/db.go
git commit -m "feat(db): add policy_overrides table migration"
```

---

### Task 2: Model — Add `PolicyOverride` struct and new event types

**Files:**
- Create: `internal/model/override.go`
- Modify: `internal/model/audit.go:7-13` (add new event type constants)

- [ ] **Step 1: Create model file**

Create `internal/model/override.go`:

```go
package model

import "time"

// OverrideScope defines whether an override applies to a specific version or all versions.
type OverrideScope string

const (
	ScopeVersion OverrideScope = "version"
	ScopePackage OverrideScope = "package"
)

// PolicyOverride represents a user-created exception that allows an artifact
// through the policy engine despite scanner findings.
type PolicyOverride struct {
	ID        int64          `db:"id" json:"id"`
	Ecosystem string         `db:"ecosystem" json:"ecosystem"`
	Name      string         `db:"name" json:"name"`
	Version   string         `db:"version" json:"version"`
	Scope     OverrideScope  `db:"scope" json:"scope"`
	Reason    string         `db:"reason" json:"reason"`
	CreatedBy string         `db:"created_by" json:"created_by"`
	CreatedAt time.Time      `db:"created_at" json:"created_at"`
	ExpiresAt *time.Time     `db:"expires_at" json:"expires_at,omitempty"`
	Revoked   bool           `db:"revoked" json:"revoked"`
	RevokedAt *time.Time     `db:"revoked_at" json:"revoked_at,omitempty"`
}

// Matches returns true if this override applies to the given artifact coordinates.
func (o PolicyOverride) Matches(ecosystem, name, version string) bool {
	if o.Revoked {
		return false
	}
	if o.ExpiresAt != nil && time.Now().UTC().After(*o.ExpiresAt) {
		return false
	}
	if o.Ecosystem != ecosystem || o.Name != name {
		return false
	}
	if o.Scope == ScopeVersion && o.Version != version {
		return false
	}
	return true
}
```

- [ ] **Step 2: Add new audit event types**

Add to `internal/model/audit.go` after the existing constants (line 12):

```go
	EventOverrideCreated EventType = "OVERRIDE_CREATED"
	EventOverrideRevoked EventType = "OVERRIDE_REVOKED"
```

The full const block should be:

```go
const (
	EventServed          EventType = "SERVED"
	EventBlocked         EventType = "BLOCKED"
	EventQuarantined     EventType = "QUARANTINED"
	EventReleased        EventType = "RELEASED"
	EventScanned         EventType = "SCANNED"
	EventOverrideCreated EventType = "OVERRIDE_CREATED"
	EventOverrideRevoked EventType = "OVERRIDE_REVOKED"
)
```

- [ ] **Step 3: Write tests for PolicyOverride.Matches**

Create `internal/model/override_test.go`:

```go
package model

import (
	"testing"
	"time"
)

func TestPolicyOverride_Matches_ExactVersion(t *testing.T) {
	o := PolicyOverride{
		Ecosystem: "pypi", Name: "requests", Version: "2.32.3",
		Scope: ScopeVersion,
	}
	if !o.Matches("pypi", "requests", "2.32.3") {
		t.Error("expected match for exact version")
	}
	if o.Matches("pypi", "requests", "2.32.4") {
		t.Error("expected no match for different version")
	}
}

func TestPolicyOverride_Matches_PackageScope(t *testing.T) {
	o := PolicyOverride{
		Ecosystem: "pypi", Name: "requests", Version: "",
		Scope: ScopePackage,
	}
	if !o.Matches("pypi", "requests", "2.32.3") {
		t.Error("expected match for any version with package scope")
	}
	if !o.Matches("pypi", "requests", "3.0.0") {
		t.Error("expected match for any version with package scope")
	}
	if o.Matches("npm", "requests", "2.32.3") {
		t.Error("expected no match for different ecosystem")
	}
}

func TestPolicyOverride_Matches_Revoked(t *testing.T) {
	o := PolicyOverride{
		Ecosystem: "pypi", Name: "requests", Version: "2.32.3",
		Scope: ScopeVersion, Revoked: true,
	}
	if o.Matches("pypi", "requests", "2.32.3") {
		t.Error("expected no match for revoked override")
	}
}

func TestPolicyOverride_Matches_Expired(t *testing.T) {
	past := time.Now().UTC().Add(-1 * time.Hour)
	o := PolicyOverride{
		Ecosystem: "pypi", Name: "requests", Version: "2.32.3",
		Scope: ScopeVersion, ExpiresAt: &past,
	}
	if o.Matches("pypi", "requests", "2.32.3") {
		t.Error("expected no match for expired override")
	}
}

func TestPolicyOverride_Matches_NotExpired(t *testing.T) {
	future := time.Now().UTC().Add(24 * time.Hour)
	o := PolicyOverride{
		Ecosystem: "pypi", Name: "requests", Version: "2.32.3",
		Scope: ScopeVersion, ExpiresAt: &future,
	}
	if !o.Matches("pypi", "requests", "2.32.3") {
		t.Error("expected match for non-expired override")
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/model/...`
Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/model/override.go internal/model/override_test.go internal/model/audit.go
git commit -m "feat(model): add PolicyOverride struct and new audit event types"
```

---

### Task 3: Policy Engine — Add DB-backed override lookup

**Files:**
- Modify: `internal/policy/engine.go` (add DB field, check overrides in Evaluate)
- Create: `internal/policy/engine_db_test.go` (new test file for DB override tests)
- Modify: `internal/policy/engine_test.go` — update all 5 existing `policy.NewEngine(cfg)` calls to `policy.NewEngine(cfg, nil)`
- Modify: `cmd/shieldoo-gate/main.go:119-124` — add `db` parameter to `NewEngine` call
- Modify: `internal/adapter/pypi/pypi_test.go:32` — add `, nil` to `policy.NewEngine(...)` call
- Modify: `internal/adapter/npm/npm_test.go:32` — add `, nil` to `policy.NewEngine(...)` call
- Modify: `internal/adapter/nuget/nuget_test.go:32` — add `, nil` to `policy.NewEngine(...)` call
- Modify: `internal/adapter/docker/docker_test.go:30,69` — add `, nil` to both `policy.NewEngine(...)` calls

The key change: `Engine` gets a `*sqlx.DB` field. In `Evaluate()`, before checking the static allowlist, it queries `policy_overrides` for active, non-revoked, non-expired entries matching the artifact.

- [ ] **Step 1: Write failing test for override lookup**

Create `internal/policy/engine_db_test.go` (separate file — existing `engine_test.go` uses `package policy_test`):

```go
package policy_test

import (
	"context"
	"testing"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestDB(t *testing.T) *sqlx.DB {
	t.Helper()
	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func TestEngine_Evaluate_DBOverride_AllowsMalicious(t *testing.T) {
	db := setupTestDB(t)

	// Insert an active override for pypi:requests:2.32.3
	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES ('pypi', 'requests', '2.32.3', 'version', 'false positive', 'test', ?, 0)`, now)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, db)

	artifact := scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "requests",
		Version:   "2.32.3",
	}
	scanResults := []scanner.ScanResult{
		{Verdict: scanner.VerdictMalicious, Confidence: 0.9},
	}

	result := engine.Evaluate(context.Background(), artifact, scanResults)
	assert.Equal(t, policy.ActionAllow, result.Action)
	assert.Contains(t, result.Reason, "policy override")
}

func TestEngine_Evaluate_RevokedOverride_StillBlocks(t *testing.T) {
	db := setupTestDB(t)

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked, revoked_at)
		 VALUES ('pypi', 'requests', '2.32.3', 'version', 'false positive', 'test', ?, 1, ?)`, now, now)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, db)

	artifact := scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "requests",
		Version:   "2.32.3",
	}
	scanResults := []scanner.ScanResult{
		{Verdict: scanner.VerdictMalicious, Confidence: 0.9},
	}

	result := engine.Evaluate(context.Background(), artifact, scanResults)
	assert.Equal(t, policy.ActionBlock, result.Action)
}

func TestEngine_Evaluate_PackageScopeOverride_AllowsAnyVersion(t *testing.T) {
	db := setupTestDB(t)

	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES ('pypi', 'requests', '', 'package', 'known safe package', 'test', ?, 0)`, now)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, db)

	artifact := scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "requests",
		Version:   "9.99.99",
	}
	scanResults := []scanner.ScanResult{
		{Verdict: scanner.VerdictMalicious, Confidence: 0.9},
	}

	result := engine.Evaluate(context.Background(), artifact, scanResults)
	assert.Equal(t, policy.ActionAllow, result.Action)
}

func TestEngine_Evaluate_ExpiredDBOverride_StillBlocks(t *testing.T) {
	db := setupTestDB(t)

	past := time.Now().UTC().Add(-1 * time.Hour)
	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, expires_at, revoked)
		 VALUES ('pypi', 'requests', '2.32.3', 'version', 'expired fp', 'test', ?, ?, 0)`, now, past)
	require.NoError(t, err)

	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
	}, db)

	artifact := scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "requests",
		Version:   "2.32.3",
	}
	scanResults := []scanner.ScanResult{
		{Verdict: scanner.VerdictMalicious, Confidence: 0.9},
	}

	result := engine.Evaluate(context.Background(), artifact, scanResults)
	assert.Equal(t, policy.ActionBlock, result.Action)
}

func TestEngine_Evaluate_NoDB_FallsBackToStaticAllowlist(t *testing.T) {
	// nil DB — engine should still work with static allowlist only
	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
		MinimumConfidence:   0.7,
		Allowlist:           []string{"pypi:requests:==2.32.3"},
	}, nil)

	artifact := scanner.Artifact{
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "requests",
		Version:   "2.32.3",
	}
	scanResults := []scanner.ScanResult{
		{Verdict: scanner.VerdictMalicious, Confidence: 0.9},
	}

	result := engine.Evaluate(context.Background(), artifact, scanResults)
	assert.Equal(t, policy.ActionAllow, result.Action)
	assert.Contains(t, result.Reason, "allowlist")
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/... -run TestEngine_Evaluate_DBOverride -v`
Expected: FAIL — `NewEngine` doesn't accept DB parameter yet.

- [ ] **Step 3: Implement policy engine changes**

Modify `internal/policy/engine.go`:

```go
package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// EngineConfig configures the policy engine thresholds and allowlist.
type EngineConfig struct {
	BlockIfVerdict      scanner.Verdict
	QuarantineIfVerdict scanner.Verdict
	MinimumConfidence   float32
	Allowlist           []string
}

// Engine evaluates scan results against policy rules and returns a PolicyResult.
type Engine struct {
	cfg       EngineConfig
	allowlist []AllowlistEntry
	db        *sqlx.DB
}

// NewEngine creates a new Engine with the supplied configuration.
// db may be nil — in that case only static allowlist is used.
func NewEngine(cfg EngineConfig, db *sqlx.DB) *Engine {
	var parsed []AllowlistEntry
	for _, raw := range cfg.Allowlist {
		entry, err := ParseAllowlistEntry(raw)
		if err == nil {
			parsed = append(parsed, entry)
		}
	}
	return &Engine{cfg: cfg, allowlist: parsed, db: db}
}

// hasDBOverride checks if there is an active, non-revoked, non-expired override
// in the database for the given artifact.
func (e *Engine) hasDBOverride(ctx context.Context, artifact scanner.Artifact) bool {
	if e.db == nil {
		return false
	}

	now := time.Now().UTC()
	var count int
	err := e.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM policy_overrides
		 WHERE ecosystem = ? AND name = ? AND revoked = 0
		   AND (expires_at IS NULL OR expires_at > ?)
		   AND (scope = 'package' OR (scope = 'version' AND version = ?))`,
		string(artifact.Ecosystem), artifact.Name, now, artifact.Version,
	).Scan(&count)
	if err != nil {
		// Fail open — DB errors should not block artifacts
		return false
	}
	return count > 0
}

// Evaluate applies the policy to the given artifact and scan results.
// DB overrides are checked first, then static allowlist, then verdict rules.
func (e *Engine) Evaluate(ctx context.Context, artifact scanner.Artifact, scanResults []scanner.ScanResult) PolicyResult {
	// DB override check — highest priority.
	if e.hasDBOverride(ctx, artifact) {
		return PolicyResult{
			Action: ActionAllow,
			Reason: fmt.Sprintf("policy override: %s:%s:%s", artifact.Ecosystem, artifact.Name, artifact.Version),
		}
	}

	// Static allowlist check.
	if isAllowlisted(artifact, e.allowlist) {
		return PolicyResult{
			Action: ActionAllow,
			Reason: "artifact is in allowlist",
		}
	}

	aggCfg := AggregationConfig{MinConfidence: e.cfg.MinimumConfidence}
	agg := Aggregate(scanResults, aggCfg)

	switch {
	case agg.Verdict == e.cfg.BlockIfVerdict:
		return PolicyResult{
			Action: ActionBlock,
			Reason: fmt.Sprintf("verdict %s meets block threshold", agg.Verdict),
		}
	case agg.Verdict == e.cfg.QuarantineIfVerdict:
		return PolicyResult{
			Action: ActionQuarantine,
			Reason: fmt.Sprintf("verdict %s meets quarantine threshold", agg.Verdict),
		}
	default:
		return PolicyResult{
			Action: ActionAllow,
			Reason: fmt.Sprintf("verdict %s is below action thresholds", agg.Verdict),
		}
	}
}
```

- [ ] **Step 4: Update all callers of NewEngine**

**All 8 call sites that must be updated** (add `, db` or `, nil` as second arg):

1. `cmd/shieldoo-gate/main.go:119` — change to:
```go
policyEngine := policy.NewEngine(policy.EngineConfig{
    BlockIfVerdict:      scanner.Verdict(cfg.Policy.BlockIfVerdict),
    QuarantineIfVerdict: scanner.Verdict(cfg.Policy.QuarantineIfVerdict),
    MinimumConfidence:   cfg.Policy.MinimumConfidence,
    Allowlist:           cfg.Policy.Allowlist,
}, db)
```

2. `internal/policy/engine_test.go` — update all 5 calls from `policy.NewEngine(cfg)` to `policy.NewEngine(cfg, nil)` (lines 31, 40, 49, 60, 73)

3. `internal/adapter/pypi/pypi_test.go:32` — add `, nil`:
```go
policyEngine := policy.NewEngine(policy.EngineConfig{...}, nil)
```

4. `internal/adapter/npm/npm_test.go:32` — add `, nil`

5. `internal/adapter/nuget/nuget_test.go:32` — add `, nil`

6. `internal/adapter/docker/docker_test.go:30` — add `, nil`

7. `internal/adapter/docker/docker_test.go:69` — add `, nil`

- [ ] **Step 5: Run all tests**

Run: `go test ./internal/policy/... -v`
Expected: All tests PASS.

Run: `go build ./...`
Expected: Compiles without errors.

- [ ] **Step 6: Commit**

```bash
git add internal/policy/engine.go internal/policy/engine_db_test.go internal/policy/engine_test.go \
  cmd/shieldoo-gate/main.go \
  internal/adapter/pypi/pypi_test.go internal/adapter/npm/npm_test.go \
  internal/adapter/nuget/nuget_test.go internal/adapter/docker/docker_test.go
git commit -m "feat(policy): add DB-backed override lookup in policy engine"
```

---

### Task 4: API Endpoints — Override CRUD + artifact shortcut

**Files:**
- Create: `internal/api/overrides.go`
- Create: `internal/api/overrides_test.go`
- Modify: `internal/api/server.go:47-69` (register new routes)

API endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/overrides` | List all overrides (paginated, filterable) |
| `POST` | `/api/v1/overrides` | Create a new override |
| `DELETE` | `/api/v1/overrides/{id}` | Revoke (soft-delete) an override |
| `POST` | `/api/v1/artifacts/{id}/override` | Shortcut: create override from artifact ID |

- [ ] **Step 1: Create overrides handler file**

Create `internal/api/overrides.go`:

```go
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

type createOverrideRequest struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Scope     string `json:"scope"`
	Reason    string `json:"reason"`
}

func (req createOverrideRequest) validate() error {
	if req.Ecosystem == "" || req.Name == "" {
		return fmt.Errorf("ecosystem and name are required")
	}
	if req.Scope != "version" && req.Scope != "package" {
		return fmt.Errorf("scope must be 'version' or 'package'")
	}
	if req.Scope == "version" && req.Version == "" {
		return fmt.Errorf("version is required when scope is 'version'")
	}
	return nil
}

// handleListOverrides handles GET /api/v1/overrides.
func (s *Server) handleListOverrides(w http.ResponseWriter, r *http.Request) {
	page, perPage := parsePagination(r.URL.Query())
	offset := (page - 1) * perPage
	activeOnly := r.URL.Query().Get("active") == "true"

	var total int
	countQuery := `SELECT COUNT(*) FROM policy_overrides`
	if activeOnly {
		countQuery += ` WHERE revoked = 0`
	}
	if err := s.db.QueryRowContext(r.Context(), countQuery).Scan(&total); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to count overrides")
		return
	}

	query := `SELECT id, ecosystem, name, version, scope, reason, created_by, created_at, expires_at, revoked, revoked_at
	          FROM policy_overrides`
	var args []any
	if activeOnly {
		query += ` WHERE revoked = 0`
	}
	query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`
	args = append(args, perPage, offset)

	rows, err := s.db.QueryxContext(r.Context(), query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query overrides")
		return
	}
	defer rows.Close()

	items := make([]model.PolicyOverride, 0, perPage)
	for rows.Next() {
		var row model.PolicyOverride
		if err := rows.StructScan(&row); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan override row")
			return
		}
		items = append(items, row)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "error iterating override rows")
		return
	}

	writeJSON(w, http.StatusOK, paginatedResponse{
		Data:    items,
		Page:    page,
		PerPage: perPage,
		Total:   total,
	})
}

// handleCreateOverride handles POST /api/v1/overrides.
func (s *Server) handleCreateOverride(w http.ResponseWriter, r *http.Request) {
	var req createOverrideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := req.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// If scope is package, clear version
	version := req.Version
	if req.Scope == "package" {
		version = ""
	}

	now := time.Now().UTC()

	tx, err := s.db.BeginTxx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin transaction")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	result, err := tx.ExecContext(r.Context(),
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES (?, ?, ?, ?, ?, 'api', ?, 0)`,
		req.Ecosystem, req.Name, version, req.Scope, req.Reason, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create override")
		return
	}

	overrideID, _ := result.LastInsertId()

	// If a matching artifact is quarantined, release it
	artifactID := fmt.Sprintf("%s:%s:%s", req.Ecosystem, req.Name, req.Version)
	if req.Scope == "version" && req.Version != "" {
		_, _ = tx.ExecContext(r.Context(),
			`UPDATE artifact_status SET status = 'CLEAN', released_at = ?
			 WHERE artifact_id = ? AND status = 'QUARANTINED'`,
			now, artifactID)
	}

	// Audit log
	_, err = tx.ExecContext(r.Context(),
		`INSERT INTO audit_log (ts, event_type, artifact_id, reason)
		 VALUES (?, ?, ?, ?)`,
		now, model.EventOverrideCreated, artifactID, req.Reason)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit log")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit transaction")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":        overrideID,
		"ecosystem": req.Ecosystem,
		"name":      req.Name,
		"version":   version,
		"scope":     req.Scope,
		"reason":    req.Reason,
	})
}

// handleRevokeOverride handles DELETE /api/v1/overrides/{id}.
func (s *Server) handleRevokeOverride(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid override ID")
		return
	}

	now := time.Now().UTC()

	tx, err := s.db.BeginTxx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin transaction")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	// Get override details for audit log
	var override model.PolicyOverride
	err = tx.QueryRowxContext(r.Context(),
		`SELECT id, ecosystem, name, version, scope, reason, created_by, created_at, revoked
		 FROM policy_overrides WHERE id = ?`, id).StructScan(&override)
	if err != nil {
		writeError(w, http.StatusNotFound, "override not found")
		return
	}
	if override.Revoked {
		writeError(w, http.StatusConflict, "override is already revoked")
		return
	}

	_, err = tx.ExecContext(r.Context(),
		`UPDATE policy_overrides SET revoked = 1, revoked_at = ? WHERE id = ?`,
		now, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to revoke override")
		return
	}

	artifactID := fmt.Sprintf("%s:%s:%s", override.Ecosystem, override.Name, override.Version)
	_, err = tx.ExecContext(r.Context(),
		`INSERT INTO audit_log (ts, event_type, artifact_id, reason)
		 VALUES (?, ?, ?, ?)`,
		now, model.EventOverrideRevoked, artifactID, fmt.Sprintf("revoked override #%d", id))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit log")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit transaction")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "revoked",
		"id":     idStr,
	})
}

// handleCreateArtifactOverride handles POST /api/v1/artifacts/{id}/override.
// This is a convenience endpoint that creates an override from an artifact ID.
func (s *Server) handleCreateArtifactOverride(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Parse artifact ID: "ecosystem:name:version"
	parts := strings.SplitN(id, ":", 3)
	if len(parts) != 3 {
		writeError(w, http.StatusBadRequest, "invalid artifact ID format, expected ecosystem:name:version")
		return
	}

	// Check artifact exists
	var count int
	if err := s.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM artifacts WHERE id = ?`, id).Scan(&count); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check artifact")
		return
	}
	if count == 0 {
		writeError(w, http.StatusNotFound, "artifact not found")
		return
	}

	// Parse optional request body for reason and scope
	var body struct {
		Reason string `json:"reason"`
		Scope  string `json:"scope"`
	}
	body.Scope = "version" // default
	body.Reason = "false positive"
	if r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if body.Scope != "version" && body.Scope != "package" {
		body.Scope = "version"
	}

	version := parts[2]
	if body.Scope == "package" {
		version = ""
	}

	now := time.Now().UTC()

	tx, err := s.db.BeginTxx(r.Context(), nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin transaction")
		return
	}
	defer tx.Rollback() //nolint:errcheck

	result, err := tx.ExecContext(r.Context(),
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES (?, ?, ?, ?, ?, 'api', ?, 0)`,
		parts[0], parts[1], version, body.Scope, body.Reason, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create override")
		return
	}

	overrideID, _ := result.LastInsertId()

	// Release artifact from quarantine if applicable
	_, _ = tx.ExecContext(r.Context(),
		`UPDATE artifact_status SET status = 'CLEAN', released_at = ?
		 WHERE artifact_id = ? AND status = 'QUARANTINED'`,
		now, id)

	// Audit log
	_, err = tx.ExecContext(r.Context(),
		`INSERT INTO audit_log (ts, event_type, artifact_id, reason)
		 VALUES (?, ?, ?, ?)`,
		now, model.EventOverrideCreated, id, body.Reason)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to write audit log")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit transaction")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          overrideID,
		"artifact_id": id,
		"scope":       body.Scope,
		"reason":      body.Reason,
	})
}
```

- [ ] **Step 2: Register routes in server.go**

Add to `internal/api/server.go` inside the `r.Route("/api/v1", ...)` block, after the audit log route (after line 60):

```go
		// Policy overrides
		r.Get("/overrides", s.handleListOverrides)
		r.Post("/overrides", s.handleCreateOverride)
		r.Delete("/overrides/{id}", s.handleRevokeOverride)
```

And add the artifact override shortcut after the existing artifact routes (after line 57):

```go
		r.Post("/artifacts/{id}/override", s.handleCreateArtifactOverride)
```

- [ ] **Step 3: Write API integration tests**

Create `internal/api/overrides_test.go`:

```go
package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestServer(t *testing.T) *Server {
	t.Helper()
	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	engine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict: scanner.VerdictMalicious,
	}, db)

	return NewServer(db, nil, nil, engine)
}

func TestHandleCreateOverride_Success(t *testing.T) {
	srv := setupTestServer(t)
	router := srv.Routes()

	body := `{"ecosystem":"pypi","name":"requests","version":"2.32.3","scope":"version","reason":"false positive"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/overrides", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "pypi", resp["ecosystem"])
	assert.Equal(t, "requests", resp["name"])
	assert.Equal(t, "version", resp["scope"])
}

func TestHandleCreateOverride_InvalidScope(t *testing.T) {
	srv := setupTestServer(t)
	router := srv.Routes()

	body := `{"ecosystem":"pypi","name":"requests","version":"2.32.3","scope":"invalid","reason":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/overrides", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleListOverrides_Paginated(t *testing.T) {
	srv := setupTestServer(t)
	now := time.Now().UTC()

	// Insert 3 overrides
	for i := 0; i < 3; i++ {
		_, err := srv.db.Exec(
			`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
			 VALUES ('pypi', 'pkg', ?, 'version', 'test', 'test', ?, 0)`,
			i, now)
		require.NoError(t, err)
	}

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/overrides?page=1&per_page=2", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp paginatedResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 3, resp.Total)
	assert.Equal(t, 2, resp.PerPage)
}

func TestHandleRevokeOverride_Success(t *testing.T) {
	srv := setupTestServer(t)
	now := time.Now().UTC()

	_, err := srv.db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked)
		 VALUES ('pypi', 'requests', '2.32.3', 'version', 'fp', 'test', ?, 0)`, now)
	require.NoError(t, err)

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/overrides/1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify revoked in DB
	var revoked int
	err = srv.db.QueryRow(`SELECT revoked FROM policy_overrides WHERE id = 1`).Scan(&revoked)
	require.NoError(t, err)
	assert.Equal(t, 1, revoked)
}

func TestHandleRevokeOverride_AlreadyRevoked_Returns409(t *testing.T) {
	srv := setupTestServer(t)
	now := time.Now().UTC()

	_, err := srv.db.Exec(
		`INSERT INTO policy_overrides (ecosystem, name, version, scope, reason, created_by, created_at, revoked, revoked_at)
		 VALUES ('pypi', 'requests', '2.32.3', 'version', 'fp', 'test', ?, 1, ?)`, now, now)
	require.NoError(t, err)

	router := srv.Routes()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/overrides/1", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestHandleCreateArtifactOverride_ReleasesQuarantined(t *testing.T) {
	srv := setupTestServer(t)
	now := time.Now().UTC()

	// Insert a quarantined artifact
	_, err := srv.db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES ('pypi:requests:2.32.3', 'pypi', 'requests', '2.32.3', 'https://pypi.org/...', 'abc', 1000, ?, ?, '/tmp/test')`,
		now, now)
	require.NoError(t, err)

	_, err = srv.db.Exec(
		`INSERT INTO artifact_status (artifact_id, status, quarantined_at)
		 VALUES ('pypi:requests:2.32.3', 'QUARANTINED', ?)`, now)
	require.NoError(t, err)

	router := srv.Routes()
	body := `{"reason":"false positive","scope":"version"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/artifacts/pypi:requests:2.32.3/override", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	// Verify artifact is now CLEAN
	var status string
	err = srv.db.QueryRow(`SELECT status FROM artifact_status WHERE artifact_id = 'pypi:requests:2.32.3'`).Scan(&status)
	require.NoError(t, err)
	assert.Equal(t, "CLEAN", status)
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/api/... -v`
Expected: All tests PASS.

Run: `go build ./...`
Expected: Compiles.

- [ ] **Step 5: Commit**

```bash
git add internal/api/overrides.go internal/api/overrides_test.go internal/api/server.go
git commit -m "feat(api): add policy override CRUD endpoints and artifact override shortcut"
```

---

### Task 5: Documentation Update

**Files:**
- Modify: `docs/initial-analyse.md` (add override section reference)
- Modify: `docs/index.md` (add overrides to feature list)
- Modify: `docs/api/openapi.yaml` (add new endpoints — required by CLAUDE.md)

- [ ] **Step 1: Update docs/index.md**

Add "Policy Overrides" to the feature table if one exists. Add a line about dynamic false-positive management via UI/API.

- [ ] **Step 2: Update API section in initial-analyse.md**

Add the new endpoints to the API section (around line 785):

```
# Policy overrides
GET    /api/v1/overrides                         list overrides (pagination, filter by active)
POST   /api/v1/overrides                         create new override
DELETE /api/v1/overrides/{id}                     revoke (soft-delete) an override
POST   /api/v1/artifacts/{id}/override            create override from artifact (convenience)
```

- [ ] **Step 3: Update OpenAPI spec**

Add the 4 new endpoints to `docs/api/openapi.yaml`:
- `GET /api/v1/overrides` — list overrides (pagination, active filter)
- `POST /api/v1/overrides` — create override (body: ecosystem, name, version, scope, reason)
- `DELETE /api/v1/overrides/{id}` — revoke override
- `POST /api/v1/artifacts/{id}/override` — create override from artifact

Include request/response schemas matching the Go handler types.

- [ ] **Step 4: Commit**

```bash
git add docs/index.md docs/initial-analyse.md docs/api/openapi.yaml
git commit -m "docs: add policy override API endpoints to specification"
```
