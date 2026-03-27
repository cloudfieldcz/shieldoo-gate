# Docker Registry Redesign — Phase 3: Scheduled Sync

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Automatically re-pull and re-scan all cached upstream Docker images on a configurable interval, quarantining images when new vulnerabilities are found.

**Architecture:** A `SyncService` runs as a background goroutine started from `main.go`. It iterates `docker_repositories` where `sync_enabled=true` and `is_internal=false`, re-pulls manifests to detect changes (digest comparison), and triggers re-scan when the manifest changes or `rescan_interval` has elapsed. Concurrency is controlled by a semaphore (`maxConcurrentSyncs`). Error handling follows a defined table: upstream unreachable → retry with backoff, 404 → disable sync, 429 → respect Retry-After, scan failure → fail open.

**Tech Stack:** Go 1.25+, time.Ticker, semaphore (golang.org/x/sync/semaphore), sqlx + SQLite, crane, testify

**Index:** [`plan-index.md`](./2026-03-27-docker-registry-redesign-plan-index.md)

---

### Task 1: SyncService Struct + Start/Stop Lifecycle

**Files:**
- Create: `internal/adapter/docker/sync.go`
- Create: `internal/adapter/docker/sync_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/adapter/docker/sync_test.go
package docker_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

func TestSyncService_StartsAndStops(t *testing.T) {
	db, err := config.InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	cfg := config.DockerSyncConfig{
		Enabled:        true,
		Interval:       "1s",
		RescanInterval: "10s",
		MaxConcurrent:  2,
	}

	svc := docker.NewSyncService(db, nil, nil, nil, cfg)
	ctx, cancel := context.WithCancel(context.Background())

	go svc.Start(ctx)
	time.Sleep(100 * time.Millisecond)
	cancel()
	// Should not panic or deadlock
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/docker/ -run TestSyncService_StartsAndStops -v`
Expected: FAIL

- [ ] **Step 3: Implement SyncService**

```go
// internal/adapter/docker/sync.go
package docker

import (
	"context"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// SyncService periodically re-pulls and re-scans upstream Docker images.
type SyncService struct {
	db         *sqlx.DB
	cache      cache.CacheStore
	scanEngine *scanner.Engine
	policyEng  *policy.Engine
	cfg        config.DockerSyncConfig
	sem        *semaphore.Weighted
}

// NewSyncService creates a new sync service.
func NewSyncService(
	db *sqlx.DB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	cfg config.DockerSyncConfig,
) *SyncService {
	maxConc := int64(cfg.MaxConcurrent)
	if maxConc <= 0 {
		maxConc = 3
	}
	return &SyncService{
		db:         db,
		cache:      cacheStore,
		scanEngine: scanEngine,
		policyEng:  policyEngine,
		cfg:        cfg,
		sem:        semaphore.NewWeighted(maxConc),
	}
}

// Start runs the sync loop until ctx is cancelled.
func (s *SyncService) Start(ctx context.Context) {
	interval, err := time.ParseDuration(s.cfg.Interval)
	if err != nil {
		interval = 6 * time.Hour
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Info().Dur("interval", interval).Msg("docker sync: service started")

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("docker sync: service stopped")
			return
		case <-ticker.C:
			s.syncAll(ctx)
		}
	}
}

// syncAll iterates all sync-enabled upstream repos and syncs them.
func (s *SyncService) syncAll(ctx context.Context) {
	repos, err := listSyncableRepos(s.db)
	if err != nil {
		log.Error().Err(err).Msg("docker sync: failed to list repos")
		return
	}

	log.Info().Int("repos", len(repos)).Msg("docker sync: starting sync cycle")

	for _, repo := range repos {
		if ctx.Err() != nil {
			return
		}
		if err := s.sem.Acquire(ctx, 1); err != nil {
			return
		}
		go func(r DockerRepository) {
			defer s.sem.Release(1)
			s.syncRepository(ctx, r)
		}(repo)
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./internal/adapter/docker/ -run TestSyncService_StartsAndStops -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/docker/sync.go internal/adapter/docker/sync_test.go
git commit -m "feat(docker): add SyncService with start/stop lifecycle"
```

---

### Task 2: Sync Single Repository Logic

**Files:**
- Modify: `internal/adapter/docker/sync.go`
- Modify: `internal/adapter/docker/sync_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestSyncService_SyncRepository_DetectsChange(t *testing.T) {
	// Setup: insert a docker_repository + docker_tag with known digest
	// Mock upstream returns different manifest digest
	// After sync: tag should be updated, re-scan triggered
}

func TestSyncService_SyncRepository_NoChange_SkipsRescan(t *testing.T) {
	// Setup: insert repo with last_synced_at = now
	// Mock upstream returns same digest
	// After sync: no re-scan (within rescan_interval)
}

func TestSyncService_SyncRepository_Upstream404_DisablesSync(t *testing.T) {
	// Setup: insert repo
	// Mock upstream returns 404
	// After sync: sync_enabled = false
}
```

- [ ] **Step 2: Implement syncRepository**

```go
func (s *SyncService) syncRepository(ctx context.Context, repo DockerRepository) {
	// 1. Fetch manifest from upstream
	// 2. Compare digest with stored docker_tags.manifest_digest
	// 3. If different → re-pull, re-scan, update tag
	// 4. If same → check rescan_interval, re-scan if due
	// 5. Handle errors per error table
	// 6. Update last_synced_at
}
```

- [ ] **Step 3: Implement listSyncableRepos helper**

```go
func listSyncableRepos(db *sqlx.DB) ([]DockerRepository, error) {
	var repos []DockerRepository
	return repos, db.Select(&repos,
		"SELECT * FROM docker_repositories WHERE sync_enabled = 1 AND is_internal = 0 ORDER BY last_synced_at ASC NULLS FIRST")
}
```

- [ ] **Step 4: Run tests, verify pass**

- [ ] **Step 5: Commit**

```bash
git add internal/adapter/docker/sync.go internal/adapter/docker/sync_test.go
git commit -m "feat(docker): sync single repository with change detection"
```

---

### Task 3: Error Handling — Retry, Backoff, Disable

**Files:**
- Modify: `internal/adapter/docker/sync.go`
- Modify: `internal/adapter/docker/sync_test.go`

- [ ] **Step 1: Write tests for each error scenario**

Test upstream unreachable (retry), 404 (disable sync), 429 (backoff), scan failure (fail open).

- [ ] **Step 2: Implement error handling in syncRepository**

- [ ] **Step 3: Run tests, verify pass**

- [ ] **Step 4: Commit**

```bash
git add internal/adapter/docker/sync.go internal/adapter/docker/sync_test.go
git commit -m "feat(docker): sync error handling - retry, backoff, disable"
```

---

### Task 4: Integrate SyncService into main.go

**Files:**
- Modify: `cmd/shieldoo-gate/main.go`

- [ ] **Step 1: Start SyncService in main.go**

After creating the Docker adapter, start the sync service if enabled:

```go
// Start Docker sync service (if enabled)
if cfg.Upstreams.Docker.Sync.Enabled {
    syncSvc := docker.NewSyncService(db, cacheStore, scanEngine, policyEngine, cfg.Upstreams.Docker.Sync)
    go syncSvc.Start(ctx)
    log.Info().Msg("docker sync service enabled")
}
```

The `ctx` from `context.WithCancel` at line 189 is already used for graceful shutdown — the sync service will stop when `cancel()` is called.

- [ ] **Step 2: Verify compilation and startup**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go build ./cmd/shieldoo-gate/`
Expected: Compiles

- [ ] **Step 3: Commit**

```bash
git add cmd/shieldoo-gate/main.go
git commit -m "feat(docker): integrate SyncService into main.go startup"
```

---

### Task 5: Documentation + Final Verification

- [ ] **Step 1: Update docs for sync feature**
- [ ] **Step 2: Run full test suite with race detector**

Run: `cd /Users/valda/src/projects/shieldoo-gate && go test ./... -count=1 -race`
Expected: PASS

- [ ] **Step 3: Build + lint**

Run: `cd /Users/valda/src/projects/shieldoo-gate && make build && make lint`

- [ ] **Step 4: Commit**

```bash
git add docs/
git commit -m "docs(docker): document scheduled sync feature"
```
