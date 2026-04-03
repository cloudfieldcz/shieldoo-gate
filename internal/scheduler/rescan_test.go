package scheduler

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// --- test helpers ---

// setupTestDB creates an in-memory SQLite database with migrations applied.
func setupTestDB(t *testing.T) *config.GateDB {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// insertTestArtifact inserts a test artifact and status into the database.
func insertTestArtifact(t *testing.T, db *config.GateDB, id, ecosystem, name, version string, status model.Status, rescanDueAt *time.Time) {
	t.Helper()
	now := time.Now().UTC()
	_, err := db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, '', 'abc123', 100, ?, ?, '')`,
		id, ecosystem, name, version, now, now,
	)
	require.NoError(t, err)

	_, err = db.Exec(
		`INSERT INTO artifact_status (artifact_id, status, quarantine_reason, rescan_due_at)
		 VALUES (?, ?, '', ?)`,
		id, string(status), rescanDueAt,
	)
	require.NoError(t, err)
}

// getArtifactStatus reads the current status of an artifact from the DB.
func getArtifactStatus(t *testing.T, db *config.GateDB, artifactID string) model.ArtifactStatus {
	t.Helper()
	var s model.ArtifactStatus
	err := db.Get(&s,
		`SELECT artifact_id, status, quarantine_reason, quarantined_at, released_at, rescan_due_at, last_scan_id
		 FROM artifact_status WHERE artifact_id = ?`, artifactID)
	require.NoError(t, err)
	return s
}

// stubCacheStore is a simple test CacheStore that maps artifact IDs to paths.
type stubCacheStore struct {
	paths map[string]string
}

func (c *stubCacheStore) Get(_ context.Context, artifactID string) (string, error) {
	if p, ok := c.paths[artifactID]; ok {
		return p, nil
	}
	return "", cache.ErrNotFound
}
func (c *stubCacheStore) Put(_ context.Context, _ scanner.Artifact, _ string) error { return nil }
func (c *stubCacheStore) Delete(_ context.Context, _ string) error                  { return nil }
func (c *stubCacheStore) List(_ context.Context, _ cache.CacheFilter) ([]string, error) {
	return nil, nil
}
func (c *stubCacheStore) Stats(_ context.Context) (cache.CacheStats, error) {
	return cache.CacheStats{}, nil
}

// stubScanner always returns the configured verdict.
type stubScanner struct {
	verdict    scanner.Verdict
	shouldFail bool
}

func (s *stubScanner) Name() string    { return "stub" }
func (s *stubScanner) Version() string { return "1.0" }
func (s *stubScanner) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{scanner.EcosystemPyPI, scanner.EcosystemNPM, scanner.EcosystemNuGet, scanner.EcosystemDocker}
}
func (s *stubScanner) Scan(_ context.Context, _ scanner.Artifact) (scanner.ScanResult, error) {
	if s.shouldFail {
		return scanner.ScanResult{}, assert.AnError
	}
	return scanner.ScanResult{
		Verdict:    s.verdict,
		Confidence: 0.9,
		ScannerID:  "stub",
		ScannedAt:  time.Now(),
	}, nil
}
func (s *stubScanner) HealthCheck(_ context.Context) error { return nil }

// createTempFile creates a temporary file for the test and returns its path.
func createTempFile(t *testing.T) string {
	t.Helper()
	f, err := os.CreateTemp("", "rescan-test-*.tmp")
	require.NoError(t, err)
	_, _ = f.WriteString("test artifact content")
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

// --- tests ---

func TestRescanScheduler_SelectsOnlyPendingScan(t *testing.T) {
	db := setupTestDB(t)

	past := time.Now().UTC().Add(-1 * time.Hour)

	// Insert a CLEAN artifact with rescan_due_at in the past — should NOT be selected.
	insertTestArtifact(t, db, "pypi:clean-pkg:1.0", "pypi", "clean-pkg", "1.0", model.StatusClean, &past)
	// Insert a PENDING_SCAN artifact — should be selected.
	insertTestArtifact(t, db, "pypi:pending-pkg:1.0", "pypi", "pending-pkg", "1.0", model.StatusPendingScan, nil)

	sched := NewRescanScheduler(db, &stubCacheStore{}, nil, nil, config.RescanConfig{
		Enabled:       true,
		Interval:      "1h",
		BatchSize:     10,
		MaxConcurrent: 1,
	})

	ctx := context.Background()
	artifacts, err := sched.selectArtifacts(ctx)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)
	assert.Equal(t, "pypi:pending-pkg:1.0", artifacts[0].ID)
}

func TestRescanScheduler_SkipsNonPendingScan(t *testing.T) {
	db := setupTestDB(t)

	past := time.Now().UTC().Add(-1 * time.Hour)

	// None of these should be selected — only PENDING_SCAN is picked up.
	insertTestArtifact(t, db, "pypi:quarantined:1.0", "pypi", "quarantined", "1.0", model.StatusQuarantined, &past)
	insertTestArtifact(t, db, "pypi:clean:1.0", "pypi", "clean", "1.0", model.StatusClean, &past)
	insertTestArtifact(t, db, "pypi:suspicious:1.0", "pypi", "suspicious", "1.0", model.StatusSuspicious, &past)

	sched := NewRescanScheduler(db, &stubCacheStore{}, nil, nil, config.RescanConfig{
		Enabled:       true,
		Interval:      "1h",
		BatchSize:     10,
		MaxConcurrent: 1,
	})

	ctx := context.Background()
	artifacts, err := sched.selectArtifacts(ctx)
	require.NoError(t, err)
	assert.Len(t, artifacts, 0)
}

func TestRescanScheduler_FailOpen_ScanError(t *testing.T) {
	db := setupTestDB(t)
	tmpPath := createTempFile(t)

	insertTestArtifact(t, db, "pypi:pkg:1.0", "pypi", "pkg", "1.0", model.StatusPendingScan, nil)

	cacheStore := &stubCacheStore{paths: map[string]string{"pypi:pkg:1.0": tmpPath}}

	// Scanner that always fails.
	failScanner := &stubScanner{shouldFail: true}
	scanEngine := scanner.NewEngine([]scanner.Scanner{failScanner}, 30*time.Second)
	policyEng := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
	}, nil)

	sched := NewRescanScheduler(db, cacheStore, scanEngine, policyEng, config.RescanConfig{
		Enabled:       true,
		Interval:      "1h",
		BatchSize:     10,
		MaxConcurrent: 1,
	})

	// Run rescan. Scanner fails but the engine itself returns fail-open results (VerdictClean with error).
	// The scheduler should detect that scan results contain errors but still process.
	ctx := context.Background()
	sched.runCycle(ctx)

	// Status should be CLEAN (fail-open). The scan engine handles the fail-open
	// by returning VerdictClean results, so the policy engine evaluates them as clean.
	status := getArtifactStatus(t, db, "pypi:pkg:1.0")
	assert.Equal(t, model.StatusClean, status.Status)
	assert.Empty(t, status.QuarantineReason)
}

func TestRescanScheduler_CacheMiss_SkipsArtifact(t *testing.T) {
	db := setupTestDB(t)

	insertTestArtifact(t, db, "pypi:pkg:1.0", "pypi", "pkg", "1.0", model.StatusPendingScan, nil)

	// Empty cache — artifact not found.
	cacheStore := &stubCacheStore{paths: map[string]string{}}
	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEng := policy.NewEngine(policy.EngineConfig{}, nil)

	sched := NewRescanScheduler(db, cacheStore, scanEngine, policyEng, config.RescanConfig{
		Enabled:       true,
		Interval:      "1h",
		BatchSize:     10,
		MaxConcurrent: 1,
	})

	ctx := context.Background()
	sched.runCycle(ctx)

	// Status should remain PENDING_SCAN (not quarantined on cache miss).
	status := getArtifactStatus(t, db, "pypi:pkg:1.0")
	assert.Equal(t, model.StatusPendingScan, status.Status)
	// rescan_due_at should be cleared (artifact evicted from cache).
	assert.Nil(t, status.RescanDueAt)
}

func TestRescanScheduler_ClearsRescanDueAtAfterSuccess(t *testing.T) {
	db := setupTestDB(t)
	tmpPath := createTempFile(t)

	insertTestArtifact(t, db, "pypi:pkg:1.0", "pypi", "pkg", "1.0", model.StatusPendingScan, nil)

	cacheStore := &stubCacheStore{paths: map[string]string{"pypi:pkg:1.0": tmpPath}}
	stubScan := &stubScanner{verdict: scanner.VerdictClean}
	scanEngine := scanner.NewEngine([]scanner.Scanner{stubScan}, 30*time.Second)
	policyEng := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
	}, nil)

	sched := NewRescanScheduler(db, cacheStore, scanEngine, policyEng, config.RescanConfig{
		Enabled:       true,
		Interval:      "1h",
		BatchSize:     10,
		MaxConcurrent: 1,
	})

	ctx := context.Background()
	sched.runCycle(ctx)

	// After successful rescan, status should be CLEAN and rescan_due_at should be NULL
	// (no automatic periodic rescans — only manual rescans are supported).
	status := getArtifactStatus(t, db, "pypi:pkg:1.0")
	assert.Equal(t, model.StatusClean, status.Status)
	assert.Nil(t, status.RescanDueAt)
}

func TestRescanScheduler_QuarantinesOnMalicious(t *testing.T) {
	db := setupTestDB(t)
	tmpPath := createTempFile(t)

	insertTestArtifact(t, db, "pypi:evil:1.0", "pypi", "evil", "1.0", model.StatusPendingScan, nil)

	cacheStore := &stubCacheStore{paths: map[string]string{"pypi:evil:1.0": tmpPath}}
	// Scanner returns MALICIOUS verdict.
	malScanner := &stubScanner{verdict: scanner.VerdictMalicious}
	scanEngine := scanner.NewEngine([]scanner.Scanner{malScanner}, 30*time.Second)
	policyEng := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
	}, nil)

	sched := NewRescanScheduler(db, cacheStore, scanEngine, policyEng, config.RescanConfig{
		Enabled:       true,
		Interval:      "1h",
		BatchSize:     10,
		MaxConcurrent: 1,
	})

	ctx := context.Background()
	sched.runCycle(ctx)

	// Should be quarantined now.
	status := getArtifactStatus(t, db, "pypi:evil:1.0")
	assert.Equal(t, model.StatusQuarantined, status.Status)
	assert.Contains(t, status.QuarantineReason, "block threshold")
	assert.Nil(t, status.RescanDueAt, "quarantined artifacts should not have rescan_due_at")

	// Audit log should record the quarantine event.
	var auditCount int
	err := db.Get(&auditCount, `SELECT COUNT(*) FROM audit_log WHERE event_type = 'QUARANTINED' AND artifact_id = 'pypi:evil:1.0'`)
	require.NoError(t, err)
	assert.Equal(t, 1, auditCount)
}

func TestRescanScheduler_ConcurrencyLimit(t *testing.T) {
	db := setupTestDB(t)
	tmpPath := createTempFile(t)

	// Insert 10 PENDING_SCAN artifacts.
	for i := 0; i < 10; i++ {
		id := "pypi:pkg" + string(rune('a'+i)) + ":1.0"
		name := "pkg" + string(rune('a'+i))
		insertTestArtifact(t, db, id, "pypi", name, "1.0", model.StatusPendingScan, nil)
	}

	paths := make(map[string]string)
	for i := 0; i < 10; i++ {
		id := "pypi:pkg" + string(rune('a'+i)) + ":1.0"
		paths[id] = tmpPath
	}
	cacheStore := &stubCacheStore{paths: paths}

	// Scanner that tracks maximum concurrent invocations.
	var concurrent int64
	var maxConcurrent int64
	slowScanner := &concurrencyTracker{
		concurrent:    &concurrent,
		maxConcurrent: &maxConcurrent,
		delay:         50 * time.Millisecond,
	}

	scanEngine := scanner.NewEngine([]scanner.Scanner{slowScanner}, 30*time.Second)
	policyEng := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
	}, nil)

	sched := NewRescanScheduler(db, cacheStore, scanEngine, policyEng, config.RescanConfig{
		Enabled:       true,
		Interval:      "1h",
		BatchSize:     10,
		MaxConcurrent: 3, // limit to 3 concurrent
	})

	ctx := context.Background()
	sched.runCycle(ctx)

	// Max concurrent scans should not exceed MaxConcurrent.
	assert.LessOrEqual(t, atomic.LoadInt64(&maxConcurrent), int64(3),
		"concurrent scans should not exceed max_concurrent=3")
}

// concurrencyTracker is a scanner that tracks concurrent invocations.
type concurrencyTracker struct {
	concurrent    *int64
	maxConcurrent *int64
	delay         time.Duration
}

func (s *concurrencyTracker) Name() string    { return "concurrency-tracker" }
func (s *concurrencyTracker) Version() string { return "1.0" }
func (s *concurrencyTracker) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{scanner.EcosystemPyPI, scanner.EcosystemNPM, scanner.EcosystemNuGet, scanner.EcosystemDocker}
}
func (s *concurrencyTracker) Scan(_ context.Context, _ scanner.Artifact) (scanner.ScanResult, error) {
	cur := atomic.AddInt64(s.concurrent, 1)
	// Update max seen concurrency.
	for {
		old := atomic.LoadInt64(s.maxConcurrent)
		if cur <= old || atomic.CompareAndSwapInt64(s.maxConcurrent, old, cur) {
			break
		}
	}
	time.Sleep(s.delay)
	atomic.AddInt64(s.concurrent, -1)
	return scanner.ScanResult{
		Verdict:    scanner.VerdictClean,
		Confidence: 0.9,
		ScannerID:  "concurrency-tracker",
		ScannedAt:  time.Now(),
	}, nil
}
func (s *concurrencyTracker) HealthCheck(_ context.Context) error { return nil }

func TestRescanScheduler_StartStop(t *testing.T) {
	db := setupTestDB(t)
	cacheStore := &stubCacheStore{paths: map[string]string{}}
	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEng := policy.NewEngine(policy.EngineConfig{}, nil)

	sched := NewRescanScheduler(db, cacheStore, scanEngine, policyEng, config.RescanConfig{
		Enabled:       true,
		Interval:      "100ms",
		BatchSize:     10,
		MaxConcurrent: 1,
	})

	sched.Start()

	// Let it tick at least once.
	time.Sleep(250 * time.Millisecond)

	// Stop should be graceful and not hang.
	done := make(chan struct{})
	go func() {
		sched.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Success.
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return within 5 seconds")
	}
}
