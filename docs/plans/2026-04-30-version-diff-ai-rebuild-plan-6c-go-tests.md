# Version-Diff AI Rebuild — Phase 6c: Go scanner tests

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cover the Phase 6b `Scan` flow with table-driven tests using a mock gRPC bridge, an in-memory SQLite, and a small in-memory cache fake. The pattern follows [internal/scanner/ai/scanner_test.go](../../internal/scanner/ai/scanner_test.go).

**Architecture:** All tests are in [internal/scanner/versiondiff/scanner_test.go](../../internal/scanner/versiondiff/scanner_test.go). The mock bridge implements `pb.UnimplementedScannerBridgeServer` and overrides `ScanArtifactDiff` + `HealthCheck`. A `*config.GateDB` from `InitDB(SQLiteMemoryConfig())` runs migrations including 024. A trivial `inMemoryCache` satisfies `cache.CacheStore` by writing files into a `t.TempDir()`.

**Tech Stack:** Go 1.25, `google.golang.org/grpc`, `github.com/stretchr/testify`, in-memory SQLite via the existing helper `SQLiteMemoryConfig()`.

**Index:** [`plan-index.md`](./2026-04-30-version-diff-ai-rebuild-plan-index.md)

---

## Context for executor

The mock bridge approach is identical to `ai/scanner_test.go`: spin up a `*grpc.Server` on a Unix socket, register a struct that embeds `pb.UnimplementedScannerBridgeServer`, override the methods that matter. `dialBridge` (Phase 6a) connects via `unix://` URL, and `grpc.NewClient` is lazy so the mock listening before the dial is sufficient.

A previous-version artifact must exist in the DB so the `WHERE … AND a.id != ?` query returns it. We seed two `artifacts` rows + matching `artifact_status` rows.

The `cache.CacheStore` interface only needs `Get` and `Put` for our purposes. We implement an in-memory adapter that writes to `t.TempDir()` so `verifySHA256` on the prev path passes.

---

### Task 1: Build the mock bridge + helpers

**Files:**
- Create/Replace: `internal/scanner/versiondiff/scanner_test.go`

- [ ] **Step 1: Write the test scaffold (mock bridge, in-memory cache, helpers)**

Replace [internal/scanner/versiondiff/scanner_test.go](../../internal/scanner/versiondiff/scanner_test.go) with:

```go
package versiondiff

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	pb "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto"
)

// --- Mock bridge ----------------------------------------------------------

type mockBridge struct {
	pb.UnimplementedScannerBridgeServer

	scanFn   func(ctx context.Context, req *pb.DiffScanRequest) (*pb.DiffScanResponse, error)
	healthFn func() *pb.HealthResponse

	calls atomic.Int32
}

func (m *mockBridge) ScanArtifactDiff(ctx context.Context, req *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
	m.calls.Add(1)
	if m.scanFn != nil {
		return m.scanFn(ctx, req)
	}
	return &pb.DiffScanResponse{Verdict: "UNKNOWN"}, nil
}

func (m *mockBridge) HealthCheck(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	if m.healthFn != nil {
		return m.healthFn(), nil
	}
	return &pb.HealthResponse{Healthy: true, Version: "test"}, nil
}

func startMockBridge(t *testing.T, m *mockBridge) string {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "bridge.sock")
	lis, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	srv := grpc.NewServer()
	pb.RegisterScannerBridgeServer(srv, m)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop()
	})
	return sockPath
}

// --- In-memory cache ------------------------------------------------------

// fakeCache implements the full cache.CacheStore interface. Only Get is
// exercised by the version-diff tests; the rest are stubs that satisfy the
// compile-time check `var _ cache.CacheStore = (*fakeCache)(nil)`.
type fakeCache struct {
	dir string
}

var _ cache.CacheStore = (*fakeCache)(nil)

func (c *fakeCache) Get(_ context.Context, artifactID string) (string, error) {
	p := filepath.Join(c.dir, artifactID)
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("not cached: %w", err)
	}
	return p, nil
}

func (c *fakeCache) Put(_ context.Context, _ scanner.Artifact, _ string) error {
	return errors.New("not used in tests")
}

func (c *fakeCache) Delete(_ context.Context, _ string) error {
	return errors.New("not used in tests")
}

func (c *fakeCache) List(_ context.Context, _ cache.CacheFilter) ([]string, error) {
	return nil, errors.New("not used in tests")
}

func (c *fakeCache) Stats(_ context.Context) (cache.CacheStats, error) {
	return cache.CacheStats{}, errors.New("not used in tests")
}

func newFakeCache(t *testing.T, files map[string][]byte) *fakeCache {
	t.Helper()
	dir := t.TempDir()
	for id, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, id), content, 0o644))
	}
	return &fakeCache{dir: dir}
}

func sha256Hex(blob []byte) string {
	h := sha256.Sum256(blob)
	return hex.EncodeToString(h[:])
}

// --- DB seed --------------------------------------------------------------

func newTestDB(t *testing.T) *config.GateDB {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seedArtifactPair(t *testing.T, db *config.GateDB, eco, name, newID, newVer, newSHA, oldID, oldVer, oldSHA string, oldCreatedHourAgo bool) {
	t.Helper()
	now := time.Now().UTC()
	oldTime := now.Add(-time.Hour)
	if !oldCreatedHourAgo {
		oldTime = now.Add(-time.Minute)
	}
	_, err := db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, '', ?, 100, ?, ?, '/tmp/' || ?)`,
		newID, eco, name, newVer, newSHA, now, now, newID,
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, '', ?, 100, ?, ?, '/tmp/' || ?)`,
		oldID, eco, name, oldVer, oldSHA, oldTime, oldTime, oldID,
	)
	require.NoError(t, err)
	_, err = db.Exec(
		`INSERT INTO artifact_status (artifact_id, status) VALUES (?, 'CLEAN'), (?, 'CLEAN')`,
		newID, oldID,
	)
	require.NoError(t, err)
}

// --- Common config --------------------------------------------------------

func defaultCfg(socket string) config.VersionDiffConfig {
	return config.VersionDiffConfig{
		Enabled:                 true,
		Mode:                    "active",
		MaxArtifactSizeMB:       50,
		MaxExtractedSizeMB:      50,
		MaxExtractedFiles:       5000,
		ScannerTimeout:          "10s",
		BridgeSocket:            socket,
		MinConfidence:           0.6,
		PerPackageRateLimit:     10,
		DailyCostLimitUSD:       5.0,
		CircuitBreakerThreshold: 3,
	}
}
```

- [ ] **Step 2: Build (only — tests come next)**

```bash
go build ./internal/scanner/versiondiff/
```

Expected: success.

(No commit yet.)

---

### Task 2: Add interface + smoke tests

**Files:**
- Modify: `internal/scanner/versiondiff/scanner_test.go`

- [ ] **Step 1: Append basic identity tests**

Append to the test file:

```go
func TestVersionDiffScanner_InterfaceCompliance(t *testing.T) {
	var _ scanner.Scanner = (*VersionDiffScanner)(nil)
}

func TestVersionDiffScanner_NameVersion(t *testing.T) {
	s := &VersionDiffScanner{}
	assert.Equal(t, "version-diff", s.Name())
	assert.Equal(t, "2.0.0", s.Version())
}

func TestVersionDiffScanner_SupportedEcosystems(t *testing.T) {
	s := &VersionDiffScanner{}
	got := s.SupportedEcosystems()
	for _, eco := range []scanner.Ecosystem{
		scanner.EcosystemPyPI, scanner.EcosystemNPM, scanner.EcosystemNuGet,
		scanner.EcosystemMaven, scanner.EcosystemRubyGems,
	} {
		assert.Contains(t, got, eco)
	}
	assert.NotContains(t, got, scanner.EcosystemDocker)
	assert.NotContains(t, got, scanner.EcosystemGo)
}

func TestNewVersionDiffScanner_BridgeSocketRequired(t *testing.T) {
	db := newTestDB(t)
	cs := newFakeCache(t, nil)
	cfg := defaultCfg("")
	_, err := NewVersionDiffScanner(db, cs, cfg)
	assert.Error(t, err)
}
```

- [ ] **Step 2: Run tests**

```bash
go test ./internal/scanner/versiondiff/ -v -run "InterfaceCompliance|NameVersion|SupportedEcosystems|BridgeSocketRequired"
```

Expected: PASS.

(No commit yet.)

---

### Task 3: Add Scan-flow tests

**Files:**
- Modify: `internal/scanner/versiondiff/scanner_test.go`

- [ ] **Step 1: Append the Scan tests**

Append:

```go
// --- Allowlist + size guard -------------------------------------------------

func TestScan_Allowlisted_ReturnsCleanWithoutBridge(t *testing.T) {
	mb := &mockBridge{}
	sock := startMockBridge(t, mb)

	db := newTestDB(t)
	cs := newFakeCache(t, nil)
	cfg := defaultCfg(sock)
	cfg.Allowlist = []string{"safe-pkg"}

	s, err := NewVersionDiffScanner(db, cs, cfg)
	require.NoError(t, err)
	defer s.Close()

	res, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:safe-pkg:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "safe-pkg", Version: "1.0",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, res.Verdict)
	assert.Equal(t, int32(0), mb.calls.Load(), "bridge must not be called")
}

func TestScan_Oversized_ReturnsCleanWithoutBridge(t *testing.T) {
	mb := &mockBridge{}
	sock := startMockBridge(t, mb)

	db := newTestDB(t)
	cs := newFakeCache(t, nil)
	cfg := defaultCfg(sock)
	cfg.MaxArtifactSizeMB = 1

	s, _ := NewVersionDiffScanner(db, cs, cfg)
	defer s.Close()

	res, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:big:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "big", Version: "1.0",
		SizeBytes: 10 * 1024 * 1024,
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, res.Verdict)
	assert.Equal(t, int32(0), mb.calls.Load())
}

// --- No previous version ---------------------------------------------------

func TestScan_NoPreviousVersion_ReturnsCleanNoDBRow(t *testing.T) {
	mb := &mockBridge{}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, nil)

	s, _ := NewVersionDiffScanner(db, cs, defaultCfg(sock))
	defer s.Close()

	res, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:lonely:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "lonely", Version: "1.0",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, res.Verdict)
	assert.Equal(t, int32(0), mb.calls.Load())

	var n int
	require.NoError(t, db.Get(&n, "SELECT COUNT(*) FROM version_diff_results"))
	assert.Equal(t, 0, n)
}

// --- Bridge verdicts -------------------------------------------------------

func TestScan_BridgeReturnsClean(t *testing.T) {
	prevContent := []byte("previous content")
	prevSHA := sha256Hex(prevContent)

	mb := &mockBridge{
		scanFn: func(_ context.Context, req *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
			assert.Equal(t, prevSHA, req.PreviousPathSha256)
			return &pb.DiffScanResponse{Verdict: "CLEAN", Confidence: 0.6, ModelUsed: "gpt-5.4-mini"}, nil
		},
	}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:foo:0.9": prevContent})
	seedArtifactPair(t, db, "pypi", "foo",
		"pypi:foo:1.0", "1.0", "newsha",
		"pypi:foo:0.9", "0.9", prevSHA, true)

	s, _ := NewVersionDiffScanner(db, cs, defaultCfg(sock))
	defer s.Close()

	res, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:foo:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "foo", Version: "1.0",
		SHA256: "newsha",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, res.Verdict)
	assert.Equal(t, int32(1), mb.calls.Load())

	var n int
	require.NoError(t, db.Get(&n, "SELECT COUNT(*) FROM version_diff_results"))
	assert.Equal(t, 1, n, "CLEAN verdict should persist for cache")
}

func TestScan_BridgeReturnsSuspiciousAboveMinConfidence(t *testing.T) {
	prevContent := []byte("p")
	prevSHA := sha256Hex(prevContent)
	mb := &mockBridge{
		scanFn: func(_ context.Context, _ *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
			return &pb.DiffScanResponse{
				Verdict: "SUSPICIOUS", Confidence: 0.85,
				Findings: []string{"new subprocess in setup.py"},
				Explanation: "looks bad",
				ModelUsed:   "gpt-5.4-mini",
			}, nil
		},
	}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:x:0.9": prevContent})
	seedArtifactPair(t, db, "pypi", "x",
		"pypi:x:1.0", "1.0", "n",
		"pypi:x:0.9", "0.9", prevSHA, true)

	s, _ := NewVersionDiffScanner(db, cs, defaultCfg(sock))
	defer s.Close()
	res, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:x:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "x", Version: "1.0", SHA256: "n",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictSuspicious, res.Verdict)
	assert.NotEmpty(t, res.Findings)
}

func TestScan_BridgeReturnsSuspiciousBelowMinConfidence_DowngradesAndAuditsCLEAN(t *testing.T) {
	prevContent := []byte("p")
	prevSHA := sha256Hex(prevContent)
	mb := &mockBridge{
		scanFn: func(_ context.Context, _ *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
			return &pb.DiffScanResponse{
				Verdict: "SUSPICIOUS", Confidence: 0.30,
				Findings: []string{"weak signal"},
				ModelUsed: "gpt-5.4-mini",
			}, nil
		},
	}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:x:0.9": prevContent})
	seedArtifactPair(t, db, "pypi", "x",
		"pypi:x:1.0", "1.0", "n",
		"pypi:x:0.9", "0.9", prevSHA, true)

	cfg := defaultCfg(sock)
	cfg.MinConfidence = 0.6
	s, _ := NewVersionDiffScanner(db, cs, cfg)
	defer s.Close()

	res, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:x:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "x", Version: "1.0", SHA256: "n",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, res.Verdict, "should downgrade")
	assert.Equal(t, float32(0), res.Confidence, "downgrade-to-CLEAN must not surface SUSPICIOUS confidence")

	var auditCount int
	require.NoError(t, db.Get(&auditCount,
		"SELECT COUNT(*) FROM audit_log WHERE event_type = 'SCANNER_VERDICT_DOWNGRADED'"))
	assert.Equal(t, 1, auditCount, "expected audit_log row for downgrade")

	// Critical: SUSPICIOUS→CLEAN downgrade must NOT persist a cache row, so a
	// future prompt improvement that would correctly classify the same pair as
	// MALICIOUS isn't shadowed by a cached "downgraded CLEAN".
	var dbCount int
	require.NoError(t, db.Get(&dbCount, "SELECT COUNT(*) FROM version_diff_results"))
	assert.Equal(t, 0, dbCount, "low-confidence downgrade must not persist cache row")
}

func TestScan_BridgeReturnsMalicious_DowngradesToSuspicious(t *testing.T) {
	prevContent := []byte("p")
	prevSHA := sha256Hex(prevContent)
	mb := &mockBridge{
		scanFn: func(_ context.Context, _ *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
			return &pb.DiffScanResponse{
				Verdict: "MALICIOUS", Confidence: 0.95,
				Findings: []string{"setup.py exfiltrates ~/.aws"},
				Explanation: "clear malware",
				ModelUsed: "gpt-5.4-mini",
			}, nil
		},
	}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:x:0.9": prevContent})
	seedArtifactPair(t, db, "pypi", "x",
		"pypi:x:1.0", "1.0", "n",
		"pypi:x:0.9", "0.9", prevSHA, true)

	s, _ := NewVersionDiffScanner(db, cs, defaultCfg(sock))
	defer s.Close()
	res, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:x:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "x", Version: "1.0", SHA256: "n",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictSuspicious, res.Verdict, "MALICIOUS must downgrade to SUSPICIOUS")
	assert.NotEmpty(t, res.Findings)
	assert.Equal(t, scanner.SeverityCritical, res.Findings[0].Severity)

	var rawAI string
	require.NoError(t, db.Get(&rawAI,
		"SELECT ai_verdict FROM version_diff_results WHERE artifact_id = ?", "pypi:x:1.0"))
	assert.Equal(t, "MALICIOUS", rawAI, "raw AI verdict preserved for audit")

	var n int
	require.NoError(t, db.Get(&n, "SELECT COUNT(*) FROM audit_log WHERE event_type = 'SCANNER_VERDICT_DOWNGRADED'"))
	assert.Equal(t, 1, n)
}

func TestScan_BridgeReturnsUnknown_NoDBRow(t *testing.T) {
	prevContent := []byte("p")
	prevSHA := sha256Hex(prevContent)
	mb := &mockBridge{
		scanFn: func(_ context.Context, _ *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
			return &pb.DiffScanResponse{Verdict: "UNKNOWN", Confidence: 0.0}, nil
		},
	}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:x:0.9": prevContent})
	seedArtifactPair(t, db, "pypi", "x",
		"pypi:x:1.0", "1.0", "n",
		"pypi:x:0.9", "0.9", prevSHA, true)

	s, _ := NewVersionDiffScanner(db, cs, defaultCfg(sock))
	defer s.Close()
	res, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:x:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "x", Version: "1.0", SHA256: "n",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, res.Verdict)

	var n int
	require.NoError(t, db.Get(&n, "SELECT COUNT(*) FROM version_diff_results"))
	assert.Equal(t, 0, n, "UNKNOWN must NOT persist (cache integrity)")
}

func TestScan_BridgeError_FailsOpen(t *testing.T) {
	prevContent := []byte("p")
	prevSHA := sha256Hex(prevContent)
	mb := &mockBridge{
		scanFn: func(_ context.Context, _ *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
			return nil, errors.New("simulated bridge error")
		},
	}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:x:0.9": prevContent})
	seedArtifactPair(t, db, "pypi", "x",
		"pypi:x:1.0", "1.0", "n",
		"pypi:x:0.9", "0.9", prevSHA, true)

	s, _ := NewVersionDiffScanner(db, cs, defaultCfg(sock))
	defer s.Close()
	res, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:x:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "x", Version: "1.0", SHA256: "n",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, res.Verdict)
	assert.Error(t, res.Error)
}

func TestScan_BridgeReturnsMaliciousLowConfidence_StillDowngradesToSuspicious(t *testing.T) {
	// Defense against a future "optimization" that would gate MALICIOUS on
	// MinConfidence and flip it to CLEAN. MALICIOUS at any confidence MUST
	// downgrade to SUSPICIOUS, never below.
	prevContent := []byte("p")
	prevSHA := sha256Hex(prevContent)
	mb := &mockBridge{
		scanFn: func(_ context.Context, _ *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
			return &pb.DiffScanResponse{
				Verdict: "MALICIOUS", Confidence: 0.30, // far below MinConfidence
				Findings: []string{"low-conf MALICIOUS"},
				ModelUsed: "gpt-5.4-mini", PromptVersion: "abc123",
			}, nil
		},
	}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:x:0.9": prevContent})
	seedArtifactPair(t, db, "pypi", "x",
		"pypi:x:1.0", "1.0", "n",
		"pypi:x:0.9", "0.9", prevSHA, true)

	cfg := defaultCfg(sock)
	cfg.MinConfidence = 0.6 // would block SUSPICIOUS@0.3 — but MUST NOT touch MALICIOUS path
	s, _ := NewVersionDiffScanner(db, cs, cfg)
	defer s.Close()
	res, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:x:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "x", Version: "1.0", SHA256: "n",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictSuspicious, res.Verdict, "MALICIOUS at any confidence must reach SUSPICIOUS")
	assert.NotEmpty(t, res.Findings)
}

func TestScan_BridgeFindings_PersistedAsJSONArray(t *testing.T) {
	prevContent := []byte("p")
	prevSHA := sha256Hex(prevContent)
	mb := &mockBridge{
		scanFn: func(_ context.Context, _ *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
			return &pb.DiffScanResponse{
				Verdict: "SUSPICIOUS", Confidence: 0.85,
				Findings:    []string{"first finding", "second finding with \"quotes\""},
				Explanation: "ok",
				ModelUsed:   "gpt-5.4-mini", PromptVersion: "abc123",
			}, nil
		},
	}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:fj:0.9": prevContent})
	seedArtifactPair(t, db, "pypi", "fj",
		"pypi:fj:1.0", "1.0", "n",
		"pypi:fj:0.9", "0.9", prevSHA, true)

	s, _ := NewVersionDiffScanner(db, cs, defaultCfg(sock))
	defer s.Close()
	_, _ = s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:fj:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "fj", Version: "1.0", SHA256: "n",
	})

	var raw string
	require.NoError(t, db.Get(&raw,
		"SELECT findings_json FROM version_diff_results WHERE artifact_id = ?", "pypi:fj:1.0"))
	assert.Contains(t, raw, "first finding")
	assert.Contains(t, raw, "second finding")
	// Valid JSON array — not empty literal, not malformed
	assert.True(t, strings.HasPrefix(raw, "["), "findings_json must be JSON array, got %q", raw)
}

// --- Idempotency cache hit ------------------------------------------------

func TestScan_CachedRowReturnedWithoutBridgeCall(t *testing.T) {
	prevContent := []byte("p")
	prevSHA := sha256Hex(prevContent)

	mb := &mockBridge{
		scanFn: func(_ context.Context, _ *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
			t.Fatalf("bridge must not be called on cache hit")
			return nil, nil
		},
	}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:x:0.9": prevContent})
	seedArtifactPair(t, db, "pypi", "x",
		"pypi:x:1.0", "1.0", "n",
		"pypi:x:0.9", "0.9", prevSHA, true)

	// Pre-populate version_diff_results — must match the model+prompt key
	// the scanner uses.
	_, err := db.Exec(
		`INSERT INTO version_diff_results
		 (artifact_id, previous_artifact, diff_at, verdict, findings_json,
		  ai_verdict, ai_confidence, ai_model_used, ai_prompt_version, ai_tokens_used)
		 VALUES (?, ?, ?, 'CLEAN', '[]', 'CLEAN', 0.6, 'gpt-5.4-mini', '', 100)`,
		"pypi:x:1.0", "pypi:x:0.9", time.Now().UTC(),
	)
	require.NoError(t, err)

	s, _ := NewVersionDiffScanner(db, cs, defaultCfg(sock))
	defer s.Close()
	res, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:x:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "x", Version: "1.0", SHA256: "n",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, res.Verdict)
	assert.Equal(t, int32(0), mb.calls.Load(), "cache hit must skip bridge")
}

// --- Concurrent same-pair singleflight + INSERT ON CONFLICT --------------

func TestScan_ConcurrentSamePair_SingleflightCoalesces(t *testing.T) {
	// Singleflight should make only ONE bridge call even with N concurrent
	// scans of the same pair. This test forces overlap with a sync barrier
	// inside the mock bridge so both goroutines are guaranteed in-flight.
	prevContent := []byte("p")
	prevSHA := sha256Hex(prevContent)

	const N = 5
	releaseFirst := make(chan struct{})
	firstCallEntered := make(chan struct{}, 1)
	mb := &mockBridge{
		scanFn: func(_ context.Context, _ *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
			// Signal that this bridge call has started, then wait for the test
			// to release. With singleflight only the first scan reaches here.
			select {
			case firstCallEntered <- struct{}{}:
			default:
			}
			<-releaseFirst
			return &pb.DiffScanResponse{
				Verdict: "CLEAN", Confidence: 0.6,
				ModelUsed: "gpt-5.4-mini", PromptVersion: "abc123",
			}, nil
		},
	}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:x:0.9": prevContent})
	seedArtifactPair(t, db, "pypi", "x",
		"pypi:x:1.0", "1.0", "n",
		"pypi:x:0.9", "0.9", prevSHA, true)

	s, _ := NewVersionDiffScanner(db, cs, defaultCfg(sock))
	defer s.Close()

	art := scanner.Artifact{
		ID: "pypi:x:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "x", Version: "1.0", SHA256: "n",
	}

	// Start N concurrent scans. Wait for the first to reach the bridge, then
	// release them all.
	var wg sync.WaitGroup
	startBarrier := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startBarrier // ensure all goroutines try to enter together
			_, _ = s.Scan(context.Background(), art)
		}()
	}
	close(startBarrier)
	<-firstCallEntered
	close(releaseFirst) // unblock the (one) bridge call; followers all return via singleflight
	wg.Wait()

	assert.Equal(t, int32(1), mb.calls.Load(), "singleflight must coalesce N scans into 1 bridge call")

	var n int
	require.NoError(t, db.Get(&n,
		"SELECT COUNT(*) FROM version_diff_results WHERE artifact_id = ?", "pypi:x:1.0"))
	assert.Equal(t, 1, n, "exactly 1 row persisted")
}

// --- Shadow mode ----------------------------------------------------------

func TestScan_ShadowMode_VerdictForcedClean(t *testing.T) {
	prevContent := []byte("p")
	prevSHA := sha256Hex(prevContent)
	mb := &mockBridge{
		scanFn: func(_ context.Context, _ *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
			return &pb.DiffScanResponse{
				Verdict: "SUSPICIOUS", Confidence: 0.9,
				Findings: []string{"shadow mode test"},
				ModelUsed: "gpt-5.4-mini",
			}, nil
		},
	}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:x:0.9": prevContent})
	seedArtifactPair(t, db, "pypi", "x",
		"pypi:x:1.0", "1.0", "n",
		"pypi:x:0.9", "0.9", prevSHA, true)

	cfg := defaultCfg(sock)
	cfg.Mode = "shadow"
	s, _ := NewVersionDiffScanner(db, cs, cfg)
	defer s.Close()

	res, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:x:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "x", Version: "1.0", SHA256: "n",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, res.Verdict, "shadow mode forces CLEAN")
	assert.Empty(t, res.Findings, "shadow mode strips findings")

	var aiVerdict string
	require.NoError(t, db.Get(&aiVerdict,
		"SELECT ai_verdict FROM version_diff_results WHERE artifact_id = ?", "pypi:x:1.0"))
	assert.Equal(t, "SUSPICIOUS", aiVerdict, "DB row preserves raw AI verdict")
}

// --- Rate limit ------------------------------------------------------------

func TestScan_RateLimited_SkipsBridge(t *testing.T) {
	prevContent := []byte("p")
	prevSHA := sha256Hex(prevContent)
	mb := &mockBridge{
		scanFn: func(_ context.Context, _ *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
			return &pb.DiffScanResponse{Verdict: "CLEAN", Confidence: 0.6, ModelUsed: "gpt-5.4-mini"}, nil
		},
	}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:rl:0.9": prevContent})
	seedArtifactPair(t, db, "pypi", "rl",
		"pypi:rl:1.0", "1.0", "n",
		"pypi:rl:0.9", "0.9", prevSHA, true)

	cfg := defaultCfg(sock)
	cfg.PerPackageRateLimit = 1 // 1/h, burst 1
	s, _ := NewVersionDiffScanner(db, cs, cfg)
	defer s.Close()

	art := scanner.Artifact{
		ID: "pypi:rl:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "rl", Version: "1.0", SHA256: "n",
	}
	_, _ = s.Scan(context.Background(), art)
	calls1 := mb.calls.Load()
	// Reset cache row so the second scan would otherwise call the bridge.
	_, err := db.Exec("DELETE FROM version_diff_results WHERE artifact_id = ?", "pypi:rl:1.0")
	require.NoError(t, err)
	_, _ = s.Scan(context.Background(), art)
	calls2 := mb.calls.Load()
	assert.Equal(t, calls1, calls2, "second call within rate window must skip bridge")
}

// --- Circuit breaker -------------------------------------------------------

func TestScan_ConsecutiveBridgeErrors_OpensCircuit(t *testing.T) {
	prevContent := []byte("p")
	prevSHA := sha256Hex(prevContent)
	mb := &mockBridge{
		scanFn: func(_ context.Context, _ *pb.DiffScanRequest) (*pb.DiffScanResponse, error) {
			return nil, errors.New("oops")
		},
	}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:cb:0.9": prevContent})
	seedArtifactPair(t, db, "pypi", "cb",
		"pypi:cb:1.0", "1.0", "n",
		"pypi:cb:0.9", "0.9", prevSHA, true)

	cfg := defaultCfg(sock)
	cfg.CircuitBreakerThreshold = 2
	s, _ := NewVersionDiffScanner(db, cs, cfg)
	defer s.Close()

	art := scanner.Artifact{
		ID: "pypi:cb:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "cb", Version: "1.0", SHA256: "n",
	}
	for i := 0; i < 2; i++ {
		_, _ = s.Scan(context.Background(), art)
	}
	callsAfter2 := mb.calls.Load()
	// Third call: circuit open, no bridge call.
	_, _ = s.Scan(context.Background(), art)
	assert.Equal(t, callsAfter2, mb.calls.Load(), "circuit must short-circuit further bridge calls")
}

// --- SHA256 mismatch -------------------------------------------------------

func TestScan_PreviousSHAMismatch_FailsOpenWithoutBridge(t *testing.T) {
	mb := &mockBridge{}
	sock := startMockBridge(t, mb)
	db := newTestDB(t)
	cs := newFakeCache(t, map[string][]byte{"pypi:x:0.9": []byte("actual content")})
	// Wrong SHA in DB — actual content has a different hash.
	seedArtifactPair(t, db, "pypi", "x",
		"pypi:x:1.0", "1.0", "n",
		"pypi:x:0.9", "0.9", "0000deadbeef", true)

	s, _ := NewVersionDiffScanner(db, cs, defaultCfg(sock))
	defer s.Close()
	res, err := s.Scan(context.Background(), scanner.Artifact{
		ID: "pypi:x:1.0", Ecosystem: scanner.EcosystemPyPI, Name: "x", Version: "1.0", SHA256: "n",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, res.Verdict)
	assert.Equal(t, int32(0), mb.calls.Load(), "bridge must not be called on SHA mismatch")
}
```

- [ ] **Step 2: Run the full test file**

```bash
go test ./internal/scanner/versiondiff/ -v
```

Expected: all tests pass.

- [ ] **Step 3: Run `make test` (full suite, race detector enabled)**

```bash
make test
```

Expected: all tests pass.

- [ ] **Step 4: Run `make lint`**

```bash
make lint
```

Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/versiondiff/scanner_test.go
git commit -m "test(version-diff): cover Scan flow, rate limit, breaker, downgrade audit, idempotency cache"
```

---

## Verification — phase-end

```bash
# Tests pass with race detector (Makefile applies -race)
make test

# Lint clean
make lint

# Coverage of the package (informational)
go test -cover ./internal/scanner/versiondiff/
```

## What this phase ships

- A complete test file with mock bridge, fake cache, in-memory SQLite seeding helpers, and 14 tests covering: interface compliance, identity, allowlist, oversize guard, no-previous, bridge CLEAN/SUSPICIOUS-above/below-confidence/MALICIOUS/UNKNOWN, bridge error fail-open, idempotency cache hit, concurrent same-pair INSERT, shadow mode, rate limit, circuit breaker, SHA mismatch.

## What this phase deliberately does NOT ship

- E2E tests (Phase 8b).
- Pre-rollout validation against production data (Phase 7.5).
- Tests for daily cost circuit breaker (deferred — feature itself is deferred).

## Risks during this phase

- **Test flakiness from `go func()` concurrency:** the concurrent-INSERT test uses two goroutines and a small wait. If the channel pattern is replaced, ensure barriers are deterministic.
- **`pypi:foo:0.9` ID conventions** in tests must match the format produced by adapters. The ID format is opaque to the version-diff scanner (it's just a string), but make sure the seeded pair uses **a non-empty, unique** ID per artifact — the FK in `artifact_status` requires it.
- **Race detector:** `make test` runs with `-race`. The atomic counter on `mockBridge.calls` and the package-level limiter use `sync.Mutex` correctly. Verify by running `make test` repeatedly.
- **`InitDB(SQLiteMemoryConfig())` runs ALL migrations** including 024. If migration 024 is missing (Phase 2 not yet merged), these tests fail at setup with `no such column: ai_verdict`. This phase therefore **depends on Phase 2 being merged**.
