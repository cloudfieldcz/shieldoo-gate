# Shieldoo Gate v1.0 Core — Phase 4: Cache Store + Policy Engine + Threat Feed

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the local filesystem cache store, policy evaluation engine with scan result aggregation, and the threat feed HTTP client.

**Architecture:** The local cache uses `{basePath}/{ecosystem}/{name}/{version}/{filename}` layout with atomic writes via `os.Rename`. The policy engine evaluates rules in order (first match wins) with actions: allow/block/quarantine/warn. The aggregator combines multiple scan results into a single verdict. The threat feed client polls a remote JSON feed and stores entries in the `threat_feed` DB table.

**Tech Stack:** Go 1.23+, `os` (filesystem), `sqlx` (DB operations), `net/http` (threat feed client), testify

**Index:** [`plan-index.md`](./2026-03-25-v1-core-plan-index.md)

---

### Task 1: Local Filesystem Cache Store

**Files:**
- Create: `internal/cache/local/local.go`
- Test: `internal/cache/local/local_test.go`

- [ ] **Step 1: Write tests**

```go
// internal/cache/local/local_test.go
package local

import (
    "context"
    "os"
    "path/filepath"
    "testing"

    "github.com/cloudfieldcz/shieldoo-gate/internal/cache"
    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestLocalCacheStore_PutGet_RoundTrip(t *testing.T) {
    dir := t.TempDir()
    store, err := NewLocalCacheStore(dir, 10)
    require.NoError(t, err)

    // Create a temp artifact file
    tmpFile := filepath.Join(t.TempDir(), "artifact.whl")
    require.NoError(t, os.WriteFile(tmpFile, []byte("test artifact content"), 0644))

    artifact := scanner.Artifact{
        ID:        "pypi:requests:2.31.0",
        Ecosystem: scanner.EcosystemPyPI,
        Name:      "requests",
        Version:   "2.31.0",
    }

    err = store.Put(context.Background(), artifact, tmpFile)
    require.NoError(t, err)

    path, err := store.Get(context.Background(), "pypi:requests:2.31.0")
    require.NoError(t, err)

    content, err := os.ReadFile(path)
    require.NoError(t, err)
    assert.Equal(t, "test artifact content", string(content))
}

func TestLocalCacheStore_Get_NotFound(t *testing.T) {
    dir := t.TempDir()
    store, err := NewLocalCacheStore(dir, 10)
    require.NoError(t, err)

    _, err = store.Get(context.Background(), "pypi:nonexistent:1.0.0")
    assert.ErrorIs(t, err, cache.ErrNotFound)
}

func TestLocalCacheStore_Delete_RemovesFile(t *testing.T) {
    dir := t.TempDir()
    store, err := NewLocalCacheStore(dir, 10)
    require.NoError(t, err)

    tmpFile := filepath.Join(t.TempDir(), "artifact.whl")
    require.NoError(t, os.WriteFile(tmpFile, []byte("content"), 0644))

    artifact := scanner.Artifact{
        ID:        "pypi:pkg:1.0.0",
        Ecosystem: scanner.EcosystemPyPI,
        Name:      "pkg",
        Version:   "1.0.0",
    }
    require.NoError(t, store.Put(context.Background(), artifact, tmpFile))
    require.NoError(t, store.Delete(context.Background(), "pypi:pkg:1.0.0"))

    _, err = store.Get(context.Background(), "pypi:pkg:1.0.0")
    assert.ErrorIs(t, err, cache.ErrNotFound)
}

func TestLocalCacheStore_StoragePath_CorrectLayout(t *testing.T) {
    dir := t.TempDir()
    store, err := NewLocalCacheStore(dir, 10)
    require.NoError(t, err)

    path := store.artifactPath("pypi", "requests", "2.31.0")
    expected := filepath.Join(dir, "pypi", "requests", "2.31.0")
    assert.Equal(t, expected, path)
}

func TestLocalCacheStore_PathTraversal_Rejected(t *testing.T) {
    dir := t.TempDir()
    store, err := NewLocalCacheStore(dir, 10)
    require.NoError(t, err)

    tmpFile := filepath.Join(t.TempDir(), "artifact.whl")
    require.NoError(t, os.WriteFile(tmpFile, []byte("content"), 0644))

    artifact := scanner.Artifact{
        ID:        "pypi:../../../etc/passwd:1.0.0",
        Ecosystem: scanner.EcosystemPyPI,
        Name:      "../../../etc/passwd",
        Version:   "1.0.0",
    }
    err = store.Put(context.Background(), artifact, tmpFile)
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "invalid")
}

func TestLocalCacheStore_Stats(t *testing.T) {
    dir := t.TempDir()
    store, err := NewLocalCacheStore(dir, 10)
    require.NoError(t, err)

    stats, err := store.Stats(context.Background())
    require.NoError(t, err)
    assert.Equal(t, int64(0), stats.TotalItems)
}

// Compile-time interface check
var _ cache.CacheStore = (*LocalCacheStore)(nil)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/cache/local/ -v`
Expected: FAIL

- [ ] **Step 3: Implement Local Cache Store**

```go
// internal/cache/local/local.go
package local

import (
    "context"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "regexp"
    "strings"

    "github.com/cloudfieldcz/shieldoo-gate/internal/cache"
    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

var validNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)

type LocalCacheStore struct {
    basePath  string
    maxSizeGB int64
}

func NewLocalCacheStore(basePath string, maxSizeGB int64) (*LocalCacheStore, error) {
    if err := os.MkdirAll(basePath, 0755); err != nil {
        return nil, fmt.Errorf("cache: creating base path %s: %w", basePath, err)
    }
    return &LocalCacheStore{
        basePath:  basePath,
        maxSizeGB: maxSizeGB,
    }, nil
}

func (s *LocalCacheStore) Get(_ context.Context, artifactID string) (string, error) {
    eco, name, version, err := parseArtifactID(artifactID)
    if err != nil {
        return "", err
    }

    dir := s.artifactPath(eco, name, version)
    entries, err := os.ReadDir(dir)
    if err != nil {
        if os.IsNotExist(err) {
            return "", cache.ErrNotFound
        }
        return "", fmt.Errorf("cache: reading directory %s: %w", dir, err)
    }

    for _, entry := range entries {
        if !entry.IsDir() {
            return filepath.Join(dir, entry.Name()), nil
        }
    }
    return "", cache.ErrNotFound
}

func (s *LocalCacheStore) Put(_ context.Context, artifact scanner.Artifact, localPath string) error {
    eco := string(artifact.Ecosystem)
    if err := validateName(eco); err != nil {
        return fmt.Errorf("cache: invalid ecosystem %q: %w", eco, err)
    }
    if err := validateName(artifact.Name); err != nil {
        return fmt.Errorf("cache: invalid name %q: %w", artifact.Name, err)
    }
    if err := validateName(artifact.Version); err != nil {
        return fmt.Errorf("cache: invalid version %q: %w", artifact.Version, err)
    }

    dir := s.artifactPath(eco, artifact.Name, artifact.Version)
    if err := os.MkdirAll(dir, 0755); err != nil {
        return fmt.Errorf("cache: creating directory %s: %w", dir, err)
    }

    filename := filepath.Base(localPath)
    destPath := filepath.Join(dir, filename)

    // Atomic write: copy to temp file, then rename
    tmpPath := destPath + ".tmp"
    if err := copyFile(localPath, tmpPath); err != nil {
        os.Remove(tmpPath)
        return fmt.Errorf("cache: copying artifact to %s: %w", tmpPath, err)
    }

    if err := os.Rename(tmpPath, destPath); err != nil {
        os.Remove(tmpPath)
        return fmt.Errorf("cache: renaming %s to %s: %w", tmpPath, destPath, err)
    }

    return nil
}

func (s *LocalCacheStore) Delete(_ context.Context, artifactID string) error {
    eco, name, version, err := parseArtifactID(artifactID)
    if err != nil {
        return err
    }
    dir := s.artifactPath(eco, name, version)
    if err := os.RemoveAll(dir); err != nil {
        return fmt.Errorf("cache: deleting %s: %w", dir, err)
    }
    return nil
}

func (s *LocalCacheStore) List(_ context.Context, filter cache.CacheFilter) ([]string, error) {
    var ids []string
    ecosystems, err := os.ReadDir(s.basePath)
    if err != nil {
        return nil, fmt.Errorf("cache: listing base path: %w", err)
    }

    for _, ecoDir := range ecosystems {
        if !ecoDir.IsDir() {
            continue
        }
        if filter.Ecosystem != "" && ecoDir.Name() != filter.Ecosystem {
            continue
        }
        ecoPath := filepath.Join(s.basePath, ecoDir.Name())
        packages, err := os.ReadDir(ecoPath)
        if err != nil {
            continue
        }
        for _, pkgDir := range packages {
            if !pkgDir.IsDir() {
                continue
            }
            if filter.Name != "" && pkgDir.Name() != filter.Name {
                continue
            }
            pkgPath := filepath.Join(ecoPath, pkgDir.Name())
            versions, err := os.ReadDir(pkgPath)
            if err != nil {
                continue
            }
            for _, verDir := range versions {
                if verDir.IsDir() {
                    ids = append(ids, fmt.Sprintf("%s:%s:%s", ecoDir.Name(), pkgDir.Name(), verDir.Name()))
                }
            }
        }
    }
    return ids, nil
}

func (s *LocalCacheStore) Stats(_ context.Context) (cache.CacheStats, error) {
    stats := cache.CacheStats{
        ByEcosystem: make(map[string]int64),
    }

    err := filepath.Walk(s.basePath, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return nil
        }
        if !info.IsDir() {
            stats.TotalItems++
            stats.TotalBytes += info.Size()
            // Extract ecosystem from path
            rel, _ := filepath.Rel(s.basePath, path)
            parts := strings.SplitN(rel, string(filepath.Separator), 2)
            if len(parts) > 0 {
                stats.ByEcosystem[parts[0]] += info.Size()
            }
        }
        return nil
    })
    return stats, err
}

func (s *LocalCacheStore) artifactPath(ecosystem, name, version string) string {
    return filepath.Join(s.basePath, ecosystem, name, version)
}

func validateName(name string) error {
    if !validNamePattern.MatchString(name) {
        return fmt.Errorf("invalid name: contains disallowed characters")
    }
    if strings.Contains(name, "..") {
        return fmt.Errorf("invalid name: path traversal attempt")
    }
    return nil
}

func parseArtifactID(id string) (ecosystem, name, version string, err error) {
    parts := strings.SplitN(id, ":", 3)
    if len(parts) != 3 {
        return "", "", "", fmt.Errorf("cache: invalid artifact ID format: %s", id)
    }
    return parts[0], parts[1], parts[2], nil
}

func copyFile(src, dst string) error {
    in, err := os.Open(src)
    if err != nil {
        return err
    }
    defer in.Close()

    out, err := os.Create(dst)
    if err != nil {
        return err
    }
    defer out.Close()

    _, err = io.Copy(out, in)
    return err
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/cache/local/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cache/local/
git commit -m "feat(cache): add local filesystem cache store with atomic writes and path traversal protection"
```

---

### Task 2: Scan Result Aggregator

**Files:**
- Create: `internal/policy/aggregator.go`
- Test: `internal/policy/aggregator_test.go`

Aggregation logic from `docs/initial-analyse.md` section 6.2:
1. Threat feed hit → immediate MALICIOUS regardless of confidence
2. Any MALICIOUS with confidence >= minimum → MALICIOUS
3. Any SUSPICIOUS with confidence >= minimum → SUSPICIOUS
4. All CLEAN or error → CLEAN

- [ ] **Step 1: Write tests**

```go
// internal/policy/aggregator_test.go
package policy

import (
    "testing"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/stretchr/testify/assert"
)

func TestAggregate_ThreatFeedHit_ImmediateMalicious(t *testing.T) {
    results := []scanner.ScanResult{
        {Verdict: scanner.VerdictClean, Confidence: 1.0, ScannerID: "osv"},
        {Verdict: scanner.VerdictMalicious, Confidence: 1.0, ScannerID: "builtin-threat-feed"},
    }
    agg := Aggregate(results, AggregationConfig{MinConfidence: 0.7})
    assert.Equal(t, scanner.VerdictMalicious, agg.Verdict)
}

func TestAggregate_MaliciousHighConfidence_ReturnsMalicious(t *testing.T) {
    results := []scanner.ScanResult{
        {Verdict: scanner.VerdictClean, Confidence: 1.0, ScannerID: "osv"},
        {Verdict: scanner.VerdictMalicious, Confidence: 0.95, ScannerID: "guarddog"},
    }
    agg := Aggregate(results, AggregationConfig{MinConfidence: 0.7})
    assert.Equal(t, scanner.VerdictMalicious, agg.Verdict)
}

func TestAggregate_MaliciousLowConfidence_DowngradedToClean(t *testing.T) {
    results := []scanner.ScanResult{
        {Verdict: scanner.VerdictMalicious, Confidence: 0.3, ScannerID: "guarddog"},
    }
    agg := Aggregate(results, AggregationConfig{MinConfidence: 0.7})
    assert.Equal(t, scanner.VerdictClean, agg.Verdict)
}

func TestAggregate_SuspiciousHighConfidence_ReturnsSuspicious(t *testing.T) {
    results := []scanner.ScanResult{
        {Verdict: scanner.VerdictSuspicious, Confidence: 0.8, ScannerID: "osv"},
    }
    agg := Aggregate(results, AggregationConfig{MinConfidence: 0.7})
    assert.Equal(t, scanner.VerdictSuspicious, agg.Verdict)
}

func TestAggregate_AllClean_ReturnsClean(t *testing.T) {
    results := []scanner.ScanResult{
        {Verdict: scanner.VerdictClean, Confidence: 1.0, ScannerID: "trivy"},
        {Verdict: scanner.VerdictClean, Confidence: 1.0, ScannerID: "osv"},
    }
    agg := Aggregate(results, AggregationConfig{MinConfidence: 0.7})
    assert.Equal(t, scanner.VerdictClean, agg.Verdict)
}

func TestAggregate_AllErrors_ReturnsClean(t *testing.T) {
    results := []scanner.ScanResult{
        {Verdict: scanner.VerdictClean, ScannerID: "trivy", Error: fmt.Errorf("timeout")},
    }
    agg := Aggregate(results, AggregationConfig{MinConfidence: 0.7})
    assert.Equal(t, scanner.VerdictClean, agg.Verdict)
}

func TestAggregate_EmptyResults_ReturnsClean(t *testing.T) {
    agg := Aggregate(nil, AggregationConfig{MinConfidence: 0.7})
    assert.Equal(t, scanner.VerdictClean, agg.Verdict)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/policy/ -v -run TestAggregate`
Expected: FAIL

- [ ] **Step 3: Implement Aggregator**

```go
// internal/policy/aggregator.go
package policy

import (
    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

type AggregationConfig struct {
    MinConfidence float32
}

type AggregatedResult struct {
    Verdict  scanner.Verdict
    Findings []scanner.Finding
}

func Aggregate(results []scanner.ScanResult, cfg AggregationConfig) AggregatedResult {
    if len(results) == 0 {
        return AggregatedResult{Verdict: scanner.VerdictClean}
    }

    var allFindings []scanner.Finding
    hasMalicious := false
    hasSuspicious := false

    for _, r := range results {
        allFindings = append(allFindings, r.Findings...)

        // Fast path: threat feed hit is always MALICIOUS regardless of confidence
        if r.ScannerID == "builtin-threat-feed" && r.Verdict == scanner.VerdictMalicious {
            return AggregatedResult{
                Verdict:  scanner.VerdictMalicious,
                Findings: allFindings,
            }
        }

        // Skip low-confidence results
        if r.Confidence < cfg.MinConfidence {
            continue
        }

        switch r.Verdict {
        case scanner.VerdictMalicious:
            hasMalicious = true
        case scanner.VerdictSuspicious:
            hasSuspicious = true
        }
    }

    if hasMalicious {
        return AggregatedResult{Verdict: scanner.VerdictMalicious, Findings: allFindings}
    }
    if hasSuspicious {
        return AggregatedResult{Verdict: scanner.VerdictSuspicious, Findings: allFindings}
    }
    return AggregatedResult{Verdict: scanner.VerdictClean, Findings: allFindings}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/ -v -run TestAggregate`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/policy/aggregator.go internal/policy/aggregator_test.go
git commit -m "feat(policy): add scan result aggregator with confidence threshold and threat feed fast-path"
```

---

### Task 3: Policy Engine

**Files:**
- Create: `internal/policy/engine.go`
- Create: `internal/policy/rules.go`
- Test: `internal/policy/engine_test.go`

- [ ] **Step 1: Write tests**

```go
// internal/policy/engine_test.go
package policy

import (
    "context"
    "testing"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestPolicyEngine_MaliciousVerdict_ReturnsBlock(t *testing.T) {
    engine := NewEngine(EngineConfig{
        BlockIfVerdict:      "MALICIOUS",
        QuarantineIfVerdict: "SUSPICIOUS",
        MinimumConfidence:   0.7,
        Allowlist:           nil,
    })

    action, err := engine.Evaluate(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        Name:      "evil-pkg",
        Version:   "1.0.0",
    }, []scanner.ScanResult{
        {Verdict: scanner.VerdictMalicious, Confidence: 0.95, ScannerID: "guarddog"},
    })
    require.NoError(t, err)
    assert.Equal(t, ActionBlock, action.Action)
}

func TestPolicyEngine_SuspiciousVerdict_ReturnsQuarantine(t *testing.T) {
    engine := NewEngine(EngineConfig{
        BlockIfVerdict:      "MALICIOUS",
        QuarantineIfVerdict: "SUSPICIOUS",
        MinimumConfidence:   0.7,
    })

    action, err := engine.Evaluate(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
    }, []scanner.ScanResult{
        {Verdict: scanner.VerdictSuspicious, Confidence: 0.8, ScannerID: "osv"},
    })
    require.NoError(t, err)
    assert.Equal(t, ActionQuarantine, action.Action)
}

func TestPolicyEngine_CleanVerdict_ReturnsAllow(t *testing.T) {
    engine := NewEngine(EngineConfig{
        BlockIfVerdict:      "MALICIOUS",
        QuarantineIfVerdict: "SUSPICIOUS",
        MinimumConfidence:   0.7,
    })

    action, err := engine.Evaluate(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
    }, []scanner.ScanResult{
        {Verdict: scanner.VerdictClean, Confidence: 1.0, ScannerID: "trivy"},
    })
    require.NoError(t, err)
    assert.Equal(t, ActionAllow, action.Action)
}

func TestPolicyEngine_AllowlistOverride_AllowsMalicious(t *testing.T) {
    engine := NewEngine(EngineConfig{
        BlockIfVerdict:      "MALICIOUS",
        QuarantineIfVerdict: "SUSPICIOUS",
        MinimumConfidence:   0.7,
        Allowlist:           []string{"pypi:litellm:==1.82.6"},
    })

    action, err := engine.Evaluate(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        Name:      "litellm",
        Version:   "1.82.6",
    }, []scanner.ScanResult{
        {Verdict: scanner.VerdictMalicious, Confidence: 0.95, ScannerID: "guarddog"},
    })
    require.NoError(t, err)
    assert.Equal(t, ActionAllow, action.Action)
}

func TestPolicyEngine_AllowlistNoMatch_StillBlocks(t *testing.T) {
    engine := NewEngine(EngineConfig{
        BlockIfVerdict:      "MALICIOUS",
        QuarantineIfVerdict: "SUSPICIOUS",
        MinimumConfidence:   0.7,
        Allowlist:           []string{"pypi:litellm:==1.82.6"},
    })

    action, err := engine.Evaluate(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        Name:      "litellm",
        Version:   "1.82.7", // different version — NOT allowlisted
    }, []scanner.ScanResult{
        {Verdict: scanner.VerdictMalicious, Confidence: 0.95, ScannerID: "guarddog"},
    })
    require.NoError(t, err)
    assert.Equal(t, ActionBlock, action.Action)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/policy/ -v -run TestPolicyEngine`
Expected: FAIL

- [ ] **Step 3: Implement rules and engine**

```go
// internal/policy/rules.go
package policy

import (
    "fmt"
    "strings"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

type Action string

const (
    ActionAllow      Action = "allow"
    ActionBlock      Action = "block"
    ActionQuarantine Action = "quarantine"
    ActionWarn       Action = "warn"
)

type PolicyResult struct {
    Action Action
    Reason string
}

// ParseAllowlistEntry parses "ecosystem:name:==version" into components.
// v1.0 supports only exact match.
func ParseAllowlistEntry(entry string) (ecosystem, name, version string, err error) {
    parts := strings.SplitN(entry, ":", 3)
    if len(parts) != 3 {
        return "", "", "", fmt.Errorf("policy: invalid allowlist entry: %s", entry)
    }
    version = strings.TrimPrefix(parts[2], "==")
    return parts[0], parts[1], version, nil
}

func isAllowlisted(artifact scanner.Artifact, allowlist []string) bool {
    for _, entry := range allowlist {
        eco, name, version, err := ParseAllowlistEntry(entry)
        if err != nil {
            continue
        }
        if string(artifact.Ecosystem) == eco && artifact.Name == name && artifact.Version == version {
            return true
        }
    }
    return false
}
```

```go
// internal/policy/engine.go
package policy

import (
    "context"
    "fmt"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

type EngineConfig struct {
    BlockIfVerdict      string
    QuarantineIfVerdict string
    MinimumConfidence   float32
    Allowlist           []string
}

type Engine struct {
    cfg EngineConfig
}

func NewEngine(cfg EngineConfig) *Engine {
    return &Engine{cfg: cfg}
}

func (e *Engine) Evaluate(_ context.Context, artifact scanner.Artifact, scanResults []scanner.ScanResult) (PolicyResult, error) {
    // Rule 1: Allowlist override — first match wins
    if isAllowlisted(artifact, e.cfg.Allowlist) {
        return PolicyResult{
            Action: ActionAllow,
            Reason: fmt.Sprintf("allowlisted: %s:%s:%s", artifact.Ecosystem, artifact.Name, artifact.Version),
        }, nil
    }

    // Aggregate scan results
    aggResult := Aggregate(scanResults, AggregationConfig{
        MinConfidence: float32(e.cfg.MinimumConfidence),
    })

    // Rule 2: Block if verdict matches block threshold
    if string(aggResult.Verdict) == e.cfg.BlockIfVerdict {
        return PolicyResult{
            Action: ActionBlock,
            Reason: fmt.Sprintf("verdict %s matches block policy", aggResult.Verdict),
        }, nil
    }

    // Rule 3: Quarantine if verdict matches quarantine threshold
    if string(aggResult.Verdict) == e.cfg.QuarantineIfVerdict {
        return PolicyResult{
            Action: ActionQuarantine,
            Reason: fmt.Sprintf("verdict %s matches quarantine policy", aggResult.Verdict),
        }, nil
    }

    // Rule 4: Check for high-severity findings → warn
    for _, f := range aggResult.Findings {
        if f.Severity == scanner.SeverityHigh || f.Severity == scanner.SeverityCritical {
            return PolicyResult{
                Action: ActionWarn,
                Reason: fmt.Sprintf("high severity finding: %s", f.Category),
            }, nil
        }
    }

    // Default: allow
    return PolicyResult{
        Action: ActionAllow,
        Reason: "all checks passed",
    }, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/policy/
git commit -m "feat(policy): add policy engine with allowlist, block/quarantine/warn/allow actions"
```

---

### Task 4: Threat Feed HTTP Client

**Files:**
- Create: `internal/threatfeed/client.go`
- Test: `internal/threatfeed/client_test.go`

Polls the community threat feed URL and stores entries in the `threat_feed` DB table.

- [ ] **Step 1: Write tests**

```go
// internal/threatfeed/client_test.go
package threatfeed

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/cloudfieldcz/shieldoo-gate/internal/config"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestClient_Refresh_StoresEntries(t *testing.T) {
    db, err := config.InitDB(":memory:")
    require.NoError(t, err)
    defer db.Close()

    feed := FeedResponse{
        SchemaVersion: "1.0",
        Entries: []FeedEntry{
            {
                SHA256:      "abc123",
                Ecosystem:   "pypi",
                PackageName: "evil-pkg",
                Versions:    []string{"1.0.0"},
                ReportedAt:  "2026-03-24T12:00:00Z",
                SourceURL:   "https://example.com/advisory",
            },
        },
    }

    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(feed)
    }))
    defer server.Close()

    client := NewClient(db, server.URL)
    err = client.Refresh(context.Background())
    require.NoError(t, err)

    var count int
    err = db.Get(&count, "SELECT COUNT(*) FROM threat_feed")
    require.NoError(t, err)
    assert.Equal(t, 1, count)
}

func TestClient_Refresh_ServerDown_ReturnsError(t *testing.T) {
    db, err := config.InitDB(":memory:")
    require.NoError(t, err)
    defer db.Close()

    client := NewClient(db, "http://localhost:1/nonexistent")
    err = client.Refresh(context.Background())
    assert.Error(t, err)
}

func TestClient_Refresh_Idempotent(t *testing.T) {
    db, err := config.InitDB(":memory:")
    require.NoError(t, err)
    defer db.Close()

    feed := FeedResponse{
        Entries: []FeedEntry{
            {SHA256: "abc", Ecosystem: "pypi", PackageName: "pkg", ReportedAt: "2026-03-24T12:00:00Z"},
        },
    }

    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(feed)
    }))
    defer server.Close()

    client := NewClient(db, server.URL)
    require.NoError(t, client.Refresh(context.Background()))
    require.NoError(t, client.Refresh(context.Background())) // second call should not error

    var count int
    db.Get(&count, "SELECT COUNT(*) FROM threat_feed")
    assert.Equal(t, 1, count) // still just one entry
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/threatfeed/ -v`
Expected: FAIL

- [ ] **Step 3: Implement Threat Feed Client**

```go
// internal/threatfeed/client.go
package threatfeed

import (
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"

    "github.com/jmoiron/sqlx"
)

type FeedResponse struct {
    SchemaVersion string      `json:"schema_version"`
    Updated       string      `json:"updated"`
    Entries       []FeedEntry `json:"entries"`
}

type FeedEntry struct {
    SHA256      string   `json:"sha256"`
    Ecosystem   string   `json:"ecosystem"`
    PackageName string   `json:"package"`
    Versions    []string `json:"versions"`
    ReportedAt  string   `json:"reported_at"`
    SourceURL   string   `json:"source"`
    IoCs        []string `json:"iocs"`
}

type Client struct {
    db         *sqlx.DB
    feedURL    string
    httpClient *http.Client
}

func NewClient(db *sqlx.DB, feedURL string) *Client {
    return &Client{
        db:      db,
        feedURL: feedURL,
        httpClient: &http.Client{
            Timeout: 30 * time.Second,
        },
    }
}

func (c *Client) Refresh(ctx context.Context) error {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.feedURL, nil)
    if err != nil {
        return fmt.Errorf("threatfeed: creating request: %w", err)
    }

    resp, err := c.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("threatfeed: fetching feed from %s: %w", c.feedURL, err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return fmt.Errorf("threatfeed: feed returned status %d", resp.StatusCode)
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return fmt.Errorf("threatfeed: reading response: %w", err)
    }

    var feed FeedResponse
    if err := json.Unmarshal(body, &feed); err != nil {
        return fmt.Errorf("threatfeed: parsing feed JSON: %w", err)
    }

    for _, entry := range feed.Entries {
        iocsJSON, _ := json.Marshal(entry.IoCs)
        version := ""
        if len(entry.Versions) > 0 {
            version = entry.Versions[0]
        }

        _, err := c.db.ExecContext(ctx, `
            INSERT OR REPLACE INTO threat_feed (sha256, ecosystem, package_name, version, reported_at, source_url, iocs_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            entry.SHA256, entry.Ecosystem, entry.PackageName, version,
            entry.ReportedAt, entry.SourceURL, string(iocsJSON),
        )
        if err != nil {
            return fmt.Errorf("threatfeed: inserting entry %s: %w", entry.SHA256, err)
        }
    }

    return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/threatfeed/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/threatfeed/
git commit -m "feat(threatfeed): add HTTP client for community threat feed polling and DB storage"
```

---

### Task 5: Verify All Phase 4 Tests Pass

- [ ] **Step 1: Run all tests**

Run: `go test ./internal/cache/... ./internal/policy/... ./internal/threatfeed/... -v -race`
Expected: All PASS.

- [ ] **Step 2: Run vet**

Run: `go vet ./internal/cache/... ./internal/policy/... ./internal/threatfeed/...`
Expected: No issues.
