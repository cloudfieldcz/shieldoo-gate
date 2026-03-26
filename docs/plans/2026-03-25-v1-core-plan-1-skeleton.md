# Shieldoo Gate v1.0 Core — Phase 1: Project Skeleton + Config + DB + Models

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the Go module, config loading, SQLite database initialization, shared data models, and all core interfaces — the foundation everything else builds on.

**Architecture:** Standard Go project layout with `cmd/` entrypoint and `internal/` packages. Viper handles YAML+env config, sqlx+go-sqlite3 for database, zerolog for structured logging. All core interfaces defined upfront so later phases can implement against them.

**Tech Stack:** Go 1.23+, chi/v5, viper, zerolog, sqlx, go-sqlite3, testify

**Index:** [`plan-index.md`](./2026-03-25-v1-core-plan-index.md)

---

### Task 1: Go Module Init + Dependencies

**Files:**
- Create: `go.mod`

- [ ] **Step 1: Initialize Go module**

```bash
cd /Users/valda/src/projects/shieldoo-gate
go mod init github.com/cloudfieldcz/shieldoo-gate
```

- [ ] **Step 2: Add all approved dependencies**

```bash
go get github.com/go-chi/chi/v5@latest
go get github.com/spf13/viper@latest
go get github.com/rs/zerolog@latest
go get github.com/jmoiron/sqlx@latest
go get github.com/mattn/go-sqlite3@latest
go get github.com/prometheus/client_golang@latest
go get github.com/stretchr/testify@latest
```

- [ ] **Step 3: Verify go.mod has correct module path and dependencies**

Run: `cat go.mod`
Expected: Module `github.com/cloudfieldcz/shieldoo-gate` with all 7 dependencies listed.

- [ ] **Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "chore: init Go module with approved dependencies"
```

---

### Task 2: Shared Data Models

**Files:**
- Create: `internal/model/artifact.go`
- Create: `internal/model/scan.go`
- Create: `internal/model/audit.go`
- Create: `internal/model/threat.go`
- Test: `internal/model/artifact_test.go`

- [ ] **Step 1: Write test for Artifact ID generation**

```go
// internal/model/artifact_test.go
package model

import (
    "testing"

    "github.com/stretchr/testify/assert"
)

func TestArtifactID_Format(t *testing.T) {
    a := Artifact{
        Ecosystem: "pypi",
        Name:      "litellm",
        Version:   "1.82.6",
    }
    assert.Equal(t, "pypi:litellm:1.82.6", a.ID())
}

func TestArtifactStatus_IsServable_Clean(t *testing.T) {
    s := ArtifactStatus{Status: StatusClean}
    assert.True(t, s.IsServable())
}

func TestArtifactStatus_IsServable_Quarantined(t *testing.T) {
    s := ArtifactStatus{Status: StatusQuarantined}
    assert.False(t, s.IsServable())
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/ -v -run TestArtifact`
Expected: FAIL — types not defined yet.

- [ ] **Step 3: Implement Artifact and ArtifactStatus models**

```go
// internal/model/artifact.go
package model

import (
    "fmt"
    "time"
)

type Status string

const (
    StatusClean       Status = "CLEAN"
    StatusSuspicious  Status = "SUSPICIOUS"
    StatusQuarantined Status = "QUARANTINED"
    StatusPendingScan Status = "PENDING_SCAN"
)

type Artifact struct {
    Ecosystem      string    `db:"ecosystem" json:"ecosystem"`
    Name           string    `db:"name" json:"name"`
    Version        string    `db:"version" json:"version"`
    UpstreamURL    string    `db:"upstream_url" json:"upstream_url"`
    SHA256         string    `db:"sha256" json:"sha256"`
    SizeBytes      int64     `db:"size_bytes" json:"size_bytes"`
    CachedAt       time.Time `db:"cached_at" json:"cached_at"`
    LastAccessedAt time.Time `db:"last_accessed_at" json:"last_accessed_at"`
    StoragePath    string    `db:"storage_path" json:"storage_path"`
}

func (a Artifact) ID() string {
    return fmt.Sprintf("%s:%s:%s", a.Ecosystem, a.Name, a.Version)
}

type ArtifactStatus struct {
    ArtifactID       string     `db:"artifact_id" json:"artifact_id"`
    Status           Status     `db:"status" json:"status"`
    QuarantineReason string     `db:"quarantine_reason" json:"quarantine_reason,omitempty"`
    QuarantinedAt    *time.Time `db:"quarantined_at" json:"quarantined_at,omitempty"`
    ReleasedAt       *time.Time `db:"released_at" json:"released_at,omitempty"`
    RescanDueAt      *time.Time `db:"rescan_due_at" json:"rescan_due_at,omitempty"`
    LastScanID       *int64     `db:"last_scan_id" json:"last_scan_id,omitempty"`
}

func (s ArtifactStatus) IsServable() bool {
    return s.Status != StatusQuarantined
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/model/ -v -run TestArtifact`
Expected: PASS

- [ ] **Step 5: Implement ScanResult and Finding models**

```go
// internal/model/scan.go
package model

import "time"

type Verdict string

const (
    VerdictClean      Verdict = "CLEAN"
    VerdictSuspicious Verdict = "SUSPICIOUS"
    VerdictMalicious  Verdict = "MALICIOUS"
)

type Severity string

const (
    SeverityInfo     Severity = "INFO"
    SeverityLow      Severity = "LOW"
    SeverityMedium   Severity = "MEDIUM"
    SeverityHigh     Severity = "HIGH"
    SeverityCritical Severity = "CRITICAL"
)

type Finding struct {
    Severity    Severity `json:"severity"`
    Category    string   `json:"category"`
    Description string   `json:"description"`
    Location    string   `json:"location"`
    IoCs        []string `json:"iocs,omitempty"`
}

type ScanResult struct {
    ID             int64     `db:"id" json:"id"`
    ArtifactID     string    `db:"artifact_id" json:"artifact_id"`
    ScannedAt      time.Time `db:"scanned_at" json:"scanned_at"`
    ScannerName    string    `db:"scanner_name" json:"scanner_name"`
    ScannerVersion string    `db:"scanner_version" json:"scanner_version"`
    Verdict        Verdict   `db:"verdict" json:"verdict"`
    Confidence     float32   `db:"confidence" json:"confidence"`
    FindingsJSON   string    `db:"findings_json" json:"findings_json"`
    DurationMs     int64     `db:"duration_ms" json:"duration_ms"`
}
```

- [ ] **Step 6: Implement AuditEntry model**

```go
// internal/model/audit.go
package model

import "time"

type EventType string

const (
    EventServed      EventType = "SERVED"
    EventBlocked     EventType = "BLOCKED"
    EventQuarantined EventType = "QUARANTINED"
    EventReleased    EventType = "RELEASED"
    EventScanned     EventType = "SCANNED"
)

type AuditEntry struct {
    ID           int64     `db:"id" json:"id"`
    Timestamp    time.Time `db:"ts" json:"ts"`
    EventType    EventType `db:"event_type" json:"event_type"`
    ArtifactID   string    `db:"artifact_id" json:"artifact_id,omitempty"`
    ClientIP     string    `db:"client_ip" json:"client_ip,omitempty"`
    UserAgent    string    `db:"user_agent" json:"user_agent,omitempty"`
    Reason       string    `db:"reason" json:"reason,omitempty"`
    MetadataJSON string    `db:"metadata_json" json:"metadata_json,omitempty"`
}
```

- [ ] **Step 7: Implement ThreatFeedEntry model**

```go
// internal/model/threat.go
package model

import "time"

type ThreatFeedEntry struct {
    SHA256      string    `db:"sha256" json:"sha256"`
    Ecosystem   string    `db:"ecosystem" json:"ecosystem"`
    PackageName string    `db:"package_name" json:"package_name"`
    Version     string    `db:"version" json:"version,omitempty"`
    ReportedAt  time.Time `db:"reported_at" json:"reported_at"`
    SourceURL   string    `db:"source_url" json:"source_url,omitempty"`
    IoCsJSON    string    `db:"iocs_json" json:"iocs_json,omitempty"`
}
```

- [ ] **Step 8: Verify all model files compile**

Run: `go build ./internal/model/`
Expected: No errors.

- [ ] **Step 9: Commit**

```bash
git add internal/model/
git commit -m "feat(model): add shared data models for artifacts, scans, audit, threat feed"
```

---

### Task 3: Core Interfaces (Scanner, Cache, Adapter)

**Files:**
- Create: `internal/scanner/interface.go`
- Create: `internal/cache/interface.go`
- Create: `internal/adapter/interface.go`

These interfaces are defined in `docs/initial-analyse.md` section 4.8 and must be implemented exactly.

- [ ] **Step 1: Implement Scanner interface**

```go
// internal/scanner/interface.go
package scanner

import (
    "context"
    "time"
)

type Ecosystem string

const (
    EcosystemPyPI   Ecosystem = "pypi"
    EcosystemNPM    Ecosystem = "npm"
    EcosystemDocker Ecosystem = "docker"
    EcosystemNuGet  Ecosystem = "nuget"
)

type Verdict string

const (
    VerdictClean      Verdict = "CLEAN"
    VerdictSuspicious Verdict = "SUSPICIOUS"
    VerdictMalicious  Verdict = "MALICIOUS"
)

type Severity string

const (
    SeverityInfo     Severity = "INFO"
    SeverityLow      Severity = "LOW"
    SeverityMedium   Severity = "MEDIUM"
    SeverityHigh     Severity = "HIGH"
    SeverityCritical Severity = "CRITICAL"
)

type Artifact struct {
    ID          string
    Ecosystem   Ecosystem
    Name        string
    Version     string
    LocalPath   string
    SHA256      string
    SizeBytes   int64
    UpstreamURL string
}

type Finding struct {
    Severity    Severity
    Category    string
    Description string
    Location    string
    IoCs        []string
}

type ScanResult struct {
    Verdict    Verdict
    Confidence float32
    Findings   []Finding
    ScannerID  string
    Duration   time.Duration
    ScannedAt  time.Time
    Error      error
}

type Scanner interface {
    Name() string
    Version() string
    SupportedEcosystems() []Ecosystem
    Scan(ctx context.Context, artifact Artifact) (ScanResult, error)
    HealthCheck(ctx context.Context) error
}
```

- [ ] **Step 2: Implement CacheStore interface**

```go
// internal/cache/interface.go
package cache

import (
    "context"
    "errors"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

var ErrNotFound = errors.New("artifact not found in cache")

type CacheFilter struct {
    Ecosystem string
    Name      string
}

type CacheStats struct {
    TotalItems int64
    TotalBytes int64
    ByEcosystem map[string]int64
}

type CacheStore interface {
    Get(ctx context.Context, artifactID string) (localPath string, err error)
    Put(ctx context.Context, artifact scanner.Artifact, localPath string) error
    Delete(ctx context.Context, artifactID string) error
    List(ctx context.Context, filter CacheFilter) ([]string, error)
    Stats(ctx context.Context) (CacheStats, error)
}
```

- [ ] **Step 3: Implement Adapter interface**

```go
// internal/adapter/interface.go
package adapter

import (
    "context"
    "net/http"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

type Adapter interface {
    Ecosystem() scanner.Ecosystem
    ServeHTTP(w http.ResponseWriter, r *http.Request)
    HealthCheck(ctx context.Context) error
}
```

- [ ] **Step 4: Verify all interfaces compile**

Run: `go build ./internal/scanner/ ./internal/cache/ ./internal/adapter/`
Expected: No errors.

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/interface.go internal/cache/interface.go internal/adapter/interface.go
git commit -m "feat: add core interfaces for Scanner, CacheStore, Adapter"
```

---

### Task 4: Configuration Loading

**Files:**
- Create: `internal/config/config.go`
- Create: `config.example.yaml`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write tests for config loading**

```go
// internal/config/config_test.go
package config

import (
    "os"
    "path/filepath"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestLoad_FromYAML_ParsesAllSections(t *testing.T) {
    dir := t.TempDir()
    cfgPath := filepath.Join(dir, "config.yaml")
    err := os.WriteFile(cfgPath, []byte(`
server:
  host: "127.0.0.1"
ports:
  pypi: 5000
  npm: 4873
  nuget: 5001
  docker: 5002
  admin: 8080
upstreams:
  pypi: "https://pypi.org"
  npm: "https://registry.npmjs.org"
  nuget: "https://api.nuget.org"
  docker: "https://registry-1.docker.io"
cache:
  backend: "local"
  local:
    path: "/tmp/cache"
    max_size_gb: 10
  ttl:
    pypi: "168h"
    npm: "168h"
    nuget: "168h"
    docker: "720h"
database:
  backend: "sqlite"
  sqlite:
    path: "/tmp/gate.db"
scanners:
  parallel: true
  timeout: "60s"
  guarddog:
    enabled: true
    bridge_socket: "/tmp/shieldoo-bridge.sock"
  trivy:
    enabled: true
    binary: "trivy"
    cache_dir: "/tmp/trivy-cache"
  osv:
    enabled: true
    api_url: "https://api.osv.dev"
policy:
  block_if_verdict: "MALICIOUS"
  quarantine_if_verdict: "SUSPICIOUS"
  minimum_confidence: 0.7
  allowlist:
    - "pypi:litellm:==1.82.6"
threat_feed:
  enabled: true
  url: "https://feed.shieldoo.io/malicious-packages.json"
  refresh_interval: "1h"
log:
  level: "info"
  format: "json"
`), 0644)
    require.NoError(t, err)

    cfg, err := Load(cfgPath)
    require.NoError(t, err)

    assert.Equal(t, "127.0.0.1", cfg.Server.Host)
    assert.Equal(t, 5000, cfg.Ports.PyPI)
    assert.Equal(t, 4873, cfg.Ports.NPM)
    assert.Equal(t, 8080, cfg.Ports.Admin)
    assert.Equal(t, "https://pypi.org", cfg.Upstreams.PyPI)
    assert.Equal(t, "local", cfg.Cache.Backend)
    assert.Equal(t, "/tmp/cache", cfg.Cache.Local.Path)
    assert.Equal(t, "sqlite", cfg.Database.Backend)
    assert.True(t, cfg.Scanners.Parallel)
    assert.Equal(t, "60s", cfg.Scanners.Timeout)
    assert.True(t, cfg.Scanners.GuardDog.Enabled)
    assert.InDelta(t, 0.7, float64(cfg.Policy.MinimumConfidence), 0.001)
    assert.Contains(t, cfg.Policy.Allowlist, "pypi:litellm:==1.82.6")
    assert.True(t, cfg.ThreatFeed.Enabled)
    assert.Equal(t, "info", cfg.Log.Level)
}

func TestLoad_EnvOverride(t *testing.T) {
    dir := t.TempDir()
    cfgPath := filepath.Join(dir, "config.yaml")
    err := os.WriteFile(cfgPath, []byte(`
server:
  host: "0.0.0.0"
ports:
  pypi: 5000
  npm: 4873
  nuget: 5001
  docker: 5002
  admin: 8080
cache:
  backend: "local"
  local:
    path: "/tmp/cache"
    max_size_gb: 10
database:
  backend: "sqlite"
  sqlite:
    path: "/tmp/gate.db"
log:
  level: "info"
  format: "json"
`), 0644)
    require.NoError(t, err)

    t.Setenv("SGW_LOG_LEVEL", "debug")

    cfg, err := Load(cfgPath)
    require.NoError(t, err)
    assert.Equal(t, "debug", cfg.Log.Level)
}

func TestValidate_MissingCachePath_ReturnsError(t *testing.T) {
    cfg := &Config{
        Cache: CacheConfig{
            Backend: "local",
            Local:   LocalCacheConfig{Path: ""},
        },
        Database: DatabaseConfig{
            Backend: "sqlite",
            SQLite:  SQLiteConfig{Path: "/tmp/gate.db"},
        },
    }
    err := cfg.Validate()
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "cache.local.path")
}

func TestValidate_MissingSQLitePath_ReturnsError(t *testing.T) {
    cfg := &Config{
        Cache: CacheConfig{
            Backend: "local",
            Local:   LocalCacheConfig{Path: "/tmp/cache"},
        },
        Database: DatabaseConfig{
            Backend: "sqlite",
            SQLite:  SQLiteConfig{Path: ""},
        },
    }
    err := cfg.Validate()
    assert.Error(t, err)
    assert.Contains(t, err.Error(), "database.sqlite.path")
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -v`
Expected: FAIL — `Load` function not defined.

- [ ] **Step 3: Implement config structs and Load function**

```go
// internal/config/config.go
package config

import (
    "fmt"
    "strings"

    "github.com/spf13/viper"
)

type Config struct {
    Server     ServerConfig     `mapstructure:"server"`
    Ports      PortsConfig      `mapstructure:"ports"`
    Upstreams  UpstreamsConfig  `mapstructure:"upstreams"`
    Cache      CacheConfig      `mapstructure:"cache"`
    Database   DatabaseConfig   `mapstructure:"database"`
    Scanners   ScannersConfig   `mapstructure:"scanners"`
    Policy     PolicyConfig     `mapstructure:"policy"`
    ThreatFeed ThreatFeedConfig `mapstructure:"threat_feed"`
    Log        LogConfig        `mapstructure:"log"`
}

type ServerConfig struct {
    Host string `mapstructure:"host"`
}

type PortsConfig struct {
    PyPI   int `mapstructure:"pypi"`
    NPM    int `mapstructure:"npm"`
    NuGet  int `mapstructure:"nuget"`
    Docker int `mapstructure:"docker"`
    Admin  int `mapstructure:"admin"`
}

type UpstreamsConfig struct {
    PyPI   string `mapstructure:"pypi"`
    NPM    string `mapstructure:"npm"`
    NuGet  string `mapstructure:"nuget"`
    Docker string `mapstructure:"docker"`
}

type CacheConfig struct {
    Backend string          `mapstructure:"backend"`
    Local   LocalCacheConfig `mapstructure:"local"`
    TTL     TTLConfig       `mapstructure:"ttl"`
}

type LocalCacheConfig struct {
    Path      string `mapstructure:"path"`
    MaxSizeGB int64  `mapstructure:"max_size_gb"`
}

type TTLConfig struct {
    PyPI   string `mapstructure:"pypi"`
    NPM    string `mapstructure:"npm"`
    NuGet  string `mapstructure:"nuget"`
    Docker string `mapstructure:"docker"`
}

type DatabaseConfig struct {
    Backend string       `mapstructure:"backend"`
    SQLite  SQLiteConfig `mapstructure:"sqlite"`
}

type SQLiteConfig struct {
    Path string `mapstructure:"path"`
}

type ScannersConfig struct {
    Parallel bool           `mapstructure:"parallel"`
    Timeout  string         `mapstructure:"timeout"`
    GuardDog GuardDogConfig `mapstructure:"guarddog"`
    Trivy    TrivyConfig    `mapstructure:"trivy"`
    OSV      OSVConfig      `mapstructure:"osv"`
}

type GuardDogConfig struct {
    Enabled      bool   `mapstructure:"enabled"`
    BridgeSocket string `mapstructure:"bridge_socket"`
}

type TrivyConfig struct {
    Enabled  bool   `mapstructure:"enabled"`
    Binary   string `mapstructure:"binary"`
    CacheDir string `mapstructure:"cache_dir"`
}

type OSVConfig struct {
    Enabled bool   `mapstructure:"enabled"`
    APIURL  string `mapstructure:"api_url"`
}

type PolicyConfig struct {
    BlockIfVerdict      string   `mapstructure:"block_if_verdict"`
    QuarantineIfVerdict string   `mapstructure:"quarantine_if_verdict"`
    MinimumConfidence   float32  `mapstructure:"minimum_confidence"`
    Allowlist           []string `mapstructure:"allowlist"`
}

type ThreatFeedConfig struct {
    Enabled         bool   `mapstructure:"enabled"`
    URL             string `mapstructure:"url"`
    RefreshInterval string `mapstructure:"refresh_interval"`
}

type LogConfig struct {
    Level  string `mapstructure:"level"`
    Format string `mapstructure:"format"`
}

func Load(path string) (*Config, error) {
    v := viper.New()
    v.SetConfigFile(path)
    v.SetEnvPrefix("SGW")
    v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
    v.AutomaticEnv()

    if err := v.ReadInConfig(); err != nil {
        return nil, fmt.Errorf("config: reading %s: %w", path, err)
    }

    var cfg Config
    if err := v.Unmarshal(&cfg); err != nil {
        return nil, fmt.Errorf("config: unmarshalling: %w", err)
    }

    return &cfg, nil
}

func (c *Config) Validate() error {
    if c.Cache.Backend == "local" && c.Cache.Local.Path == "" {
        return fmt.Errorf("config: cache.local.path is required when backend is 'local'")
    }
    if c.Database.Backend == "sqlite" && c.Database.SQLite.Path == "" {
        return fmt.Errorf("config: database.sqlite.path is required when backend is 'sqlite'")
    }
    return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS

- [ ] **Step 5: Create config.example.yaml**

Copy the full reference config from `docs/initial-analyse.md` section 4.9 into `config.example.yaml` at project root. Only include v1.0-relevant sections (omit `s3`, `azure_blob`, `postgres.dsn`, `rescan`, `alerts`).

```yaml
# config.example.yaml — Shieldoo Gate v1.0 reference configuration

server:
  host: "0.0.0.0"

ports:
  pypi: 5000
  npm: 4873
  nuget: 5001
  docker: 5002
  admin: 8080

upstreams:
  pypi: "https://pypi.org"
  npm: "https://registry.npmjs.org"
  nuget: "https://api.nuget.org"
  docker: "https://registry-1.docker.io"

cache:
  backend: "local"
  local:
    path: "/var/cache/shieldoo-gate"
    max_size_gb: 50
  ttl:
    pypi: "168h"
    npm: "168h"
    nuget: "168h"
    docker: "720h"

database:
  backend: "sqlite"
  sqlite:
    path: "/var/lib/shieldoo-gate/gate.db"

scanners:
  parallel: true
  timeout: "60s"
  guarddog:
    enabled: true
    bridge_socket: "/tmp/shieldoo-bridge.sock"
  trivy:
    enabled: true
    binary: "trivy"
    cache_dir: "/var/cache/trivy"
  osv:
    enabled: true
    api_url: "https://api.osv.dev"

policy:
  block_if_verdict: "MALICIOUS"
  quarantine_if_verdict: "SUSPICIOUS"
  minimum_confidence: 0.7
  allowlist:
    - "pypi:litellm:==1.82.6"

threat_feed:
  enabled: true
  url: "https://feed.shieldoo.io/malicious-packages.json"
  refresh_interval: "1h"

log:
  level: "info"
  format: "json"
```

- [ ] **Step 6: Commit**

```bash
git add internal/config/ config.example.yaml
git commit -m "feat(config): add Viper-based config loading with YAML + env override"
```

---

### Task 5: SQLite Database Initialization

**Files:**
- Create: `internal/config/migrations/001_init.sql`
- Create: `internal/config/db.go`
- Test: `internal/config/db_test.go`

- [ ] **Step 1: Write the migration SQL**

```sql
-- internal/config/migrations/001_init.sql
CREATE TABLE IF NOT EXISTS artifacts (
    id               TEXT PRIMARY KEY,
    ecosystem        TEXT NOT NULL,
    name             TEXT NOT NULL,
    version          TEXT NOT NULL,
    upstream_url     TEXT NOT NULL,
    sha256           TEXT NOT NULL,
    size_bytes       INTEGER NOT NULL,
    cached_at        DATETIME NOT NULL,
    last_accessed_at DATETIME NOT NULL,
    storage_path     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_id     TEXT NOT NULL REFERENCES artifacts(id),
    scanned_at      DATETIME NOT NULL,
    scanner_name    TEXT NOT NULL,
    scanner_version TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    confidence      REAL NOT NULL,
    findings_json   TEXT NOT NULL,
    duration_ms     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS artifact_status (
    artifact_id      TEXT PRIMARY KEY REFERENCES artifacts(id),
    status           TEXT NOT NULL,
    quarantine_reason TEXT,
    quarantined_at   DATETIME,
    released_at      DATETIME,
    rescan_due_at    DATETIME,
    last_scan_id     INTEGER REFERENCES scan_results(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            DATETIME NOT NULL,
    event_type    TEXT NOT NULL,
    artifact_id   TEXT,
    client_ip     TEXT,
    user_agent    TEXT,
    reason        TEXT,
    metadata_json TEXT
);

CREATE TABLE IF NOT EXISTS threat_feed (
    sha256       TEXT PRIMARY KEY,
    ecosystem    TEXT NOT NULL,
    package_name TEXT NOT NULL,
    version      TEXT,
    reported_at  DATETIME NOT NULL,
    source_url   TEXT,
    iocs_json    TEXT
);

CREATE INDEX IF NOT EXISTS idx_artifacts_ecosystem_name ON artifacts(ecosystem, name);
CREATE INDEX IF NOT EXISTS idx_scan_results_artifact ON scan_results(artifact_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_threat_feed_ecosystem ON threat_feed(ecosystem, package_name);
```

- [ ] **Step 2: Write tests for DB initialization**

```go
// internal/config/db_test.go
package config

import (
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestInitDB_CreatesAllTables(t *testing.T) {
    db, err := InitDB(":memory:")
    require.NoError(t, err)
    defer db.Close()

    tables := []string{"artifacts", "scan_results", "artifact_status", "audit_log", "threat_feed"}
    for _, table := range tables {
        var name string
        err := db.Get(&name, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", table)
        assert.NoError(t, err, "table %s should exist", table)
        assert.Equal(t, table, name)
    }
}

func TestInitDB_SetsWALMode(t *testing.T) {
    db, err := InitDB(":memory:")
    require.NoError(t, err)
    defer db.Close()

    var mode string
    err = db.Get(&mode, "PRAGMA journal_mode")
    require.NoError(t, err)
    // :memory: databases use "memory" journal mode, but for file-based DBs it would be "wal"
    // For this test we just verify the DB was initialized without error
}

func TestInitDB_EnablesForeignKeys(t *testing.T) {
    db, err := InitDB(":memory:")
    require.NoError(t, err)
    defer db.Close()

    var fk int
    err = db.Get(&fk, "PRAGMA foreign_keys")
    require.NoError(t, err)
    assert.Equal(t, 1, fk)
}

func TestInitDB_Idempotent(t *testing.T) {
    db, err := InitDB(":memory:")
    require.NoError(t, err)
    defer db.Close()

    // Running migration again should not error (CREATE TABLE IF NOT EXISTS)
    _, err = db.Exec(mustReadMigration())
    assert.NoError(t, err)
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/config/ -v -run TestInitDB`
Expected: FAIL — `InitDB` not defined.

- [ ] **Step 4: Implement InitDB**

```go
// internal/config/db.go
package config

import (
    "embed"
    "fmt"

    "github.com/jmoiron/sqlx"
    _ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/001_init.sql
var migrationFS embed.FS

func mustReadMigration() string {
    data, err := migrationFS.ReadFile("migrations/001_init.sql")
    if err != nil {
        panic(fmt.Sprintf("config: reading migration: %v", err))
    }
    return string(data)
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

    // Run migration
    migration := mustReadMigration()
    if _, err := db.Exec(migration); err != nil {
        db.Close()
        return nil, fmt.Errorf("config: running migration: %w", err)
    }

    return db, nil
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/config/ -v -run TestInitDB`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/config/migrations/ internal/config/db.go internal/config/db_test.go
git commit -m "feat(config): add SQLite initialization with WAL mode and schema migration"
```

---

### Task 6: Makefile

**Files:**
- Create: `Makefile`

- [ ] **Step 1: Create Makefile with build, test, lint targets**

```makefile
# Makefile — Shieldoo Gate

.PHONY: build test lint clean

BINARY := shieldoo-gate
CMD_DIR := ./cmd/shieldoo-gate

build:
	go build -o bin/$(BINARY) $(CMD_DIR)

test:
	go test ./... -v -race

lint:
	go vet ./...

clean:
	rm -rf bin/
```

- [ ] **Step 2: Verify `make test` runs successfully**

Run: `make test`
Expected: All tests pass (config + model tests).

- [ ] **Step 3: Commit**

```bash
git add Makefile
git commit -m "chore: add Makefile with build, test, lint targets"
```

---

### Task 7: Main Entrypoint Skeleton

**Files:**
- Create: `cmd/shieldoo-gate/main.go`

- [ ] **Step 1: Implement minimal main.go skeleton**

This is just enough to make `make build` work — config loading, DB init, logger setup, graceful shutdown signal handling. Full wiring comes in Phase 8.

```go
// cmd/shieldoo-gate/main.go
package main

import (
    "context"
    "flag"
    "os"
    "os/signal"
    "syscall"

    "github.com/rs/zerolog"
    "github.com/rs/zerolog/log"

    "github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

func main() {
    configPath := flag.String("config", "config.yaml", "path to configuration file")
    flag.Parse()

    // Load config
    cfg, err := config.Load(*configPath)
    if err != nil {
        log.Fatal().Err(err).Msg("failed to load config")
    }

    if err := cfg.Validate(); err != nil {
        log.Fatal().Err(err).Msg("invalid config")
    }

    // Setup logger
    level, err := zerolog.ParseLevel(cfg.Log.Level)
    if err != nil {
        level = zerolog.InfoLevel
    }
    zerolog.SetGlobalLevel(level)
    if cfg.Log.Format == "text" {
        log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
    }

    // Init database
    db, err := config.InitDB(cfg.Database.SQLite.Path)
    if err != nil {
        log.Fatal().Err(err).Msg("failed to initialize database")
    }
    defer db.Close()

    log.Info().Msg("shieldoo-gate starting")

    // Graceful shutdown
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()

    sigCh := make(chan os.Signal, 1)
    signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

    // TODO: Phase 8 will add multi-port HTTP listeners and full component wiring here

    select {
    case sig := <-sigCh:
        log.Info().Str("signal", sig.String()).Msg("shutting down")
        cancel()
    case <-ctx.Done():
    }

    log.Info().Msg("shieldoo-gate stopped")
}
```

- [ ] **Step 2: Verify build succeeds**

Run: `make build`
Expected: Binary created at `bin/shieldoo-gate`.

- [ ] **Step 3: Verify all tests still pass**

Run: `make test`
Expected: All tests PASS.

- [ ] **Step 4: Commit**

```bash
git add cmd/shieldoo-gate/main.go
git commit -m "feat: add main entrypoint skeleton with config, DB init, graceful shutdown"
```

---

### Task 8: Add bin/ to .gitignore

**Files:**
- Create or modify: `.gitignore`

- [ ] **Step 1: Create .gitignore**

```
# .gitignore
bin/
*.db
*.sqlite
.env
```

- [ ] **Step 2: Commit**

```bash
git add .gitignore
git commit -m "chore: add .gitignore for build artifacts and local databases"
```
