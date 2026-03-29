# Scanners

> Scan engine architecture, built-in and external scanners, result aggregation, and threat feed.

## Scan Engine

The scan engine (`internal/scanner/engine.go`) orchestrates multiple scanners in parallel. When an adapter downloads an artifact, it calls `engine.ScanAll()` which:

1. Filters scanners to those supporting the artifact's ecosystem
2. Creates a shared `context.WithTimeout` (default 60 seconds)
3. Runs all applicable scanners concurrently using goroutines
4. Collects results with `sync.WaitGroup` + `sync.Mutex`
5. Returns all results — errors are captured as `VerdictClean` (fail-open)

```go
// Simplified flow
func (e *Engine) ScanAll(ctx context.Context, artifact Artifact) ([]ScanResult, error) {
    applicable := filterByEcosystem(e.scanners, artifact.Ecosystem)
    scanCtx, cancel := context.WithTimeout(ctx, e.timeout)
    // Run each scanner in a goroutine, collect results
    // Scanner errors → ScanResult{Verdict: VerdictClean, Error: err}
}
```

**Fail-open semantics:** If a scanner returns an error (network failure, timeout, crash), the engine wraps it as a `VerdictClean` result with the error recorded. Scanner failures never produce `VerdictMalicious`. This ensures that scanner outages do not block all package installations.

## Scanner Interface

Every scanner implements this interface (`internal/scanner/interface.go`):

```go
type Scanner interface {
    Name() string                                        // Unique identifier
    Version() string                                     // Current version
    SupportedEcosystems() []Ecosystem                    // Which ecosystems this scanner handles
    Scan(ctx context.Context, artifact Artifact) (ScanResult, error)
    HealthCheck(ctx context.Context) error               // Liveness check
}
```

The `Artifact` struct passed to scanners:

```go
type Artifact struct {
    ID          string     // "ecosystem:name:version"
    Ecosystem   Ecosystem  // pypi, npm, nuget, docker
    Name        string
    Version     string
    LocalPath   string     // Path to downloaded artifact on disk
    SHA256      string
    SizeBytes   int64
    UpstreamURL string
}
```

## Built-in Scanners (Go-native)

Six scanners are always active. They are registered in `cmd/shieldoo-gate/main.go` at startup:

| Scanner | ID | Ecosystems | What it detects |
|---|---|---|---|
| **Hash Verifier** | `builtin-hash-verifier` | All | Verifies SHA-256 checksum of the downloaded artifact matches the expected hash from upstream metadata |
| **Install Hook Analyzer** | `builtin-install-hook` | PyPI, npm | Detects suspicious `setup.py` hooks, `postinstall` scripts, and install-time code execution |
| **Obfuscation Detector** | `builtin-obfuscation` | All | Detects `base64.decode(exec(...))`, packed JavaScript, encrypted blobs, and other obfuscation patterns |
| **Exfil Detector** | `builtin-exfil` | All | Detects HTTP/DNS calls to non-registry domains during install, data exfiltration patterns |
| **PTH Inspector** | `builtin-pth` | PyPI | Detects `.pth` files with executable code — the exact attack vector from the LiteLLM incident |
| **Threat Feed Checker** | `builtin-threat-feed` | All | Fast-path SHA-256 lookup against the local threat feed database. If a match is found, immediately returns `MALICIOUS` |

All built-in scanners are in `internal/scanner/builtin/`:
- `hash_verifier.go`
- `install_hook.go`
- `obfuscation.go`
- `exfil_detector.go`
- `pth_inspector.go`
- `threat_feed_checker.go`

### Threat Feed Checker — Special Role

The threat feed checker has a special fast-path in the [aggregation logic](#scan-result-aggregation): if it returns `MALICIOUS`, the aggregator immediately returns `MALICIOUS` regardless of confidence thresholds or other scanner results. This ensures that known-malicious packages from the community feed are blocked instantly.

## External Scanners

External scanners are **optional** — enabled/disabled via configuration. They integrate with third-party tools:

### GuardDog (gRPC Bridge)

| | |
|---|---|
| **Package** | `internal/scanner/guarddog/` |
| **Ecosystems** | PyPI, npm |
| **Communication** | gRPC over Unix socket to Python sidecar |
| **Config key** | `scanners.guarddog.enabled`, `scanners.guarddog.bridge_socket` |

GuardDog is a behavioral scanner by Datadog that detects malicious patterns in Python and JavaScript packages using heuristic rules. Since GuardDog is Python-native, it runs in a separate Python process (`scanner-bridge/main.py`) communicating via gRPC.

The gRPC protocol (`scanner-bridge/proto/scanner.proto`):

```protobuf
service ScannerBridge {
    rpc ScanArtifact(ScanRequest) returns (ScanResponse);
    rpc HealthCheck(HealthRequest) returns (HealthResponse);
}
```

The Go client sends the artifact's local path, ecosystem, package name, and version. The Python bridge runs GuardDog's analysis and returns verdict, confidence, and findings.

**Failure handling:** If the bridge is unreachable or GuardDog fails, the scanner returns `VerdictClean` (fail-open) and logs the error.

### Trivy (Subprocess)

| | |
|---|---|
| **Package** | `internal/scanner/trivy/` |
| **Ecosystems** | Docker, PyPI, npm, NuGet |
| **Communication** | Local subprocess (`trivy` binary) |
| **Config key** | `scanners.trivy.enabled`, `scanners.trivy.binary`, `scanners.trivy.cache_dir` |

Trivy scans for known CVEs, misconfigurations, and secrets. It runs as a subprocess with JSON output. The Go wrapper parses Trivy's output into the standard `ScanResult` format.

Trivy is the primary scanner for Docker images, where it scans image layers for vulnerabilities. For other ecosystems, it provides CVE detection complementary to the built-in heuristic scanners.

### OSV Scanner (HTTP API)

| | |
|---|---|
| **Package** | `internal/scanner/osv/` |
| **Ecosystems** | PyPI, npm, NuGet |
| **Communication** | HTTP API calls to `api.osv.dev` |
| **Config key** | `scanners.osv.enabled`, `scanners.osv.api_url` |

OSV queries the [OSV.dev](https://osv.dev) vulnerability database, which aggregates data from NVD, GitHub Advisory Database, and other sources. It checks whether a specific package version has known vulnerabilities.

## Scan Result Aggregation

After all scanners complete, the **policy aggregator** (`internal/policy/aggregator.go`) combines multiple `ScanResult` values into a single verdict. The rules, applied in priority order:

1. **Fast-path: threat feed hit** — If any result from scanner ID `builtin-threat-feed` has verdict `MALICIOUS`, return `MALICIOUS` immediately. No confidence threshold check.

2. **Skip low-confidence results** — Results with `confidence < MinConfidence` (default 0.7) are ignored.

3. **Skip errored results** — Results where `Error != nil` are treated as `CLEAN` (fail-open).

4. **Highest verdict wins** — Among remaining results: `MALICIOUS > SUSPICIOUS > CLEAN`.

5. **Default** — If no valid results remain, verdict is `CLEAN`.

```
Scanner Results         Aggregation                 Policy Engine
┌────────────────┐
│ hash-verifier  │─── CLEAN (1.0) ──┐
│ install-hook   │─── SUSPICIOUS    │     ┌──────────┐     ┌─────────┐
│ obfuscation    │─── CLEAN (0.9) ──├────▶│Aggregate │────▶│Evaluate │──▶ ALLOW/BLOCK/QUARANTINE
│ exfil          │─── CLEAN (0.8) ──│     │          │     │         │
│ pth-inspector  │─── CLEAN (1.0) ──│     └──────────┘     └─────────┘
│ threat-feed    │─── CLEAN (1.0) ──│
│ guarddog       │─── SUSPICIOUS    │
│ trivy          │─── (error) ──────┘  ← treated as CLEAN
└────────────────┘
```

## Threat Feed

The community threat feed (`internal/threatfeed/client.go`) provides a database of known-malicious package hashes. It is fetched from a remote URL and stored in the `threat_feed` table.

**Refresh cycle:**
1. On startup: initial fetch in a background goroutine (errors logged, not fatal)
2. Periodic refresh via `time.Ticker` at configured interval (default 1 hour)
3. Entries are upserted using `INSERT OR REPLACE`

**Feed format** (OSV-compatible JSON):
```json
{
  "schema_version": "1.0",
  "updated": "2026-03-25T10:00:00Z",
  "entries": [
    {
      "sha256": "abc123...",
      "ecosystem": "pypi",
      "package_name": "litellm",
      "versions": ["1.82.7", "1.82.8"],
      "reported_at": "2026-03-24T12:00:00Z",
      "source_url": "https://github.com/shieldoo/shieldoo-gate/issues/1",
      "iocs": ["models.litellm.cloud", "~/.config/sysmon/sysmon.py"]
    }
  ]
}
```

The threat feed checker scanner (`builtin-threat-feed`) performs a fast-path SHA-256 lookup against this local table during every scan.

## Ecosystem Coverage Matrix

| Scanner | PyPI | npm | NuGet | Docker |
|---|:---:|:---:|:---:|:---:|
| Hash Verifier | x | x | x | x |
| Install Hook Analyzer | x | x | | |
| Obfuscation Detector | x | x | x | x |
| Exfil Detector | x | x | x | x |
| PTH Inspector | x | | | |
| Threat Feed Checker | x | x | x | x |
| GuardDog (bridge) | x | x | | |
| Trivy (subprocess) | x | x | x | x |
| OSV (API) | x | x | x | |
| Sandbox (gVisor) | x | x | x | | x | x |

## Dynamic Sandbox Scanner (gVisor)

The sandbox scanner (`internal/scanner/sandbox/`) provides **dynamic behavioral analysis** by executing artifacts inside a gVisor (runsc) sandbox and monitoring syscall behavior. Unlike all other scanners, it runs **asynchronously** — it does not block the download path.

### How It Works

1. After an artifact is served to the client (synchronous scanners have already passed), the sandbox scanner is invoked in the background.
2. The artifact is copied into a temporary workspace.
3. An OCI runtime spec is generated with strict resource limits (512MB memory, 1 CPU core, 100 PIDs).
4. The ecosystem-specific install command runs inside a gVisor sandbox:
   - **PyPI:** `pip install --no-deps <artifact>`
   - **npm:** `npm install <artifact>`
   - **NuGet:** `dotnet add package --source <dir>`
   - **Maven:** `mvn install:install-file -Dfile=<artifact>`
   - **RubyGems:** `gem install <artifact> --local`
5. gVisor strace logs capture all syscalls during execution.
6. Behavioral rules analyze the logs for malicious indicators.
7. If malicious behavior is detected, the artifact is **retroactively quarantined** and an alert is fired.

### Behavioral Detection Rules

| Rule | Severity | Description |
|---|---|---|
| DNS non-registry queries | HIGH | DNS query to unknown domain during install |
| HTTP POST to external | CRITICAL | Data exfiltration attempt |
| SSH/config writes | CRITICAL | Write to `.ssh` or `.config` — credential theft |
| Shell execution | HIGH | `/bin/sh` or `-c` during install |
| .pth file creation | CRITICAL | Python auto-execute vector |
| Cron job creation | CRITICAL | Persistence mechanism |
| Excessive forking | HIGH | More than 10 `clone()` calls — potential fork bomb |

### Configuration

```yaml
scanners:
  sandbox:
    enabled: false                   # disabled by default
    runtime_binary: "runsc"          # path to gVisor runtime binary
    timeout: "30s"                   # per-sandbox execution timeout
    network_policy: "none"           # "none" (no network) or "monitor" (DNS/HTTP logging)
    max_concurrent: 2                # max concurrent sandbox executions
```

**Network policy:**
- `"none"` (default, production): No network access in sandbox. Safe, but cannot detect exfiltration attempts.
- `"monitor"` (research/analysis): Network via DNS proxy allowlist. Official registry domains allowed, others blocked and logged.

### Requirements

- **Linux only:** gVisor (runsc) requires a Linux host. On macOS/Windows, the scanner is automatically skipped.
- **Disk:** ~5 GB for base images + 1 GB per concurrent sandbox.
- **Memory:** `max_concurrent * 512MB` (default 1 GB).

### Failure Semantics

The sandbox scanner uses **fail-open with visibility**: if gVisor is unavailable, the scan times out, or any error occurs, it returns `VerdictSuspicious` with confidence 0.0 and the error recorded (not `VerdictClean`). The policy engine can be configured to warn or block on unknown verdicts.

### Orphan Cleanup

At startup, the sandbox scanner lists all containers with the `sgw-sandbox-` prefix and deletes stale ones. This prevents resource leaks from previous crashes.

### Known Limitations

- Sophisticated malware may fingerprint the gVisor environment (incomplete syscall support, timing differences).
- `npm install` with native compilation (node-gyp) may exceed the 512MB memory limit, causing OOM kill and `VerdictUnknown`.
- Docker and Go ecosystems are not supported (Docker images are not "installed", Go modules have no install hooks).

## Health Checks

`Engine.HealthCheck()` runs `HealthCheck()` on every registered scanner and returns a map of scanner name to error (nil = healthy). This is exposed via `GET /api/v1/health` and includes scanner status in the response.
