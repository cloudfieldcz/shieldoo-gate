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
    Ecosystem   Ecosystem  // pypi, npm, nuget, docker, maven, rubygems, go
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

### AI Scanner (LLM-based, gRPC Bridge)

| | |
|---|---|
| **Package** | `internal/scanner/ai/` |
| **Ecosystems** | PyPI, npm, NuGet, Maven, RubyGems |
| **Communication** | gRPC over Unix socket to Python sidecar (shared with GuardDog bridge) |
| **Config key** | `scanners.ai.enabled`, `scanners.ai.provider`, `scanners.ai.model` |

The AI scanner uses a single-pass LLM call (Azure OpenAI `gpt-5.4-mini`) to perform semantic security analysis of install-time scripts extracted from packages. Unlike pattern-based scanners, it can understand **intent** — detecting novel obfuscation techniques, credential harvesting patterns, and self-replication behaviors that rule-based scanners miss.

#### How It Works

1. The Go wrapper (`internal/scanner/ai/scanner.go`) sends an `AIScanRequest` to the Python scanner-bridge via gRPC.
2. The Python bridge (`scanner-bridge/ai_scanner.py`) extracts install-time scripts using ecosystem-specific extractors (`scanner-bridge/extractors/`).
3. Extracted files are assembled into a prompt (max 32K tokens / ~128K characters) and sent to the LLM with a security analyst system prompt.
4. The LLM returns a structured JSON verdict: `CLEAN`, `SUSPICIOUS`, or `MALICIOUS` with confidence and findings.
5. The response is mapped to a standard `ScanResult` and returned to the scan engine.

#### What Gets Extracted Per Ecosystem

| Ecosystem | Extracted Files | Why |
|---|---|---|
| **PyPI** | `setup.py`, `*.pth`, top-level `__init__.py`, `METADATA` | `.pth` auto-exec, install hooks, module-load side effects |
| **npm** | `package.json`, `scripts/*`, files referenced from `preinstall`/`postinstall` | install-time execution points |
| **NuGet** | `*.targets`, `*.props`, `install.ps1`, `init.ps1`, `tools/*.ps1` | MSBuild hooks, PowerShell scripts |
| **Maven** | `pom.xml` (plugin sections), `*.sh` in root, assembly descriptors | exec-maven-plugin, antrun |
| **RubyGems** | `extconf.rb`, `Rakefile`, `*.gemspec`, `bin/*` | native extension build hooks |

#### Real-World Attack Detection

The AI scanner is specifically designed to catch attacks like:

- **LiteLLM/TeamPCP (PyPI, March 2026):** Double base64-encoded `.pth` file with credential-stealing payload. The AI scanner understands that `.pth` files should only contain filesystem paths, not executable code.
- **Shai-Hulud 2.0 (npm, November 2025):** Obfuscated `preinstall` script that downloads TruffleHog, harvests credentials, and self-replicates. The AI scanner follows the execution chain from `package.json` → `setup_bun.js` and identifies the full attack.

#### Configuration

```yaml
scanners:
  ai:
    enabled: false                    # opt-in
    provider: "azure_openai"          # "azure_openai" or "openai"
    model: "gpt-5.4-mini"
    api_key_env: "AI_SCANNER_API_KEY" # env var name for API key
    timeout: "15s"                    # per-LLM-call timeout
    max_input_tokens: 32000
    bridge_socket: "/tmp/shieldoo-bridge.sock"
    # Azure OpenAI settings:
    azure_endpoint: ""                # e.g. "https://<instance>.openai.azure.com/"
    azure_deployment: "gpt-54-mini"
```

**Environment variables** (set in `.env` or `docker-compose.yml`):

| Variable | Description |
|---|---|
| `AI_SCANNER_ENABLED` | `"true"` to enable the scanner in the Python bridge |
| `AI_SCANNER_API_KEY` | Azure OpenAI or OpenAI API key |
| `AI_SCANNER_PROVIDER` | `"azure_openai"` (default) or `"openai"` |
| `AI_SCANNER_MODEL` | Model name (only for `provider: "openai"`; Azure uses deployment name) |
| `AI_SCANNER_AZURE_ENDPOINT` | Azure OpenAI endpoint URL (required for Azure provider) |
| `AI_SCANNER_AZURE_DEPLOYMENT` | Azure deployment name (required for Azure provider) |

#### Performance

- **Latency:** ~4–6 seconds per scan (extraction + LLM call + parsing)
- **Token window:** 32K input tokens (~128K characters) — sufficient for most packages without truncation
- **Throughput:** ~150–180 tokens/second, time-to-first-token ~3–5 seconds

#### Failure Handling

The AI scanner follows **fail-open semantics**: if the LLM API is unreachable, times out, or returns an error, the scanner returns `VerdictClean` with confidence 0 and logs the error. This ensures that OpenAI/Azure outages never block package installations. Every fail-open event is logged and can be monitored via metrics.

#### Added Value vs Existing Scanners

| Attack Pattern | Builtin Scanners | **AI Scanner** |
|---|---|---|
| `.pth` with base64+exec | PTH Inspector detects `.pth` | + semantic understanding of intent |
| `preinstall` → external JS | Install Hook detects hook | + follows execution chain, understands downloaded payload |
| Credential harvesting | Not detected | Detected |
| Self-replication (token abuse) | Not detected | Detected |
| IMDS metadata queries | Not detected | Detected |
| Novel obfuscation patterns | Pattern-based (may miss) | Semantic understanding |
| Fork bomb patterns | Not detected | Detected |

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

| Scanner | PyPI | npm | NuGet | Docker | Maven | RubyGems | Go |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Hash Verifier | x | x | x | x | | | |
| Install Hook Analyzer | x | x | | | | | |
| Obfuscation Detector | x | x | x | x | | | |
| Exfil Detector | x | x | x | x | | | |
| PTH Inspector | x | | | | | | |
| Threat Feed Checker | x | x | x | x | | | |
| GuardDog (bridge) | x | x | | | | | |
| Trivy (subprocess) | x | x | x | x | | | |
| OSV (API) | x | x | x | | | | |
| Sandbox (gVisor) | x | x | x | | x | x | |
| **AI Scanner (LLM)** | x | x | x | | x | x | |

### Scanner Coverage Gaps

With the addition of the **AI Scanner**, Maven and RubyGems now have both static AI analysis (synchronous, before serving) and dynamic sandbox analysis (asynchronous, after serving). This significantly improves coverage for these ecosystems.

**Go modules remain without scanner coverage** — neither built-in, external, AI, nor sandbox scanners support the Go ecosystem. Go modules have no install-time hooks, so there is no meaningful install-time behavior to analyze. Go modules are proxied and cached but pass through without any scan.

For Go modules, the only protection mechanisms are:

1. **Policy engine** — manual quarantine and overrides still work
2. **Tag mutability detection** — detects upstream digest changes

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
- **Docker** is not supported — Docker images are not "installed" in the traditional sense; Trivy handles Docker scanning via image layer analysis instead.
- **Go** is not supported — Go modules have no install hooks or post-install scripts, so there is no meaningful install-time behavior to observe.
- **Maven and RubyGems are supported** — the sandbox can execute `mvn install:install-file` and `gem install --local` respectively to observe install-time behavior.

## Health Checks

`Engine.HealthCheck()` runs `HealthCheck()` on every registered scanner and returns a map of scanner name to error (nil = healthy). This is exposed via `GET /api/v1/health` and includes scanner status in the response.
