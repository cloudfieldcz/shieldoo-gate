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
func (e *Engine) ScanAll(ctx context.Context, artifact Artifact, excludeNames ...string) ([]ScanResult, error) {
    applicable := filterByEcosystem(e.scanners, artifact.Ecosystem)
    // Optional excludeNames filters out specific scanners (e.g., AI scanner during rescan)
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
    ID          string     // "ecosystem:name:version" (or "ecosystem:name:version:filename")
    Ecosystem   Ecosystem  // pypi, npm, nuget, docker, maven, rubygems, go
    Name        string
    Version     string
    LocalPath   string     // Path to downloaded artifact on disk
    Filename    string     // Original filename (when available)
    SHA256      string
    SizeBytes   int64
    UpstreamURL string
}
```

## Built-in Scanners (Go-native)

Eight scanners are available built-in (six core + typosquatting + version diff). They are registered in `cmd/shieldoo-gate/main.go` at startup:

| Scanner | ID | Ecosystems | What it detects |
|---|---|---|---|
| **Hash Verifier** | `hash-verifier` | PyPI, npm, NuGet, Docker | Verifies SHA-256 checksum of the downloaded artifact matches the expected hash from upstream metadata |
| **Install Hook Analyzer** | `install-hook-analyzer` | PyPI, npm | Detects suspicious `setup.py` hooks, `postinstall` scripts, and install-time code execution |
| **Obfuscation Detector** | `obfuscation-detector` | PyPI, npm, NuGet, Docker | Detects `base64.decode(exec(...))`, packed JavaScript, encrypted blobs, and other obfuscation patterns |
| **Exfil Detector** | `exfil-detector` | PyPI, npm, NuGet, Docker | Detects HTTP/DNS calls to non-registry domains during install, data exfiltration patterns |
| **PTH Inspector** | `pth-inspector` | PyPI | Detects `.pth` files with executable code — the exact attack vector from the LiteLLM incident |
| **Threat Feed Checker** | `builtin-threat-feed` | PyPI, npm, NuGet, Docker | Fast-path SHA-256 lookup against the local threat feed database. If a match is found, immediately returns `MALICIOUS` |
| **Typosquat Scanner** | `builtin-typosquat` | PyPI, npm, NuGet, Docker, Maven, RubyGems, Go | Detects typosquatting, homoglyph substitution, combosquatting, and namespace confusion by checking package names against popular packages |
| **Version Diff Scanner** | `version-diff` | PyPI, npm, NuGet, Maven, RubyGems, Go | Compares new versions against cached previous versions to detect suspicious changes (install hooks, size anomaly, high entropy, new deps) |

All built-in scanners are in `internal/scanner/builtin/` (except version-diff in `internal/scanner/versiondiff/`):
- `hash_verifier.go`
- `install_hook.go`
- `obfuscation.go`
- `exfil_detector.go`
- `pth_inspector.go`
- `threat_feed_checker.go`
- `typosquat.go` + `typosquat_data.go`

### Threat Feed Checker — Special Role

The threat feed checker has a special fast-path in the [aggregation logic](#scan-result-aggregation): if it returns `MALICIOUS`, the aggregator immediately returns `MALICIOUS` regardless of confidence thresholds or other scanner results. This ensures that known-malicious packages from the community feed are blocked instantly.

### Typosquat Scanner — Name-Based Detection

The typosquat scanner (`builtin-typosquat`) detects supply chain attacks based on package naming patterns. It loads popular package names from the `popular_packages` database table into memory at startup and checks each artifact's name using four strategies:

1. **Edit distance** — Levenshtein distance against top N packages per ecosystem. Flags packages within configurable distance (default: 2). Name normalization strips npm scoped prefixes (`@scope/name` → `scope-name`) so that e.g. `@babel/core` correctly matches popular `babel-core` instead of being flagged as a typosquat.
2. **Homoglyph detection** — NFKC normalization + confusable character mapping (`l`→`1`, `o`→`0`, etc.). Catches Unicode substitution attacks.
3. **Combosquatting** — Detects popular names concatenated with common suffixes (`-utils`, `-helper`, `-lib`, `-dev`, `-tool`, `-sdk`).
4. **Namespace confusion** — Flags packages matching configured internal namespace prefixes fetched from public registries.

The scanner seeds the `popular_packages` table from embedded data on first run. All checks run in <1ms with no file I/O. Configuration is under `scanners.typosquat` in `config.yaml` — see the [feature documentation](features/typosquatting-detection.md) for details.

### Version Diff Scanner — Cross-Version Comparison

The version diff scanner (`version-diff`) compares newly downloaded package versions against previously cached versions to detect suspicious changes. It lives in `internal/scanner/versiondiff/` (separate package due to cache dependency).

**Supported ecosystems:** PyPI, npm, NuGet, Maven, RubyGems, Go (not Docker — handled by Trivy).

**Detection strategies:**

1. **File inventory diff** — Compares file lists between old and new version. Flags when many new files are added (threshold: `max_new_files`, default 20).
2. **Size anomaly** — Computes ratio of new total extracted size to old. Flags when ratio exceeds `code_volume_ratio` (default 5.0x).
3. **Sensitive file changes** — Per-ecosystem list of security-sensitive files (setup.py, postinstall, .pth, etc.). New or modified install hooks are CRITICAL findings. Non-executable package metadata that changes on virtually every release is MEDIUM (not HIGH) to avoid noise — new deps are already caught by strategy #5:
   - **PyPI:** `__init__.py`, `pyproject.toml`, `setup.cfg` → MEDIUM. Only `setup.py` and `*.pth` are CRITICAL.
   - **npm:** `package.json` → MEDIUM. Only `preinstall*`/`postinstall*`/`install*` are CRITICAL.
   - **NuGet:** `.targets`, `.props` → MEDIUM. Only `install.ps1`/`init.ps1` are CRITICAL.
   - **Maven:** `pom.xml` → MEDIUM. `*.sh` stays HIGH.
   - **Go:** `go.mod` → MEDIUM.
   - **RubyGems:** `Rakefile` stays HIGH. `extconf.rb` is CRITICAL.
4. **Entropy analysis** — Shannon entropy for added/modified files. Samples first `entropy_sample_bytes` (default 8192) bytes. High entropy (>6.0 bits/byte) in code files suggests obfuscated/packed content. Skips known binary extensions.
5. **New dependency detection** — Parses ecosystem metadata (package.json, setup.cfg, go.mod, etc.) to find newly added dependencies.

**Scoring:** Critical findings → SUSPICIOUS (0.90), High → SUSPICIOUS (0.80), Medium → SUSPICIOUS (0.60). The scanner never produces MALICIOUS verdict (heuristic-based).

**Operation:** Synchronous within the scan pipeline. Large artifacts (> `max_artifact_size_mb`, default 20 MB) are skipped. A sub-timeout (`scanner_timeout`, default 10s) prevents cloud cache latency from blocking other scanners. Fail-open on any error.

**Security protections:** Decompression bomb limits, path traversal rejection, symlink/hardlink rejection, SHA256 verification of cached previous version (TOCTOU protection), stale temp dir cleanup on startup.

**Configuration:** Under `scanners.version_diff` in `config.yaml`. Disabled by default (opt-in). See `config.example.yaml` for all options.

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

> **Companion package — `scanner-bridge/extractors_diff/`** (Phase 3+ of the version-diff AI rebuild). A parallel package alongside `extractors/` produces a `DiffPayload` comparing TWO archives of the same package (new vs cached previous version) for the AI-driven version-diff scanner. Each per-ecosystem module exposes `extract(new_path, old_path, *, original_filename) -> DiffPayload`. The PyPI implementation handles wheels and sdists, applies path-aware filtering (tests/examples/docs at depth ≥ 2 are filtered, install hooks bypass the filter), enforces a 1 MB per-file read cap with overflow detection (defends against decompression bombs), uses head+tail truncation for content > 8 KB (28 KB head + 4 KB tail for install hooks, 4 KB + 4 KB for regular files), and rejects path traversal / symlinks / hardlinks. Phase 4 extends the registry with NPM, NuGet, Maven, RubyGems; Phase 5 wires it into the version-diff scanner orchestrator.

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

## Reputation Scanner (Maintainer Risk Scoring)

The reputation scanner (`internal/scanner/reputation/`) evaluates package trustworthiness based on upstream registry metadata — maintainer history, publication patterns, download counts — and produces a composite risk score.

| | |
|---|---|
| **Package** | `internal/scanner/reputation/` |
| **ID** | `builtin-reputation` |
| **Ecosystems** | PyPI, npm, NuGet |
| **Communication** | Direct HTTP to upstream registry APIs |
| **Config key** | `scanners.reputation.enabled`, `scanners.reputation.cache_ttl` |

### How It Works

1. When a new artifact is scanned, the reputation scanner fetches package metadata from the upstream registry (PyPI JSON API, npm Registry API, NuGet Gallery API).
2. Metadata is cached in the `package_reputation` database table with configurable TTL (default 24h + random jitter to prevent thundering herd).
3. The scanner evaluates 14 configurable risk signals against the metadata.
4. Each signal has a weight (0.0–1.0). Fired signals are combined into a composite risk score using the formula: `risk = 1 - ∏(1 - weight_i × signal_i)`.
5. The composite score is compared against configurable thresholds to produce a verdict.

### Risk Signals

**V1 signals (core):**

| # | Signal | Weight | What it detects |
|---|--------|--------|-----------------|
| 1 | `package_age` | 0.3 | Package less than 30 days old |
| 2 | `low_downloads` | 0.2 | Fewer than 100 downloads |
| 3 | `no_source_repo` | 0.3 | No source repository linked |
| 4 | `dormant_reactivation` | 0.7 | No update for 12+ months, then new version |
| 5 | `few_versions` | 0.15 | Only 1 version published |
| 6 | `no_description` | 0.1 | No package description |
| 7 | `version_count_spike` | 0.4 | 10+ versions published in last 7 days |
| 8 | `ownership_change` | 0.8 | Maintainer list changed recently |

**V2 signals (extended):**

| # | Signal | Weight | What it detects |
|---|--------|--------|-----------------|
| 9 | `yanked_versions` | 0.6 | Previous versions were yanked/deleted |
| 10 | `unusual_versioning` | 0.2 | Version numbers like 99.0.0 or 0.0.1 that skip semver conventions |
| 11 | `maintainer_email_domain` | 0.15 | All maintainer emails use free providers (gmail, outlook) |
| 12 | `first_publication` | 0.25 | Maintainer has published only this package |
| 13 | `repo_mismatch` | 0.4 | Source repository name doesn't match package name |
| 14 | `classifier_anomaly` | 0.15 | Package classifiers appear inconsistent |

All signal weights are configurable via `config.yaml`. Signals can be individually enabled/disabled.

### Scoring

The composite risk score uses a multiplicative formula that allows multiple weak signals to add up to significant risk without any single weak signal dominating:

```
risk_score = 1 - ∏(1 - weight_i × signal_i)
```

where `signal_i` is 1.0 if the signal fired, 0.0 otherwise.

**Thresholds:**
- `suspicious` (default 0.5): score >= this → `SUSPICIOUS` verdict
- `malicious` (default 0.8): score >= this → still capped at `SUSPICIOUS` by convention (the reputation scanner never produces `MALICIOUS` — it is heuristic-based)

### Hardening

- **Rate limiting:** Per-ecosystem token-bucket limiter (default 30 requests/min) prevents IP bans from upstream registries.
- **SSRF mitigation:** HTTP client rejects redirects to non-HTTPS URLs and private IP addresses. TLS 1.2+ enforced.
- **Singleflight deduplication:** Concurrent scans of different versions of the same package share a single metadata fetch via `golang.org/x/sync/singleflight`.
- **TTL jitter:** Random jitter (default 0–2h) added to cache TTL to prevent thundering herd on cache expiry.
- **Stale entry cleanup:** Background goroutine deletes reputation entries older than `retention_days` (default 30) at startup.
- **Prometheus metrics:** `shieldoo_reputation_cache_hits_total`, `shieldoo_reputation_cache_misses_total`, `shieldoo_reputation_fetch_duration_seconds`, `shieldoo_reputation_fetch_errors_total`.

### Failure Handling

The reputation scanner follows **fail-open semantics**: if the upstream API is unreachable, rate-limited, or times out, the scanner returns `VerdictClean` with confidence 0 and logs the error. Metadata fetch failures never block package installation.

### Configuration

```yaml
scanners:
  reputation:
    enabled: false                      # opt-in; queries upstream APIs for each new package
    cache_ttl: "24h"                    # cache metadata for this long before re-fetching
    cache_ttl_jitter: "2h"             # random jitter added to TTL (prevents thundering herd)
    timeout: "10s"                      # per-upstream-API request timeout
    rate_limit: 30                      # max upstream API requests per minute per ecosystem
    retention_days: 30                  # delete stale reputation entries older than this
    thresholds:
      suspicious: 0.5                   # score >= this → SUSPICIOUS verdict
      malicious: 0.8                    # score >= this (capped at SUSPICIOUS)
    signals:
      package_age:
        enabled: true
        weight: 0.3
      # ... (14 signals total, see config.example.yaml for full list)
```

See [feature documentation](features/maintainer-risk-scoring.md) for design rationale and ecosystem metadata availability matrix.

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
| **Typosquat Scanner** | x | x | x | x | x | x | x |
| **Version Diff Scanner** | x | x | x | | x | x | x |
| **Reputation Scanner** | x | x | x | | | | |
| GuardDog (bridge) | x | x | | | | | |
| Trivy (subprocess) | x | x | x | x | | | |
| OSV (API) | x | x | x | | | | |
| Sandbox (gVisor) | x | x | x | | x | x | |
| **AI Scanner (LLM)** | x | x | x | | x | x | |

### Scanner Coverage Gaps

With the **Typosquat Scanner** and **Version Diff Scanner** supporting all 7 ecosystems (including Go), and the **AI Scanner** and **Sandbox** covering Maven and RubyGems, most ecosystems now have comprehensive multi-layer coverage.

**Go modules** have the lightest scanner coverage — only the Typosquat Scanner (name-based), Version Diff Scanner (cross-version comparison), and policy engine apply. Go modules have no install-time hooks, so content-based and behavioral scanners have no meaningful attack surface to analyze.

**Docker images** are primarily covered by Trivy (CVE/misconfiguration scanning), the built-in scanners (hash, obfuscation, exfil, threat feed), the Typosquat Scanner, and tag mutability detection. Version Diff and Reputation scanners do not apply to Docker.

**Reputation Scanner** currently supports PyPI, npm, and NuGet — the ecosystems whose upstream APIs expose sufficient metadata (maintainers, download counts, publication history). Maven, RubyGems, and Go have limited upstream metadata availability.

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
- `npm install` with native compilation (node-gyp) may exceed the 512MB memory limit, causing OOM kill and `VerdictSuspicious` with confidence 0.0.
- **Docker** is not supported — Docker images are not "installed" in the traditional sense; Trivy handles Docker scanning via image layer analysis instead.
- **Go** is not supported — Go modules have no install hooks or post-install scripts, so there is no meaningful install-time behavior to observe.
- **Maven and RubyGems are supported** — the sandbox can execute `mvn install:install-file` and `gem install --local` respectively to observe install-time behavior.

## Health Checks

`Engine.HealthCheck()` runs `HealthCheck()` on every registered scanner **in parallel** and returns a map of scanner name to error (nil = healthy). This is exposed via `GET /api/v1/health` and includes scanner status in the response.

Parallelism matters here because individual scanners perform real I/O during their health check — `trivy` forks `trivy version`, `osv` does an HTTPS POST to `api.osv.dev`, `ai-scanner` makes a gRPC call to the scanner bridge. Running them sequentially would let a slow scanner consume the budget of the ones that follow, producing spurious `DeadlineExceeded` (gRPC/HTTP) or `signal: killed` (SIGKILL from `exec.CommandContext` when the parent context expires mid-fork) errors even when every individual scanner is healthy.

The HTTP handler in [`internal/api/health.go`](../internal/api/health.go) sets a **10 s ceiling** for the combined health check call. This is the upper bound across all scanners, not per-scanner — slowest scanner wins.
