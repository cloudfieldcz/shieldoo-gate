# Shieldoo Gate

> **The supply chain firewall for every package your developers and CI pull.**
> Open-source, self-hosted, multi-ecosystem. Docker, PyPI, npm, NuGet, Maven, RubyGems, Go Modules — one proxy, one policy, one audit trail.

Shieldoo Gate sits between your developers, CI runners, and the public package registries. Every artifact — every Python wheel, every npm tarball, every Docker layer, every NuGet `.nupkg` — is intercepted, scanned, and only then served. Malicious packages are blocked before they ever touch a developer laptop, a build agent, or a production image.

---

## Why This Matters

Modern software is built from public packages. A typical service pulls **thousands** of third-party dependencies, transitively, from registries that anyone on the internet can publish to. The attackers noticed.

Recent real-world attacks that Shieldoo Gate is built to stop:

- **Shai-Hulud (npm, 2025)** — a self-replicating worm infected ~180+ npm packages, ran credential-stealing `postinstall` scripts, exfiltrated npm/GitHub/cloud tokens, and used the stolen credentials to publish further trojanized releases. Victims included packages with **millions of weekly downloads**. A single `npm install` was enough to get compromised.
- **XZ Utils backdoor (CVE-2024-3094)** — a multi-year social-engineering operation planted a sophisticated backdoor in a core Linux dependency used by OpenSSH.
- **PyTorch `torchtriton` (2022)** — dependency-confusion attack pushed a malicious package with the same name as a private internal dep to PyPI; it ran on every install.
- **`ctx` / `phpass` takeover (PyPI, 2022)** — abandoned package names were re-registered and weaponized to exfiltrate environment variables (AWS keys, tokens) on install.
- **`event-stream` / `ua-parser-js` / `colors.js`** — maintainer compromise or malicious insider injected credential stealers and crypto-miners into packages used by millions.
- **LLM tooling & scanner-chain compromises** — the AI/DevSecOps ecosystem is itself a target. Supply-chain incidents affecting LiteLLM, Trivy plugins, and popular MLOps libraries have shown that **even the security tools you install are attack surface**.

What these attacks have in common: the malicious code runs **the moment the package is installed** — long before any runtime firewall, EDR, or WAF gets a chance. By then it's too late. The only effective defense is to stop the artifact from being installed in the first place.

That's what Shieldoo Gate does.

---

## How It Works

Shieldoo Gate is a **transparent, caching, scanning proxy**. You point your package managers at it instead of at the public registry. Nothing else changes in your tooling.

```
    ┌─────────────┐      ┌──────────────────────┐      ┌────────────────┐
    │  developer  │      │                      │      │ PyPI / npm /   │
    │  or CI job  │─────▶│   Shieldoo Gate      │─────▶│ Docker Hub /   │
    │             │◀─────│   (proxy + scanner)  │◀─────│ NuGet / Maven  │
    └─────────────┘      │                      │      └────────────────┘
                         │   ┌──────────────┐   │
                         │   │  scan cache  │   │
                         │   │  quarantine  │   │
                         │   │  audit log   │   │
                         │   └──────────────┘   │
                         └──────────────────────┘
```

For every request:

1. **Intercept** — the Gate speaks the native protocol of each ecosystem (PEP 503, npm registry API, OCI distribution spec, NuGet V3, etc.). Clients see a normal registry.
2. **Fetch & verify** — artifact is pulled from upstream, SHA-256 integrity is verified.
3. **Scan** — the artifact runs through a **layered scanning pipeline** (threat-feed hash lookup → heuristics → typosquat detection → version-diff → reputation scoring → GuardDog → Trivy → OSV → LLM-powered AI scanner → optional sandbox). A `malicious` verdict at **any** stage blocks delivery immediately.
4. **Cache** — clean artifacts are cached locally. Second pull is served instantly from disk, with no upstream hit and no re-scan.
5. **Quarantine & alert** — malicious artifacts are quarantined, never served, and surface in the admin UI with full scan detail and audit trail.
6. **Audit** — every request, verdict, block, and override is recorded in an append-only audit log.

Fail-closed on malicious. Fail-open on scanner outage (with full logging) — your developers are never blocked by a scanner bug, but nothing known-bad ever gets through.

---

## Who It's For

Shieldoo Gate is built for teams that take software supply chain seriously:

- **Platform / DevOps teams** — give every developer, every CI runner, every build farm a single safe package mirror. One config change, zero client-side agents, zero per-project setup.
- **Security & AppSec teams** — enforce allow/block policy centrally, get an audit trail of every dependency ever pulled, and block known-bad packages across the whole org in seconds.
- **Regulated industries (fintech, health, gov)** — meet supply-chain provenance requirements (SLSA, SSDF, EO 14028, NIS2, DORA) with a self-hostable, air-gap-friendly, open-source solution.
- **AI / ML teams** — the PyPI + Docker dependency graph under a modern LLM stack is enormous and fast-moving. Shieldoo Gate's AI scanner is built specifically to reason about obfuscated install-time code in this ecosystem.
- **Enterprises under egress control** — the Gate can be your **only allowed path** to public registries. Everything else on the network gets no internet access to package mirrors.

### Typical Use Cases

- Replace the raw PyPI/npm/Docker Hub endpoint on every dev laptop and CI runner.
- Mirror public packages behind a corporate firewall with full scan + quarantine.
- Enforce a "no install-time code from unreviewed maintainers" policy at the proxy layer.
- Get instant org-wide protection when a new supply-chain attack (like Shai-Hulud) breaks — push the malicious hashes into the threat feed and you're covered within minutes.
- Produce the forensic audit trail ("what exactly did we install, when, from where, with which scan verdict") regulators and incident responders now expect.

---

## Key Features

- **Transparent proxy** — zero client-side changes beyond pointing at the Gate URL
- **Multi-ecosystem** — Docker, PyPI, npm, NuGet, Maven, RubyGems, Go Modules
- **Deep, layered scanning pipeline** — hash feed, static heuristics, typosquat detection, version-diff, reputation, GuardDog, Trivy, OSV, LLM-powered AI analysis, optional sandbox
- **License policy enforcement (v1.2+)** — block GPL/AGPL or any other SPDX license at the proxy layer; per-project overrides; runtime-editable from the admin UI with one-click "License Groups" presets (strong copyleft, network copyleft, weak copyleft, permissive…)
- **Project segmentation (v1.2+)** — per-team / per-service audit trail and policy, derived from the HTTP Basic-auth username, zero client changes
- **CycloneDX SBOM (v1.2+)** — every scanned artifact gets a CycloneDX 1.5 SBOM persisted alongside the cache, accessible via API and admin UI
- **Block & quarantine** — malicious packages never reach developers, CI, or production
- **Community threat feed** — fast-path blocking of known malicious package hashes, updated continuously
- **Append-only audit log** — every request, scan verdict, and override is recorded
- **Admin UI** — browse artifacts, review verdicts, manage quarantine, override with justification
- **Self-hostable** — single Docker Compose stack, Helm chart, air-gap friendly
- **Open source, Apache 2.0** — no vendor lock-in, auditable code, community-driven

## Scanners

Shieldoo Gate ships with a layered scanning pipeline — from fast hash checks to deep AI analysis. Scanners run in order; a malicious verdict at any stage blocks delivery immediately.

| Scanner | What it does | Mode |
|---|---|---|
| **Threat Feed Checker** | Instant lookup against known-malicious package hashes from the community threat feed | Sync |
| **Built-in Heuristics** | Static pattern detectors — install-hook injection, data exfiltration, obfuscation, path traversal (.pth) | Sync |
| **Typosquatting Detection** | Edit distance, homoglyph, combosquatting, and namespace confusion analysis against top 5000 packages per ecosystem | Sync |
| **Version Diff Analysis** | Compares new versions against cached previous versions — detects anomalous code additions, new install hooks, entropy spikes, new dependencies | Sync |
| **Reputation Scoring** | Queries upstream registry APIs for maintainer history, publication patterns, download counts. Produces a composite risk score from 14 signals (dormant reactivation, yanked versions, ownership change, etc.) | Sync |
| **GuardDog** | Open-source malware scanner for PyPI & npm (via Python sidecar over gRPC) | Sync |
| **Trivy** | Vulnerability scanner for container images and filesystem artifacts | Sync |
| **OSV** | Queries the OSV.dev database for known vulnerabilities by package name & version | Sync |
| **AI Scanner** | LLM-powered code analysis — sends install-time scripts to a large language model that reasons about malicious intent, catching novel attacks that pattern matching misses | Sync |
| **Sandbox (Behavioral)** | Runs the package install inside a gVisor sandbox, monitors syscalls for suspicious runtime behavior (DNS to non-registry domains, HTTP POST to external hosts, file writes outside install tree, etc.) | Async |

The **AI Scanner** is a key differentiator: most supply chain security tools rely solely on static signatures and known-vulnerability databases. Shieldoo Gate adds LLM reasoning that can detect zero-day malicious packages — obfuscated data exfiltration, novel backdoors, and social-engineering lures — that no signature has ever seen before.

## Quick Start

```bash
# 1. Start the full stack (Shieldoo Gate + GuardDog scanner bridge).
#    docker/config.yaml ships with proxy auth ENABLED and a well-known dev
#    token (test-token-123) so the examples/ projects work out of the box.
docker compose -f docker/docker-compose.yml up -d

# 2. Check the Admin API
curl http://localhost:8080/api/v1/health

# 3. Try one of the smoke-test examples
cd examples/npm-chalk && npm install && node index.mjs
```

The bundled `docker/config.yaml` is a **dev-friendly reference** — auth is on,
the token is hard-coded (`test-token-123`), and SBOM + project registry are
enabled. For a clean template, start from `config.example.yaml` (which has
safer defaults: auth off, SBOM off). Do not deploy the dev token to any
shared environment.

### Authenticating through the proxy (v1.2+)

When `proxy_auth.enabled: true`, every request uses HTTP Basic Auth. The
**username is interpreted as a project label** (used for audit segmentation
and per-project license policy); the **password** carries the PAT (or the
global shared token).

```bash
# Using the dev token shipped in docker/docker-compose.yml:
export SGW_TOKEN="test-token-123"
PROJECT="default"     # or your team/service name: backend-team, data-pipeline…

# pip / uv
pip install --index-url http://$PROJECT:$SGW_TOKEN@localhost:5010/simple/ requests

# docker
echo $SGW_TOKEN | docker login localhost:5002 -u $PROJECT --password-stdin
```

In **lazy** mode (default) a new label auto-creates a project. In **strict** mode the
project must be pre-created via `POST /api/v1/projects`. Full details:
[docs/features/projects.md](docs/features/projects.md).

Port reference:

| Service | Port | Protocol |
|---|---|---|
| PyPI proxy | 5010 | HTTP |
| npm proxy | 4873 | HTTP |
| NuGet proxy | 5001 | HTTP |
| Docker proxy | 5002 | HTTP |
| Maven proxy | 8085 | HTTP |
| RubyGems proxy | 8086 | HTTP |
| Go module proxy | 8087 | HTTP |
| Admin API / Metrics | 8080 | HTTP |

## Testing

```bash
# Unit tests
make test

# E2E tests — containerized (recommended, only requires Docker)
make test-e2e-containerized

# E2E tests — host-based (requires uv, npm, dotnet, crane, etc.)
./tests/e2e-shell/run.sh
```

`make test-e2e-containerized` builds a test-runner container with all package managers pre-installed and runs the full E2E suite inside Docker — no host tools needed beyond Docker itself. This is the recommended approach for CI/CD and local validation.

See [`tests/e2e-shell/README.md`](tests/e2e-shell/README.md) for details on the host-based runner and its flags (`--no-build`, `--keep`).

## Documentation

**Full documentation is available in [`docs/`](docs/index.md).**

## License

Apache 2.0 — see [LICENSE](LICENSE).
