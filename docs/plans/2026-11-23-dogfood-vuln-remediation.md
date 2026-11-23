# Dogfood Vulnerability Remediation — 2026-11-23

This plan records a snapshot of the `shieldoo-gate` project's own vulnerability
findings and the remediation for them. The snapshot comes from the production
gate (`ssh shieldoo-gate` → `shieldoo-gate-postgres-1`) on 2026-11-23. The
format follows [2026-11-03](2026-11-03-dogfood-vuln-remediation.md).

**Data source:** `scan_findings` joined to `components.last_scan_id` for
`projects.label = 'shieldoo-gate'`, unsuppressed rows only. Production runs
`0.19.14`, and `main` was equal to the `v0.19.14` tag.

## 1. Snapshot

| Component | CRIT | HIGH | MED | LOW | INFO |
|---|---:|---:|---:|---:|---:|
| `gate` | 0 | 0 | 0 | 0 | 1 |
| `gate-image` | 0 | 3 | 11 | 4 | 10 |
| `scanner-bridge-image` | 0 | 52 | 99 | 80 | 103 |

The `scanner-bridge` (pypi) and `ui` (npm) components had no findings.

## 2. Findings by origin and fix

| Origin | Packages (version in prod) | Fix |
|---|---|---|
| Trivy binary bundled in `gate-image` | containerd 2.4.1, go-jose 4.1.5, x/net 0.60.0 (HIGH) | trivy 0.76.1 → 0.76.2 (containerd 2.4.2, go-jose 4.1.6, x/net 0.62.0). |
| Alpine base | libcrypto3/libssl3 3.5.9-r0, zlib 1.3.2-r1 | alpine 3.24.4 + the existing `apk upgrade`. |
| Our Go module graph | x/crypto 0.58.0 (GO-2026-5932, INFO) | x/crypto 0.59.0 through the go module refresh. |
| Go toolchain | — | Go 1.27.4 in all ADR-010 locations (security release, 2026-11-10). |
| Debian base (scanner-bridge) | apt 3.0.3, libc6/libc-bin deb13u4, zlib1g 1-1+b1 | Rebuilt `python:3.13.18-slim` digest + the existing `apt-get upgrade`. |

## 3. Result

Local image builds from this branch were scanned with trivy 0.76.2
(`--scanners vuln`):

- `gate-image`: 0 HIGH/CRIT. Three MEDIUM findings and one UNKNOWN finding
  remain, all in the bundled trivy binary: otel/sdk and otel/trace 1.46.0,
  stdlib go1.27.3, and x/crypto 0.58.0. Trivy 0.76.2 is the newest upstream
  release. Only a trivy release built with go ≥ 1.27.4 and otel ≥ 1.47.0 can
  clear them. ADR-010 tracks them; we do not suppress them.
- `scanner-bridge-image`: 0 Python findings. 213 Debian trixie OS findings
  remain, and none of them has a fixed version in Debian yet.
- `govulncheck ./...`: no vulnerabilities.

The production numbers change only after the next release, because only
`release.yml` refreshes the SBOM.

## 4. Dependabot PRs in the same branch

This branch supersedes all open dependabot PRs, because several of them break
a lockstep invariant:

- Go: #343 (gomod group), #332 and #333 (golang 1.27.4; their image digest
  is outdated).
- Docker: #317 (trivy, needs the `cmd/shdg/trivy.go` pin), #331 (alpine).
- scanner-bridge: #323, #326, #328, #336, #340, #342 (regenerated from
  `requirements.in` with hashes).
- UI: #341 (npm group; Playwright 1.65 needs a new `PW_IMAGE`).
- GitHub Actions: #315, #318, #320, #321 (codeql-action, moved together),
  #316, #319, #322, #338, #339.
