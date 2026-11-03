# Dogfood Vulnerability Remediation — 2026-11-03

This plan records a snapshot of the `shieldoo-gate` project's own vulnerability
findings and the remediation for them. The snapshot comes from the production
gate (`ssh shieldoo-gate` → `shieldoo-gate-postgres-1`) on 2026-11-03. The
format follows [2026-09-03](2026-09-03-dogfood-vuln-remediation.md).

**Data source:** `scan_findings` joined to `components.last_scan_id` for
`projects.label = 'shieldoo-gate'`, unsuppressed rows only. Production runs
`0.19.11`, and `main` was equal to the `v0.19.11` tag. All five components
were rescanned on 2026-11-03, and no scan run was stuck in `pending`/`running`.

## 1. Snapshot

| Component | Ecosystem | CRIT | HIGH | MED | LOW |
|---|---|---:|---:|---:|---:|
| `scanner-bridge` | pypi | 3 | 9 | 10 | 1 |
| `gate` | go | 3 | 14 | 17 | 2 |
| `ui` | npm | 0 | 3 | 0 | 0 |
| `gate-image` | docker | 0 | 13 | 32 | 5 |
| `scanner-bridge-image` | docker | 3 | 66 | 119 | 69 |

The `gate` component SBOM covers the whole repository tree. It therefore
repeats the Python and npm findings of `scanner-bridge` and `ui`.

## 2. Findings by origin and fix

| Origin | Packages (version in prod) | Fix |
|---|---|---|
| scanner-bridge `requirements.txt` | pyjwt 2.13.0 (1 CRIT, 6 HIGH), anyio 4.14.1 (CRIT), certifi 2026.6.17 (CRIT), urllib3 2.7.0, setuptools 84.0.0 | pyjwt 2.15.1, anyio 4.14.2, certifi 2026.10.19, urllib3 2.8.0, setuptools 84.2.1. anyio and certifi are transitive, so `requirements.in` now pins them explicitly. |
| Base-image pip in scanner-bridge runtime | msgpack 1.1.2, setuptools 70.3.0, both vendored in `pip/_vendor/` | Remove pip from the runtime stage, see [deployment.md](../deployment.md#why-the-runtime-image-has-no-pip). `pip-bootstrap.txt` is deleted. |
| Our Go module graph | go-jose/v4 4.1.4, x/net 0.58.0, chi 5.3.2, otel 1.44.0 | `go get -u ./...` → go-jose 4.1.8, x/net 0.62.0, chi 5.5.0, otel 1.47.0. |
| Go toolchain (our binary) | stdlib 1.27.1 (4 HIGH, 9 MED) | Go 1.27.3 in all seven ADR-010 locations. |
| UI npm | follow-redirects 1.16.0 (3 HIGH) | `overrides` → 1.16.2. vite 8.3.5 plus the npm minor/patch group. |
| Trivy binary bundled in `gate-image` | stdlib 1.26.6, grpc 1.82.1, containerd 2.3.3, x/crypto 0.55.0, x/net 0.58.0 | trivy 0.74.0 → 0.76.1 (built with go1.27.3). |
| Alpine base | zlib 1.3.2-r0 | alpine 3.24.3 + the existing `apk upgrade`. |
| Debian base (scanner-bridge) | openssl, libpcre2, libsqlite3, gzip, libc | python 3.13.18-slim + the existing `apt-get upgrade`. |

## 3. Result

Local image builds from this branch were scanned with trivy 0.76.1
(`--scanners vuln`):

- `gate-image`: 1 HIGH remains. It is go-jose v4.1.5 inside the bundled trivy
  0.76.1 (fixed in 4.1.6). Trivy 0.76.1 is the newest upstream release, so
  only the next trivy release can clear it.
- `scanner-bridge-image`: 0 Python findings. Only Debian trixie OS packages
  remain (util-linux family, ncurses, libsqlite3, libsystemd/libudev, libacl,
  libc, gcc-14 runtime, tar, zlib, pam). None of them has a fixed version in
  Debian yet, and the `apt-get upgrade` step picks them up when one appears.
- `govulncheck ./...`: 0 vulnerabilities affect our code.

The production numbers change only after the next release. A rescan replays
the stored SBOM, and only `release.yml` refreshes the SBOM.

## 4. Other changes in the same branch

- GitHub Actions pins: codeql-action 4.39.0 (all four refs together),
  scorecard-action 2.5.0, upload-artifact 7.0.2, download-artifact 8.0.2,
  setup-node 7.1.0, setup-buildx-action 4.4.1, build-push-action 7.4.0.
- `examples/python-strawberry`: strawberry-graphql 0.327.2.
- Production config (`.deploy/config.yaml`, not in git): `builtin-threat-feed` is `best_effort`.
  `threat_feed.enabled` is `false` on production because `feed.shieldoo.io`
  still serves the Azure App Service wildcard certificate. With the feed off,
  the checker can only return CLEAN.
