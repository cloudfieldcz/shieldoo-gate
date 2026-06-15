# ADR-010: Base-image security patching and Go toolchain unification

**Status:** Accepted

## Context

Container-image dogfood scans (`shdg --image`, gated on `critical` in
[`release.yml`](../../.github/workflows/release.yml)) repeatedly surface OS-package
and Go-stdlib CVEs in the two release images:

- **`scanner-bridge-image`** (`python:3.13.x-slim`, Debian trixie) carries the bulk
  of findings — `openssl`, `perl-base`, `ncurses`, `libsqlite3`, `glibc`,
  `util-linux`, etc. These come from the Debian base, not from our Python code
  (the source-tree `scanner-bridge` component is clean).
- **`gate-image`** (`alpine`) findings are Go stdlib only, embedded in the compiled
  binaries: `shieldoo-gate` (our binary) and the bundled `aquasec/trivy` binary.

Two structural problems made remediation harder than it should be:

1. **Pinning vs. patching tension.** CLAUDE.md mandates explicit version pinning
   (base images on digest or exact tag — no floating/`latest`). A pinned base tag is
   immutable, so OS security fixes published *after* the tag was cut never reach the
   image until the tag itself is bumped — but tag bumps are infrequent, so the image
   accumulates fixable OS CVEs between bumps.
2. **Go version skew.** The build embedded three different Go versions:
   `go.mod` `go 1.25.10`, `docker/Dockerfile` `golang:1.25.10-alpine`, and CI
   `GO_VERSION: 1.25.7`. The stdlib version baked into a binary is set by the
   *toolchain that compiles it*, so the skew produced inconsistent stdlib findings
   (e.g. `gate-image` reporting stdlib `v1.25.10`) and made "which Go fixes this?"
   ambiguous.

## Decision

1. **Pin the base tag, then layer security patches at build time.** The base image
   stays pinned to an exact tag for reproducibility, and a `RUN apt-get update &&
   apt-get upgrade -y && rm -rf /var/lib/apt/lists/*` layer in the **runtime** stage
   pulls whatever fixed package versions Debian-security has published at build time.
   This is a *bounded, deliberate* exception to strict version pinning: it applies
   only to base-image OS packages (never to application dependencies), runs only in
   the final/runtime stage, and is reproducible-per-build because the base tag is
   pinned. Application dependencies remain strictly pinned with hashes
   (`requirements.txt` via `uv pip compile --generate-hashes`, `go.sum`,
   `package-lock.json`) — this ADR does **not** relax CLAUDE.md security invariant #4.

1a. **Force-remove `perl-base` from the scanner-bridge runtime.** `perl-base` is a
   Debian *essential* package shipped by `python:3.13-slim` but used nowhere by the
   bridge — a glibc Python gRPC service whose scanner (guarddog) is Python, whose
   engine (semgrep) is a Rust binary, and whose git access (pygit2) bundles libgit2.
   Nothing invokes the Perl interpreter. It was the source of the **only two
   critical findings** (CVE-2026-42496, CVE-2026-8376) plus the perl-base
   highs/mediums, none with an upstream fix. The runtime stage force-purges it
   (`dpkg --purge --force-remove-essential --force-depends perl-base`) and asserts
   `! command -v perl`; apt/dpkg are never run at runtime, so the resulting dpkg
   "essential removed" state is inert. Alpine/musl was rejected as the perl-free
   route: the heavy native deps (semgrep, pygit2, cryptography, grpcio) publish
   **glibc-only wheels**, so musl would force slow, fragile from-source builds.

2. **Unify the Go toolchain on a single patched version.** `go.mod`'s `go`
   directive, the `golang:<ver>-alpine` builder tag in `docker/Dockerfile`, and CI
   `GO_VERSION` must always name the **same** version. Bumping the Go patch level is
   done in lockstep across all three. The current target is **1.26.4** (fixes
   CVE-2026-42504, CVE-2026-42507, CVE-2026-27145), validated with a full
   `make build && make lint && make test` pass after the 1.25 → 1.26
   minor-version jump.

3. **Third-party embedded binaries are tracked, not silently shipped.** Go-stdlib
   findings originating from bundled third-party binaries (e.g. `aquasec/trivy`'s
   own build) are out of reach of our toolchain bump. The **preferred** resolution is
   bumping the pinned third-party image once a safe rebuilt release exists. A
   `cve_ignore` is a last-resort stopgap only — note that `cve_ignore` suppression
   matches `(component, cve, package_name)` with **version excluded from the
   predicate** ([`store.go` ApplySuppression](../../internal/component/store.go)), so a
   `stdlib`-keyed ignore on an image would also mask a *future* stdlib regression in
   our own binary. Trivy is pinned deliberately (CycloneDX 1.6 support, parity with
   the `shdg`-bundled Trivy) and was itself the target of a 2026 supply-chain
   incident, so its version is not bumped reflexively to chase a stdlib finding.

## Consequences

- **Positive:** OS CVEs with an upstream fix clear on the next image build without
  waiting for a base-tag bump. Stdlib findings become deterministic (one Go version
  everywhere). The remediation path for every image finding is now one of a small,
  documented set: *bump base tag*, *apt upgrade clears it*, *bump Go*, *bump pinned
  third-party image*, or *time-boxed `cve_ignore`*.
- **Negative / accepted:** `apt-get upgrade` makes the runtime layer's exact OS
  package set vary with Debian-security's publish state at build time — two builds of
  the same commit on different days can differ in OS package patch levels. This is
  the intended trade-off (security currency over byte-for-byte reproducibility of the
  OS layer); the base tag and all application deps remain pinned, so application
  behaviour is unchanged.
- `perl-base` (both criticals + the perl highs/mediums) is **eliminated** by the
  force-purge above — removed from the dpkg DB, so the scanner no longer reports it.
- Remaining no-upstream-fix OS CVEs (e.g. `ncurses`, `libsqlite3` at the 2026-06-15
  snapshot) are not fixable by `apt upgrade`. They can be suppressed with
  `cve_ignore` records, but with an important caveat: **ignore expiry is notify-only**
  — the expiry watcher ([`ignore_expiry.go`](../../internal/scheduler/ignore_expiry.go))
  emits an `ignore_expired` audit event but does **not** auto-revoke, and
  `FindActiveIgnoresForRun` does not filter on `expires_at`, so a suppression persists
  until an operator manually revokes it. Suppressing a *critical* finding this way is
  therefore effectively permanent-until-manual-action and must not be treated as
  self-healing. The durable fix for the `perl-base` criticals is a perl-free base
  image (distroless / minimal), tracked as a follow-up.

## References

- [ADR-007 — vulnerability scan](./ADR-007-vulnerability-scan.md) (scan + ignore lifecycle)
- CLAUDE.md — "Version Pinning — MANDATORY", security invariant #4
- Go 1.26.4 / 1.25.11 release (2026-06-02): CVE-2026-42504 / -42507 / -27145
