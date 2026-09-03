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
- **`gate-image`** (`alpine`) findings are Go stdlib embedded in the compiled
  binaries (`shieldoo-gate` and the bundled `aquasec/trivy` binary) **plus**
  alpine base-package CVEs — `libssl3`/`libcrypto3` at `3.5.7-r0` (2 HIGH + 6
  MEDIUM + 12 LOW, fixed in `3.5.8-r0`), missed for the same structural reason
  as the Debian findings below: the runtime stage only ran `apk add`, never
  `apk upgrade` (added 2026-09, see Decision §1).

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
   stays pinned to an exact tag for reproducibility, and an OS-package-manager
   upgrade layer in the **runtime** stage pulls whatever fixed package versions
   the distro's security repo has published at build time: `RUN apt-get update &&
   apt-get upgrade -y && rm -rf /var/lib/apt/lists/*` for `scanner-bridge-image`
   (Debian), and `RUN apk upgrade --no-cache && apk add --no-cache …` for
   `gate-image` (alpine, added 2026-09 — see Context above). Both package
   managers verify fetched package signatures against the distro keys baked
   into the pinned base layer (`/etc/apk/keys` for apk, the base image's APT
   keyring for apt), fetched over HTTPS — that signature check, not the digest
   pin, is what bounds the trust surface this upgrade step opens up. This is a
   *bounded, deliberate* exception to strict version pinning: it applies only
   to base-image OS packages (never to application dependencies), runs only in
   the final/runtime stage, and is reproducible-per-build because the base tag is
   pinned. Application dependencies remain strictly pinned with hashes
   (`requirements.txt` via `uv pip compile --generate-hashes`, `go.sum`,
   `package-lock.json`) — this ADR does **not** relax CLAUDE.md security invariant #4.

1a. **Force-remove `perl-base` from the scanner-bridge runtime.** `perl-base` is a
   Debian *essential* package shipped by `python:3.13-slim` but used nowhere by the
   bridge — a glibc Python gRPC service whose scanner (guarddog) is Python and whose
   git access (pygit2) bundles libgit2. Nothing invokes the Perl interpreter. It was the source of the **only two
   critical findings** (CVE-2026-42496, CVE-2026-8376) plus the perl-base
   highs/mediums, none with an upstream fix. The runtime stage force-purges it
   (`dpkg --purge --force-remove-essential --force-depends perl-base`) and asserts
   `! command -v perl`; apt/dpkg are never run at runtime, so the resulting dpkg
   "essential removed" state is inert. Alpine/musl was rejected as the perl-free
   route: the heavy native deps (pygit2, cryptography, grpcio) publish
   **glibc-only wheels**, so musl would force slow, fragile from-source builds.

2. **Unify the Go toolchain on a single patched version.** `go.mod`'s `go`
   directive, the `golang:<ver>-alpine` builder tag in both `docker/Dockerfile`
   (`go-builder` stage) and `tests/e2e-shell/Dockerfile.test-runner`
   (`shdg-build` stage), CI `GO_VERSION` (`ci.yml`, `codeql.yml`,
   `release.yml`), and the `ARG GO_VERSION` / `ARG GO_SHA256` pair that
   installs a *second*, independent Go toolchain later in the **same**
   `tests/e2e-shell/Dockerfile.test-runner` file must always name the
   **same** version. That file carries two unrelated Go toolchains in two
   different stages, neither visible to the other: the `shdg-build` build
   stage compiles the `shdg` CLI (only its finished binary is
   `COPY --from=`'d into the final image — its toolchain never leaves that
   stage), while the later `ARG GO_VERSION` tarball install runs in the
   **final/runtime** stage and puts a separate toolchain on that image's
   own `PATH`, for the e2e test client itself. Neither stage's version
   implies or updates the other, so both must be bumped by hand. The `ARG`
   location is also a **two-value** bump: `GO_VERSION` and `GO_SHA256`
   change together, or the Dockerfile's `sha256sum -c` fails the build —
   get the checksum from `https://go.dev/dl/?mode=json` (the `linux-amd64`
   archive entry for that version), never invent one.

   The two `FROM golang:<ver>-alpine@sha256:<digest>` locations are the
   *same trap in a worse form*. Docker resolves a `name:tag@digest`
   reference **by digest** and ignores the tag, so bumping only the version
   in the tag keeps building the **old, unpatched** toolchain image — with a
   green build, a correct-looking Dockerfile, and no checksum failure to
   catch it. Unlike the `ARG GO_VERSION`/`ARG GO_SHA256` pair, nothing here
   fails loudly when the two halves disagree. **The tag and the `@sha256:`
   digest must always move together.** Take the new digest from the registry
   (e.g. `docker buildx imagetools inspect golang:<ver>-alpine`) or from the
   digest Dependabot proposes — never carry a digest across a version bump,
   and never "resolve" the mismatch by dropping the digest, which the
   SHA/digest-pinning rules in ADR-014/ADR-015 forbid. Both Go builder
   stages are expected to pin the *same* digest, so a difference between
   those two lines is itself a signal that one of them was missed.

   Bumping the Go patch level is done in lockstep across all **seven**
   locations. The current target is **1.27.0** (carries the go1.26.6 stdlib
   fixes for GO-2026-6218 (net/url), GO-2026-6091 (html/template),
   GO-2026-6090 (crypto/tls), GO-2026-6089 (net/http), GO-2026-6088 (encoding/xml),
   GO-2026-5972 (encoding/asn1) and GO-2026-5026 (net/http); previously
   1.26.5 for GO-2026-5856 / CVE-2026-39822 — crypto/tls Encrypted Client
   Hello privacy leak), validated with a full `make build && make lint &&
   make test` pass plus a clean `govulncheck ./...` after the jump.

3. **Third-party embedded binaries are tracked, not silently shipped.** Go-stdlib
   findings originating from bundled third-party binaries (e.g. `aquasec/trivy`'s
   own build) are out of reach of our toolchain bump. The **preferred** resolution is
   bumping the pinned third-party image once a safe rebuilt release exists. A
   `cve_ignore` is a last-resort stopgap only — note that `cve_ignore` suppression
   matches `(component, cve, package_name)` with **version excluded from the
   predicate** ([`store.go` ApplySuppression](../../internal/component/store.go)), so a
   `stdlib`-keyed ignore on an image would also mask a *future* stdlib regression in
   our own binary. Trivy is pinned deliberately (must decode CycloneDX 1.6+ SBOMs — Trivy
   itself now emits 1.7 as of 0.72+ — parity with the `shdg`-bundled Trivy)
   and was itself the target of a 2026 supply-chain
   incident, so its version is not bumped reflexively to chase a stdlib finding.

## Consequences

- **Positive:** OS CVEs with an upstream fix clear on the next image build without
  waiting for a base-tag bump. Stdlib findings become deterministic (one Go version
  everywhere). The remediation path for every image finding is now one of a small,
  documented set: *bump base tag*, *apt/apk upgrade clears it*, *bump Go*, *bump pinned
  third-party image*, or *time-boxed `cve_ignore`*.
- **Negative / accepted:** `apt-get upgrade` (scanner-bridge) and `apk upgrade`
  (gate) make each runtime layer's exact OS package set vary with the distro's
  security repo publish state at build time — two builds of the same commit on
  different days can differ in OS package patch levels, and for `gate-image` this
  now covers the *entire* installed base set (previously only the two packages
  `apk add` itself installed). This is the intended trade-off (security currency
  deliberately bought at the cost of byte-for-byte reproducibility of the OS
  layer), bounded by each package manager's signature verification against the
  distro keys baked into the pinned base (see Decision §1); the base tag and all
  application deps remain pinned, so application behaviour is unchanged.
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
- [ADR-014 — base-image digest pinning](./ADR-014-base-image-digest-pinning.md)
  (why every base image carries a `@sha256:` digest, and why it may never be dropped)
- [ADR-015 — SHA-pin GitHub Actions](./ADR-015-sha-pin-github-actions.md)
- CLAUDE.md — "Version Pinning — MANDATORY", security invariant #4
- Go 1.26.4 / 1.25.11 release (2026-06-02): CVE-2026-42504 / -42507 / -27145
- Go 1.26.6 / 1.27.0 release: GO-2026-6218 (net/url), GO-2026-6091
  (html/template), GO-2026-6090 (crypto/tls), GO-2026-6089 (net/http),
  GO-2026-6088 (encoding/xml), GO-2026-5972 (encoding/asn1), GO-2026-5026
  (net/http)
