# ADR-014: Pin Base Images by Digest

Date: 2026-06-19

## Status

Accepted

## Context

All Dockerfiles previously pinned base images by tag only (e.g. `alpine:3.20.10`,
`python:3.13.14-slim`). A tag is mutable: the registry can re-point it to a new
build at any time, so two builds of the same commit can pull different bytes.
For a supply-chain security tool this is a reproducibility and integrity gap —
the artifact we ship is not pinned to the bytes we reviewed. CLAUDE.md already
permits "pin to digest **or** exact tag"; this ADR tightens that to digest for
base images. It complements [ADR-010](ADR-010-base-image-security-patching.md),
which patches OS packages *on top of* the pinned base at build time.

## Decision

Every external image reference in `docker/Dockerfile`,
`scanner-bridge/Dockerfile`, and `tests/e2e-shell/Dockerfile.test-runner` is
pinned as `name:tag@sha256:…`. The tag is kept for human readability; the digest
is authoritative. We pin the **multi-arch index (manifest-list) digest**, not a
per-architecture digest, so builds on both `amd64` and `arm64` continue to
resolve the correct image. This covers `FROM` lines and external
`COPY --from=<image>` stages (e.g. `ghcr.io/astral-sh/uv`).

Digests are refreshed **manually** when a base tag is bumped. Automated digest
bumping (Dependabot/Renovate) is deliberately deferred — see Consequences.

## Consequences

Builds are now reproducible and integrity-pinned to reviewed bytes. The cost is
staleness: a digest pin freezes the image even after the upstream tag is rebuilt
to fix a CVE. Two mitigations keep this from becoming a security regression:
ADR-010's build-time `apt-get upgrade` still pulls Debian-security patches on top
of the pinned Debian bases, and digests must be refreshed on a regular cadence
(at minimum every release). Re-resolving a tag to its current index digest:
`docker buildx imagetools inspect <name:tag> --format '{{.Manifest.Digest}}'`.
Adopting automated digest bumping remains an open follow-up.
