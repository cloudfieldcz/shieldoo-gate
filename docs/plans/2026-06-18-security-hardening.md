# Security & Supply-Chain Hardening Plan

**Date:** 2026-06-18
**Status:** In progress — implement task by task
**Trigger:** Security finding — public repo lacks `SECURITY.md`/VDP and security CI (only `release.yml`, no CodeQL); base images pinned by tag (not digest).

## Context (verified state on 2026-06-18)

- `.github/workflows/` contains only `release.yml`. **No PR CI** (build/lint/test), no CodeQL, no dependency scan.
- Dockerfiles pin by **tag, not digest**:
  - `docker/Dockerfile`: `node:20.19.0-alpine3.21`, `golang:1.26.4-alpine`, `aquasec/trivy:0.71.1`, runtime `alpine:3.20.10`
  - `scanner-bridge/Dockerfile`: `python:3.13.14-slim` (×2)
  - `tests/e2e-shell/Dockerfile.test-runner`: `golang:1.26.4-alpine`, `ubuntu:24.04`
- GitHub Actions pinned by **tag, not SHA** (`checkout@v4`, `build-push-action@v6`, …). — ✅ fixed by T6 (2026-06-19), all `uses:` now SHA-pinned.
- Missing: `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, `dependabot.yml`.

## Decisions

- **Digest pinning** for base images: pin to `image:tag@sha256:…`. The original plan paired this with Dependabot auto-bump so patches aren't frozen, but **T2/Dependabot was skipped (2026-06-19)**. T5 shipped digest pins with **manual** bump instead; staleness is mitigated by ADR-010's build-time `apt-get upgrade` and a per-release digest-refresh discipline (see T5 follow-up). Adopting auto-bump (Dependabot/Renovate) remains an open item.
- This is a supply-chain security tool, so OpenSSF Scorecard / Best Practices Badge is the target metric for credibility.

## Task list (ordered by value/effort)

### P0 — Docs + policy (quick wins)
- [x] **T1 — `SECURITY.md` + VDP.** ✅ Done 2026-06-18. **Minimalist** single-file `SECURITY.md` (root, ~39 lines); linked from `docs/index.md` (Reference + Security section) and `README.md`. Decision: **GitHub PVR only, no email alias** (variant A); no separate `docs/security/disclosure.md` (avoids duplication). SLA: 5 business days initial ack, 90-day coordinated disclosure, safe harbor, scope = repo code + official images. `security.txt` deferred.
  - **✅ MANUAL DONE 2026-06-18:** GitHub Private Vulnerability Reporting enabled by user — "Report a vulnerability" button live on the Security tab.
- [x] **T2 — `CODEOWNERS` + `dependabot.yml`.** ✅ Done 2026-06-22. `.github/CODEOWNERS` (default `@cloudfieldcz/shdg` team + explicit security-critical paths: `internal/scanner/`, `internal/auth/`, `internal/policy/`, `docker/`, `.github/`, pinned `scanner-bridge/requirements.{in,txt}`). `.github/dependabot.yml` covers all 5 ecosystems: `gomod` (`/`), `npm` (`/ui`), `pip` (`/scanner-bridge`, reads uv-compiled `requirements.txt`), `docker` (`/docker`, `/scanner-bridge`, `/tests/e2e-shell` — digest-pin bumps), `github-actions` (`/` — SHA bumps). Weekly; minor/patch grouped for gomod+npm. This unfreezes the T5 digest pins and T6 action SHAs. Ownership is the dedicated `@cloudfieldcz/shdg` org team (admin/push on the repo, so code-ownership resolves).

### P1 — Security CI (core of the finding)
- [ ] **T3 — PR CI workflow** (`ci.yml`): `make build`/`lint`/`test` on PR + push to `main`. Do NOT set `SGW_TOKEN`/`SGW_USER` in CI (reroutes GOPROXY → 403); use `env -u` if present. `permissions: contents: read` default.
- [ ] **T4 — CodeQL** (`codeql.yml`): matrix `go` + `javascript-typescript`, weekly + PR. Add `govulncheck` (Go-native CVE check) and consider `gosec`.

### P2 — Supply-chain hardening (image + build)
- [x] **T5 — Digest-pin base images.** ✅ Done 2026-06-19. All 9 external image refs across the 3 Dockerfiles pinned `tag@sha256:…` (multi-arch index digests; covers `FROM` + `COPY --from=ghcr.io/astral-sh/uv`). `docker buildx --check` passes both production Dockerfiles. [ADR-014](../adr/ADR-014-base-image-digest-pinning.md) records the decision; linked from `docs/index.md`.
  - **✅ FOLLOW-UP RESOLVED 2026-06-22:** Digest auto-bump now handled by Dependabot `docker` ecosystem (T2). ADR-010 build-time `apt-get upgrade` remains as belt-and-suspenders; per-release manual re-resolution (`docker buildx imagetools inspect <name:tag> --format '{{.Manifest.Digest}}'`) is now a fallback only.
- [x] **T6 — SHA-pin GitHub Actions.** ✅ Done 2026-06-19. All 16 `uses:` refs in `release.yml` (the only workflow) pinned to full 40-char commit SHA with trailing `# vX.Y.Z` comment — 9 distinct actions (checkout, setup-go, upload/download-artifact, docker setup-buildx/login/metadata/build-push, softprops/action-gh-release). SHAs resolved via `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` (annotated tags dereferenced); YAML re-validated. [ADR-015](../adr/ADR-015-sha-pin-github-actions.md) records the decision; linked from `docs/index.md`. **This also satisfies T10** (release.yml is the priority target with `packages: write`).
  - **✅ FOLLOW-UP RESOLVED 2026-06-22:** SHA auto-bump now handled by Dependabot `github-actions` ecosystem (T2).
- [ ] **T7 — Build provenance / signing**: SLSA provenance attestation + cosign sign image in `release.yml`; sign the dogfooded SBOM too.
- [ ] **T8 — OpenSSF Scorecard** (`scorecard.yml`): weekly + README badge.

### P3 — Extras
- [ ] **T9 — Branch protection** on `main`: required CI checks, required review, no force-push.
- [x] **T10 — Pin actions to SHA in `release.yml`.** ✅ Done 2026-06-19 as part of **T6** — `release.yml` is currently the only workflow, so T6 covered it. See T6.
- [ ] **T11 — Secret scanning + push protection** enabled in repo settings.

### P4 — GitHub Community Standards (not security-critical; close the checklist)
Surfaced by Insights → Community Standards. None are part of the original security finding; tracked here so the checklist can go fully green.
- [ ] **T12 — `CONTRIBUTING.md`.** Already referenced from `docs/index.md` and `CLAUDE.md` but the file does not exist — add it (build/test/lint workflow, PR conventions, link to `SECURITY.md`).
- [ ] **T13 — `CODE_OF_CONDUCT.md`** (Contributor Covenant 2.1).
- [ ] **T14 — Issue + PR templates** under `.github/` (`ISSUE_TEMPLATE/`, `PULL_REQUEST_TEMPLATE.md`).
- [ ] **T15 — Repo "Description"** (GitHub About) + **"Repository admins accept content reports"** toggle. **MANUAL (repo-admin):** set the About description and enable content reports in repo settings.

## Notes
- Several tasks (enable PVR, branch protection, secret scanning, signing keys) require repo-admin actions on GitHub that Claude cannot do — these will be flagged for the user to do manually.
