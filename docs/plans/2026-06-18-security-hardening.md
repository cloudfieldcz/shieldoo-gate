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
- GitHub Actions pinned by **tag, not SHA** (`checkout@v4`, `build-push-action@v6`, …).
- Missing: `SECURITY.md`, `CONTRIBUTING.md`, `CODEOWNERS`, `dependabot.yml`.

## Decisions

- **Digest pinning + Dependabot** for base images: pin to `image:tag@sha256:…` AND configure Dependabot to auto-bump digests, so security patches are not frozen. (Bare digest pin without auto-bump = security regression — do not do that.)
- This is a supply-chain security tool, so OpenSSF Scorecard / Best Practices Badge is the target metric for credibility.

## Task list (ordered by value/effort)

### P0 — Docs + policy (quick wins)
- [x] **T1 — `SECURITY.md` + VDP.** ✅ Done 2026-06-18. **Minimalist** single-file `SECURITY.md` (root, ~39 lines); linked from `docs/index.md` (Reference + Security section) and `README.md`. Decision: **GitHub PVR only, no email alias** (variant A); no separate `docs/security/disclosure.md` (avoids duplication). SLA: 5 business days initial ack, 90-day coordinated disclosure, safe harbor, scope = repo code + official images. `security.txt` deferred.
  - **⏳ MANUAL (repo-admin, user must do):** Enable GitHub Private Vulnerability Reporting — Repo → Settings → Code security and analysis → "Private vulnerability reporting" → Enable. Without this, the "Report a vulnerability" button referenced in `SECURITY.md`/README does not appear.
- [ ] **T2 — `CODEOWNERS` + `dependabot.yml`.** CODEOWNERS on `internal/scanner/`, `internal/auth/`, `internal/policy/`, `docker/`. Dependabot for `gomod`, `npm` (ui), `pip`/`uv` (scanner-bridge), `docker`, `github-actions`. (Prereq for T5 digest auto-bump.)

### P1 — Security CI (core of the finding)
- [ ] **T3 — PR CI workflow** (`ci.yml`): `make build`/`lint`/`test` on PR + push to `main`. Do NOT set `SGW_TOKEN`/`SGW_USER` in CI (reroutes GOPROXY → 403); use `env -u` if present. `permissions: contents: read` default.
- [ ] **T4 — CodeQL** (`codeql.yml`): matrix `go` + `javascript-typescript`, weekly + PR. Add `govulncheck` (Go-native CVE check) and consider `gosec`.

### P2 — Supply-chain hardening (image + build)
- [ ] **T5 — Digest-pin base images** (all 3 Dockerfiles) + Dependabot digest auto-bump (depends on T2). ADR `docs/adr/ADR-NNN-base-image-digest-pinning.md` (version pinning is normative in CLAUDE.md → policy change needs ADR).
- [ ] **T6 — SHA-pin GitHub Actions** across all workflows (`@<full-sha> # vX`). Dependabot maintains.
- [ ] **T7 — Build provenance / signing**: SLSA provenance attestation + cosign sign image in `release.yml`; sign the dogfooded SBOM too.
- [ ] **T8 — OpenSSF Scorecard** (`scorecard.yml`): weekly + README badge.

### P3 — Extras
- [ ] **T9 — Branch protection** on `main`: required CI checks, required review, no force-push.
- [ ] **T10 — Pin actions to SHA in `release.yml`** (priority because it has `packages: write`).
- [ ] **T11 — Secret scanning + push protection** enabled in repo settings.

## Notes
- Several tasks (enable PVR, branch protection, secret scanning, signing keys) require repo-admin actions on GitHub that Claude cannot do — these will be flagged for the user to do manually.
