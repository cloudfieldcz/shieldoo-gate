# ADR-001: Project identification via HTTP Basic-auth username

**Status:** Accepted
**Date:** 2026-04-15
**Context window:** [analysis](../plans/2026-04-15-sbom-and-license-policy.md)

## Context

We wanted per-team / per-service segmentation of proxy usage (for license policy, audit, reporting) without forcing client-side changes for the majority of deployments that already use Basic auth (pip, npm, docker all support it).

Considered alternatives:

1. **Per-PAT project binding.** Create PATs that carry a fixed `project_id`. Pro: strongest security. Con: every developer needs a PAT per project, admins must pre-provision.
2. **Custom HTTP header.** `X-Shieldoo-Project: my-team`. Pro: orthogonal to auth. Con: clients cannot be configured to send arbitrary headers for these protocols.
3. **Basic-auth username as project label.** Pro: every standard client already sets it (and we currently ignore it). Pro: zero friction for lazy-mode adoption. Con: in lazy mode any PAT can pick any label → can't be used as a hard security boundary.

## Decision

Use HTTP Basic-auth **username** as the project label. Validate it against a regex, lowercase-normalize it, and resolve it to a `projects` row via middleware.

Two runtime modes:

- **Lazy (default)** — unknown labels auto-create projects. Rate-limited per PAT, capped globally.
- **Strict** — unknown labels are rejected at auth time. Per-project license overrides are only honored in this mode (S-01).

## Consequences

**Positive:**

- Zero client-side changes for existing deployments.
- Compatible with every proxy protocol we support (pip, npm, docker, nuget, maven, rubygems, go mod).
- Drops cleanly into existing `APIKeyMiddleware` — we were already reading username and throwing it away.

**Negative / mitigated:**

- Label spoofing is possible in lazy mode. Mitigated by making per-project license policy overrides strict-mode-only. Audit records still attribute usage to whatever label the client presented — not a security boundary in lazy mode, just a segmentation hint.
- An attacker with a stolen PAT could spam random labels. Mitigated by per-PAT rate limiter + global hard cap on `projects` count.

## Future work

- PAT → project binding (v1.3+). When a PAT is created, admin optionally pins it to a project_id. Middleware rejects mismatched labels. Closes S-01 fully.
- `enabled = false` runtime enforcement. v1.2 stores it as metadata only.
