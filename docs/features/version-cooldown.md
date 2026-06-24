# Version Cooldown / Maturity Gating

> Refuse to serve package versions younger than a configurable age. The cheapest possible defense against zero-day supply-chain worms.

**Status:** Proposed (roadmap Tier 1)
**Priority:** High
**Perspective:** Secure Development / Incident Response
**Effort:** Low

## Problem

Self-replicating worms (Shai-Hulud, September & November 2025) and compromised-maintainer releases (LiteLLM, March 2026) share one property: **the malicious version is brand new**. The window between a poisoned version being published and the community detecting and yanking it is typically hours, occasionally a day or two. Almost all of the damage happens by auto-updating consumers fetching the version in that window.

Content scanning, AI analysis and behavioral sandboxing all help, but they are a race against a novel, sometimes obfuscated payload. There is a far cheaper control that doesn't need to *understand* the package at all: **just don't install versions that are too young.** By the time a 24–72 h cooldown elapses, the ecosystem's own detection (npm/PyPI yanks, OSV entries, our threat feed) has usually already flagged the bad release — and our scanners get a second, calmer pass at it.

Most teams never need the newest release the day it drops. The cost of waiting a day or two is near zero; the security benefit is enormous.

## Proposed Solution

Add a **maturity gate** to the policy engine: an artifact whose published-at timestamp is newer than `now - min_age` is blocked (or quarantined/warned, per policy tier) with a clear, distinct verdict reason (`VERSION_TOO_NEW`).

### Key requirements

1. **Publish-time resolver (per ecosystem).** Resolve the upstream publication timestamp for a specific `(ecosystem, package, version)`:
   - **npm** — registry metadata `time[version]`.
   - **PyPI** — JSON API `releases[version][].upload_time_iso_8601`.
   - **NuGet** — registration `published`.
   - **Maven** — artifact `lastModified` / `maven-metadata.xml`.
   - **RubyGems** — versions API `created_at`.
   - **Go** — module proxy `@v/<ver>.info` `Time`.
   - **Docker/OCI** — image config `created` (note: mutable; combine with existing tag-mutability + integrity checks).

2. **Policy knobs — the project is the unit.** A global default and per-ecosystem defaults, then resolved and overridable **per project** — the same unit license policy already uses ([ADR-008](../adr/ADR-008-license-overrides-per-project.md)). One project can run a stricter cooldown (e.g. prod-facing services), another can relax it. This keeps cooldown consistent with how the rest of policy is segmented (Basic-auth project label → per-project policy):
   ```yaml
   policy:
     cooldown:
       enabled: true
       default_min_age: "72h"
       per_ecosystem:
         npm: "72h"
         pypi: "72h"
         docker: "0h"        # tags mutable; rely on integrity gate instead
       action: "block"        # block | quarantine | warn
   # per-project overrides (strict mode) or auto-created project policy (lazy mode)
   # e.g. project "payments" → min_age 168h; project "sandbox" → min_age 0h
   ```

3. **Override path.** Reuse the existing per-project / per-package override mechanism ([ADR-006](../adr/ADR-006-per-project-package-overrides.md)) so an operator can release a too-new version for a single project when there's a genuine need (e.g. an urgent security fix that is itself newer than the cooldown).

4. **Bypass for already-trusted versions.** A version that previously passed the cooldown and was cached/served must not be re-blocked when its age was fine at first fetch — gate on *first* fetch only.

5. **Distinct verdict + audit.** `VERSION_TOO_NEW` is its own verdict reason (not lumped with `MALICIOUS`), surfaced in the CLI/UI and written to the audit log. Operators must be able to tell "blocked because young" from "blocked because dangerous".

6. **Interaction with the threat feed.** A version flagged by the threat feed is blocked regardless of age; cooldown is an *additional* gate, never a relaxation.

### Edge cases

- **Urgent security upgrade newer than the cooldown.** Documented escape hatch: per-project override, or a per-package `min_age: 0`.
- **Registry has no/unreliable timestamp.** Fail according to `policy.on_scan_error` semantics — default to *not* blocking on a missing timestamp (fail-open for this gate, since it's defense-in-depth), but log it.
- **Backdated publish timestamps.** For ecosystems where the timestamp is attacker-influenceable, prefer the registry's server-side record over package-embedded metadata.

## Why this is Tier 1

Pure Go, no new infrastructure, no new heavy dependency, reuses the policy engine and override machinery that already exist. It is plausibly the highest security-impact-to-effort feature on the entire roadmap, and it would have blocked both Shai-Hulud waves at the point of consumption regardless of whether any scanner recognized the payload.

## Open questions

- Should cooldown be measured from *upstream publish* or *first-seen-by-this-gate*? (Lean: upstream publish, falling back to first-seen when upstream time is absent.)
- Default age: 24 h, 48 h, or 72 h out of the box? (Lean: 72 h default, clearly documented as tunable.)
