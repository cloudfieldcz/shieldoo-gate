# License Policy Enforcement

> Block or warn on artifacts that contain licenses incompatible with your organization's policy.

**Status:** Planned (v1.2+)
**Origin:** Initial analysis roadmap, section 15; also listed as a non-goal for v1.0

## Problem

Many organizations have strict rules about which open-source licenses are acceptable. A developer pulling in a GPL-3.0 dependency into a proprietary codebase can create legal liability. Currently, Shieldoo Gate focuses on security (malicious content) but does not enforce license compliance.

## Proposed Solution

Add a license policy layer to the policy engine that can block, quarantine, or warn on artifacts based on their declared licenses.

### Key Requirements

1. **License detection:** Extract license information from artifacts during scan:
   - **PyPI:** `METADATA` file contains `License` and `Classifier` fields
   - **npm:** `package.json` has a `license` field
   - **NuGet:** `.nuspec` inside `.nupkg` has `<license>` element
   - **Maven:** `pom.xml` has `<licenses>` section
   - **RubyGems:** Gemspec has `licenses` attribute
   - **Go:** `LICENSE` file in module zip
   - **Docker:** Trivy can detect licenses in image layers

2. **SPDX license identifiers:** Normalize all detected licenses to [SPDX identifiers](https://spdx.org/licenses/) for consistent matching.

3. **Policy rules:** Extend the policy engine with license rules:
   ```yaml
   policy:
     licenses:
       blocked:           # Always block these licenses
         - "GPL-3.0-only"
         - "AGPL-3.0-only"
       warned:            # Allow but warn
         - "LGPL-2.1-only"
         - "MPL-2.0"
       allowed:           # Explicit allowlist (if set, anything not listed is blocked)
         - "MIT"
         - "Apache-2.0"
         - "BSD-2-Clause"
         - "BSD-3-Clause"
         - "ISC"
       unknown_action: "warn"  # What to do with undetected/unknown licenses
   ```

4. **License database:** Store detected licenses in a `artifact_licenses` table or as part of `scan_results.findings_json` with a `license` category.

5. **API + UI:** Surface license information in the artifact detail view. Allow filtering artifacts by license in the artifact list.

### How It Fits Into the Architecture

- **Scan Engine:** License detection can be a new built-in scanner (`license-detector`) or integrated into the SBOM generation pipeline (since SBOMs already contain license information).
- **Policy Engine:** New evaluation step between overrides and verdict rules: check license compatibility.
- **Audit Log:** New event type `LICENSE_BLOCKED` for artifacts blocked due to license policy.
- **Alerting:** `LICENSE_BLOCKED` and `LICENSE_WARNED` as filterable event types.

### Considerations

- **Dual-licensed packages:** Some packages are available under multiple licenses (e.g., "MIT OR Apache-2.0"). The policy should allow if ANY of the offered licenses is acceptable.
- **Transitive dependencies:** License detection at the proxy level only covers the direct artifact, not its transitive dependencies. Full transitive license analysis requires SBOM data.
- **Unknown licenses:** Many packages have non-standard or missing license declarations. The `unknown_action` policy controls whether to block, warn, or allow these.
- **Dependency on SBOM feature:** License detection is most accurate when combined with SBOM generation. Consider implementing both features together.
