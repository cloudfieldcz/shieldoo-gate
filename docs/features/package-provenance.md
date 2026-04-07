# Package Provenance & Signature Verification

> Verify that artifacts are authentically published by their claimed maintainers using cryptographic signatures and build provenance attestations.

**Status:** Proposed
**Priority:** High
**Perspective:** CISO / Secure Development

## Problem

Even if a package contains no malicious code *today*, there is no guarantee it was published by its legitimate maintainer. Account takeovers, compromised CI/CD pipelines, and registry-level breaches can inject malicious versions under trusted package names. The LiteLLM incident (March 2026) demonstrated that a compromised PyPI account can push a trojanized release that passes basic content scanning.

Cryptographic provenance verification — checking that a package was built from a known source repository by an authorized build system — is the strongest defense against this class of attack. Sigstore, npm provenance, PyPI attestations, and Docker content trust / cosign are gaining adoption but are not yet enforced by default.

## Proposed Solution

Add a provenance verification layer that checks cryptographic signatures and build attestations before serving artifacts. Operate in "verify-if-available" mode by default (do not break packages that lack provenance), with optional strict mode that blocks unsigned artifacts.

### Verification Methods

1. **Sigstore / cosign (containers):** Verify cosign signatures on OCI images. Check that the signing identity matches expected maintainers. Support keyless verification via Fulcio + Rekor transparency log.
2. **npm provenance:** Verify SLSA provenance attestations embedded in npm packages (available since npm v9). Check `source_repository`, `build_trigger`, and `builder_id` claims.
3. **PyPI attestations:** Verify PEP 740 attestations (Trusted Publishers). Check that the package was built by the claimed GitHub Actions / GitLab CI workflow.
4. **NuGet signing:** Verify author and repository signatures on `.nupkg` files. Check against NuGet's certificate trust store.
5. **Maven GPG signatures:** Verify PGP signatures on `.jar` / `.pom` files against keys published on public keyservers or repository-configured trusted keys.
6. **RubyGems signing:** Verify gem signatures when present (adoption is low, but should be checked when available).

### Key Requirements

1. **Verify-if-available mode (default):** If a provenance attestation or signature exists, verify it. If verification fails, verdict is `SUSPICIOUS` or `MALICIOUS`. If no provenance exists, pass through (no penalty).
2. **Strict mode (optional):** Block all artifacts that lack valid provenance. Intended for high-security environments. Configurable per ecosystem since adoption varies widely.
3. **Trusted identity registry:** Organizations configure expected signing identities per package (e.g., "requests must be signed by a GitHub Actions workflow from `psf/requests`"). Mismatches trigger alerts.
4. **Transparency log checks:** For Sigstore-based verification, query the Rekor transparency log to confirm the signature was publicly recorded (prevents backdated signatures).
5. **Audit trail:** Log all provenance checks (pass/fail/absent) in the audit log for compliance reporting.

### Configuration

```yaml
scanners:
  provenance:
    enabled: true
    mode: "verify-if-available"       # "verify-if-available" | "strict"
    strict_ecosystems: []             # Ecosystems where unsigned = blocked
    sigstore:
      rekor_url: "https://rekor.sigstore.dev"
      fulcio_url: "https://fulcio.sigstore.dev"
    trusted_identities:               # Expected signing identities per package
      - ecosystem: "docker"
        pattern: "library/*"
        identity: "https://github.com/docker-library/*"
      - ecosystem: "pypi"
        pattern: "requests"
        identity: "https://github.com/psf/requests"
    keyservers:                       # For Maven PGP verification
      - "https://keys.openpgp.org"
      - "https://keyserver.ubuntu.com"
```

### How It Fits Into the Architecture

- **Scanner:** New `ProvenanceScanner` in `internal/scanner/provenance/`. Implements the `Scanner` interface. Per-ecosystem verification logic in sub-packages.
- **Dependencies:** Add `github.com/sigstore/cosign/v2` (for cosign verification), `github.com/sigstore/rekor` (for transparency log queries).
- **Database:** New `provenance_checks` table (artifact_id, ecosystem, has_provenance, verified, signer_identity, transparency_log_entry, checked_at).
- **Admin UI:** Show provenance status on artifact detail page (verified ✓ / unverified / failed ✗ / no provenance available).
- **Metrics:** `shieldoo_gate_provenance_checks_total{ecosystem, result}` where result ∈ {verified, failed, absent}.

### Ecosystem Coverage

| Ecosystem | Provenance Maturity | Verification Approach |
|---|---|---|
| Docker/OCI | High | cosign signatures, SLSA provenance via in-toto |
| npm | Medium-High | SLSA provenance (built into npm CLI since v9) |
| PyPI | Medium | PEP 740 attestations (Trusted Publishers, 2024+) |
| NuGet | Medium | Author + repository signatures |
| Maven | Medium | PGP signatures (long-standing but inconsistent adoption) |
| RubyGems | Low | Gem signing exists but adoption is minimal |
| Go | Low | `go.sum` handles integrity; module provenance is emerging |

### Considerations

- **Adoption gap:** Many legitimate packages are not signed. Strict mode should be used carefully and only for ecosystems/packages where signing is common.
- **Key management:** Trusted identity configuration is powerful but requires maintenance. Consider auto-learning mode that records signing identities on first encounter and alerts on changes.
- **Performance:** Transparency log queries add network latency (~100–300ms). Cache verification results alongside scan results.
- **Sigstore ecosystem changes:** Sigstore is evolving rapidly. Pin client library versions and monitor for breaking changes.
