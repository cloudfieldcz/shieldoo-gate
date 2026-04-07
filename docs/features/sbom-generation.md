# SBOM Generation

> Automatic Software Bill of Materials generation for every cached artifact.

**Status:** Planned (v1.2+)
**Origin:** Initial analysis roadmap, section 15

## Problem

Organizations increasingly require SBOMs (Software Bill of Materials) for compliance (EU Cyber Resilience Act, US Executive Order 14028) and supply chain visibility. Currently, Shieldoo Gate scans artifacts for malicious content but does not produce a machine-readable inventory of what each artifact contains.

## Proposed Solution

Generate an SBOM for every artifact that passes through the proxy, stored alongside the cached artifact and accessible via the Admin API.

### Key Requirements

1. **Format support:** Generate SBOMs in both [CycloneDX](https://cyclonedx.org/) and [SPDX](https://spdx.dev/) formats (industry standards).
2. **Automatic generation:** Produce the SBOM during the scan phase, as part of the scan-on-download pipeline. Trivy already has SBOM generation capabilities (`trivy sbom`).
3. **Storage:** Store SBOMs in the cache alongside the artifact (e.g., `{artifact_path}.sbom.cdx.json`). Reference the SBOM path in the `artifacts` or `scan_results` table.
4. **API exposure:** New endpoints:
   - `GET /api/v1/artifacts/{id}/sbom?format=cyclonedx` — download SBOM for an artifact
   - `GET /api/v1/artifacts/{id}/sbom?format=spdx` — same in SPDX format
5. **UI integration:** Show SBOM summary (component count, license breakdown) on the artifact detail page. Allow download.

### How It Fits Into the Architecture

- **Scan Engine:** Add an optional `GenerateSBOM` method to the `Scanner` interface, or create a dedicated `SBOMGenerator` component. Trivy is the natural candidate since it already supports SBOM output.
- **Cache Store:** SBOMs are stored as companion files to the artifact. The `CacheStore` interface may need a `PutMeta()` method or SBOMs can be stored as separate objects with a `.sbom` suffix.
- **Admin API:** New endpoint group under `/api/v1/artifacts/{id}/sbom`.
- **Database:** Optional `sbom_path` column on `scan_results` or a new `artifact_sboms` table.

### Ecosystem Coverage

| Ecosystem | SBOM Feasibility | Notes |
|---|---|---|
| PyPI | High | Trivy can generate from wheel/sdist metadata |
| npm | High | `package.json` has explicit dependency declarations |
| NuGet | High | `.nuspec` inside `.nupkg` lists dependencies |
| Docker | High | Trivy already does full image SBOM |
| Maven | High | `pom.xml` declares all dependencies |
| RubyGems | Medium | Gemspec has dependencies, but runtime deps may differ |
| Go | High | `go.mod` / `go.sum` are authoritative |

### Considerations

- **Performance:** SBOM generation adds latency to the scan pipeline. Consider generating SBOMs asynchronously (like the sandbox scanner) to avoid blocking downloads.
- **Storage cost:** SBOMs can be large (100KB–10MB for Docker images). Account for this in cache size calculations.
- **Freshness:** SBOMs are generated at cache time. If the artifact is served from cache for months, the SBOM may not reflect newly discovered vulnerabilities — but it accurately describes the artifact's contents.
