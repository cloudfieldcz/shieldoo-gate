# SBOM Generation

> Automatic CycloneDX Software Bill of Materials generation for every cached artifact.

**Status:** Implemented (v1.2)
**Origin:** Initial analysis roadmap, section 15
**Analysis:** [2026-04-15-sbom-and-license-policy.md](../plans/2026-04-15-sbom-and-license-policy.md)

## Problem

Organizations increasingly require SBOMs (Software Bill of Materials) for compliance (EU Cyber Resilience Act, US Executive Order 14028) and supply chain visibility. Before v1.2, Shieldoo Gate scanned artifacts for malicious content but did not produce a machine-readable inventory of what each artifact contains.

## How It Works

When `sbom.enabled: true`, the Trivy scanner is invoked in **single-run CycloneDX mode** with both `vuln` and `license` scanners enabled:

```
trivy fs|image --format cyclonedx --scanners vuln,license --quiet ...
```

The same subprocess output feeds two consumers:

1. Vulnerability findings flow into the existing `ScanResult.Findings`.
2. Component licenses and the raw CycloneDX blob flow into new `ScanResult.Licenses` + `ScanResult.SBOMContent` fields.

After the scan pipeline completes and the request is served, the adapter triggers an **async write** to the configured blob backend. This keeps the hot request path free of blob-storage I/O:

```
adapter.TriggerAsyncSBOMWrite(ctx, artifactID, scanResults)
```

The writer persists the blob (default path: `sbom/{prefix}/{artifactID}.cdx.json`) and records metadata in the `sbom_metadata` table (one row per artifact).

### Path Sanitization

Internal artifact cache paths (e.g. `/var/cache/shieldoo-gate/pypi/...`) are stripped from the SBOM JSON before persistence. This prevents infrastructure leakage through the admin API. See [internal/sbom/sanitize.go](../../internal/sbom/sanitize.go).

### Storage Backend

SBOM blobs reuse the active artifact cache backend — local, S3, Azure Blob, or GCS. All four implementations satisfy the new `cache.BlobStore` sub-interface:

```go
type BlobStore interface {
    PutBlob(ctx, path, data) error
    GetBlob(ctx, path) ([]byte, error)
    DeleteBlob(ctx, path) error
}
```

## Configuration

```yaml
sbom:
  enabled: true              # default false — enables CycloneDX generation
  format: cyclonedx-json     # only format in v1.2
  async_write: true          # default true; write blob in a goroutine
  ttl: 30d                   # retention hint (cleanup scheduler TBD)
```

License evaluation (see [license-policy.md](./license-policy.md)) consumes the pre-extracted `licenses_json` column from `sbom_metadata`, so enabling SBOM is a prerequisite for runtime license enforcement.

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/artifacts/{id}/sbom` | CycloneDX 1.x JSON blob (content-type `application/vnd.cyclonedx+json`) |
| GET | `/api/v1/artifacts/{id}/licenses` | Pre-extracted SPDX IDs + component count |

Both endpoints require admin (OIDC) authentication.

## Schema

```sql
CREATE TABLE sbom_metadata (
    artifact_id     TEXT PRIMARY KEY REFERENCES artifacts(id) ON DELETE CASCADE,
    format          TEXT NOT NULL,
    blob_path       TEXT NOT NULL,
    size_bytes      INTEGER NOT NULL,
    component_count INTEGER NOT NULL,
    licenses_json   TEXT NOT NULL DEFAULT '[]',
    generated_at    DATETIME NOT NULL,
    generator       TEXT NOT NULL
);
```

See migrations `021_sbom_metadata.sql` (SQLite + Postgres).

## Ecosystem Coverage

What Trivy 0.50 + Shieldoo Gate's per-artifact extraction layer can produce, by ecosystem. The matrix separates **vulnerabilities** (Trivy's `vuln` scanner) from **license metadata** (which requires reading the package's own descriptor file, not lockfiles).

| Ecosystem  | Artifact format    | Outer extraction          | Metadata file used                                    | Vulns | Licenses | Notes |
|------------|--------------------|---------------------------|--------------------------------------------------------|-------|----------|-------|
| **PyPI**   | `.whl`             | unzip                     | `*.dist-info/METADATA` (RFC-822)                       | ✅    | ✅       | `License-Expression` (PEP 639) preferred; falls back to `License:` and `Classifier: License :: OSI Approved :: …` |
| **PyPI**   | `.tar.gz` sdist    | tar+gzip                  | `PKG-INFO` (same RFC-822 format)                       | ✅    | ✅       | Same parser as wheel METADATA |
| **npm**    | `.tgz`             | tar+gzip                  | `package/package.json` → `license`                     | ✅    | ✅       | Both `"license":"MIT"` and the deprecated `"licenses":[{"type":"MIT"},…]` array |
| **NuGet**  | `.nupkg`           | unzip                     | `*.nuspec` → `<license type="expression">` or `<licenseUrl>` | ✅    | ✅       | SPDX expression preferred; `<licenseUrl>` is forwarded verbatim — admins decide if they trust it |
| **Maven**  | `.jar`             | unzip                     | `META-INF/maven/{group}/{artifact}/pom.xml` → `<licenses>` + **effective-POM parent chain** | ✅    | ✅       | Inline `<licenses>` extracted first; if empty, the [effective-POM resolver](../../internal/maven/effectivepom/) fetches standalone `.pom` from upstream and walks the `<parent>` chain (up to 5 levels, cached 24h). Covers ~95% of enterprise JARs that inherit licenses (e.g. mysql-connector-j → GPL-2.0, commons-lang3 → Apache-2.0). Names normalized to SPDX via alias map. |
| **Maven**  | `.pom` (raw)       | (no extract — already XML) | the file itself                                       | ✅    | ✅       | Top-level `pom.xml` parsed directly |
| **RubyGems** | `.gem`           | tar + nested gunzip       | `metadata` (YAML gemspec)                              | ✅    | ⚠️ best-effort | `.gem` wraps `data.tar.gz` + `metadata.gz`; we unpack inner archives but Trivy's gemspec analyzer expects an installed layout |
| **Go**     | `.zip` module      | unzip                     | `<module>@<version>/go.mod`                            | ✅    | ⚠️ rare  | Go module zips don't carry license metadata in a structured way; license file in repo root is unstructured text |
| **Docker** | OCI image tarball  | (handled by `trivy image --input`) | layer metadata + lockfiles inside the image           | ✅    | ✅       | Pre-existing path — not touched by the per-artifact extractor |

### Why this matters

Trivy 0.50's package detectors only fire on **installed-tree layouts** (lockfiles + dep dirs walked from a project root). They do **not** parse a single artifact's metadata file — `trivy fs requests-2.33.1.whl` produces an SBOM with `components: []`. To make license enforcement actually work on a proxy that scans one artifact at a time, Shieldoo Gate adds two layers on top of Trivy:

1. **Magic-byte archive extraction** ([`prepareScanPath`](../../internal/scanner/trivy/trivy.go)) — sniffs the first 4 bytes (`PK\x03\x04` → ZIP, `\x1f\x8b` → gzip), extracts into a fresh temp dir, and points Trivy at the directory.
2. **Per-ecosystem metadata extractor** ([`license_extractor.go`](../../internal/scanner/trivy/license_extractor.go)) — walks the unpacked tree, finds the canonical metadata file per ecosystem, and feeds the discovered SPDX strings into `ScanResult.Licenses`.
3. **Effective-POM parent chain resolver** (Maven only) ([`internal/maven/effectivepom/`](../../internal/maven/effectivepom/)) — fetches standalone `.pom` files from the upstream repository and walks the `<parent>` chain to discover inherited licenses. Most Maven artifacts (~95%) don't declare licenses inline but inherit them from a parent POM (e.g. `org.apache:apache`, `com.mysql:oss-parent`). Resolver results are passed via `Artifact.ExtraLicenses` and merged into `ScanResult.Licenses` by the Trivy scanner. Configurable via `upstreams.maven_resolver` in config. Fails open on network errors.

Trivy's vulnerability data still comes from Trivy itself — the extractor only fills the license gap.

### License enforcement on cached artifacts (v1.3)

Since v1.3, **every cache-hit serve checks the current license policy** before responding. This ensures that license policy changes take effect immediately — even for already-cached artifacts. Two mechanisms work in tandem:

1. **Synchronous gate (Fix A):** Every adapter checks `EvaluateLicensesOnly()` before `http.ServeFile()`. If the artifact's SBOM licenses are blocked by the current policy, the request is rejected with 403. This is fail-closed: DB/resolver errors block the request.

2. **Async re-evaluation (Fix B):** When a license policy changes (global or per-project), all cached artifacts with SBOM metadata are re-evaluated asynchronously. Artifacts with blocked licenses are quarantined; artifacts previously quarantined *by license policy* are released when their license becomes allowed. Scanner-originated quarantines are never released by policy changes.

## Performance

- **Single-run Trivy:** vulnerabilities and licenses come from the same subprocess invocation. A second Trivy run would serialize on the cache file lock anyway (halving scan throughput) — so the single-run approach has zero throughput cost relative to the legacy vuln-only mode.
- **Async write:** the response is served immediately; the blob-storage PUT happens in a background goroutine with a 30s timeout. The only synchronous cost is `sbom_metadata` INSERT which happens on the scan result persist path. If the blob write fails (e.g. storage backend down), metadata (licenses, component count, generator) is still persisted with `blob_path=""` so the `/licenses` endpoint works even when the raw SBOM blob is unavailable.
- **Storage:** CycloneDX JSONs are typically a few KB to a few MB (Docker images are the outlier). TTL-based cleanup is deferred to a future release.

## Known Limitations (v1.3)

- Only CycloneDX JSON is generated; SPDX conversion is future work.
- `sbom.ttl` is a metadata field only — automatic cleanup is not yet wired.
- SBOMs for artifacts pulled **before** v1.2 are not backfilled. License checks on such artifacts follow `policy.licenses.on_sbom_error`.
- **Azurite (local dev emulator) 3.34 vs Azure SDK v1.6.4 mismatch:** Azure SDK
  sends `x-ms-version: 2026-02-06` which Azurite 3.34 rejects with HTTP 400.
  This affects BOTH the existing artifact cache backend AND SBOM blob writes;
  the former fails open silently while SBOMs surface the error. Real Azure
  Blob Storage (the production target) accepts the API version. Since v1.3,
  license metadata is persisted even when the blob write fails (`blob_path=""`),
  so the `/licenses` endpoint and license policy enforcement work correctly
  even with Azurite. Only the raw `/sbom` blob endpoint returns an error.
  The E2E suite skips blob-specific assertions when `SGW_CACHE_BACKEND=azure_blob`
  but still tests the license metadata path. Resolved either by upgrading the
  Azurite container image in `docker-compose.e2e.azurite.yml` or pinning the
  SDK API version in `azureblob.NewAzureBlobStore` when a newer SDK release
  exposes `ClientOptions.APIVersion`.
