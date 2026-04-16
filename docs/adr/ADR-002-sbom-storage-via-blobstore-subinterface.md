# ADR-002: SBOM storage via a `BlobStore` sub-interface (not a separate backend stack)

**Status:** Accepted
**Date:** 2026-04-15

## Context

SBOMs are generated per-artifact, are typically small (kB–MB), and should land in the same storage backend as the cached artifacts themselves — deployments already configure S3/Azure/GCS/local cache and don't want to configure a second backend.

The existing `cache.CacheStore` interface is tightly coupled to the scanner artifact shape (`eco:name:version[:filename]`, SHA256-addressed). SBOMs have no such structure — they are path→bytes.

## Options considered

1. **Overload `CacheStore`.** Add `PutBlob/GetBlob/DeleteBlob` methods to the existing interface. Pro: one interface. Con: breaks the artifact-only abstraction; callers must pass a dummy `scanner.Artifact`.
2. **Separate config block + parallel backend stack.** New `sbom_storage.*` config with its own backend impls. Pro: clean separation. Con: deployments configure storage twice and can drift.
3. **New `cache.BlobStore` sub-interface, same struct.** Each backend (`local`, `s3`, `azureblob`, `gcs`) implements **both** `CacheStore` and `BlobStore`. `main.go` stores the same instance in two typed variables.

## Decision

Option 3. The four cache backends each gained a `blob.go` file adding `PutBlob/GetBlob/DeleteBlob`. All use the same underlying client — S3 reuses the AWS SDK, Azure reuses `azblob.Client`, GCS reuses `storage.Client`, local reuses the filesystem root with path sanitization.

`main.go` wires:

```go
cacheStore cache.CacheStore
blobStore  cache.BlobStore
// both point at the same concrete struct
```

SBOM storage uses only `blobStore`. Artifact cache uses only `cacheStore`. Neither side can accidentally invoke methods outside its contract.

## Consequences

**Positive:**

- One deployment-level storage config.
- Independent testability — `BlobStore` has focused unit tests.
- Zero changes to existing cache code paths.

**Negative / mitigated:**

- Path namespacing is the caller's responsibility (we namespace SBOMs under `sbom/`). Accepted — no risk of collision because artifact paths always start with an ecosystem (pypi/, npm/, ...).
- Backends without a natural "raw blob" primitive (none currently) would require a wrapper. Accepted — revisit if that becomes an issue.

## Future work

- If other subsystems need blob storage (e.g. audit-log exports), they reuse this interface.
- Consider a `BlobStore.List(prefix)` method when we add cleanup jobs for expired SBOMs.
