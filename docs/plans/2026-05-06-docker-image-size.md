# Docker image size — surface real image size in admin UI

## Overview

Today the admin UI shows `artifacts.size_bytes` in the "Cached Manifests" table on the Docker repository detail page. For Docker artifacts that value is the **size of the manifest JSON document** (typically 800 B – 10 KB), not the size of the image. Operators looking at "redis 8-alpine = 10 KB" reasonably expect that to be ~30 MB (the actual compressed image size). The displayed number is technically correct (it is the bytes-on-wire of the artifact we cached) but operationally misleading.

This change adds a separate **image size** field, sourced from the manifest's `config.size + sum(layers[].size)`, exposed via the API and displayed by the UI. The legacy `size_bytes` field stays unchanged (it accurately reflects what's in the cache and is consistent with how every other ecosystem populates it).

### Why

- **UX truth-in-labelling.** Users repeatedly read `Size` as "how big is this image". Showing the manifest size for Docker is a recurring source of confusion. (Direct user feedback, this conversation.)
- **Operational utility.** Knowing that pulling `postgres:18.2` will cost ~120 MB of egress is useful for capacity / quota planning. Knowing that the manifest is 2.6 KB is not.
- **Extensibility.** Several other docker-specific data points (`is_index`, `architecture`, `media_type`, `layer_count`) are useful in the UI today and will compound — putting them in a dedicated table avoids polluting `artifacts` with ecosystem-specific columns.
- **No breaking change.** `size_bytes` keeps its current semantics, so any downstream consumer (alerts, retention) continues to work.

## Acceptance criteria

The change is complete when an operator can verify all of the following on a freshly-deployed environment:

1. **Single-arch image** (`docker pull localhost:5002/library/redis:8-alpine`): the Cached Manifests row shows an "Image size" within ±5 % of `docker manifest inspect redis:8-alpine | jq '[.config.size, (.layers[].size)] | add'` (the upstream-reported total compressed size).
2. **Multi-arch index** (`docker pull localhost:5002/library/postgres:18.2`): the index row shows a **multi-arch** badge instead of a numeric size; a hover/tooltip explains why. Each per-arch digest pulled afterwards appears as its own row with a real size.
3. **Attestation manifest** (image built with `docker buildx --attest=...`): the row is rendered with a distinct "attestation" treatment (separate badge / muted styling) so operators don't confuse it with a real image. Total size, if shown at all, is not labelled "Image size".
4. **Old (pre-feature) artifacts**: after Phase 3 backfill runs, every `artifacts` row with `ecosystem='docker'` either has a `docker_manifest_meta` sidecar row, or is logged as "cache miss — backfill skipped". No hand-edits required.
5. **Sort by Size**: clicking the Size column header sorts by `image_size_bytes`. Index rows (NULL) sort last regardless of direction. (NULL-last is locked even if Postgres / SQLite differ on default — explicit `NULLS LAST`.)
6. **No regression**: artifacts of other ecosystems (PyPI, npm, NuGet, …) continue to display `size_bytes` as before. The Size column on a mixed-ecosystem list remains coherent.
7. **No breaking change**: every existing `artifacts.size_bytes` value is preserved. Downstream consumers (alerts, retention schedulers) read identical numbers as before this change.

## Current state

### Where `size_bytes` is set for Docker artifacts

Every Docker write path persists `size_bytes = len(manifestBytes)`:

- [`internal/adapter/docker/docker.go:472,488,504,522`](../../internal/adapter/docker/docker.go) — push-handler call sites (variable name in scope: `body`)
- [`internal/adapter/docker/docker.go:851,868,884,945`](../../internal/adapter/docker/docker.go) — pull-handler call sites (variable name in scope: `manifestBytes`)
- [`internal/adapter/docker/docker.go:1108-1140`](../../internal/adapter/docker/docker.go) — the `persistArtifact` helper itself (writes `art.SizeBytes = manifestSize`)
- [`internal/adapter/docker/sync.go:262,270,279`](../../internal/adapter/docker/sync.go) — sync flow (`SyncService.persistArtifact`, also has its own copy of the helper with the same signature)
- [`internal/adapter/docker/docker.go:812`](../../internal/adapter/docker/docker.go) — one outlier where `SizeBytes = tarSize` (synthesized tarball for `docker save`-style serving — different code path, not in scope here)

The manifest body itself is also cached on disk by `cache.Put` and reachable via `LocalCacheStore.Get(artifactID) → filesystem path`. This is the artifact our backfill needs to read.

### Manifest types we encounter

| Media type | Has `layers[]`? | What size means |
|---|---|---|
| `application/vnd.docker.distribution.manifest.v2+json` | yes | `config.size + sum(layers[].size)` |
| `application/vnd.oci.image.manifest.v1+json` | yes | same as above (OCI variant) |
| `application/vnd.docker.distribution.manifest.list.v2+json` | no — `manifests[]` only | N/A — index. Per-arch sizes live in the referenced manifests, which clients pull as separate digests. |
| `application/vnd.oci.image.index.v1+json` | no — `manifests[]` only | same as above (OCI variant) |
| Attestation manifests (BuildKit) | yes, but tiny | technically computable but uninteresting — these are signature/SBOM blobs |

Detection already exists in [`internal/adapter/docker/docker.go:1327-1335`](../../internal/adapter/docker/docker.go) (`detectManifestContentType`).

### API exposure

- [`internal/api/artifacts.go:51-65`](../../internal/api/artifacts.go) — `artifactResponse.SizeBytes`
- [`internal/api/artifacts.go:79-98`](../../internal/api/artifacts.go) — `toArtifactResponse` mapping
- [`internal/api/artifacts.go:191-200`](../../internal/api/artifacts.go) — list query SELECT
- [`internal/api/artifacts.go:290-300`](../../internal/api/artifacts.go) — single-artifact query SELECT
- [`internal/api/projects/...`](../../internal/api/) — project-scoped artifact queries that may also surface size

### UI consumers

- [`ui/src/pages/DockerRepositoryDetail.tsx`](../../ui/src/pages/DockerRepositoryDetail.tsx) — Cached Manifests table, "Size" column (just shipped in v0.8.2)
- [`ui/src/components/ArtifactTable.tsx:formatBytes()`](../../ui/src/components/ArtifactTable.tsx) — main artifacts list, "Size" column

### Cache backfill source

`LocalCacheStore.Get(ctx, artifactID)` returns a filesystem path to the cached manifest bytes — same data we'd get fresh from upstream. Backfill can be 100% offline.

| Aspect | Current state | Proposed state |
|---|---|---|
| `artifacts.size_bytes` for docker | manifest JSON bytes (~1–10 KB) | unchanged |
| API field for image size | none | `image_size_bytes int64` (nullable) |
| Multi-arch index handling | implicit, indistinguishable from single-arch row in UI | explicit `is_index: true`, `image_size_bytes: null` |
| Manifest media type, arch, OS | not stored | optional fields in `docker_manifest_meta` |
| Existing rows | manifest size only | backfilled via Go data migration |

## Proposed solution

### Architecture

A new normalized table `docker_manifest_meta` stores parsed manifest metadata 1:1 with `artifacts.id` for `ecosystem='docker'` rows. The persistence write paths get a thin parsing helper (`docker.parseManifestMeta(manifestBytes) → ManifestMeta`) that's invoked alongside `persistArtifact`. The API list endpoint LEFT JOINs the new table and surfaces extra fields. The UI prefers `image_size_bytes` over `size_bytes` for docker rows.

```
┌───────────────────┐                  ┌───────────────────────────┐
│ artifacts          │   1:1 (LEFT      │  docker_manifest_meta      │
│  id (PK)           │   JOIN; NULL OK) │  artifact_id (PK, FK)      │
│  ecosystem='docker'│ ────────────▶    │  total_size_bytes (NULL)   │
│  size_bytes (manifest)│               │  layer_count   (NULL)      │
└───────────────────┘                  │  media_type                │
                                        │  is_index (BOOL)           │
                                        │  architecture (NULL)       │
                                        │  os (NULL)                 │
                                        │  parsed_at                 │
                                        │  schema_version (INTEGER)  │
                                        └───────────────────────────┘
```

`schema_version` is a small integer we control — bumping it triggers a re-parse on next access (migration semantics for the parser itself). Starts at `1`.

### Database changes

**New SQL migration `027_docker_manifest_meta.sql`** (both sqlite and postgres variants).

Postgres DDL:

```sql
CREATE TABLE IF NOT EXISTS docker_manifest_meta (
    artifact_id      TEXT PRIMARY KEY REFERENCES artifacts(id) ON DELETE CASCADE,
    media_type       TEXT NOT NULL,
    is_index         BOOLEAN NOT NULL DEFAULT FALSE,
    is_attestation   BOOLEAN NOT NULL DEFAULT FALSE,
    total_size_bytes BIGINT,
    layer_count      INTEGER,
    architecture     TEXT,
    os               TEXT,
    schema_version   INTEGER NOT NULL DEFAULT 1,
    parsed_at        TIMESTAMPTZ NOT NULL
);
```

**No secondary indexes.** The PK on `artifact_id` is enough — the table is read exclusively via `LEFT JOIN docker_manifest_meta ON artifact_id = artifacts.id` (PK→PK), and the only column we'd plausibly filter by (`is_index`) has ~50/50 cardinality where a Postgres seq scan beats any b-tree access. If a future "show only multi-arch" filter materializes, add a partial index then: `CREATE INDEX ... WHERE is_index = TRUE`.

SQLite uses `INTEGER` for `BOOLEAN`; the migration body is otherwise identical.

| Column | Type | Description |
|---|---|---|
| `artifact_id` | TEXT PK FK ON DELETE CASCADE | References `artifacts.id`. 1:1 with the docker artifact row. |
| `media_type` | TEXT NOT NULL | Manifest media type (e.g. `application/vnd.oci.image.manifest.v1+json`). Drives UI badging. |
| `is_index` | BOOLEAN NOT NULL DEFAULT FALSE | TRUE for manifest list / OCI image index (no `layers[]`). |
| `is_attestation` | BOOLEAN NOT NULL DEFAULT FALSE | TRUE for BuildKit attestation manifests (in-toto config or `vnd.docker.reference.type=attestation-manifest` annotation). UI renders these distinctly so operators don't read their tiny total as a real image. |
| `total_size_bytes` | BIGINT NULL | `config.size + sum(layers[].size)`. NULL for index rows, for manifests we couldn't parse, and for any input where summing would overflow / a layer reports a negative size. |
| `layer_count` | INTEGER NULL | `len(layers)`. NULL for index rows. |
| `architecture` | TEXT NULL | Single-arch manifests carry this in their `config` blob — but that blob is itself a separate fetch. **Phase 1 leaves this NULL** and only populates from `manifest.platform` if it's present (rare on per-arch manifests, common on the manifest references inside an index). Stays optional. |
| `os` | TEXT NULL | Same as above. |
| `schema_version` | INTEGER NOT NULL DEFAULT 1 | Parser-version pin. Bumping invalidates rows. |
| `parsed_at` | TIMESTAMPTZ NOT NULL | When this row was computed. |

**No changes to `artifacts.size_bytes`** — it stays as manifest size, consistent with existing rows and with what other ecosystems write.

### Backfill (Go data migration)

Add `028_docker_manifest_meta_backfill` to the `dataMigrations` list in [`internal/config/data_migrations.go`](../../internal/config/data_migrations.go). For each existing `artifacts` row with `ecosystem='docker'`:

0. **Validate `id`** with the same component check used by `LocalCacheStore.Put` (`validateName` on each segment after `parseArtifactID`). Reject IDs containing `..`, `/`, `\`, NUL, or absolute-path segments — log + skip the row. (Defense in depth: today's ID writers all validate inputs, but feeding stored IDs back into a filesystem path is the kind of step that needs an explicit guard.)
1. Resolve cached manifest path via `cache.Get(ctx, artifactID)`. If cache miss → log + skip (the row is unbackfillable; next pull repopulates).
2. Read manifest bytes from disk through an `io.LimitReader(f, 15 << 20)` — anything ≥ 15 MB is rejected (the upstream handler caps at 10 MB; the slack absorbs format drift while still bounding parser memory). On cap hit, log + skip.
3. Run the same `ParseManifestMeta` helper used by the write path.
4. UPSERT into `docker_manifest_meta`.
5. **For remote cache backends only** (S3, Azure Blob, GCS), `cache.Get` materializes the blob into a fresh `os.CreateTemp` per call. The backfill **must `defer os.Remove(path)`** for each row, otherwise a multi-thousand-row run leaks tempfiles. Local backend already returns a stable path inside the cache root and must **not** be removed.
6. **Progress log every 1000 rows** (`log.Info().Int("processed", n).Int("total", N).Msg("docker_manifest_meta: backfill progress")`).

The migration is idempotent: re-running it on rows that already have a `docker_manifest_meta` row with `schema_version >= current` is a no-op. This lets us re-trigger via numbered migration when the parser improves.

**Eager-vs-lazy threshold.** The migration runs inside `runDataMigrations`, which has a hard 10-minute context timeout (`internal/config/data_migrations.go:46`). At ~5 ms/row on a local disk that ceiling is ~120k rows; remote backends (network round-trip per blob) drop the ceiling by an order of magnitude. The migration therefore short-circuits when the backlog is too large:

```
n := SELECT COUNT(*) FROM artifacts a
       LEFT JOIN docker_manifest_meta m ON m.artifact_id = a.id
       WHERE a.ecosystem = 'docker' AND m.artifact_id IS NULL
if n > 50_000 {
    log.Warn().Int("pending", n).Msg("docker_manifest_meta: backlog too large for eager backfill — falling back to lazy-on-read")
    // mark the migration applied so we don't retry every startup
    return nil
}
```

When the eager path is skipped, the API list endpoint becomes the lazy backfill: a `LEFT JOIN` row with `dmm.artifact_id IS NULL` triggers `ParseManifestMeta` + UPSERT inline before the response is built. Rate-limited to ≤16 in-flight parses per request to bound CPU. (Out of scope for v1 if prod stays small; spec'd here so the choice is explicit.)

Cache miss / size-cap / parse-error handling all share the same policy: never fail the migration, never fail the API request — log at INFO and move on.

### Service layer changes

#### New file `internal/adapter/docker/manifest_meta.go`

Public types and helper:

```go
const ManifestMetaSchemaVersion = 1
const maxManifestMetaInput   = 10 << 20 // 10 MB — matches handler's maxManifestSize

type ManifestMeta struct {
    MediaType       string
    IsIndex         bool
    IsAttestation   bool      // see "Attestation manifests" below
    TotalSizeBytes  *int64    // nil for index manifests, attestation, parse failures, overflow
    LayerCount      *int      // nil for index manifests
    Architecture    string    // empty when unknown
    OS              string    // empty when unknown
    SchemaVersion   int       // = ManifestMetaSchemaVersion at write time
}

// ParseManifestMeta inspects the manifest body and extracts size/layer info.
// Never returns an error for unknown media types — falls back to is_index=false,
// TotalSizeBytes=nil. The only errors returned are for malformed JSON or
// oversize input.
//
// Defense-in-depth invariants:
//   - body length is rejected if > maxManifestMetaInput
//   - layer/config sizes are summed with overflow saturation: any negative
//     individual size or any addition that would exceed math.MaxInt64 yields
//     TotalSizeBytes = nil rather than a wrapped negative number
func ParseManifestMeta(body []byte) (ManifestMeta, error)
```

Implementation strategy: unmarshal into a small struct that covers all four media types — `mediaType`, `manifests[]` (presence triggers `is_index=true`), `config.size`, `layers[].size`, `architecture`, `os` (the last two only present on per-arch manifests inside an index, and on manifest body's optional `config` block — we don't deref the config blob, just read what's locally available).

**Overflow-safe sum** (pseudo-code, normative):

```
total := config.Size
if config.Size < 0 { return meta with TotalSizeBytes=nil }
for _, l := range layers {
    if l.Size < 0 || total > math.MaxInt64 - l.Size {
        return meta with TotalSizeBytes=nil   // saturate to "unknown"
    }
    total += l.Size
}
```

**Attestation detection.** BuildKit attestation manifests appear inside an index with `manifests[i].platform.architecture == "unknown"` and `platform.os == "unknown"`. They are themselves regular image manifests (have `layers[]`) with tiny payloads. To avoid misleading "Image size: 8 KB" rows in the UI, the per-arch manifest's `IsAttestation` is set when the manifest body itself carries `config.mediaType` matching `application/vnd.in-toto+json` **or** when its annotations include `vnd.docker.reference.type = attestation-manifest`. The flag flows to UI rendering (Phase 2) which renders attestation rows with a distinct badge and does not label their total as "Image size". The parser **always** stores `TotalSizeBytes` for attestation rows (it's accurate); the UI is responsible for the labelling change.

Schema-version bump workflow: increment `ManifestMetaSchemaVersion` when the parser's interpretation changes, then add a **new numbered data migration** (e.g. `029_docker_manifest_meta_schema_v2_backfill`) that re-parses rows where `schema_version < ManifestMetaSchemaVersion`. Bumping the constant alone does **not** trigger a re-parse — `data_migrations` is keyed by name, not version.

DB writer in `internal/adapter/docker/manifest_meta.go`:

```go
// UpsertManifestMeta writes a docker_manifest_meta row. Idempotent on artifact_id.
func UpsertManifestMeta(db *config.GateDB, artifactID string, m ManifestMeta) error
```

#### Modified `internal/adapter/docker/docker.go`

`persistArtifact` (line 1108) gets one extra step: parse the manifest body it already has in scope and upsert into `docker_manifest_meta`. To avoid plumbing `manifestBytes` deep, change the signature:

```go
// before
func (a *DockerAdapter) persistArtifact(artifactID string, sa scanner.Artifact, manifestSHA string, manifestSize int64, ...) error

// after
func (a *DockerAdapter) persistArtifact(artifactID string, sa scanner.Artifact, manifestSHA string, manifestBody []byte, ...) error {
    // ... existing artifact + status writes (size now derived as int64(len(manifestBody))) ...
    // new:
    if meta, err := ParseManifestMeta(manifestBody); err == nil {
        _ = UpsertManifestMeta(a.db, artifactID, meta)
    }
}
```

The push handler (`docker.go:472,488,504,522`) currently uses the local var `body` — at the call site we pass it as `manifestBody` (rename happens in the helper signature, not the caller). Pull handler (`docker.go:851,868,884,945`) uses `manifestBytes` and is renamed similarly at the call site only. **The helper signature uses the neutral name `manifestBody`** to avoid implying either origin.

The same change applies to `SyncService.persistArtifact` ([`sync.go`](../../internal/adapter/docker/sync.go)) — it has its own copy of the helper with the same parameter list.

The synthetic tar bundle path at `docker.go:812` (`tarSize`) does **not** get a `docker_manifest_meta` row — it's not a manifest. The LEFT JOIN handles this naturally (NULL row).

#### Modified `internal/api/artifacts.go`

Extend `artifactDBRow` (the SQL-scan struct in [`internal/api/artifacts.go:22-30`](../../internal/api/artifacts.go), **not** `model.Artifact` — those new fields are HTTP/transport concerns and don't belong on the domain model that lives under `internal/model/`):

```go
type artifactDBRow struct {
    // ... existing fields ...

    // Populated only for ecosystem='docker' rows; LEFT JOIN means NULL elsewhere.
    DMMTotalSizeBytes *int64  `db:"dmm_total_size_bytes"`
    DMMIsIndex        *bool   `db:"dmm_is_index"`
    DMMIsAttestation  *bool   `db:"dmm_is_attestation"`
    DMMMediaType      *string `db:"dmm_media_type"`
    DMMLayerCount     *int    `db:"dmm_layer_count"`
}
```

`artifactResponse` (the JSON struct, line 51) gets matching fields — `omitempty` so non-docker rows don't carry empty docker keys:

```go
type artifactResponse struct {
    // ... existing ...
    ImageSizeBytes *int64  `json:"image_size_bytes,omitempty"`
    IsIndex        *bool   `json:"is_index,omitempty"`
    IsAttestation  *bool   `json:"is_attestation,omitempty"`
    MediaType      string  `json:"media_type,omitempty"`
    LayerCount     *int    `json:"layer_count,omitempty"`
}
```

The list query at [`internal/api/artifacts.go:191-200`](../../internal/api/artifacts.go) and the single-artifact query at line 290-300 gain a `LEFT JOIN docker_manifest_meta dmm ON dmm.artifact_id = a.id` plus the five `dmm.*` columns aliased to `dmm_…`. NULLs map to `nil` pointers → omitted from JSON.

**Sort-by-size semantics.** When the future "sort by size" feature lands (out of scope for this analysis but worth pinning the contract): the ORDER BY clause uses `COALESCE(dmm.total_size_bytes, a.size_bytes) DESC NULLS LAST` so docker rows sort by image size, non-docker rows by file size, and any NULL sinks to the bottom regardless of direction.

**Do NOT replicate the `sbom_metadata` SELECT pattern.** The existing list endpoint loads the *entire* `sbom_metadata` table into memory and filters in Go ([`internal/api/artifacts.go:253-274`](../../internal/api/artifacts.go) — no `WHERE artifact_id IN (...)` predicate). At today's row counts this is fine; at 100k+ it is a full table scan per page render. The new `docker_manifest_meta` data **must** be served via the LEFT JOIN above (O(1) hash on PK→PK), never via a separate "load-all-then-filter" pass. A separate follow-up issue will fix the existing sbom path; that is **not** in scope here, but the implementer of this change must not perpetuate the antipattern.

### UI changes

`ui/src/api/types.ts` — add the optional fields to `Artifact`:

```ts
image_size_bytes?: number
is_index?: boolean
is_attestation?: boolean
media_type?: string
layer_count?: number
```

**Column rename + tooltip** in [`ui/src/pages/DockerRepositoryDetail.tsx`](../../ui/src/pages/DockerRepositoryDetail.tsx). The "Size" column on Docker pages is renamed to "Image size", with a small info-icon tooltip:

> Compressed download size for this image manifest. Multi-arch index entries show the size of each platform-specific manifest pulled separately.

The existing main list at [`ui/src/components/ArtifactTable.tsx`](../../ui/src/components/ArtifactTable.tsx) keeps the column header "Size" because it's mixed-ecosystem; the cell itself transparently renders `image_size_bytes` for docker rows and `size_bytes` for everything else. (Mixed-ecosystem note: a docker "30 MB" and a PyPI "1.2 MB" displayed side-by-side mean different things — image install size vs wheel-on-disk. Documented in `docs/data-model.md`'s `size_bytes` section.)

**Cell rendering rules**, applied uniformly across both surfaces:

| `is_attestation` | `is_index` | `image_size_bytes` | Render |
|---|---|---|---|
| true  | —     | —     | "attestation" muted badge (no size) |
| —     | true  | —     | "multi-arch" badge (no size) |
| —     | false | non-null | `formatBytes(image_size_bytes)` (the happy path) |
| —     | false | null  | `formatBytes(size_bytes)` (fallback for not-yet-backfilled or parse-failed rows) |
| ecosystem ≠ docker | — | — | `formatBytes(size_bytes)` (existing behavior) |

A small `<MediaTypeBadge>` (e.g. "OCI", "Docker v2") is a nice-to-have but **not required** for v1 — punt to a follow-up.

**Sort by Size** is locked to NULLS-LAST regardless of direction (see "Sort-by-size semantics" above).

### Configuration

None. The feature is always-on; data migration is automatic.

## Affected files

### New files

- `docs/plans/2026-05-06-docker-image-size.md` — this analysis
- `internal/config/migrations/postgres/027_docker_manifest_meta.sql` — schema
- `internal/config/migrations/sqlite/027_docker_manifest_meta.sql` — schema
- `internal/adapter/docker/manifest_meta.go` — `ManifestMeta`, `ParseManifestMeta`, `UpsertManifestMeta`
- `internal/adapter/docker/manifest_meta_test.go` — table-driven parser tests for all 4 media types + malformed input + attestation manifests
- `internal/config/data_migrations_docker_manifest.go` — backfill migration body (or co-located in `data_migrations.go`)

### Modified files

- `internal/adapter/docker/docker.go:1108-1140` — `persistArtifact` signature: `manifestSize int64` → `manifestBody []byte`; new upsert call
- `internal/adapter/docker/docker.go:472,488,504,522` — push call sites (local var `body` passed as `manifestBody`)
- `internal/adapter/docker/docker.go:851,868,884,945` — pull call sites (local var `manifestBytes` passed as `manifestBody`)
- `internal/adapter/docker/sync.go:262,270,279` — same as above for sync path
- `internal/api/artifacts.go:22-30` — `artifactDBRow` gains 5 nullable `dmm_*` fields
- `internal/api/artifacts.go:51-98` — `artifactResponse` gains 5 optional JSON fields; `toArtifactResponse` maps them
- `internal/api/artifacts.go:191-200,290-300` — SELECT statements add `LEFT JOIN docker_manifest_meta`
- `internal/cache/local/local.go:107-128` — `LocalCacheStore.Get` adds `validateName` per parsed component (defense-in-depth path-traversal guard)
- `internal/config/data_migrations.go:25-27` — register `028_docker_manifest_meta_backfill`
- `ui/src/api/types.ts` — extra optional fields on `Artifact`
- `ui/src/components/ArtifactTable.tsx` — render image-size-aware Size cell per the rules table (column header stays "Size")
- `ui/src/pages/DockerRepositoryDetail.tsx` — column renamed to "Image size" with tooltip; multi-arch / attestation badges
- `docs/data-model.md` — document `docker_manifest_meta` table; explicit note that `size_bytes` for docker rows is the manifest body size, not the image size; mixed-ecosystem caveat for the API
- `docs/adapters.md` — Docker adapter section: explain image-size derivation, attestation handling, multi-arch index semantics
- `docs/api/openapi.yaml` — document the five new response fields

### Unchanged files (intentional)

- `internal/cache/{s3,azureblob,gcs}/*.go` — backends keep their existing `Get` contract (return a filesystem path, possibly via tempfile). The backfill is responsible for `defer os.Remove` on remote-backed paths.
- `internal/adapter/base.go:497` — `InsertArtifact` is generic; keeps writing manifest size to `artifacts.size_bytes`.
- `internal/api/projects/*` — project-scoped artifact endpoints can be enriched later; not in v1 to keep scope tight.

## Implementation phases

The work is structured so that **the user-visible release is a single deploy** containing API + UI + backfill — operators never see the Phase-2-without-Phase-3 mixed-truth state where some rows show "Image size: 30 MB" alongside others showing "Image size: 8 KB" (because they were pulled before the feature). Phase 1 ships dark first to de-risk the schema/parser; Phase 2 follows as a single user-facing release.

### Phase 1: Schema + parser + write path (dark deploy)

- [ ] Add `027_docker_manifest_meta.sql` (sqlite + postgres)
- [ ] Implement `ParseManifestMeta` + `UpsertManifestMeta` with unit tests covering: all 4 media types, attestation manifest (real-world fixture), malformed JSON, oversize input (> 10 MB cap), int64 overflow scenarios (negative layer size, MaxInt64 sum), unknown media type fallback
- [ ] **Add `validateName`-equivalent to `LocalCacheStore.Get`** so future callers can't smuggle `..` / absolute paths via stored artifact IDs. Tests: `TestLocalCacheStore_Get_RejectsTraversal`.
- [ ] Modify `persistArtifact` (both `DockerAdapter` and `SyncService`) to call `UpsertManifestMeta`
- [ ] `make build && make lint && make test` green

**Outcome:** New rows write `docker_manifest_meta` correctly. Existing rows still have nothing. API and UI unchanged. Safe to deploy in isolation; release notes can mention nothing.

**Release-note status:** internal only.

### Phase 2: API + UI surfacing + backfill (single user-facing release)

Deployed as one PR. The migration runs at startup of the new binary, immediately followed by the UI now reading the populated table — no operator-visible window where old rows look broken.

- [ ] Add data migration `028_docker_manifest_meta_backfill` to `dataMigrations` (eager path with the >50k pivot to lazy-on-read; progress log every 1000 rows; `defer os.Remove(path)` for remote cache backends)
- [ ] Extend `artifactDBRow` and `artifactResponse` with the five new fields
- [ ] Add `LEFT JOIN docker_manifest_meta dmm` to the list and get queries (do **not** copy the sbom_metadata "load-all-then-filter" antipattern)
- [ ] Update `ui/src/api/types.ts`, [`ui/src/components/ArtifactTable.tsx`](../../ui/src/components/ArtifactTable.tsx), and [`ui/src/pages/DockerRepositoryDetail.tsx`](../../ui/src/pages/DockerRepositoryDetail.tsx) per the cell-rendering rules table; rename column to "Image size" on Docker pages with tooltip
- [ ] OpenAPI spec update for the five new response fields
- [ ] Documentation: `docs/data-model.md` adds the new table; `docs/adapters.md` Docker section explains image-size derivation; brief release note explaining the user-visible change
- [ ] E2E spot-check: pull a single-arch image, a multi-arch index, and an image with attestations; verify all three render correctly and the backfill log shows "applied" for old rows

**Outcome:** Operators see real image sizes for both old and new artifacts. Multi-arch and attestation rows render with distinct treatment (no misleading sizes).

**Release-note status:** user-facing — "Cached Manifests now shows real image size".

### Phase 3 (optional, deferred): UI polish

- [ ] Media-type badge ("OCI", "Docker v2")
- [ ] Layer-count column in the Cached Manifests table
- [ ] Per-arch sibling navigation (clicking a multi-arch index reveals its per-arch entries)

Out of scope for v1; tracked as separate follow-ups.

## Risks and mitigations

| Risk | Impact | Probability | Mitigation |
|---|---|---|---|
| Malformed manifest crashes the parser and breaks `persistArtifact` | Pull-path 5xx — high blast radius | Low | Parser never propagates errors to `persistArtifact`; logged + skipped. Artifact still persists with `size_bytes`. |
| Path traversal via stored artifact ID feeds backfill into arbitrary file read | File-existence oracle / arbitrary read of files the proxy can read | Low (today's writers validate inputs) | `LocalCacheStore.Get` adds `validateName` per component (matches `Put`); backfill validates `id` before calling `cache.Get`. Defense in depth. |
| `int64` overflow when summing layer sizes | Negative size displayed; downstream sums poisoned | Low (requires malformed manifest) | Saturating sum: any negative individual size or addition that would overflow yields `total_size_bytes = NULL`. Tested explicitly. |
| Tempfile leak from remote cache backends during backfill | Disk fills up over a 10k-row backfill | Medium on remote backends | Backfill `defer os.Remove(path)` for each row when backend is non-local. Local backend returns a stable cache path and is **not** removed. |
| Schema version drift between sqlite/postgres migrations | Migration apply fails on one backend | Low | Both files in the same PR; CI runs both backends; standard review. |
| Backfill runs against 50k+ docker artifacts and stalls startup | Service unavailable | Very low (current prod has 9 docker artifacts) | 10-minute migration timeout in `runDataMigrations` is the safety rail. The migration itself short-circuits when the pending count exceeds 50k and falls back to lazy-on-read. |
| Multi-arch index gets `total_size_bytes = sum of small manifest sizes`, displayed as a tiny image | UI lies in a different way | Medium if implemented naively | Explicitly leave `total_size_bytes = NULL` for `is_index = true` rows. UI shows "multi-arch" badge instead. |
| Attestation manifest gets a `total_size_bytes` and shows up alongside real images | Minor UI noise | Medium | `is_attestation` flag stored in v1; UI renders attestation rows with a distinct muted treatment and does not label them "Image size". Trades the original lie for clarity, not for a different lie. |
| `manifest_meta` row gets stale when manifest is re-pulled with different content (digest-pinned ID stays same — should not happen in practice) | Stale image_size displayed | Very low | UPSERT on every persist, so every pull refreshes the row. |
| Cell-rendering rules drift between `ArtifactTable.tsx` and `DockerRepositoryDetail.tsx` | Inconsistent UI | Medium | Extract a shared `renderSizeCell(artifact)` helper used by both surfaces. Tested against the rules table. |

## Testing

### Unit tests (`internal/adapter/docker/manifest_meta_test.go`)

- `TestParseManifestMeta_DockerV2_SingleArch_ReturnsTotalSize`
- `TestParseManifestMeta_OCIManifestV1_ReturnsTotalSize`
- `TestParseManifestMeta_DockerManifestList_ReturnsIsIndex`
- `TestParseManifestMeta_OCIImageIndex_ReturnsIsIndex`
- `TestParseManifestMeta_AttestationManifest_FlagsIsAttestation` (fixture: real BuildKit attestation manifest body)
- `TestParseManifestMeta_MalformedJSON_ReturnsError`
- `TestParseManifestMeta_UnknownMediaType_FallsBackGracefully`
- `TestParseManifestMeta_OversizeInput_ReturnsError` (input ≥ 10 MB cap)
- `TestParseManifestMeta_NegativeLayerSize_ReturnsNilTotal`
- `TestParseManifestMeta_LayerSizeMaxInt64_ReturnsNilTotal` (overflow saturation)
- `TestUpsertManifestMeta_Idempotent` (postgres + sqlite)

### Path-traversal regression tests (`internal/cache/local/local_test.go`)

- `TestLocalCacheStore_Get_RejectsPathTraversal_DotDotInName`
- `TestLocalCacheStore_Get_RejectsPathTraversal_AbsolutePath`
- `TestLocalCacheStore_Get_RejectsPathTraversal_NullByte`

### Integration tests

- `TestDockerAdapter_HandleManifest_PopulatesManifestMeta` — full handler test, asserts `docker_manifest_meta` row exists after a successful pull (single-arch)
- `TestDockerAdapter_HandleManifest_MultiArchIndex_FlagsIsIndex` — same for an index manifest, asserts `is_index=true` and `total_size_bytes IS NULL`
- `TestSyncService_PullsTag_PopulatesManifestMeta` — same for sync flow
- `TestDockerAdapter_QuarantinedArtifact_StillPopulatesManifestMeta` — quarantined rows get a metadata row (write-time decision is policy-independent), but UI rendering rules are tested separately
- `TestDataMigration_DockerManifestBackfill_BackfillsCachedRows` — seeds an `artifacts` row + cached file, runs the data migration, asserts `docker_manifest_meta` populated
- `TestDataMigration_DockerManifestBackfill_SkipsCacheMiss` — no cached file; assert no row inserted, migration succeeds
- `TestDataMigration_DockerManifestBackfill_SkipsLargeBacklog` — seed > 50k pending rows; assert eager path is skipped, migration marked applied
- `TestDataMigration_DockerManifestBackfill_SkipsOversizedManifest` — cached file > 15 MB; assert skip + log, migration succeeds
- `TestDataMigration_DockerManifestBackfill_RemoteBackend_CleansTempFiles` — fake `cache.Store` returning unique tempfile paths; assert all are removed after backfill

### Manual / E2E

1. `docker pull localhost:5002/library/redis:8-alpine` (single arch) → UI shows ~30 MB
2. `docker pull localhost:5002/library/postgres:18.2-alpine` (multi-arch index) → UI shows "multi-arch", per-arch digest pulls show real size
3. Pull a docker image with a BuildKit attestation → attestation row shows tiny size, doesn't break UI

### Verification

- `make build && make lint && make test`
- `psql ... -c "SELECT COUNT(*) FROM docker_manifest_meta"` after backfill on a prod-like dump
- Grep for residual references to `int64(len(manifestBytes))` in docker code paths after refactor: `grep -n "int64(len(manifestBytes))" internal/adapter/docker/`

## Notes

### Idempotence

- Parser is pure (input bytes → output struct). Same input always produces same output.
- `UpsertManifestMeta` uses `INSERT ... ON CONFLICT (artifact_id) DO UPDATE`.
- Backfill checks `data_migrations` table → guaranteed run-once. Per-row idempotency via UPSERT means partial-completion is safe to retry.

### Edge cases

- **Cache miss on backfill:** logged at INFO, skipped. Subsequent pull writes the row normally.
- **Manifest > 10 MB cap:** the existing handler rejects these (`maxManifestSize = 10 << 20`), so we never see one in steady-state writes. The parser independently enforces the same cap (`maxManifestMetaInput`) so that backfill reading from disk has its own bound — defense in depth.
- **Old SQLite installations:** the `BOOLEAN` column type is just `INTEGER 0/1` — handled identically in code via Go's `bool` mapping.
- **Renamed/deleted artifact:** `ON DELETE CASCADE` cleans up the `docker_manifest_meta` row.
- **Quarantined artifacts:** `persistArtifact` is called for every policy outcome (CLEAN, SUSPICIOUS, QUARANTINED), so quarantined Docker manifests **do** get a `docker_manifest_meta` row. The UI's quarantine badge already renders separately from the size cell, so showing the real image size on a quarantined row is informational, not misleading. ("Image size: 30 MB · Status: Quarantined" is the desired UX.)
- **Concurrent pulls of the same digest:** two simultaneous `persistArtifact` calls race two UPSERTs. SQLite serializes via the WAL; Postgres handles via `ON CONFLICT DO UPDATE`. The "winner" determines `parsed_at`; the row content is identical (parser is pure).
- **Schema-version bump:** bumping `ManifestMetaSchemaVersion` does **not** trigger a re-parse of existing rows. To re-process, add a new numbered data migration (e.g. `029_docker_manifest_meta_schema_v2_backfill`) that upserts rows where `schema_version < ManifestMetaSchemaVersion`. This is documented in the parser source so future contributors don't expect implicit re-parsing.
- **Mixed-ecosystem global view:** the main artifacts list shows rows from PyPI, npm, Docker, etc. side-by-side. Docker rows now show image size; non-docker rows still show file-on-disk size. These are different physical quantities; `docs/data-model.md` documents this caveat for API consumers.
- **Failed pull:** if upstream returns 4xx/5xx, `persistArtifact` is not called; no `docker_manifest_meta` row is written. The artifact never enters the cache, so there's nothing to surface in UI.
- **Synthetic-tar path** (`docker.go:812`): not a manifest, not in scope. The LEFT JOIN naturally returns NULL for these rows, and the UI fallback rule (`is_index = false`, `image_size_bytes = null`) renders `formatBytes(size_bytes)` — the tar size — which is the correct value.

### Backward compatibility

- API: only **additions** (5 optional fields, all `omitempty`). Existing UIs and clients ignore them.
- Database: new table, no column changes on existing tables.
- `size_bytes` semantics: unchanged. Anything that was reading "manifest bytes" continues to work.

### Performance considerations

- **Write path:** parsing adds one JSON unmarshal per manifest pull (~10 KB body). Negligible (<1 ms) versus the upstream HTTP round-trip.
- **Read path:** LEFT JOIN on a 1:1 PK→PK relationship with both sides indexed. PostgreSQL planner produces a hash join with the same row count. No noticeable cost.
- **Backfill:** O(N) reads from cache + O(N) UPSERTs. Currently N=9 in prod; even at N=10k this is seconds. The hard 10-minute timeout on `runDataMigrations` is the safety rail; the >50k pivot to lazy-on-read prevents startup outages on deployments with large backlogs and/or remote cache backends (S3/Azure/GCS) where each `cache.Get` is a network round-trip.
- **Index footprint:** zero additional indexes on `docker_manifest_meta`. The PK is the only one needed; secondary indexes were considered and explicitly rejected (see schema section).

### Follow-up work (not in this analysis)

- **Fix existing N+1 in `sbom_metadata` SELECT** at [`internal/api/artifacts.go:253-274`](../../internal/api/artifacts.go) — currently loads the full table per page render. File a separate issue. Not required to ship this change, but the implementer **must not** copy the antipattern.
- **Per-arch sibling navigation** — clicking a multi-arch index reveals the cached per-arch manifests. Useful UX but distinct feature.
- **Media-type badge** — visual chip for "OCI" / "Docker v2".

## References

- OCI Image Manifest spec: https://github.com/opencontainers/image-spec/blob/main/manifest.md
- OCI Image Index spec: https://github.com/opencontainers/image-spec/blob/main/image-index.md
- BuildKit attestation manifests: https://docs.docker.com/build/attestations/attestation-storage/
- Existing data migration pattern: [`internal/config/data_migrations.go`](../../internal/config/data_migrations.go)
- Existing SBOM-metadata table (similar 1:1 sidecar pattern): [`internal/config/migrations/postgres/021_sbom_metadata.sql`](../../internal/config/migrations/postgres/021_sbom_metadata.sql)
