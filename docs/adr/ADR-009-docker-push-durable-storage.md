# ADR-009: Durable storage for Docker push blobs

**Status:** Accepted

## Context

Docker push blobs and manifests were stored in `os.TempDir()/shieldoo-gate-blobs`
(the `local` filesystem store, rooted under `/tmp`). Pushed images are durable
application state, yet this layout lost them on restart, container recreation,
`docker image prune`, or OOM, and grew `/tmp` without bound. A durable
`cache.BlobStore` (Azure/S3/GCS/local) is already wired into the runtime and used
by SBOM storage (see [ADR-002](./ADR-002-sbom-storage-via-blobstore-subinterface.md)).

Two pre-existing serve-path weaknesses became reliably exploitable once storage is
durable:

- `serveInternalBlob` served any layer blob by digest with **no quarantine check**,
  so layers of a quarantined image remained pullable by digest.
- Serve-path backend errors **fell through to the upstream registry**, which could
  return unscanned upstream bytes for a name:ref that has an internal image.

## Decision

- Store push blobs and manifests in the active `cache.BlobStore` under a
  `docker-push/` key namespace instead of `/tmp`. Blobs are content-addressed
  (`docker-push/blobs/{algo}/{hex[:2]}/{hex}`), so integrity is inherent — the key
  is the content hash.
- Extend `cache.BlobStore` with `StatBlob` (size without body transfer, for blob
  HEAD) and `GetBlobStream` (streamed serve, to avoid buffering whole 2 GB layers in
  memory). All four backends implement both. Phase 0 confirmed a 2 GB blob
  round-trips on local and Azurite; whole-blob reads cost ~2× the blob size in RAM,
  which is why the serve path streams.
- Gate `serveInternalBlob` against quarantine via a `docker_blob_refs` table that
  records, at manifest-allow time, which manifest (artifact) references each blob.
  A blob is servable only if referenced by at least one non-quarantined manifest —
  one indexed lookup, no per-pull manifest parsing.
- **Fail closed** on backend/transport errors for a known internal name: serve
  paths return `503` (or `404` for a referenced-but-missing blob) and never fall
  through to upstream.
- Provide a one-shot, operator-run, content-verified, idempotent migration
  (`-migrate-push-blobs`) that recomputes each legacy blob's SHA-256 **before**
  writing it to the durable backend, then reclaims `/tmp`.
- Enforce a durable backend at startup when push is enabled: with the `local`
  backend, `cache.local.path` must be set and not under `/tmp`, else the gate fails
  fast.

## Consequences

- (+) Pushed images survive restarts; `/tmp` no longer grows from pushes; the
  quarantine bypass and fail-open-to-upstream paths are closed.
- (+) One configured storage target serves cache, SBOM, and push blobs.
- (−) Internal pulls incur backend I/O latency (to be mitigated by a read-through
  cache follow-up); push still buffers the blob in memory.
- (−) Push blobs accumulate in object storage with no GC yet (retention follow-up:
  delete on tag-delete / quarantine purge).
- (−) Enabling push requires a durable backend; `local` must not be `/tmp`.
- Read-time integrity is intentionally not re-verified on the push-blob serve path
  (content-addressed keys make the digest the integrity guarantee); this diverges
  from Security Invariant #7, which governs SBOM reads.
- The manifest `HEAD` path must serve internal images locally and must not leak an
  upstream `401`/`403` for a push-allowed name — otherwise the docker push client's
  manifest existence probe aborts the push. The initial implementation proxied
  `HEAD` straight to upstream; this was fixed (mirror `GET`, map push-allowed
  upstream auth errors to `404`). The durable-push e2e is harness-driven (HTTP push
  API), so this real-client behavior is covered by unit tests in
  `manifest_head_test.go` — a real `docker push`/`pull` e2e remains a follow-up.
- Alternatives rejected: handler-direct `cache.BlobStore` calls (more churn, no
  digest-keying seam); write-through local cache + async promote (superseded by the
  read-through-cache follow-up).
