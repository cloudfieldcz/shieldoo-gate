# ADR-003: PyPI canonical package names (PEP 503) as the storage key

**Status:** Accepted
**Date:** 2026-04-29
**Context window:** [plan](../plans/pypi-canonical-name-normalization.md)

## Context

PyPI distributes the same package under two name forms governed by separate PEPs:

- **PEP 503** — the simple-index URL form: lowercase ASCII with runs of `-`, `_`, or `.` collapsed to a single `-`. Example: `strawberry-graphql`.
- **PEP 427** — the wheel filename form: as-published, with `-` rewritten to `_` so the filename can be split on `-`. Example: `strawberry_graphql-0.263.0-py3-none-any.whl`.

The original PyPI adapter built its artifact identifier by `parseFilename()`-ing the wheel filename, so artifact rows landed in the database under the underscore form. Every consumer downstream — admin UI search, the static allowlist (`policy:allowlist` in `config.yaml`), the `policy_overrides` table, and the audit log — keyed on this stored name and therefore inherited the underscore form too.

In practice this surfaced as the bug Josef reported on 2026-04-29: a developer types `strawberry-graphql` in `requirements.txt`, the proxy quarantines version `0.263.0`, and when the developer searches the admin UI under the name they typed they find nothing — the stored row is `strawberry_graphql`. The same trap applies to allowlist entries: `pypi:strawberry-graphql:==0.263.0` does not match the artifact because the matcher does an exact string compare on `entry.Name == artifact.Name`.

This affects every PyPI distribution whose name contains `-`, `_`, or `.` — `python-dateutil`, `graphql-core`, `typing-extensions`, `zope.interface`, etc.

## Decision

**The PEP 503 canonical name is the single source of truth** for every PyPI artifact reference inside Shieldoo Gate.

- The adapter (`internal/adapter/pypi/pypi.go`) canonicalizes the name extracted from the wheel filename before constructing the artifact ID. The wheel filename itself stays untouched (segment 4 of the artifact ID), since it must equal the file actually transferred over the wire.
- The allowlist parser (`internal/policy/rules.go`) and the override-creation API (`internal/api/overrides.go`) canonicalize the package name on parse / insert. Admins may type either spelling; both round-trip to the same stored row.
- The dispatcher lives in `internal/scanner/canonicalname.go` (`scanner.CanonicalPackageName(eco, name)`) so adapter, policy, and API layers share one implementation. Other ecosystems pass through unchanged.
- A Go-level data migration (`024_pypi_canonical_names`, see `internal/config/data_migrations.go`) rewrites every pre-migration row in `artifacts`, the cascade tables (`scan_results`, `artifact_status`, `audit_log`, `version_diff_results`, `artifact_project_usage`, `sbom_metadata`), and the side tables that key on `(ecosystem, name)` (`policy_overrides`, `triage_cache`, `package_reputation`, `popular_packages`).

## Considered alternatives

1. **Lookup-time canonicalization only.** Keep storing whatever `parseFilename()` returns; canonicalize both sides on every lookup. Rejected — the admin UI would still display `strawberry_graphql`, which is exactly what Josef's bug report flagged. Also forces every reader to remember to canonicalize, with no compile-time enforcement.
2. **Bidirectional matching.** Store the underscore form, but accept either spelling on lookup by trying both. Rejected for the same UI-visibility reason and because it muddies the data model — there would be no single answer to "what is this package called?"
3. **Pure-SQL migration with chained REPLACE.** Avoids a Go-level migration track. Rejected because the canonicalization rule is already a Go function (`scanner.CanonicalPackageName`); reimplementing it as nested REPLACEs in two SQL dialects (SQLite without `regexp_replace`, PostgreSQL with) would silently drift if the rule ever changes.

## Consequences

**Positive.**

- A user typing `strawberry-graphql` in `requirements.txt`, in the admin UI search box, in `config.yaml` allowlist, or via the override creation API, hits the same row. The bug class is closed at the boundary.
- The migration is idempotent — re-running is a no-op because canonical names are fixed points under canonicalization. Safe to ship.
- The dispatch shape (`scanner.CanonicalPackageName(eco, name)`) leaves room for npm scopes, NuGet case folding, etc. without further restructuring.

**Negative / one-time costs.**

- Existing cache files for affected packages live under `pypi/<old-name>/...` and are now orphan; the canonical artifact ID maps to a different cache path, so the next request is a cache miss and a re-download. Documented as expected behavior — the alternative (renaming files in object storage during migration) is operationally hairy and provides little value.
- The migration runs synchronously on first startup after the upgrade. On databases with millions of PyPI rows this could add a few seconds to startup, but it is bounded by the count of rows whose name is non-canonical and each rewrite is a small transaction.
- Orphan cache files take disk space until the existing TTL/size-based cache GC reclaims them. No additional cleanup logic was added.

**Neutral.**

- Other ecosystems are out of scope. npm package names with scopes (`@remix-run/router`), NuGet's case-insensitive identifiers, and Maven's `groupId:artifactId` model all have their own normalization rules; adding them is a separate decision per ecosystem and would extend the dispatch in `scanner.CanonicalPackageName`.
