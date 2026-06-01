# SBOM Export — Project View

> CycloneDX 1.5 JSON SBOM aggregating every artifact a project has pulled
> through Shieldoo Gate.

## Overview

An **SBOM** (Software Bill of Materials) is a machine-readable inventory of
every third-party component a piece of software contains. It is consumed by
vulnerability scanners, license-policy tools, and supply-chain audit
pipelines.

Each `Project` in Shieldoo Gate (the entity addressed by the Basic-auth
username — see [Client Authentication](index.md#client-authentication--how-basic-auth-maps-to-projects-v12))
exposes a single endpoint that returns a freshly generated **CycloneDX 1.5**
JSON SBOM:

```
GET /api/v1/projects/{id}/sbom
```

The response is a complete CycloneDX 1.5 document describing every artifact
this project has **successfully pulled** at least once through the proxy —
rows in `artifact_project_usage`, written on `EventServed`. Artifacts
that were **blocked on first scan and never served** (malicious,
license-blocked, integrity-violation, …) do NOT appear here; they have
no usage row because the consumer never received them. Look in the
audit log (`event_type` = `BLOCKED`, `LICENSE_BLOCKED`, `QUARANTINED`)
for those.

Artifacts that were served once and **later quarantined** (e.g. a rescan
discovered a new threat) DO appear, with `shieldoo:status=QUARANTINED`
in their `properties` — they were once part of this project's supply
chain even if they're no longer servable.

Artifacts that were **quarantined and then admin-released** (a manual
override via `POST /api/v1/artifacts/{id}/release`) carry both
`shieldoo:status=CLEAN` and a non-empty `shieldoo:released_at` timestamp.
Consumers should treat the presence of `shieldoo:released_at` as the
signal that this component's CLEAN status is admin-overridden rather
than scanner-native — a weaker supply-chain guarantee. The full reason
and operator identity live in the audit log (`event_type=RELEASED`).

This matches industry SBOM semantics ("what's actually here") and
intentionally diverges from the project Artifacts tab in the admin UI,
which additionally surfaces blocked-attempt rows so operators can see
"what was tried but refused."

The SBOM is **not cached** — it is rebuilt on every request from the
underlying tables, because the set of pulled artifacts changes with every
new request. Empty projects produce a valid SBOM with `components: []`
rather than an error.

> **Note on the SBOM SHA-256 integrity invariant** (CLAUDE.md #7):
> that invariant applies to user-uploaded SBOMs in the vuln-scan flow
> (pushed via `shdg` from CI), whose bytes are persisted and re-verified
> on every read. Per-project SBOMs from this endpoint are regenerated
> fresh on each request from DB rows — there's nothing persisted to
> compare against, so no `sbom_integrity_violation` event applies here.

### Why no `dependencies` graph

The proxy could parse declared dependencies from each artifact's metadata
(`METADATA`, `package.json`, `pom.xml`, …) but those are **requested**
ranges, not the **resolved** versions the consumer actually installed.
Emitting them would mislead CVE and license tooling, which expects a
resolved graph. Version ranges, environment markers, `--no-deps`, and
lockfile pins all change what actually gets installed — none of which the
proxy sees.

For accurate `dependencies`, use a build-time SBOM (e.g. `shdg` from CI).
This per-project SBOM is complementary: "what the project pulled through
the proxy."

## Authentication

Same admin auth chain as the rest of `/api/v1/projects/{id}/...` — OIDC
session cookie or a PAT-Bearer admin token. Rate-limited by the
`sbom-download` bucket (per-token; the same bucket used by
`/vulnerabilities/scan-runs/{id}/sbom`).

Every successful export writes a `SBOM_GENERATED` row to the audit log
(see [Data Model — audit_log](data-model.md#audit_log)) with the calling
user's email, client IP, user agent, and SBOM size. Operators can query
"who exported what about this project, when" via `GET /api/v1/audit?event_type=SBOM_GENERATED`
or filter the Audit Log page in the admin UI.

## Response

- `Content-Type: application/vnd.cyclonedx+json; version=1.5`
- `Content-Disposition: attachment; filename="sbom-<label>-YYYYMMDD.cdx.json"`
  so the browser Save-As dialog suggests a meaningful name.

Example (truncated to one component):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:608eb0f4-4c3f-4705-bd2c-8b5c979cf920",
  "version": 1,
  "metadata": {
    "timestamp": "2026-05-29T12:48:43Z",
    "lifecycles": [{ "phase": "discovery" }],
    "tools": {
      "components": [
        {
          "type": "application",
          "name": "shieldoo-gate",
          "version": "v1.0.0-rc1",
          "supplier": { "name": "Cloudfield" }
        }
      ]
    },
    "component": {
      "type": "application",
      "bom-ref": "project/marketing-project-test",
      "name": "marketing-project-test",
      "description": "marketing-project-test"
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:pypi/requests@2.34.2",
      "name": "requests",
      "version": "2.34.2",
      "purl": "pkg:pypi/requests@2.34.2",
      "hashes": [
        { "alg": "SHA-256", "content": "2a0d60c172f83ac6ab31e4554906c0f3b3588d37b5cb939b1c061f4907e278e0" }
      ],
      "licenses": [
        { "license": { "id": "Apache-2.0" } }
      ],
      "externalReferences": [
        { "type": "distribution", "url": "https://files.pythonhosted.org/packages/a0/f4/.../requests-2.34.2-py3-none-any.whl" }
      ],
      "properties": [
        { "name": "shieldoo:status",     "value": "CLEAN" },
        { "name": "shieldoo:size_bytes", "value": "73075" },
        { "name": "shieldoo:cached_at",  "value": "2026-05-28T17:38:13Z" }
      ]
    }
  ]
}
```

## Field Mapping

Per-component fields:

| CycloneDX field        | Meaning                                                                                  | Source in Shieldoo Gate                                                  |
|------------------------|------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| `type`                 | What kind of thing this is. `library` = a software package; `container` = a Docker/OCI image. | `container` for docker artifacts, `library` for everything else.         |
| `bom-ref`              | A unique handle within this one SBOM file — other entries in the same document can reference this component by it. Most tooling expects `bom-ref` to equal the `purl`. | The component's `purl`. Falls back to `<ecosystem>:<name>@<version>` when no PURL can be built, or to `<ecosystem>:<name>` if the version is unknown. |
| `name`                 | Package name as the ecosystem knows it.                                                  | `artifacts.name`                                                         |
| `version`              | The specific package version (e.g. `2.34.2`).                                            | `artifacts.version`                                                      |
| `purl`                 | Universal package identifier ([purl spec](https://github.com/package-url/purl-spec)). Lets scanners find this exact artifact across ecosystems without guessing. | Built from `(ecosystem, name, version, sha256, upstream_url)` — see [PURL Mapping](#purl-mapping-by-ecosystem). |
| `hashes[].alg`         | Hash algorithm used to verify the file is exactly this one.                              | Always `SHA-256`.                                                        |
| `hashes[].content`     | The actual hash value.                                                                   | `artifacts.sha256` (with any `sha256:` prefix stripped).                 |
| `licenses[]`           | What licenses the package is distributed under. Consumed by license-compliance tooling.  | `sbom_metadata.licenses_json` — list of SPDX IDs (or SPDX expressions like `MIT OR Apache-2.0`). |
| `externalReferences[]` | Pointers off-doc: where to download, source repo, homepage, etc. We only emit the download URL. | `{type: "distribution", url: artifacts.upstream_url}`                    |
| `properties[]`         | Vendor-specific extras — namespaced key/value pairs CycloneDX doesn't standardize. Tools that don't recognize the namespace simply ignore them. | `shieldoo:status` (CLEAN/QUARANTINED/…), `shieldoo:size_bytes`, `shieldoo:cached_at`, `shieldoo:released_at` (only when the artifact was once quarantined and then admin-released). |

Top-level / metadata fields:

| CycloneDX field        | Meaning                                                                                                        | Value in this SBOM                                                       |
|------------------------|----------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| `bomFormat`            | Format discriminator — tells parsers "this is CycloneDX" (vs SPDX).                                            | `"CycloneDX"`                                                            |
| `specVersion`          | CycloneDX spec version this document validates against.                                                        | `"1.5"`                                                                  |
| `serialNumber`         | Globally unique ID of *this specific SBOM document*. Lets you tell two SBOMs apart even with the same content. | A fresh `urn:uuid:<v4>` on every request.                                |
| `version`              | Document revision counter — defined by CycloneDX for re-publishing a corrected SBOM under the same `serialNumber`. Not a request counter and not the version of the project. | Always `1`. Shieldoo Gate doesn't re-revise: each request returns a fresh document with a new `serialNumber`, so there's nothing to bump. |
| `metadata.timestamp`   | When this SBOM was generated.                                                                                  | Generation time in RFC 3339.                                             |
| `metadata.lifecycles`  | At which point in the software lifecycle this SBOM was produced. Enum: `design`, `pre-build`, `build`, `post-build`, `operations`, `discovery`, `decommission`. Lets a vulnerability tracker distinguish "what a project declared at build time" from "what we observed flowing through the proxy", so it can weight findings differently. | Always `[{phase: "discovery"}]` — Shieldoo Gate passively observes pull events; it sees no build resolution or runtime install state. |
| `metadata.tools`       | What program generated this SBOM.                                                                              | `shieldoo-gate` with its build version, as an `application` component.   |
| `metadata.component`   | The "subject" of the SBOM — *what the document is about*. The components list below describes things this subject uses. | The project: `type=application`, `bom-ref=project/<label>`, `name=<label>`. `version` is intentionally omitted (a Project has no version). `display_name` and `description` from the `projects` table are merged into the CycloneDX `description` as `"<display_name> — <description>"`, or whichever single field is set. **Lazy-created projects** have `display_name=label` set by `internal/project/service.go`, so `description` ends up equal to `name` until an admin overrides it via `PATCH /api/v1/projects/{id}`. |

The `metadata.tools.components[].version` is stamped from the Shieldoo Gate
build version (`-ldflags "-X main.Version=..."`, defaults to `dev` for
unstamped local builds).

## PURL Mapping by Ecosystem

For every ecosystem, `<version>` in the output comes from `artifacts.version`
and (where applicable) `<sha256>` from `artifacts.sha256`. The middle column
below shows only what is stored in the `artifacts.name` field.

| Ecosystem | `artifacts.name` shape       | PURL                                                                      |
|-----------|------------------------------|---------------------------------------------------------------------------|
| pypi      | `name`                       | `pkg:pypi/<name>@<version>`                                               |
| npm       | `name` or `@scope/name`      | `pkg:npm/<name>@<version>` or `pkg:npm/%40scope/<name>@<version>`         |
| maven     | `groupId:artifactId`         | `pkg:maven/<groupId>/<artifactId>@<version>`                              |
| nuget     | `name`                       | `pkg:nuget/<name>@<version>`                                              |
| rubygems  | `name`                       | `pkg:gem/<name>@<version>`                                                |
| go        | `module/path`                | `pkg:golang/<namespace>/<name>@<version>` (split on last `/`)             |
| docker    | repository-derived safe name | `pkg:oci/<lastpath>@sha256:<digest>?repository_url=<host/path>&tag=<tag>` |

PURLs are omitted (rather than fabricated) when essential inputs are
missing: empty name, unknown ecosystem, docker without a SHA-256, or maven
where `name` lacks a `:` separating `groupId` from `artifactId`.

> The `docker` ecosystem maps to `pkg:oci/` rather than `pkg:docker/`
> because the purl-spec uses `oci` as the canonical type for container
> images (it covers Docker Hub, ghcr.io, Quay, ECR, and any other OCI
> distribution registry). The original `pkg:docker/` is legacy.

**Per-ecosystem normalisation:**

- **pypi** — lowercase + runs of `.`, `-`, `_` collapsed to `-` (per
  [PEP 503](https://peps.python.org/pep-0503/#normalized-names)).
  So `Django_filter` → `pkg:pypi/django-filter@…`.
- **go** — namespace and name lowercased (per
  [purl-spec golang](https://github.com/package-url/purl-spec/blob/main/types-doc/golang-definition.md)).
  Matches Trivy. Lossy for rare mixed-case module paths.

Without these, scanners like Dependency-Track see `Django_filter` and
`django-filter` as two different components and can't match CVEs.

## Conformance Notes

- `metadata.tools` uses the **1.5 object form** (`{components: [...]}`),
  not the deprecated 1.4 array form. We populate `components` only — never
  `services`.
- License entries use the union shape: exactly one of `license.id`,
  `license.name`, or `expression` is set per entry. Expressions (anything
  containing ` AND `, ` OR `, ` WITH `, or parentheses) are emitted as
  `expression`; everything else is treated as an SPDX ID under `license.id`.
- `hashes[].alg` is `SHA-256` (case-sensitive enum value from the schema).
- `serialNumber` is an RFC 4122 UUID in URN form (`urn:uuid:<uuid>`),
  matching the CycloneDX schema regex
  `^urn:uuid:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`.
- **1.6-only fields are intentionally omitted** so the document validates
  against the strict 1.5 schema: `component.manufacturer` (added in 1.6 —
  we use `component.supplier` instead) and `license.acknowledgement`
  (added in 1.6). When the project later moves to CycloneDX 1.6, these can
  be added.

Output validated against the official CycloneDX 1.5 JSON schema with
`cyclonedx-cli validate --input-version v1_5`.

## What Shieldoo Gate Captures vs What CycloneDX Allows

Fields populated **on the SBOM subject** (`metadata.component`) and **on
the tool** (`metadata.tools.components[]`): `type`, `name`, `version`
(tool only), `supplier` (tool only), `description` (subject only),
`bom-ref`.

Fields **not currently populated on per-package components** but which
CycloneDX permits — possible follow-ups:

- `supplier` / `publisher` — would require parsing per-ecosystem metadata
  (PyPI `Author`, npm `author`, NuGet `authors`, Maven POM
  `developers`/`organization`).
- `description` — same source as above.
- `externalReferences[type=vcs]` / `[type=website]` — requires extracting
  `Project-URL` (PyPI), `repository` (npm), `projectUrl` (NuGet), POM
  `scm`/`url` (Maven).

These would need new columns on `artifacts` (`description`, `homepage_url`,
`vcs_url`, `supplier`) and an extension to the per-ecosystem metadata
extractors in `internal/scanner/trivy`. Tracked as a follow-up; not
required for spec compliance.

## Validating the Output

To verify the SBOM passes the official CycloneDX 1.5 JSON schema:

```bash
# Using cyclonedx-cli (pinned by SHA in your tooling)
cyclonedx-cli validate \
  --input-file sbom-<label>-YYYYMMDD.cdx.json \
  --input-format json \
  --input-version v1_5
```
