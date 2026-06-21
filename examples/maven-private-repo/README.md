# Maven Example — multi-upstream-index (private repo behind the gate)

Demonstrates a **multi-index Maven setup**: the gate fronts the public default
(`repo1.maven.org`) plus a scoped private Maven repository. Clients point a
single `<mirror>` at the gate; the gate fans out per-coordinate requests
(`maven-metadata.xml`, `.pom`, checksums) across indexes with ordered fallback +
glob scoping on the `groupId:artifactId` coordinate, downloads + scans the
artifact (`.jar`/`.war`/`.aar`/`.zip`), and caches it under the namespaced
ecosystem `maven__<index>` before serving. The client never speaks to the
private repo directly.

Maven embeds **no download URLs** in its metadata (clients construct artifact
URLs from the coordinate themselves), so metadata is relayed verbatim — there is
nothing to rewrite. The **effective-POM resolver** walks the parent POM chain
against the *same* serving index (with its auth), so a private artifact's parent
licenses are resolved from the private repo, not silently from public.

This is a **configuration-demonstration** example. Running it end-to-end requires
your own private Maven repository (Nexus, Artifactory, GitHub Packages, …)
serving the standard Maven repository layout:

- metadata at `GET /{groupPath}/{artifactId}/maven-metadata.xml`
- POM at `GET /{groupPath}/{artifactId}/{version}/{artifactId}-{version}.pom`
- artifact at `GET /{groupPath}/{artifactId}/{version}/{artifactId}-{version}.jar`

If you only want a self-contained smoke test, use [maven-example](../maven-example/).

## Gate config

Add a scoped private repo to `upstreams.maven` in the gate's `config.yaml`:

```yaml
upstreams:
  maven:
    default: "https://repo1.maven.org/maven2"
    extra_indexes:
      - name: "corp"                          # ^[a-z0-9-]+$ — used in artifact-ID namespacing (maven__corp)
        url: "https://nexus.internal.example.com/repository/maven-releases"
        packages: ["com.mycompany:*"]         # only these groupId:artifactId globs route here (MUST be scoped)
        auth:
          type: "bearer"                      # "bearer" | "basic"
          token_env: "SGW_MAVEN_CORP_TOKEN"
```

Notes:

- All index URLs must be `https`. `files_host` is PyPI-only and rejected here.
- **Extra indexes MUST be `packages`-scoped.** The flat coordinate download route
  recovers the serving index by re-resolving the `groupId:artifactId`, so an
  *unscoped* extra index cannot be recovered on download.
- Scopes match the `groupId:artifactId` coordinate verbatim (Maven names are
  case-sensitive), e.g. `com.mycompany:*` or `com.mycompany:lib`.
- A **scoped-namespace miss** (a `com.mycompany:*` coordinate absent from every
  claiming index) is a hard **404** on the metadata leg — never a public fallback
  (prevents dependency confusion).
- **Version-listing limitation:** version-level `maven-metadata.xml` (SNAPSHOT
  resolution) is resolved on a best-effort coordinate heuristic; an artifactId
  starting with a digit may mis-resolve a *version listing* (never an artifact
  download — the `.jar` always resolves on the exact coordinate).

## Client config

Point Maven's `settings.xml` `<mirror>` at the gate so **all** repository traffic
flows through it (see [settings.xml.example](settings.xml.example)). With proxy
auth enabled, the Basic-auth username is your project label and the password is
the shared token (see the [examples README](../README.md)).

```bash
mvn -s settings.xml dependency:get -Dartifact=com.mycompany:lib:1.0.0
```

## Verifying the scan+cache (not bypassed)

```bash
curl -s "http://localhost:8080/api/v1/artifacts?ecosystem=maven__corp" | jq '.data[].name'
```

The executable spec for this behaviour is
[`tests/e2e-shell/test_maven_multi_index.sh`](../../tests/e2e-shell/test_maven_multi_index.sh).
