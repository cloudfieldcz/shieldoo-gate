# NuGet Example — multi-upstream-index (private feed behind the gate)

Demonstrates a **multi-index NuGet V3 setup**: the gate fronts the public
default (`api.nuget.org`) plus a scoped private feed. The client points a single
`<packageSources>` at the gate's service index; the gate fans out per-package
registration across indexes, rewrites `packageContent` download URLs through its
scan pipeline, downloads + scans the `.nupkg`, and caches it under the namespaced
ecosystem `nuget__<index>` before serving. The client never speaks to the private
feed directly.

This is a **configuration-demonstration** example. Running it end-to-end requires
your own private NuGet V3 feed (BaGet, Azure Artifacts, GitHub Packages, …) that
exposes the standard V3 resources (`PackageBaseAddress`, `RegistrationsBaseUrl`).

If you only want a self-contained smoke test, use [dotnet-json](../dotnet-json/).

## Gate config

Add a scoped private feed to `upstreams.nuget` in the gate's `config.yaml`:

```yaml
upstreams:
  nuget:
    default: "https://api.nuget.org"
    extra_indexes:
      - name: "corp"                        # ^[a-z0-9-]+$ — used in artifact-ID namespacing (nuget__corp)
        url: "https://nuget.internal.example.com"
        packages: ["MyCompany.*"]           # only these globs route here
        auth:
          type: "bearer"                    # "bearer" | "basic"
          token_env: "SGW_NUGET_CORP_TOKEN" # credential read from this env var only — never plaintext
```

Notes:

- All index URLs must be `https`.
- The **service index** (`/v3/index.json`) is served from the **default** only
  (it is index-wide, not per-package); per-package **registration** fans out.
- A **scoped-namespace miss** is a hard **404** — never a public fallback
  (dependency-confusion guard).
- The registration rewrite is **fail-closed**: if any `packageContent` or
  registration sub-page `@id` still points at a foreign host after rewriting, the
  gate returns **502** rather than risk an unscanned `.nupkg` reaching the client.

## Client config

Point `nuget.config` at the gate (see [nuget.config.example](nuget.config.example)).

```bash
dotnet add package MyCompany.PrivateLib
```

## Verifying the scan+cache (not bypassed)

```bash
curl -s "http://localhost:8080/api/v1/artifacts?ecosystem=nuget__corp" | jq '.data[].name'
```

The executable spec is
[`tests/e2e-shell/test_nuget_multi_index.sh`](../../tests/e2e-shell/test_nuget_multi_index.sh).
