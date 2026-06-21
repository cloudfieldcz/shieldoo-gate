# RubyGems Example — multi-upstream-index (private source behind the gate)

Demonstrates a **multi-index RubyGems setup**: the gate fronts the public default
(`rubygems.org`) plus a scoped private gem source. Clients point a single
`source` at the gate; the gate fans out per-gem metadata across indexes
(`/info/{name}` compact index, `/api/v1/gems/{name}.json`,
`/api/v1/versions/{name}.json`), downloads + scans the `.gem`, and caches it
under the namespaced ecosystem `rubygems__<index>` before serving. The client
never speaks to the private source directly.

This is a **configuration-demonstration** example. Running it end-to-end requires
your own private gem source (Geminabox, GitHub Packages, Artifactory, …) serving
the standard layout:

- compact-index per-gem at `GET /info/{name}`
- gem JSON at `GET /api/v1/gems/{name}.json`
- gem artifact at `GET /gems/{name}-{version}.gem`

If you only want a self-contained smoke test, use [rubygems-example](../rubygems-example/).

## Gate config

Add a scoped private source to `upstreams.rubygems` in the gate's `config.yaml`:

```yaml
upstreams:
  rubygems:
    default: "https://rubygems.org"
    extra_indexes:
      - name: "corp"                          # ^[a-z0-9-]+$ — used in artifact-ID namespacing (rubygems__corp)
        url: "https://gems.internal.example.com"
        packages: ["mycompany-*"]             # only these globs route here (MUST be scoped)
        auth:
          type: "bearer"                      # "bearer" | "basic"
          token_env: "SGW_RUBYGEMS_CORP_TOKEN"
```

Notes:

- All index URLs must be `https`. `files_host` is PyPI-only and rejected here.
- **Extra indexes MUST be `packages`-scoped.** The flat `/gems/{file}` download
  route recovers the serving index by re-resolving the gem name, so an *unscoped*
  extra index cannot be recovered on download.
- A **scoped-namespace miss** (a `mycompany-*` gem absent from every claiming
  index) is a hard **404** — never a public fallback (prevents dependency
  confusion).
- The `gem_uri` rewrite in `/api/v1/gems/{name}.json` is **fail-closed**: if its
  host is not the source/files host, the gate returns **502**.
- **Discoverability limitation:** whole-index files (`/versions`, `/names`,
  `/specs*.4.8.gz`, `/quick/Marshal.4.8/*`) are served from the default only and
  do not list private gems. Private gems are resolvable **by name** (the path
  Bundler/`gem` use for gems in the dependency graph), but won't appear in a
  full-index enumeration.

## Client config

Point the `Gemfile`'s `source` at the gate (see [Gemfile.example](Gemfile.example)).
With proxy auth enabled, the Basic-auth username is your project label and the
password is the shared token (see the [examples README](../README.md)).

```bash
gem install mycompany-gem --source "http://default:test-token-123@localhost:8086"
```

## Verifying the scan+cache (not bypassed)

```bash
curl -s "http://localhost:8080/api/v1/artifacts?ecosystem=rubygems__corp" | jq '.data[].name'
```

The executable spec for this behaviour is
[`tests/e2e-shell/test_rubygems_multi_index.sh`](../../tests/e2e-shell/test_rubygems_multi_index.sh).
