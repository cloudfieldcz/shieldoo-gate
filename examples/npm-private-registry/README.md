# npm Example — multi-upstream-index (private registry behind the gate)

Demonstrates a **multi-index npm setup**: the gate fronts the public default
(`registry.npmjs.org`) plus a scoped private registry. Clients point a single
`registry=` at the gate; the gate fans out across indexes, rewrites the
packument's `dist.tarball` URLs through its scan pipeline, downloads + scans the
tarball, and caches it under the namespaced ecosystem `npm__<index>` before
serving. The client never speaks to the private registry directly.

This is a **configuration-demonstration** example. Running it end-to-end
requires your own private npm registry (Verdaccio, GitHub Packages, Artifactory,
Azure Artifacts, …) that serves the standard layout:

- packument at `GET /{pkg}` (or `/@scope/{pkg}`)
- tarball at `GET /{pkg}/-/{pkg}-{version}.tgz`

If you only want a self-contained smoke test, use [npm-chalk](../npm-chalk/).

## Gate config

Add a scoped private registry to `upstreams.npm` in the gate's `config.yaml`:

```yaml
upstreams:
  npm:
    default: "https://registry.npmjs.org"
    extra_indexes:
      - name: "corp"                       # ^[a-z0-9-]+$ — used in artifact-ID namespacing (npm__corp)
        url: "https://npm.internal.example.com"
        packages: ["@mycompany/*", "mycompany-*"]   # only these globs route here
        auth:
          type: "bearer"                   # "bearer" | "basic"
          token_env: "SGW_NPM_CORP_TOKEN"  # credential read from this env var only — never plaintext
```

Notes:

- All index URLs must be `https`.
- `files_host` is **PyPI-only** and ignored for npm (npm tarballs share the
  registry origin).
- A **scoped-namespace miss** (a `mycompany-*` package absent from every claiming
  index) is a hard **404** — never a public fallback. This prevents
  dependency-confusion.
- The packument rewrite is **fail-closed**: if a `dist.tarball` URL points at a
  host that is neither the registry nor its files host, the gate returns **502**
  rather than letting npm fetch an unscanned artifact directly.

## Client config

Point `.npmrc` at the gate (see [.npmrc.example](.npmrc.example)). With proxy
auth enabled, the Basic-auth username is your project label and the password is
the shared token (see the [examples README](../README.md)).

```bash
npm install --registry "http://default:test-token-123@localhost:4873/" @mycompany/private-lib
```

## Verifying the scan+cache (not bypassed)

After installing a private package, confirm the gate scanned + cached it under
the namespaced ecosystem (this is the release-gate proof — no scan bypass):

```bash
curl -s "http://localhost:8080/api/v1/artifacts?ecosystem=npm__corp" | jq '.data[].name'
```

The executable spec for this behaviour is
[`tests/e2e-shell/test_npm_multi_index.sh`](../../tests/e2e-shell/test_npm_multi_index.sh).
