# Go modules Example — multi-upstream-index (private GOPROXY behind the gate)

Demonstrates a **multi-index Go modules setup**: the gate fronts the public
default (`proxy.golang.org`) plus a scoped private GOPROXY. Set a single
`GOPROXY` at the gate; the gate fans out per-module metadata across indexes
(`@v/list`, `.info`, `.mod`, `@latest` — relayed verbatim, GOPROXY metadata
carries no download URLs), downloads + scans the `.zip`, and caches it under the
namespaced ecosystem `go__<index>` before serving. The client never speaks to the
private GOPROXY directly.

This is a **configuration-demonstration** example. Running it end-to-end requires
your own private GOPROXY (Athens, Artifactory, GitHub, …) serving the standard
[GOPROXY protocol](https://go.dev/ref/mod#goproxy-protocol).

If you only want a self-contained smoke test, use [go-example](../go-example/).

## Gate config

Add a scoped private GOPROXY to `upstreams.gomod` in the gate's `config.yaml`:

```yaml
upstreams:
  gomod:
    default: "https://proxy.golang.org"
    extra_indexes:
      - name: "corp"                          # ^[a-z0-9-]+$ — used in artifact-ID namespacing (go__corp)
        url: "https://goproxy.internal.example.com"
        packages: ["github.com/mycompany/*"]  # scopes match the case-sensitive decoded module path
        auth:
          type: "bearer"
          token_env: "SGW_GOMOD_CORP_TOKEN"
```

Notes:

- All index URLs must be `https`. `files_host` is PyPI-only and rejected here.
- **Extra indexes MUST be `packages`-scoped.** The `.zip` download route recovers
  the serving index by re-resolving the module path; an unscoped extra index
  cannot be recovered on download.
- A **scoped-namespace miss** (a `github.com/mycompany/*` module absent from every
  claiming index) is a hard **404** — never a public fallback.
- There is **no metadata rewrite surface**: the Go client constructs `…/@v/{ver}.zip`
  against the gate itself, so the `.zip` download route is the unconditional scan
  chokepoint.

## Client config

Point `GOPROXY` at the gate and mark the private path `GOPRIVATE` so the client
does not consult the public checksum database (`sum.golang.org`) for private
modules (see [env.example](env.example)). With proxy auth enabled, embed
`PROJECT:TOKEN` in the URL userinfo.

```bash
export GOPROXY="http://default:test-token-123@localhost:8087"
export GOPRIVATE="github.com/mycompany/*"
export GONOSUMCHECK=1
go get github.com/mycompany/lib@v1.0.0
```

## Verifying the scan+cache (not bypassed)

```bash
curl -s "http://localhost:8080/api/v1/artifacts?ecosystem=go__corp" | jq '.data[].name'
```

The executable spec for this behaviour is
[`tests/e2e-shell/test_gomod_multi_index.sh`](../../tests/e2e-shell/test_gomod_multi_index.sh).
