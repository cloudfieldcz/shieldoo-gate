# Python Example — multi-upstream-index (private + public vendor index)

Demonstrates a real-world **multi-index PyPI setup**: the gate fronts a public
default (pypi.org), an unscoped commercial vendor index, and a scoped private
corporate index — all behind a single `--index-url` pointed at the gate.
Clients never speak to the upstream indexes directly; the gate fans out, rewrites
download URLs, scans each artifact, and caches it before serving.

This is a **configuration-demonstration** example. Running it end-to-end
requires:

- A corporate private PyPI index with packages matching your `packages:` scope
  (e.g. `mycorp-*`) and a bearer or basic-auth credential.
- Optionally, a Hexaly licence and access to its public index `https://pip.hexaly.com`
  (or substitute any other commercial vendor index whose simple API is served at
  `<base>/simple/` — the gate appends `/simple/` to the configured `url`).

If you only want to smoke-test the gate locally, the existing
[python-requests](../python-requests/) example is self-contained.

## How it works

```
pip / uv                           Shieldoo Gate                 Upstream indexes
─────────────────────────────────────────────────────────────────────────────────
pip install mycorp-utils            ──► /simple/mycorp-utils/
                                         scoped → corp only
                                         auth header injected      ──► corp index
                                         href rewritten to
                                         /ext-packages/corp/…
                                         download → scan → cache
  ◄─── artifact served ────────────────────────────────────────────────────────

pip install hexaly                  ──► /simple/hexaly/
                                         unscoped: default first
                                         (miss), then hexaly       ──► pip.hexaly.com
                                         href rewritten to
                                         /ext-packages/hexaly/…
                                         download → scan → cache
  ◄─── artifact served ────────────────────────────────────────────────────────

pip install requests                ──► /simple/requests/
                                         default (pypi.org) hit    ──► pypi.org
                                         scan → cache
  ◄─── artifact served ────────────────────────────────────────────────────────
```

Key properties:

- The client sets **one** `--index-url` — the gate. It never configures
  upstream indexes directly, so credentials never leave the gate node.
- Package names matching `mycorp-*` (or any `packages:` glob) route **only** to
  the claiming index. A miss there returns HTTP 404 — no silent fallback to
  pypi.org (dependency-confusion guard).
- Credentials live in a single server-side env var (`MYCORP_INDEX_TOKEN`). The
  client request carries the gate's own proxy token, not the upstream credential.
- Every artifact (public or private) is scanned and cached under an
  ecosystem-namespaced key (`pypi__hexaly`, `pypi__corp`). Re-installs are
  served from cache — no repeated upstream round-trips.

## Gate configuration

Add the following to your gate's `config.yaml` (see `config.example.yaml` for
the full reference):

```yaml
upstreams:
  pypi:
    default: "https://pypi.org"
    extra_indexes:
      # `url` is the registry BASE — the gate appends the PEP 503 `/simple/<pkg>/`
      # path itself (same as `default`). Do NOT include `/simple/` or it is doubled.
      # The index must serve its simple API at `<url>/simple/`.
      - name: "hexaly"                        # unscoped fallback (public vendor index)
        url: "https://pip.hexaly.com"
      - name: "corp"                          # private index, pinned to a namespace
        url: "https://pkgs.corp.example.com"
        packages: ["mycorp-*"]                # only these globs route here
        files_host: "https://files.corp.example.com/"  # optional separate file CDN
        auth:
          type: "bearer"                      # "bearer" | "basic"
          token_env: "MYCORP_INDEX_TOKEN"     # credential read from this env var only
```

Field reference (exact YAML keys from `internal/config/config_upstreams.go`):

| Key | Required | Description |
|-----|----------|-------------|
| `upstreams.pypi.default` | yes | Base URL for the default public index |
| `extra_indexes[].name` | yes | Stable identifier, `^[a-z0-9-]+$` (used in artifact namespacing and `/ext-packages/<name>/` routing) |
| `extra_indexes[].url` | yes | Index **base** URL — **must be `https`**, no userinfo, no `/simple/` (the gate appends `/simple/<pkg>/`; the index must serve its simple API at `<url>/simple/`) |
| `extra_indexes[].files_host` | no | Separate file CDN URL (PyPI only; e.g. a private Artifactory files domain) |
| `extra_indexes[].packages` | no | Glob scope — omit for unscoped fallback, set for dependency-confusion protection |
| `extra_indexes[].auth.type` | when `auth:` present | `"bearer"` or `"basic"` |
| `extra_indexes[].auth.token_env` | when `auth:` present | Name of the env var holding the credential (never plaintext in config) |

Then set the env var on the gate process/container:

```bash
export MYCORP_INDEX_TOKEN="<your-token>"
```

Or in `docker-compose.yml`:

```yaml
environment:
  MYCORP_INDEX_TOKEN: "${MYCORP_INDEX_TOKEN}"
```

## Authentication

The reference `docker/config.yaml` enables proxy auth with a well-known
**development token** (`test-token-123`) and project label `python-demo`.
Adapt the label/token to your own project.

| Field | Value |
|-------|-------|
| Basic auth **username** | `python-demo` (or any `[a-z0-9][a-z0-9_-]{0,63}`) |
| Basic auth **password** | `test-token-123` (gate proxy token, not the upstream credential) |

## Run

```bash
# Create a virtual environment
uv venv .venv
source .venv/bin/activate

# Install a public package (routes via pypi.org default)
uv pip install \
    --no-cache --reinstall \
    --index-url http://python-demo:test-token-123@localhost:5010/simple/ \
    requests

# Install the Hexaly solver (routes via hexaly unscoped extra-index)
uv pip install \
    --no-cache --reinstall \
    --index-url http://python-demo:test-token-123@localhost:5010/simple/ \
    hexaly

# Install your private package (routes via corp scoped extra-index)
uv pip install \
    --no-cache --reinstall \
    --index-url http://python-demo:test-token-123@localhost:5010/simple/ \
    mycorp-utils
```

Or use `pip.conf.example` (copy to `~/.pip/pip.conf` or `$VIRTUAL_ENV/pip.conf`)
to avoid repeating the `--index-url` flag.

## Expected behaviour

After a successful install of a private package:

1. The gate returns HTTP 200 for `/simple/mycorp-utils/` with hrefs rewritten to
   `/ext-packages/corp/…`.
2. The tarball download goes through `/ext-packages/corp/…` — never directly to
   the upstream index.
3. An artifact row appears under ecosystem `pypi__corp` in the admin UI at
   `http://localhost:8080` (`Artifacts` tab, filter by `pypi__corp`).

If a package name matches `mycorp-*` but does **not** exist on the corp index,
the gate returns HTTP 404 — it does **not** fall back to pypi.org. This is the
dependency-confusion guard in action.

## What This Tests

- The gate correctly fans out across multiple upstream indexes for a single
  `--index-url` endpoint.
- Scoped package names (`mycorp-*`) are served exclusively by the claiming index
  — no public fallback (dependency-confusion guard).
- Unscoped packages try the default first, then extra indexes in order.
- Upstream credentials (`token_env`) are injected by the gate; the client
  request carries only the gate's own proxy token — credentials never transit
  the client.
- All artifacts (public and private) are scanned and cached before being served,
  namespaced under `pypi__<index>`.
- Download URLs are rewritten through `/ext-packages/<index>/…` so every byte
  flows through the gate's scan pipeline — no bypass is possible.

The executable specification for this behaviour is
`tests/e2e-shell/test_pypi_multi_index.sh`, covering:

- **S1** — back-compat: public package still routes via default upstream
- **S2** — private unscoped package scanned+cached under `pypi__private` (the
  release gate — asserts no bypass occurred)
- **S3** — scoped package (`acme-*`) routed exclusively to the corp index
- **S4** — scoped-miss returns 404, no public fallback, BLOCKED audit event written
- **S5** — SSRF fail-closed: forged index name returns 404 immediately

The e2e config wiring is in `tests/e2e-shell/config.e2e.yaml`.
