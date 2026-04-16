# Shieldoo Gate — Example Projects

Minimal example projects that demonstrate how to configure package managers to use Shieldoo Gate as a local proxy.

Each example has **one dependency** and a tiny script that uses it, serving as a quick smoke test for the proxy.

## Prerequisites

1. **Shieldoo Gate running locally** (via Docker Compose):

   ```bash
   docker compose -f docker/docker-compose.yml up -d
   ```

   The reference `docker/config.yaml` has `proxy_auth.enabled: true`,
   `projects.mode: strict`, and bootstraps every example's project label
   on startup (`projects.bootstrap_labels`). `docker/docker-compose.yml`
   injects a well-known development token `SGW_PROXY_TOKEN=test-token-123`.
   All examples in this directory are pre-wired for that token + their
   own labels, so no admin `POST /projects` step is needed.

2. **Verify the proxy is healthy:**

   ```bash
   curl http://localhost:8080/api/v1/health
   ```

3. **Toolchains** (only needed for the examples you want to run):
   - Python: [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
   - Node.js: [Node.js 18+](https://nodejs.org/)
   - .NET: [.NET SDK 8.0+](https://dotnet.microsoft.com/download)
   - Java: [JDK 11+](https://adoptium.net/) + [Maven 3.6+](https://maven.apache.org/download.cgi)
   - Ruby: [Ruby 3.0+](https://www.ruby-lang.org/) + Bundler 2.0+
   - Go: [Go 1.21+](https://go.dev/dl/)

## Authentication & project segmentation

Every proxy request authenticates with **HTTP Basic Auth** where:

- **username** = project label (`[a-z0-9][a-z0-9_-]{0,63}`, e.g. `backend-team`, `data-pipeline`, or simply `default`)
- **password** = API token (a shared global token for bootstrapping, or a per-user PAT issued from the admin UI)

Each example here uses a **different project label** so you can see the per-project audit segmentation light up in the admin UI after running them:

| Example | Proxy Port | Project label | Dependency | Description |
|---------|-----------|---------------|------------|-------------|
| [python-requests](python-requests/) | PyPI `:5010` | `python-demo` | `requests` | HTTP GET request |
| [npm-chalk](npm-chalk/) | npm `:4873` | `npm-demo` | `chalk` | Colored terminal output |
| [dotnet-json](dotnet-json/) | NuGet `:5001` | `dotnet-demo` | `Newtonsoft.Json` | JSON serialization |
| [maven-example](maven-example/) | Maven `:8085` | `maven-demo` | `commons-lang3` | String utilities |
| [rubygems-example](rubygems-example/) | RubyGems `:8086` | `rubygems-demo` | `rake` | Build automation |
| [go-example](go-example/) | Go Modules `:8087` | `go-demo` | `zerolog` | Structured logging |

All six examples share the same token (`test-token-123`, hard-coded in
`docker/docker-compose.yml`). **If you don't care about per-project
segmentation**, you can substitute any of the `*-demo` usernames with `default`
— all unknown-but-valid labels auto-create a `projects` row in lazy mode.

Each example is fully independent — you only need the toolchain for the one you want to try.

### Where the token lives (for forks / custom deployments)

The dev token is injected into the Shieldoo Gate container via an `environment:`
block in [`docker/docker-compose.yml`](../docker/docker-compose.yml):

```yaml
environment:
  SGW_PROXY_TOKEN: "test-token-123"
```

To rotate:

1. Change the value in `docker/docker-compose.yml`.
2. Update the embedded token in each example (`.npmrc` `_auth` needs re-encoding with `base64`; Gemfile, GOPROXY, and pip `--index-url` need the new value in the URL userinfo; NuGet + Maven use a plain `<password>` element).
3. `docker compose -f docker/docker-compose.yml up -d --force-recreate`

**For production**, switch to per-user PATs issued from the admin UI (`Profile → API Keys`) and never commit a token to a file. PATs and the global token are interchangeable at the wire level — both are Basic-auth passwords — so the same `.npmrc` / `nuget.config` / `Gemfile` / `GOPROXY` patterns work unchanged.

### Switching to "I don't care about projects"

Just replace the username everywhere with `default`:

- **pip/uv:** `--index-url http://default:test-token-123@localhost:5010/simple/`
- **npm:** `_auth = $(printf "default:test-token-123" | base64)` → `ZGVmYXVsdDp0ZXN0LXRva2VuLTEyMw==`
- **NuGet:** `<add key="Username" value="default" />`
- **Maven:** `<username>default</username>` in `settings.xml`
- **RubyGems:** `source "http://default:test-token-123@localhost:8086"`
- **Go:** `GOPROXY="http://default:test-token-123@localhost:8087"`

Migration 018 seeds the `default` project on first boot, so this always works
out of the box — even in strict mode.

## Docker Registry Proxy

Shieldoo Gate also proxies Docker images on port `5002`. Docker registry configuration is more involved (requires daemon config changes + `docker login localhost:5002 -u <project> --password-stdin`), so there is no standalone example here. See the [Docker adapter documentation](../docs/adapters.md#docker-adapter) and [projects feature doc](../docs/features/projects.md) for details.

## macOS Note

The default PyPI host port is `5010` (instead of the conventional `5000`) to avoid conflicts with macOS AirPlay Receiver on Monterey+.
