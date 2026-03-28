# Shieldoo Gate — Example Projects

Minimal example projects that demonstrate how to configure package managers to use Shieldoo Gate as a local proxy.

Each example has **one dependency** and a tiny script that uses it, serving as a quick smoke test for the proxy.

## Prerequisites

1. **Shieldoo Gate running locally** (via Docker Compose):

   ```bash
   cp config.example.yaml docker/config.yaml
   docker compose -f docker/docker-compose.yml up -d
   ```

2. **Verify the proxy is healthy:**

   ```bash
   curl http://localhost:8080/api/v1/health
   ```

3. **Toolchains** (only needed for the examples you want to run):
   - Python: [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
   - Node.js: [Node.js 18+](https://nodejs.org/)
   - .NET: [.NET SDK 8.0+](https://dotnet.microsoft.com/download)
   - Java: [JDK 11+](https://adoptium.net/) + [Maven 3.6+](https://maven.apache.org/download.cgi)

## Examples

| Example | Proxy Port | Dependency | Description |
|---------|-----------|------------|-------------|
| [python-requests](python-requests/) | PyPI `:5010` | `requests` | HTTP GET request |
| [npm-chalk](npm-chalk/) | npm `:4873` | `chalk` | Colored terminal output |
| [dotnet-json](dotnet-json/) | NuGet `:5001` | `Newtonsoft.Json` | JSON serialization |
| [maven-example](maven-example/) | Maven `:8085` | `commons-lang3` | String utilities |

Each example is fully independent — you only need the toolchain for the one you want to try.

## Docker Registry Proxy

Shieldoo Gate also proxies Docker images on port `5002`. Docker registry configuration is more involved (requires daemon config changes), so there is no standalone example here. See the [technical specification](../docs/initial-analyse.md) for details.

## macOS Note

The default PyPI host port is `5010` (instead of the conventional `5000`) to avoid conflicts with macOS AirPlay Receiver on Monterey+.
