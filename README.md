# Shieldoo Gate

> Open-source supply chain security proxy for Docker, PyPI, npm, NuGet, and more.

Shieldoo Gate acts as a transparent caching proxy for all major package ecosystems, scanning every artifact before it is served and blocking delivery of malicious content in real time.

## Key Features

- **Transparent proxy** — zero client-side changes beyond pointing at the Gate URL
- **Multi-ecosystem** — Docker, PyPI, npm, NuGet (Maven, RubyGems in v1.1)
- **Pluggable scanners** — GuardDog, Trivy, OSV, built-in heuristics
- **Block & quarantine** — malicious packages never reach your developers or CI
- **Community threat feed** — fast-path blocking of known malicious package hashes
- **Self-hostable** — single Docker Compose or Helm chart

## Quick Start

```bash
# 1. Copy and customise the example config
cp config.example.yaml docker/config.yaml

# 2. Start the full stack (Shieldoo Gate + GuardDog scanner bridge)
docker compose -f docker/docker-compose.yml up -d

# 3. Point your package managers at the proxy
pip config set global.index-url http://localhost:5010/simple/
npm config set registry http://localhost:4873/
# NuGet:  dotnet nuget add source http://localhost:5001/v3/index.json
# Docker: configure daemon mirror to http://localhost:5002

# 4. Check the Admin API
curl http://localhost:8080/api/v1/health
```

Port reference:

| Service | Port | Protocol |
|---|---|---|
| PyPI proxy | 5010 | HTTP |
| npm proxy | 4873 | HTTP |
| NuGet proxy | 5001 | HTTP |
| Docker proxy | 5002 | HTTP |
| Admin API / Metrics | 8080 | HTTP |

## Testing

```bash
# Unit tests
make test

# E2E shell tests (spins up isolated Docker stack, installs real packages, validates API)
./tests/e2e-shell/run.sh
```

See [`tests/e2e-shell/README.md`](tests/e2e-shell/README.md) for details and flags (`--no-build`, `--keep`).

## Documentation

**Full documentation is available in [`docs/`](docs/index.md).**

## License

Apache 2.0 — see [LICENSE](LICENSE).
