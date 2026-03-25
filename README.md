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
docker compose -f docker/docker-compose.yml up
```

Then point your package manager at the Gate:

```bash
pip config set global.index-url http://localhost:5000/simple/
npm config set registry http://localhost:4873/
```

## Documentation

**Full documentation is available in [`docs/`](docs/index.md).**

## License

Apache 2.0 — see [LICENSE](LICENSE).
