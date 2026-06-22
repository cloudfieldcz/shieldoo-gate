# Contributing to Shieldoo Gate

Thanks for your interest in contributing! Shieldoo Gate is an open-source
supply-chain security proxy licensed under **Apache 2.0**. Contributions of code,
documentation, tests, and threat intelligence are all welcome.

By contributing you agree that your work is licensed under Apache 2.0 and that you
have the right to submit it.

## Before You Start

- **Security vulnerabilities — do not open a public issue or PR.** Report them
  privately. See [`SECURITY.md`](SECURITY.md).
- Be excellent to each other. See [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
- `docs/` is the source of truth for design, architecture, and conventions —
  [`docs/index.md`](docs/index.md) is the entry point. Read it before proposing
  larger changes.

## Development Setup

Prerequisites: **Go 1.25+**, **Node.js 20+**, **Python 3.13+** with
[uv](https://docs.astral.sh/uv/), and `protoc` (Protocol Buffers compiler).

```bash
make proto          # generate gRPC code (Go + Python)
make build          # build the shieldoo-gate + shdg binaries
make test           # unit + integration tests
make lint           # Go vet/lint + UI ESLint
```

Run locally with Docker Compose:

```bash
docker compose -f docker/docker-compose.yml up
```

See [`docs/index.md`](docs/index.md) for full local-development and scanner-bridge
setup instructions.

### End-to-End Tests

```bash
make test-e2e-containerized   # recommended — only Docker required
./tests/e2e-shell/run.sh      # host-based — needs uv, npm, dotnet, crane, etc.
make test-e2e                 # Go E2E tests
```

## Making Changes

1. **Fork & branch.** Branch off `main`; use a descriptive name
   (`feat/npm-adapter`, `fix/trivy-timeout`).
2. **One module per change.** Keep a change scoped to a single module — one
   adapter, one scanner, one storage backend, one API endpoint group. Don't mix
   unrelated modules in one PR.
3. **Pin all versions.** No floating or `latest` specifiers — Go deps pinned in
   `go.mod`, Python in `requirements.txt` (with `==` and hashes, via `uv`), Node
   in `package-lock.json`, Docker base images by digest. See
   [`CLAUDE.md`](CLAUDE.md) for the version-pinning policy.
4. **Write tests.** Every new function needs a test. Naming convention:
   `Test{FunctionName}_{Scenario}_{ExpectedOutcome}`.
5. **Update the docs.** Every code change that affects architecture, API,
   configuration, or behavior must update the relevant page under `docs/`.
   Architecture decisions go in `docs/adr/` as `ADR-NNN-title.md`; API changes
   update `docs/api/openapi.yaml`.
6. **Verify before you push.** Run `make build`, `make lint`, and `make test` —
   and the relevant E2E suite — locally. CI runs the same checks (see
   [`docs/development/ci.md`](docs/development/ci.md)).

## Commit & PR Conventions

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(pypi): implement PEP 503 proxy adapter
fix(scanner): apply trivy subprocess timeout
test(npm): add integration test for malicious tarball
docs(adr): ADR-003 use gRPC for scanner bridge
chore(deps): pin trivy to commit abc1234
```

Pull requests:

- Target `main`. Fill in the PR template.
- Keep PRs focused and reasonably small (multi-file changes should touch ~5 files
  per logical step).
- All required CI checks must pass, and security-critical paths
  (`internal/scanner/`, `internal/auth/`, `internal/policy/`, `docker/`,
  `.github/`) require review from the code owners in
  [`.github/CODEOWNERS`](.github/CODEOWNERS).
- Never violate the **Security Invariants** in [`CLAUDE.md`](CLAUDE.md) (never
  serve a quarantined artifact, never trust content before scan, never log
  secrets, never unpin scanner deps, audit log is append-only).

## Threat Intelligence Contributions

Reports of malicious packages are especially welcome. Submit them as OSV-format
JSON with supporting evidence (package name, version, ecosystem, indicators).

## License

By contributing, you agree your contributions are licensed under the
[Apache License 2.0](LICENSE).
