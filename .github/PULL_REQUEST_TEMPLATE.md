<!--
Thanks for contributing! Please read CONTRIBUTING.md first.
Keep PRs focused — ideally one module per change.
-->

## What & why

<!-- What does this change do, and why? Link related issues (e.g. Closes #123). -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup
- [ ] Docs only
- [ ] CI / build / chore

## Checklist

- [ ] Scoped to a single module (no unrelated changes)
- [ ] Tests added/updated; `make test` passes locally
- [ ] `make build` and `make lint` pass locally
- [ ] Relevant E2E suite run if behavior changed (`make test-e2e-containerized`)
- [ ] Docs updated under `docs/` (and `docs/adr/` / `docs/api/openapi.yaml` if applicable)
- [ ] All versions pinned (no `latest` / floating specifiers)
- [ ] No secrets in code, config, or logs
- [ ] Security invariants in `CLAUDE.md` respected (quarantine gate, scan-before-cache, append-only audit log, pinned scanner deps)

## Notes for reviewers

<!-- Anything the reviewer should pay special attention to, manual test steps, screenshots for UI changes, etc. -->
