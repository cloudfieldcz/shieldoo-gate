# Version-Diff AI Rebuild — Plan Index

**Source:** [`2026-04-30-version-diff-ai-rebuild.md`](./2026-04-30-version-diff-ai-rebuild.md) (design + analysis)

**Created:** 2026-04-30

**Branch:** `feature/version-diff-ai-rebuild`

## Phases

| # | Phase | Plan File | Status | Dependencies |
|---|-------|-----------|--------|--------------|
| 1 | Proto + bridge skeleton | [plan-1-proto-bridge-skeleton.md](./2026-04-30-version-diff-ai-rebuild-plan-1-proto-bridge-skeleton.md) | ✅ Complete | — |
| 2 | DB migration 024 | [plan-2-db-migration.md](./2026-04-30-version-diff-ai-rebuild-plan-2-db-migration.md) | ✅ Complete | — |
| 3 | PyPI extractor (reference) | [plan-3-pypi-extractor.md](./2026-04-30-version-diff-ai-rebuild-plan-3-pypi-extractor.md) | ✅ Complete | Phase 1 |
| 4 | Other extractors (NPM/NuGet/Maven/RubyGems) | [plan-4-other-extractors.md](./2026-04-30-version-diff-ai-rebuild-plan-4-other-extractors.md) | ✅ Complete | Phase 3 |
| 5 | Python diff_scanner + prompt | [plan-5-diff-scanner-prompt.md](./2026-04-30-version-diff-ai-rebuild-plan-5-diff-scanner-prompt.md) | ✅ Complete | Phase 4 |
| 6a | Go skeleton + config | [plan-6a-go-skeleton-config.md](./2026-04-30-version-diff-ai-rebuild-plan-6a-go-skeleton-config.md) | ✅ Complete | Phases 1, 2 |
| 6b | Go Scan flow integration | [plan-6b-go-scan-flow.md](./2026-04-30-version-diff-ai-rebuild-plan-6b-go-scan-flow.md) | ✅ Complete | Phases 5, 6a |
| 6c | Go tests | [plan-6c-go-tests.md](./2026-04-30-version-diff-ai-rebuild-plan-6c-go-tests.md) | ✅ Complete | Phase 6b |
| 7 | Config + documentation | [plan-7-config-docs.md](./2026-04-30-version-diff-ai-rebuild-plan-7-config-docs.md) | ✅ Complete | Phase 6c |
| 7.5 | Pre-rollout validation | [plan-7-5-pre-rollout-validation.md](./2026-04-30-version-diff-ai-rebuild-plan-7-5-pre-rollout-validation.md) | ✅ Complete (known-malicious 10/10 PASS; historical replay deferred — see findings) | Phase 7 |
| 8a | Shadow rollout (7 days) | [plan-8a-shadow-rollout.md](./2026-04-30-version-diff-ai-rebuild-plan-8a-shadow-rollout.md) | 🔨 Deployed 2026-05-01 — observation in progress | Phase 7.5 |
| 8b | Activation + E2E | [plan-8b-activation-e2e.md](./2026-04-30-version-diff-ai-rebuild-plan-8b-activation-e2e.md) | ⬚ Not started | Phase 8a |
| 9 | Retention + cleanup | [plan-9-retention-cleanup.md](./2026-04-30-version-diff-ai-rebuild-plan-9-retention-cleanup.md) | ✅ Complete (shipped ahead of 8a/8b — code is independent and safe) | Phase 8b (deployment ordering only) |

**Status legend:** ⬚ Not started · 🔨 In progress · ✅ Complete · ⏸ Blocked

## Review summary (2026-04-30)

The plans were cross-reviewed by dev, security, and performance reviewers
before sign-off. Key fixes incorporated across the per-phase files:

- **Phase 1 + 5 + 6b:** `prompt_version` round-trip via `DiffScanResponse`.
  Bridge computes SHA[:12] of the system prompt on each scan and returns it;
  Go persists as `ai_prompt_version`. Closes the cache-poisoning gap where
  prompt edits would not invalidate cached verdicts.
- **Phase 2:** dropped explicit `BEGIN`/`COMMIT` — multi-statement migrations
  use the runner's per-`db.Exec` semantics; matches the precedent in 007.
- **Phase 3 + 4:** `_read_zip` is now truly streaming (`zf.open + read(cap+1)`)
  so decompression bombs are bounded by actual decompressed bytes, not by
  metadata-claimed `info.file_size`. Symlink/hardlink members skipped.
  Path-traversal check covers Windows drive prefix and backslash-traversal.
  Install-hook detection runs **before** the test/docs filter so
  `evil/tests/setup.py` cannot bypass inspection.
- **Phase 5:** redaction patterns expanded — OpenAI keys, GitHub fine-grained
  PATs, GitLab PATs, Slack tokens, Stripe, Twilio, Google API keys, AWS
  secret keys, PuTTY private keys. Install-hook truncation switched to
  head+tail (28 KB + 4 KB) so an attacker can't park payload at end of file.
  Truncated SUSPICIOUS@<0.85 downgrades to CLEAN as defense-in-depth.
- **Phase 6a:** `bridge_socket` validation relaxed — main.go inherits from
  `scanners.guarddog.bridge_socket` when empty, matching the AI scanner.
- **Phase 6b:** dropped bogus `crypto/sha512` and `errors` imports. Dropped
  `COALESCE` from cache lookup (defeats the unique index — now uses
  `ai_model_used IS NOT NULL` discriminator). UTF-8-safe explanation
  truncation. `json.Marshal` for `MetadataJSON`. Audit row only when INSERT
  actually wrote a row (RowsAffected). SUSPICIOUS→CLEAN downgrade no longer
  persists (preserves the cache for future prompt improvements). MALICIOUS
  at any confidence still downgrades to SUSPICIOUS (test added). Concurrent
  same-pair scans coalesced via `singleflight`. `findings_json` populated
  with the actual JSON-encoded findings (was `'[]'`).
- **Phase 6c:** `fakeCache` now implements the full `cache.CacheStore`
  interface (Delete, List, Stats). Concurrent test uses sync.WaitGroup +
  start barrier + bridge sync barrier so race is reliably exercised.
  Added MALICIOUS@low-confidence test, findings_json content test, and
  a "low-confidence downgrade does not persist" assertion.
- **Phase 7:** `scanners.timeout` default bump from 30 s to 60 s in main.go
  is **mandatory** — without it every version-diff scan would be killed by
  the outer cap before the LLM finished. Plus a startup invariant check
  that asserts the outer ≥ inner + 5 s buffer.
- **Phase 7.5:** replay tool gains `--concurrency` (default 4) and
  `--public-only` (default true) flags. Operator-consent prerequisite step
  before the run.
- **Phase 8a:** explicit bridge container `mem_limit: 2g`. `scanners.timeout: 60s`
  highlighted in the production config. KPI queries discriminate v2.0 rows
  via `ai_model_used IS NOT NULL`.
- **Phase 8b:** scoped down to two natural tests (real PyPI clean upgrade +
  idempotency cache hit) using direct curl against `E2E_PYPI_URL` — matching
  the actual harness pattern. The synthetic-suspicious and tests/-bypass
  E2E variants are deferred (FN coverage is provided by Phase 7.5's
  known-malicious set + Phase 5's bridge unit tests).
- **Phase 9:** retention scheduler matches the existing `RescanScheduler`
  struct pattern (Start/Stop/runOnce). Migration 025 adds
  `idx_version_diff_verdict_diff_at` so the daily DELETE is indexed. Test
  uses `strconv.Itoa` instead of a hand-rolled itoa. Daily cost breaker
  explicitly noted as advisory-only with follow-up task.

## Implementation findings (2026-05-01)

While wiring the e2e harness for Phase 7.5 / 8b, two latent bugs in the v2.0
implementation were uncovered and fixed in the same branch:

- **Scanner-bridge image was missing the version-diff sources.**
  `scanner-bridge/Dockerfile` did not `COPY diff_scanner.py` or
  `extractors_diff/`. The bridge crashed on startup with
  `ModuleNotFoundError: No module named 'diff_scanner'` whenever the new
  image was deployed — production rollout would have hit this on the very
  first restart.
- **Bridge had no read access to the gate cache.** Version-diff sends
  `previous_path` (a path under `/var/cache/shieldoo-gate/...`) over gRPC,
  but the `scanner-bridge` container only mounted `bridge-socket:/tmp`.
  Every diff scan hit `FileNotFoundError`, the bridge returned `UNKNOWN`,
  the Go scanner fail-opened, and the LLM step was silently bypassed for
  the entire Phase 5/6 lifetime. Fix: mount `gate-cache:/var/cache/shieldoo-gate:ro`
  into the bridge in all three compose files
  (`tests/e2e-shell/docker-compose.e2e.yml`, `docker/docker-compose.yml`,
  `.deploy/compose.yaml`). Now documented in
  [`docs/scanners/version-diff.md`](../scanners/version-diff.md#deployment-requirement-shared-cache-mount).
- **Azure Blob backend did not auto-create the container.**
  `cache.azureblob` skipped a `CreateContainer` call at init, so a
  fresh deployment using the Azure Blob backend would 404 on every Get/Put
  with `ContainerNotFound` until the operator pre-provisioned the container
  by hand. Fixed in `internal/cache/azureblob/azureblob.go` —
  `CreateContainerIfNotExists` is invoked at init (idempotent;
  `ContainerAlreadyExists` is the steady-state response and is silenced).

A new INFO log line `version-diff: ai scan completed` is emitted by the Go
scanner when the bridge returns a non-UNKNOWN verdict. The e2e suite asserts
its presence whenever `AI_SCANNER_ENABLED=true`, which would have caught
the cache-mount bug at the Phase 5 e2e gate had it been in place earlier.
A 4th e2e pass (`make test-e2e-containerized`, run 4) loads
`tests/e2e-shell/.env` and exercises the full LLM diff path. All 4 passes
are now fully green with five `ai scan completed` lines per run.

## Tagged release + production deployment (2026-05-01)

`v0.6.0` was cut from `main` (commit `4dded6d`) and the GitHub Actions
release workflow built and pushed both `ghcr.io/cloudfieldcz/shieldoo-gate:0.6.0`
and `ghcr.io/cloudfieldcz/scanner-bridge:0.6.0`. The production stack at
`shieldoo-gate.cloudfield.cz` was updated:

- `.deploy/.env` pinned to `SGW_VERSION=0.6.0` (no longer floating on `latest`).
- `.deploy/config.yaml` enables `scanners.version_diff` with `mode: "shadow"`
  and the full v2.0 config block. `scanners.timeout: "60s"` was already in
  place from earlier work.
- `.deploy/compose.yaml` adds `mem_limit: 2g` to the bridge container.
- A pre-deploy `pg_dump` backup was taken (14 MB, 21 tables) — kept locally
  at `/tmp/sg-backup-20260501-1115.sql` on the operator's machine.
- `docker compose pull && up -d --force-recreate` succeeded; both gate and
  bridge came up clean. Migrations 024 and 025 applied automatically.
- Smoke-test of `\d version_diff_results` confirms the AI columns,
  `scanner_version`, the `idx_version_diff_verdict_diff_at` retention
  index, and `uq_version_diff_pair` are all present.
- The retention scheduler logged `version-diff retention: pruned CLEAN
  rows rows_deleted=0 cutoff=2026-01-31` on the immediate-run pass —
  expected for a fresh table.

### Phase 7.5 known-malicious validation against the deployed bridge

The replay tool was cross-compiled (`CGO_ENABLED=0 GOOS=linux`), the proto
file copied to the prod box, and the 10-case synthetic-malicious set
generated locally and `scp`'d into the running bridge container at
`/tmp/cases/`. Each case was driven through `grpcurl` against the bridge's
`unix:///tmp/sock/shieldoo-bridge.sock`:

| Case | Expected | Actual | Confidence |
|------|----------|--------|------------|
| pypi-curl-pipe-sh | SUSPICIOUS | MALICIOUS | 0.99 |
| pypi-pth-import-hook | SUSPICIOUS | MALICIOUS | 0.99 |
| npm-postinstall-evil | SUSPICIOUS | MALICIOUS | 0.99 |
| pypi-aws-cred-read | SUSPICIOUS | MALICIOUS | 0.99 |
| pypi-imds-query | SUSPICIOUS | MALICIOUS | 0.99 |
| npm-base64-exec | SUSPICIOUS | MALICIOUS | 0.99 |
| nuget-install-ps1-network | SUSPICIOUS | MALICIOUS | 0.99 |
| rubygems-extconf-spawn | SUSPICIOUS | MALICIOUS | 0.99 |
| pypi-clean-bump | CLEAN | CLEAN | 0.99 |
| npm-clean-docs | CLEAN | CLEAN | 0.99 |

**Result: 10 / 10 PASS.** The bridge logged 10 INFO lines
`diff_scanner: calling LLM model=gpt-5.4-mini system_prompt_version=bf40690ec8a0`
with the prompt SHA reflecting the production prompt file. The Go-side
asymmetric downgrade (MALICIOUS → SUSPICIOUS) was not exercised here
because the replay used grpcurl directly against the bridge — verdicts
above are the bridge's raw classifications, which the gate would map to
SUSPICIOUS in the active path.

### Phase 7.5 historical-FP replay: deferred (Azure Blob backend mismatch)

The replay tool reads cached artifacts via `os.Open(storage_path)`,
which assumes the local-filesystem cache backend. **Production uses
Azure Blob Storage** (`cache.backend: azure_blob`), so the
`storage_path` column on rows produced before v2.0 is a transient
`/tmp/shieldoo-gate-{eco}-N.tmp` path that does not survive container
restarts. All 100 sampled SUSPICIOUS rows reported "new artifact not on
disk" and were skipped.

**Decision:** the historical-FP measurement is deferred to the live
shadow window (Phase 8a). The known-malicious set above provides FN
coverage independently. To unlock historical replay against blob-backed
deployments, the replay tool would need to call `cache.Get()` through
the storage backend interface (tracked in `docs/plans/follow-ups.md`).

## Notes

- Phases 1 and 2 have no inter-dependency and can be executed in parallel.
- Phases 3 → 4 → 5 are sequential (extractor reference → variants → orchestrator).
- Phase 6a depends on both Phases 1 (proto stubs regenerated) and 2 (DB columns available for reads in tests). It can run in parallel with Phases 3–5 because it only stubs the gRPC call.
- Phase 6b is the join point — it requires the Python pipeline (Phase 5) and the Go skeleton (Phase 6a).
- Each plan file is self-contained — an executor can pick up a single phase without reading others. All tests, code snippets, and verification commands are inlined.
- Phases 8a, 8b are operational (production rollout) and produce no code commits beyond config tweaks. They are gated on the acceptance criteria from the analysis document.

## Acceptance criteria (from analysis)

Rebuild is successful only when **all** of the following are met during the 7-day shadow window in production (Phase 8a):

| Criterion | Target | Measurement |
|-----------|--------|-------------|
| False-positive rate | < 5 % | (SUSPICIOUS on legit packages) / (total scans) |
| False-negative rate | 0 % on test set | Replay 20 known-malicious diffs — all SUSPICIOUS |
| p99 scan latency | < 30 s | Prometheus `version_diff_duration_seconds{quantile="0.99"}` |
| Fail-open ratio | < 1 % | `version_diff_fail_open_total / version_diff_scans_total` |
| AI cost (daily mean) | < $0.50/day | Sum `ai_tokens_used` × model price |
| Bridge timeout rate | < 0.5 % | No systematic timeout problem |
