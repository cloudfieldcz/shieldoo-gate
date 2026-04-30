# Version-Diff AI Rebuild — Phase 8a: Shadow rollout (7 days in production)

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run migration 024, deploy the binary with `version_diff.enabled: true` and `mode: "shadow"`, and observe for 7 days. The scanner runs on every applicable artifact and persists results to the DB, but `ScanResult.Verdict` is forced to CLEAN so the policy engine ignores it. Operators evaluate FP rate, latency, fail-open ratio, and AI cost before the next phase activates the verdict.

**Architecture:** This phase is operational. The deploy mechanics are already established for shieldoo-gate (see [memory: production access](../../../.claude/projects/-Users-valda-src-projects-shieldoo-gate/memory/reference_production_access.md)) — `ssh shieldoo-gate`, `/opt/shieldoo-gate`, `docker compose`. We add no code. We update production config and observe.

**Index:** [`plan-index.md`](./2026-04-30-version-diff-ai-rebuild-plan-index.md)

---

## Context for executor

This phase is gated by Phase 7.5 (pre-rollout validation must show ≥95% historical-FP correction). If 7.5 was not run or did not pass, **do not proceed to 8a** — go back and fix the prompt/extractor.

The deploy directory `.deploy/` in the repo must stay 1:1 with what's on the production server (memory note). Any config change committed here is then `git pull`'d on the server.

---

### Task 1: Pre-deploy backup

- [ ] **Step 1: SSH to production**

```bash
ssh shieldoo-gate
cd /opt/shieldoo-gate
```

- [ ] **Step 2: Snapshot the database**

```bash
# Postgres
docker compose exec postgres pg_dump -U shieldoo shieldoo > /tmp/sg-backup-$(date +%Y%m%d-%H%M).sql

# (If SQLite — current production is Postgres per the analysis. Adapt if not.)
```

Verify the file is non-empty and contains the `version_diff_results` table:

```bash
grep -c "CREATE TABLE.*version_diff_results" /tmp/sg-backup-*.sql
```

Expected: ≥ 1.

- [ ] **Step 3: Note current commit + image digest**

```bash
docker compose ps --format '{{.Service}} {{.Image}}'
git log -1 --oneline
```

Record both for rollback purposes.

---

### Task 2: Apply migration 024 + new binary

- [ ] **Step 1: Pull the latest deploy config**

```bash
cd /opt/shieldoo-gate
git pull
```

Expected: brings in the merged feature branch with migration 024 + new code.

- [ ] **Step 2: Update production `config.yaml` with shadow mode**

Edit the active config (typically `config.yaml` next to `docker-compose.yml`):

```yaml
scanners:
  timeout: "60s"                    # <-- bumped from 30s default; required for version-diff (Phase 7)
  version_diff:
    enabled: true
    mode: "shadow"                  # <-- key setting for this phase
    max_artifact_size_mb: 50
    max_extracted_size_mb: 50
    max_extracted_files: 5000
    scanner_timeout: "55s"
    bridge_socket: ""               # empty inherits scanners.guarddog.bridge_socket
    allowlist: []
    min_confidence: 0.6
    per_package_rate_limit: 10
    daily_cost_limit_usd: 5.0
    circuit_breaker_threshold: 5
```

- [ ] **Step 2b: Bridge container memory limit**

Add (or verify) a `mem_limit: 2g` on the `bridge` service in
`docker-compose.yml`. With `ThreadPoolExecutor(max_workers=64)` and ~16 MB
peak per worker (50 MB `max_extracted_size_mb` + overhead), worst-case bridge
memory is ~1–2 GB. Without an explicit limit, OOMKill becomes a tail-latency
cliff under burst.

- [ ] **Step 3: Pull new images and recreate**

```bash
docker compose pull
docker compose up -d --force-recreate
```

- [ ] **Step 4: Watch logs for migration 024 application**

```bash
docker compose logs -f gate | grep -E "migration|version_diff|error" | head -50
```

Expected log lines:
- `migration 024 applied` (or similar — implementation-defined)
- `version-diff scanner enabled`
- No errors mentioning `version_diff_results`

If migration fails:

1. Stop the gate: `docker compose stop gate`.
2. Restore from backup: `docker compose exec postgres psql -U shieldoo shieldoo < /tmp/sg-backup-*.sql`.
3. Investigate the migration error before retrying.

- [ ] **Step 5: Smoke-test a request**

Pick a small mainstream package and exercise it:

```bash
curl -sI https://shieldoo-gate.cloudfield.cz/pypi/simple/requests/ | head -1
```

Expected: HTTP/2 200 (or HTTP/1.1 200). Check logs for the corresponding scan:

```bash
docker compose logs --since=1m gate | grep -E "version-diff|requests"
```

Expected: a `version-diff` log line at the right level (DEBUG/INFO depending on global level).

---

### Task 3: 7-day observation

This is the bulk of the phase. Daily check-ins, no code changes.

- [ ] **Step 1: Set up daily KPI queries**

Run these once per day for 7 days. Save to a running observation log.

> **Filter:** these queries use `ai_model_used IS NOT NULL` to discriminate
> v2.0+ rows from legacy v1.x rows. After Phase 9 lands, prefer the more
> explicit `scanner_version = '2.0.0'` filter — both are equivalent in v2.0
> but `scanner_version` is forward-compatible if v3.0 introduces a different
> model selection.

```bash
ssh shieldoo-gate
cd /opt/shieldoo-gate

# Total scans + verdict distribution (last 24 h)
docker compose exec postgres psql -U shieldoo -d shieldoo -c "
  SELECT verdict, COUNT(*) AS n
    FROM version_diff_results
   WHERE diff_at > now() - INTERVAL '24 hours'
     AND ai_model_used IS NOT NULL  -- v2.0 rows only
   GROUP BY verdict ORDER BY n DESC;"

# AI verdict (raw, before downgrade) distribution
docker compose exec postgres psql -U shieldoo -d shieldoo -c "
  SELECT ai_verdict, COUNT(*) AS n, AVG(ai_confidence) AS mean_conf
    FROM version_diff_results
   WHERE diff_at > now() - INTERVAL '24 hours'
     AND ai_model_used IS NOT NULL
   GROUP BY ai_verdict ORDER BY n DESC;"

# Cost per day (token sum × price)
docker compose exec postgres psql -U shieldoo -d shieldoo -c "
  SELECT DATE(diff_at) AS day,
         SUM(ai_tokens_used) AS tokens,
         ROUND(SUM(ai_tokens_used) * 0.0000003 :: numeric, 4) AS approx_cost_usd
    FROM version_diff_results
   WHERE diff_at > now() - INTERVAL '7 days'
     AND ai_model_used IS NOT NULL
   GROUP BY day ORDER BY day;"

# Fail-open events from logs (count of 'fail-open' lines in the last 24 h)
docker compose logs --since=24h gate | grep -c "version-diff: fail-open" || true

# SUSPICIOUS verdicts to inspect manually
docker compose exec postgres psql -U shieldoo -d shieldoo -c "
  SELECT a.name, a.version, vdr.previous_version, vdr.ai_confidence, vdr.ai_explanation
    FROM version_diff_results vdr JOIN artifacts a ON a.id = vdr.artifact_id
   WHERE vdr.diff_at > now() - INTERVAL '24 hours'
     AND vdr.ai_verdict = 'SUSPICIOUS'
     AND vdr.ai_model_used IS NOT NULL
   ORDER BY vdr.diff_at DESC LIMIT 20;"
```

- [ ] **Step 2: Spot-check 3–5 SUSPICIOUS verdicts daily**

For each, confirm whether the AI explanation is reasonable. If you see a clear FP (mainstream package flagged for trivial change), record it.

- [ ] **Step 3: Track latency**

If Prometheus is wired up at the gate (per [docs/index.md](../../docs/index.md)), look at `version_diff_duration_seconds{quantile="0.99"}`. If not, sample log lines:

```bash
docker compose logs --since=24h gate | grep "version-diff" | grep -oE "Duration:[0-9]+ms" | sort -nr | head -5
```

Expected p99 < 30 s.

- [ ] **Step 4: Track cost**

Daily cost (from query above) should average < $0.50. If a day exceeds $1, investigate (large package burst, prompt regression, etc.).

- [ ] **Step 5: Track fail-open ratio**

```bash
# Compute fail-open ratio over the 7-day window
ssh shieldoo-gate "cd /opt/shieldoo-gate && docker compose logs --since=168h gate" \
  | awk '/version-diff/ {n++} /version-diff: fail-open/ {f++} END {printf \"fail_open=%d total=%d ratio=%.2f%%\n\", f, n, 100.0*f/n}'
```

Expected: < 1 %.

---

### Task 4: 7-day acceptance review

After the 7-day window:

- [ ] **Step 1: Compute the acceptance metrics**

| Metric | Source | Target |
|--------|--------|--------|
| FP rate on legit packages | Manual review of SUSPICIOUS list | < 5 % |
| Daily cost mean | Cost query | < $0.50/day |
| p99 latency | Prometheus or log sample | < 30 s |
| Fail-open ratio | Log grep | < 1 % |
| Bridge timeout count | Log grep `context deadline exceeded` | < 0.5 % of total scans |

- [ ] **Step 2: Document the result**

Write a short Markdown report at `docs/plans/2026-04-30-version-diff-ai-rebuild-shadow-results.md` summarizing the 7-day observation. The format:

```markdown
# Shadow rollout 7-day results — version-diff v2.0

Period: 2026-MM-DD to 2026-MM-DD
Scans: NNN
LLM calls (after cache hits): NNN
Cost: $NN.NN total / $NN.NN/day mean

| Metric | Target | Observed | Pass? |
|--------|--------|----------|-------|
| FP rate | < 5 % | NN % | ✓/✗ |
| Daily cost mean | < $0.50 | $NN | ✓/✗ |
| p99 latency | < 30 s | NN s | ✓/✗ |
| Fail-open ratio | < 1 % | NN % | ✓/✗ |
| Bridge timeout rate | < 0.5 % | NN % | ✓/✗ |

Notable SUSPICIOUS verdicts inspected: ...

Recommendation: PROCEED to Phase 8b / ITERATE / ROLLBACK
```

- [ ] **Step 3: Commit the report**

```bash
git add docs/plans/2026-04-30-version-diff-ai-rebuild-shadow-results.md
git commit -m "docs(version-diff): shadow rollout 7-day acceptance results"
```

---

## Verification — phase-end

- 7 days have elapsed since the migration was applied.
- Acceptance metrics meet (or exceed) all targets.
- The shadow-results report is written and committed.

## Decision

If acceptance passes → proceed to Phase 8b (`mode: "active"` flip).

If FP rate is the only failure but is close (e.g. 6–8 %) → iterate the prompt, redeploy in `mode: "shadow"`, observe for an additional 3 days. Do not flip to active until FP < 5 %.

If multiple metrics fail → consider rollback:

```bash
# Revert config
ssh shieldoo-gate "cd /opt/shieldoo-gate && sed -i 's/enabled: true/enabled: false/' config.yaml"
docker compose up -d --force-recreate

# (Migration 024 stays — it's compatible with the disabled scanner. Database
# rollback is not needed unless something is corrupt.)
```

## Risks during this phase

- **Cost surprise.** A burst of large packages (~100 MB sdists) could spike token usage. The 50 MB `max_artifact_size_mb` cap blocks that path. Watch the daily cost; if it exceeds $1 on a single day, drill in.
- **Cache eviction during shadow window.** If the gate's cache evicts a `previous_artifact`, subsequent `version-diff` scans for that pair will fail-open (CLEAN). This is benign — we just lose one observation. Not actionable.
- **Bridge restart kills in-flight scans.** A `docker compose restart bridge` during a scan causes a fail-open. Acceptable; the engine moves on.
- **Adversarial packages during observation.** While in shadow mode, a malicious package could slip through. The OTHER scanners (ai-scanner, guarddog, osv, reputation) still apply policy, so this is not a regression — just no marginal benefit from version-diff during this window.
