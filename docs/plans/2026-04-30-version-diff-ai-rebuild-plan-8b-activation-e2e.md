# Version-Diff AI Rebuild — Phase 8b: Activation + E2E

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add E2E shell tests covering the four critical scenarios (clean upgrade, synthetic-suspicious, idempotency, no `tests/` bypass), run them, then flip production from `mode: shadow` to `mode: active`.

**Architecture:** New directory `tests/e2e-shell/version-diff-ai/` with four shell scripts. Each script follows the existing E2E pattern: source [tests/e2e-shell/helpers.sh](../../tests/e2e-shell/helpers.sh), use the exported `E2E_PYPI_URL` / `E2E_NPM_URL` etc. with direct `curl` and `${E2E_CURL_AUTH[@]}`. There is **no** `pip_install_via_gate` helper in the harness — interaction is HTTP-direct against the gate's PyPI proxy port. We reuse the same approach for version-diff scenarios.

**Tech Stack:** Bash + the existing E2E shell harness. The container stack is the same one used by other E2E tests (`docker-compose.e2e.yml`).

**Index:** [`plan-index.md`](./2026-04-30-version-diff-ai-rebuild-plan-index.md)

---

## Context for executor

The E2E harness spins up the full stack (gate + scanner-bridge + Postgres + cache) and runs assertion shell scripts. Existing tests under [tests/e2e-shell/](../../tests/e2e-shell/) (e.g. `test_npm.sh`, `test_pypi.sh`) follow the pattern:

1. Source `helpers.sh` for `E2E_PYPI_URL` / `E2E_NPM_URL` / `E2E_CURL_AUTH` / log helpers.
2. Use `curl "${E2E_CURL_AUTH[@]}" -fsSL "${E2E_PYPI_URL}/simple/<pkg>/"` to drive the proxy.
3. Use `assert_eq` / `assert_http_status` (defined in `helpers.sh`) to record pass/fail.

The version-diff scanner needs a **previous version** in the cache. We exercise this by fetching two versions of a package in sequence — the second fetch is what triggers `version-diff`.

For tests requiring synthetic packages (a malicious-setup wheel that doesn't exist on real PyPI), we POST the synthetic blobs into the gate via the admin API or seed the database directly. This is more involved than fetching real packages, so we keep the synthetic test scope minimal: just one PyPI synthetic wheel.

> **Scope decision:** the four shell tests below cover the highest-value
> scenarios. `test_npm_clean.sh`, the `test_secret_in_package_redacted.sh`
> from the analysis, and other "nice-to-have" coverage are deferred to a
> follow-up. Phase 7.5 already provides FN coverage via the synthetic
> known-malicious set, so E2E test depth here is supplementary.

---

### Task 1: Reusable helpers

**Files:**
- Modify: [tests/e2e-shell/helpers.sh](../../tests/e2e-shell/helpers.sh)

- [ ] **Step 1: Add `wait_for_version_diff_row` and `query_vdiff` helpers**

Append at the end of `helpers.sh`:

```bash
# ---------------------------------------------------------------------------
# Version-diff scanner helpers
# ---------------------------------------------------------------------------

# wait_for_version_diff_row <artifact_id_pattern> <timeout_sec>
# Polls Postgres until a row exists in version_diff_results with artifact_id
# LIKE the pattern. Returns 0 when found, 1 on timeout.
wait_for_version_diff_row() {
    local pattern="$1"
    local timeout="${2:-90}"
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        local count
        count=$(docker compose -f tests/e2e-shell/docker-compose.e2e.yml exec -T postgres \
            psql -U shieldoo -d shieldoo -tAc \
            "SELECT COUNT(*) FROM version_diff_results WHERE artifact_id LIKE '$pattern'" 2>/dev/null || echo 0)
        if [ "${count:-0}" -ge 1 ]; then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    echo "wait_for_version_diff_row: timed out after ${timeout}s for $pattern" >&2
    return 1
}

# query_vdiff_field <artifact_id_pattern> <column>
# Returns the named column value of the most-recent matching row.
query_vdiff_field() {
    local pattern="$1"
    local column="$2"
    docker compose -f tests/e2e-shell/docker-compose.e2e.yml exec -T postgres \
        psql -U shieldoo -d shieldoo -tAc \
        "SELECT $column FROM version_diff_results WHERE artifact_id LIKE '$pattern' ORDER BY diff_at DESC LIMIT 1" \
        2>/dev/null | tr -d '[:space:]'
}

# bridge_log_count <substring>
# Returns the count of bridge log lines containing the substring.
bridge_log_count() {
    docker compose -f tests/e2e-shell/docker-compose.e2e.yml logs --since=10m bridge 2>/dev/null \
        | grep -c "$1" || true
}
```

(No commit yet — combined with the test scripts.)

---

### Task 2: `test_pypi_clean.sh`

**Files:**
- Create: `tests/e2e-shell/version-diff-ai/test_pypi_clean.sh`

- [ ] **Step 1: Write the test**

```bash
#!/usr/bin/env bash
# Test: legitimate version upgrade produces a CLEAN ai_verdict.
# Fetches two consecutive `six` versions (small, stable, low-cost) through the
# gate; expects the second fetch to produce a row in version_diff_results
# with ai_verdict=CLEAN.

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/../helpers.sh"

test_version_diff_pypi_clean() {
    log_section "Version-Diff: PyPI clean upgrade"

    # `six` is intentionally tiny + stable. Use two real released versions.
    local old_ver="1.16.0"
    local new_ver="1.17.0"

    # 1. Fetch the OLD wheel via the gate's PyPI proxy (populates cache).
    local old_url
    old_url=$(curl -sf "${E2E_CURL_AUTH[@]}" "${E2E_PYPI_URL}/simple/six/" \
        | grep -oE 'href="[^"]+six-1\.16\.0[^"]*\.whl"' | head -1 \
        | sed 's/href="//; s/"$//')
    [ -n "$old_url" ] || { log_fail "could not find six $old_ver wheel"; return; }
    curl -fsSL "${E2E_CURL_AUTH[@]}" "$old_url" -o /tmp/six-old.whl >/dev/null

    # 2. Fetch the NEW wheel.
    local new_url
    new_url=$(curl -sf "${E2E_CURL_AUTH[@]}" "${E2E_PYPI_URL}/simple/six/" \
        | grep -oE 'href="[^"]+six-1\.17\.0[^"]*\.whl"' | head -1 \
        | sed 's/href="//; s/"$//')
    [ -n "$new_url" ] || { log_fail "could not find six $new_ver wheel"; return; }
    curl -fsSL "${E2E_CURL_AUTH[@]}" "$new_url" -o /tmp/six-new.whl >/dev/null

    # 3. Wait for the version_diff_results row.
    if ! wait_for_version_diff_row "pypi:six:%${new_ver}%" 90; then
        log_fail "timed out waiting for version_diff_results row for six $new_ver"
        return
    fi

    # 4. Assert ai_verdict=CLEAN.
    local verdict
    verdict=$(query_vdiff_field "pypi:six:%${new_ver}%" "ai_verdict")
    assert_eq "Version-Diff: six $old_ver → $new_ver produces ai_verdict=CLEAN" "CLEAN" "$verdict"
}

test_version_diff_pypi_clean
```

> Adjust the artifact_id pattern (`pypi:six:%${new_ver}%`) to whatever
> format the PyPI adapter actually uses — verify with
> `psql ... -c "SELECT id FROM artifacts WHERE name='six' LIMIT 5"`. The
> exact format is internal-implementation; the LIKE pattern absorbs minor
> changes such as canonicalized casing or a trailing build identifier.

(No commit yet.)

---

### Task 3: `test_pypi_synthetic_suspicious.sh` (DEFERRED)

This test requires seeding synthetic packages into the gate's cache + DB,
which is non-trivial and would need its own helper-development sub-plan.
Phase 7.5's known-malicious set already covers FN signal via direct bridge
calls, so this E2E variant is supplementary.

**Defer to a follow-up** — track as a separate task once the rest of the
phase ships and we have shadow-mode FN data showing whether E2E synthetic
coverage is actually needed.

---

### Task 4: `test_idempotency.sh`

**Files:**
- Create: `tests/e2e-shell/version-diff-ai/test_idempotency.sh`

- [ ] **Step 1: Write the test**

```bash
#!/usr/bin/env bash
# Test: a repeat fetch of the same (new, prev) pair must NOT call the LLM
# again — the idempotency cache hit path skips the bridge.

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/../helpers.sh"

test_version_diff_idempotency() {
    log_section "Version-Diff: idempotency cache hit"

    # Pre-condition: test_version_diff_pypi_clean has already populated the
    # version_diff_results row for six 1.17.0. If running standalone, do that
    # warm-up first.
    if ! wait_for_version_diff_row "pypi:six:%1.17.0%" 5; then
        log_skip "Version-Diff: idempotency requires test_pypi_clean to have run"
        return
    fi

    # Snapshot LLM-call log count.
    local before
    before=$(bridge_log_count "diff_scanner: calling LLM")

    # Re-fetch the same NEW wheel — the gate has it cached, the version-diff
    # scanner sees an existing row in version_diff_results and skips the LLM.
    local new_url
    new_url=$(curl -sf "${E2E_CURL_AUTH[@]}" "${E2E_PYPI_URL}/simple/six/" \
        | grep -oE 'href="[^"]+six-1\.17\.0[^"]*\.whl"' | head -1 \
        | sed 's/href="//; s/"$//')
    curl -fsSL "${E2E_CURL_AUTH[@]}" "$new_url" -o /tmp/six-repeat.whl >/dev/null
    sleep 3   # let the scan dispatch settle

    local after
    after=$(bridge_log_count "diff_scanner: calling LLM")

    if [ "$after" -gt "$before" ]; then
        log_fail "Version-Diff: idempotency cache hit failed — LLM called again (before=$before after=$after)"
    else
        log_pass "Version-Diff: idempotency cache hit, LLM not re-invoked (count=$after)"
    fi
}

test_version_diff_idempotency
```

> The test is conservative — it tolerates the case where another scan
> happens to fire mid-window and bumps the count. To make it stricter, run
> the suite serially against a freshly started stack.

(No commit yet.)

---

### Task 5: `test_tests_dir_no_bypass.sh` (DEFERRED)

Same dependency on synthetic-package seeding as Task 3. The strict empty-diff
invariant is verified at the bridge unit-test level by Phase 5
`test_only_tests_changed_calls_llm`, so the E2E variant is supplementary.

**Defer** — track as a follow-up.

---

### Task 6: Wire the new tests into the runner

**Files:**
- Modify: [tests/e2e-shell/run_all.sh](../../tests/e2e-shell/run_all.sh) (or whatever orchestrator runs the suite)

- [ ] **Step 1: Add the new tests to the runner**

Inspect `run.sh` and `run_all.sh`:

```bash
grep -nE "test_pypi|source.*test_" tests/e2e-shell/run.sh tests/e2e-shell/run_all.sh 2>/dev/null
```

Existing tests are sourced (not exec'd) into `run.sh` so their functions
register. Add a sibling `tests/e2e-shell/test_version_diff.sh` that sources
the two scripts in `version-diff-ai/` and dispatches their function calls,
or — simpler — put both functions directly in `tests/e2e-shell/test_version_diff.sh`
and skip the subdirectory. Pick whichever matches the rest of the suite.

```bash
# tests/e2e-shell/test_version_diff.sh
#!/usr/bin/env bash
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/version-diff-ai/test_pypi_clean.sh"
source "$SCRIPT_DIR/version-diff-ai/test_idempotency.sh"

test_version_diff() {
    test_version_diff_pypi_clean
    test_version_diff_idempotency
}
```

Then in `run.sh` (or `run_all.sh`), wherever other test functions are
invoked, add `test_version_diff` after the basic adapter tests.

- [ ] **Step 2: Make the scripts executable**

```bash
chmod +x tests/e2e-shell/version-diff-ai/*.sh tests/e2e-shell/test_version_diff.sh
```

- [ ] **Step 3: Run the suite**

```bash
make test-e2e-containerized
```

Expected: the two new test functions pass alongside the existing suite.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e-shell/version-diff-ai/ \
        tests/e2e-shell/test_version_diff.sh \
        tests/e2e-shell/helpers.sh \
        tests/e2e-shell/run.sh tests/e2e-shell/run_all.sh 2>/dev/null
git commit -m "test(e2e): version-diff-ai shell tests (PyPI clean upgrade, idempotency cache hit)"
```

---

### Task 7: Production activation

After the four E2E tests pass on CI:

- [ ] **Step 1: SSH to production and flip the mode**

```bash
ssh shieldoo-gate
cd /opt/shieldoo-gate
git pull
sed -i 's/mode: "shadow"/mode: "active"/' config.yaml
docker compose up -d --force-recreate gate
```

- [ ] **Step 2: Watch the next 24 hours**

```bash
# Verdict distribution (live)
watch -n 60 "docker compose exec -T postgres psql -U shieldoo -d shieldoo -tAc \
    \"SELECT verdict, ai_verdict, COUNT(*) FROM version_diff_results \
       WHERE diff_at > now() - INTERVAL '1 hour' AND ai_model_used IS NOT NULL \
       GROUP BY 1,2 ORDER BY 3 DESC\""

# Watch for SUSPICIOUS verdicts that actually reach policy now
docker compose logs -f gate | grep -E "version-diff.*SUSPICIOUS|policy.*block"
```

- [ ] **Step 3: If anything looks wrong, revert to shadow**

```bash
ssh shieldoo-gate "cd /opt/shieldoo-gate && sed -i 's/mode: \"active\"/mode: \"shadow\"/' config.yaml && docker compose up -d --force-recreate gate"
```

The DB rows continue to flow regardless; only `ScanResult.Verdict` is suppressed.

---

## Verification — phase-end

```bash
# E2E green
make test-e2e-containerized

# Production active mode confirmed
ssh shieldoo-gate "grep -E 'mode:.*active' /opt/shieldoo-gate/config.yaml"

# Live verdict distribution looks healthy (no FP storm)
ssh shieldoo-gate "cd /opt/shieldoo-gate && docker compose exec -T postgres psql -U shieldoo -d shieldoo -c \"SELECT verdict, COUNT(*) FROM version_diff_results WHERE diff_at > now() - INTERVAL '1 hour' AND ai_model_used IS NOT NULL GROUP BY verdict\""
```

## Risks during this phase

- **E2E helper drift.** The exact name of `pip_install_via_gate`, `seed_pypi_artifact`, `proxy_pypi_artifact` may differ in the current harness. The executor must read the existing helpers and adapt.
- **Synthetic-suspicious test prompt-sensitivity.** If gpt-5.4-mini occasionally returns CLEAN for the synthetic, the test flakes. Mitigation: the synthetic exfiltrates `~/.aws/credentials` over HTTPS — strong signal. If still flaky after 3 runs, sharpen the synthetic with multiple bad signals (subprocess + IMDS + base64+exec).
- **Policy effect on production traffic.** Once `mode: active`, a SUSPICIOUS verdict adds findings that the policy engine evaluates. Combined with the rest of the policy stack, this may cause new BLOCK decisions. Operators should be on standby for the first 24 h after activation.
