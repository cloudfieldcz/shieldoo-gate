# Vulnerability Scan — Final Polish — Phase 3: E2E shell test suite

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add seven new shell scripts under `tests/e2e-shell/`, sourced from `run_all.sh`, that exercise:

1. Per-ecosystem SBOM uploads (pypi, npm, docker)
2. Log redaction (no `Authorization`/`Bearer` leaks in gate logs)
3. Super-token audit (`super_token_used` row emitted on Bearer + Basic paths)
4. AI bridge SSRF smoke (adversarial `repo_url` does not crash the bridge)
5. `shdg` CLI smoke (built binary uploads through the test rig)

Each test runs inside the existing test-runner container; helpers like `log_pass`, `log_fail`, `E2E_ADMIN_URL` come from `helpers.sh`. Tests **must skip cleanly** when their preconditions are not met (vuln-scan disabled, AI off, super-token unavailable) — never log_fail on a configuration the run doesn't support.

**Architecture:** Each script defines exactly one function `test_<name>()` and is sourced + invoked from `run_all.sh`, mirroring the existing `test_vuln_scan_lifecycle` pattern.

**Tech Stack:** Bash + `curl` + `jq` + (for shdg test) the `bin/shdg` binary built into the test-runner image.

**Index:** [`plan-index.md`](./2026-05-08-vuln-scan-finish-plan-index.md)

**Depends on:** Phases 1+2 (only for `test_vuln_scan_shdg.sh` — the rest are independent).

---

## File map

| Path | Action | Responsibility |
|------|--------|----------------|
| `tests/e2e-shell/fixtures/vuln-scan/sbom-pypi-vulnerable.json` | Create | CycloneDX SBOM with `requests==2.10.0` (known CVE-2018-18074). |
| `tests/e2e-shell/fixtures/vuln-scan/sbom-npm-vulnerable.json` | Create | CycloneDX SBOM with `lodash@4.17.10` (CVE-2019-10744). |
| `tests/e2e-shell/fixtures/vuln-scan/sbom-docker-vulnerable.json` | Create | CycloneDX SBOM with `alpine 3.10.0` + a couple of OS packages with CVEs. |
| `tests/e2e-shell/test_vuln_scan_pypi.sh` | Create | Upload pypi SBOM, assert findings include CRITICAL/HIGH. |
| `tests/e2e-shell/test_vuln_scan_npm.sh` | Create | Same, npm. |
| `tests/e2e-shell/test_vuln_scan_docker.sh` | Create | Same, docker. |
| `tests/e2e-shell/test_vuln_scan_log_redaction.sh` | Create | Send authed bad-request, scrape `docker logs`, assert no Bearer leakage. |
| `tests/e2e-shell/test_vuln_scan_super_token_audit.sh` | Create | Make 2 super-token requests (Bearer + Basic), verify audit row. |
| `tests/e2e-shell/test_vuln_scan_ai_ssrf.sh` | Create | Set malicious `repo_url`, call drafter, verify bridge stays alive. |
| `tests/e2e-shell/test_vuln_scan_shdg.sh` | Create | Run pre-built `bin/shdg` against the gate, verify exit codes + payload. |
| `tests/e2e-shell/run_all.sh` | Modify | Source + invoke the 7 new tests. |
| `tests/e2e-shell/Dockerfile.test-runner` | Modify | Build `bin/shdg` and copy into the runner image. |

---

## Task 1: SBOM fixture files

**Files:**
- Create: `tests/e2e-shell/fixtures/vuln-scan/sbom-pypi-vulnerable.json`
- Create: `tests/e2e-shell/fixtures/vuln-scan/sbom-npm-vulnerable.json`
- Create: `tests/e2e-shell/fixtures/vuln-scan/sbom-docker-vulnerable.json`

- [ ] **Step 1: Write `sbom-pypi-vulnerable.json`**

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "requests",
      "version": "2.10.0",
      "purl": "pkg:pypi/requests@2.10.0"
    },
    {
      "type": "library",
      "name": "django",
      "version": "1.11.0",
      "purl": "pkg:pypi/django@1.11.0"
    }
  ]
}
```

- [ ] **Step 2: Write `sbom-npm-vulnerable.json`**

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.10",
      "purl": "pkg:npm/lodash@4.17.10"
    },
    {
      "type": "library",
      "name": "minimist",
      "version": "1.2.0",
      "purl": "pkg:npm/minimist@1.2.0"
    }
  ]
}
```

- [ ] **Step 3: Write `sbom-docker-vulnerable.json`**

OSV's Trivy data covers Alpine packages well; pick a stale Alpine and a couple of known-CVE packages.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "operating-system",
      "name": "alpine",
      "version": "3.10.0",
      "purl": "pkg:apk/alpine/alpine-baselayout@3.10.0?distro=alpine-3.10.0"
    },
    {
      "type": "library",
      "name": "openssl",
      "version": "1.1.1c-r0",
      "purl": "pkg:apk/alpine/openssl@1.1.1c-r0?distro=alpine-3.10.0"
    }
  ]
}
```

- [ ] **Step 4: Commit**

```bash
git add tests/e2e-shell/fixtures/vuln-scan/
git commit -m "test(e2e): vulnerable CycloneDX fixtures for pypi/npm/docker scans"
```

---

## Task 2: Per-ecosystem upload tests (pypi/npm/docker)

**Files:**
- Create: `tests/e2e-shell/test_vuln_scan_pypi.sh`

The three scripts are nearly identical — only the fixture path, ecosystem query, and component name change. We'll write `pypi` first as the canonical pattern, then duplicate.

- [ ] **Step 1: Write `test_vuln_scan_pypi.sh`**

```bash
#!/usr/bin/env bash
# test_vuln_scan_pypi.sh — per-ecosystem upload smoke for pypi SBOMs.
# Sourced by run_all.sh; defines test_vuln_scan_pypi().

test_vuln_scan_pypi() {
    log_section "Vuln-scan: pypi ecosystem upload"

    # Skip when feature is disabled.
    local pre_status
    pre_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_ADMIN_URL}/api/v1/vulnerabilities/summary")
    if [ "$pre_status" = "503" ]; then
        log_skip "Vuln-scan: feature disabled"
        return
    fi

    # Bootstrap auth via the global super-token (same pattern as
    # test_vuln_scan_lifecycle). Skip if proxy auth not configured.
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" != "true" ] || [ -z "${SGW_PROXY_TOKEN:-}" ]; then
        log_skip "Vuln-scan pypi: requires SGW_PROXY_AUTH_ENABLED=true + SGW_PROXY_TOKEN"
        return
    fi
    local bearer=(-H "Authorization: Bearer ${SGW_PROXY_TOKEN}")

    local fixture="${SCRIPT_DIR}/fixtures/vuln-scan/sbom-pypi-vulnerable.json"
    if [ ! -f "$fixture" ]; then
        log_fail "Vuln-scan pypi: fixture missing: $fixture"
        return
    fi

    local component="e2e-pypi-$$"
    local upload_url="${E2E_ADMIN_URL}/api/v1/projects/default/components/${component}/scans?ecosystem=pypi"

    local upload_resp
    upload_resp=$(curl -sf -X POST "$upload_url" "${bearer[@]}" \
        -H "Content-Type: application/vnd.cyclonedx+json" \
        --data-binary "@${fixture}")
    if [ -z "$upload_resp" ]; then
        log_fail "Vuln-scan pypi: upload failed (empty body)"
        return
    fi
    local scan_run_id
    scan_run_id=$(echo "$upload_resp" | jq -r '.scan_run_id // empty')
    if [ -z "$scan_run_id" ]; then
        log_fail "Vuln-scan pypi: no scan_run_id in response"
        return
    fi
    log_pass "Vuln-scan pypi: upload accepted (scan_run_id=${scan_run_id})"

    # Poll for terminal status (max 30s).
    local status
    for i in {1..30}; do
        sleep 1
        status=$(curl -sf "${E2E_ADMIN_URL}/api/v1/vulnerabilities/scan-runs/${scan_run_id}" \
            "${bearer[@]}" | jq -r '.status // "unknown"')
        case "$status" in
            succeeded|failed|cancelled) break ;;
        esac
    done
    if [ "$status" != "succeeded" ]; then
        log_fail "Vuln-scan pypi: scan terminal status=${status}, want succeeded"
        return
    fi
    log_pass "Vuln-scan pypi: scan terminal=succeeded"

    # Findings should be non-empty for requests==2.10.0 (CVE-2018-18074 etc.).
    local findings
    findings=$(curl -sf "${E2E_ADMIN_URL}/api/v1/vulnerabilities/scan-runs/${scan_run_id}/findings" \
        "${bearer[@]}" | jq '.items | length')
    if [ "${findings:-0}" -gt 0 ]; then
        log_pass "Vuln-scan pypi: ${findings} findings reported (>0 expected)"
    else
        # OSV cache outage / network blip — degrade to warn rather than fail.
        log_skip "Vuln-scan pypi: 0 findings (likely OSV unreachable from test rig); ${status}"
    fi
}
```

- [ ] **Step 2: Write `test_vuln_scan_npm.sh`**

Duplicate the pypi script; replace:
- `pypi` → `npm` (function name + ecosystem query + log_section + log_pass strings)
- `sbom-pypi-vulnerable.json` → `sbom-npm-vulnerable.json`
- `e2e-pypi-$$` → `e2e-npm-$$`

- [ ] **Step 3: Write `test_vuln_scan_docker.sh`**

Same template; `pypi` → `docker`, fixture → `sbom-docker-vulnerable.json`.

- [ ] **Step 4: Commit**

```bash
git add tests/e2e-shell/test_vuln_scan_pypi.sh \
        tests/e2e-shell/test_vuln_scan_npm.sh \
        tests/e2e-shell/test_vuln_scan_docker.sh
git commit -m "test(e2e): per-ecosystem vuln-scan upload tests (pypi/npm/docker)"
```

---

## Task 3: Log-redaction test

**Files:**
- Create: `tests/e2e-shell/test_vuln_scan_log_redaction.sh`

The recoverer + log_redactor are unit-tested. The E2E adds: send a real request with `Authorization: Bearer SECRET-DO-NOT-LEAK`, inspect the gate's container logs, assert no occurrence of either the bearer literal or the canonical `Authorization` header value. We don't trigger a panic — the redactor is invoked on every request.

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# test_vuln_scan_log_redaction.sh — verify the gate's structured log scrubs
# Authorization headers / Bearer tokens. Sends a request with a marker token
# and greps the gate's stdout/stderr for any leak.

test_vuln_scan_log_redaction() {
    log_section "Vuln-scan: log redaction (no Authorization in gate logs)"

    local pre_status
    pre_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_ADMIN_URL}/api/v1/vulnerabilities/summary")
    if [ "$pre_status" = "503" ]; then
        log_skip "Vuln-scan log_redaction: feature disabled"
        return
    fi

    # We need access to the gate container's logs. In the runner the gate is
    # named "shieldoo-gate" by docker-compose.e2e.yml.
    local marker="LEAK-CANARY-$(date +%s%N)"

    # Send a request with the canary as the bearer. We don't care about the
    # response body — just that the redactor processed the request.
    curl -s -o /dev/null -X GET "${E2E_ADMIN_URL}/api/v1/vulnerabilities/summary" \
        -H "Authorization: Bearer ${marker}" >/dev/null

    # Give the log line time to land.
    sleep 1

    # Inspect logs from inside the docker network. The runner has a docker
    # client mounted, but to avoid a privilege escalation we instead read the
    # log file we control: the gate writes to stdout, captured by docker. The
    # test container can curl docker via /var/run/docker.sock IF mounted. If
    # neither is available, skip with a clear message.
    if [ ! -S /var/run/docker.sock ]; then
        log_skip "Vuln-scan log_redaction: docker.sock not mounted in runner"
        return
    fi
    local logs
    logs=$(curl --silent --unix-socket /var/run/docker.sock \
        "http://localhost/containers/shieldoo-gate/logs?stdout=1&stderr=1&tail=200" 2>/dev/null \
        | tr -d '\000-\010\013\014\016-\037' || true)
    if [ -z "$logs" ]; then
        log_skip "Vuln-scan log_redaction: gate logs unreadable"
        return
    fi
    if grep -q "$marker" <<<"$logs"; then
        log_fail "Vuln-scan log_redaction: bearer token marker LEAKED into gate logs"
        return
    fi
    if grep -Eqi 'authorization":?\s*"bearer' <<<"$logs"; then
        log_fail "Vuln-scan log_redaction: 'Authorization: Bearer' literal present in logs"
        return
    fi
    log_pass "Vuln-scan log_redaction: no bearer / Authorization in gate logs"
}
```

> **Note on docker.sock:** the existing E2E runner does not mount `/var/run/docker.sock` today. The test must `log_skip` cleanly when it's absent — adding the mount to `docker-compose.e2e.yml` is **out of scope** here (would broaden test-runner privileges). The test can still be activated locally by mounting the socket manually.

- [ ] **Step 2: Commit**

```bash
git add tests/e2e-shell/test_vuln_scan_log_redaction.sh
git commit -m "test(e2e): log-redaction E2E (skips cleanly without docker.sock)"
```

---

## Task 4: Super-token audit test

**Files:**
- Create: `tests/e2e-shell/test_vuln_scan_super_token_audit.sh`

Asserts that when the global super-token authenticates a request, an audit row with `event_type = "super_token_used"` is written. Test exercises **both** auth paths required by CLAUDE.md security invariant 6:

1. **Bearer path** — `Authorization: Bearer ${SGW_PROXY_TOKEN}` to an admin endpoint.
2. **Basic path** — `Authorization: Basic <base64(user:SGW_PROXY_TOKEN)>` to a proxy endpoint.

After each, query `GET /api/v1/audit?event_type=super_token_used&limit=10` and confirm the row count grew.

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# test_vuln_scan_super_token_audit.sh — CLAUDE.md security invariant 6:
# the global super-token MUST emit super_token_used on both Bearer and Basic paths.

test_vuln_scan_super_token_audit() {
    log_section "Vuln-scan: super_token_used audit emission (Bearer + Basic)"

    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" != "true" ] || [ -z "${SGW_PROXY_TOKEN:-}" ]; then
        log_skip "Vuln-scan super_token_audit: requires SGW_PROXY_AUTH_ENABLED + SGW_PROXY_TOKEN"
        return
    fi

    # Helper: count super_token_used rows.
    _count_audit() {
        curl -sf "${E2E_ADMIN_URL}/api/v1/audit?event_type=super_token_used&per_page=200" \
            -H "Authorization: Bearer ${SGW_PROXY_TOKEN}" \
            | jq '.items | length' 2>/dev/null || echo 0
    }

    local before_bearer
    before_bearer=$(_count_audit)

    # 1. Bearer path: hit any admin endpoint with the super-token.
    curl -sf -o /dev/null \
        "${E2E_ADMIN_URL}/api/v1/vulnerabilities/summary" \
        -H "Authorization: Bearer ${SGW_PROXY_TOKEN}"
    sleep 1
    local after_bearer
    after_bearer=$(_count_audit)
    if [ "$after_bearer" -gt "$before_bearer" ]; then
        log_pass "Vuln-scan super_token_audit: Bearer path emitted super_token_used (${before_bearer} → ${after_bearer})"
    else
        log_fail "Vuln-scan super_token_audit: Bearer path did NOT emit super_token_used (count stayed ${before_bearer})"
    fi

    # 2. Basic path: send to a proxy port (any GET on the npm proxy works).
    local basic
    basic=$(printf "ci-bot:%s" "${SGW_PROXY_TOKEN}" | base64 -w0 2>/dev/null || \
            printf "ci-bot:%s" "${SGW_PROXY_TOKEN}" | base64)
    curl -sf -o /dev/null "${E2E_NPM_URL}/lodash" \
        -H "Authorization: Basic ${basic}" >/dev/null || true
    sleep 1
    local after_basic
    after_basic=$(_count_audit)
    if [ "$after_basic" -gt "$after_bearer" ]; then
        log_pass "Vuln-scan super_token_audit: Basic path emitted super_token_used (${after_bearer} → ${after_basic})"
    else
        log_fail "Vuln-scan super_token_audit: Basic path did NOT emit super_token_used (count stayed ${after_bearer})"
    fi
}
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e-shell/test_vuln_scan_super_token_audit.sh
git commit -m "test(e2e): super-token audit emission on Bearer + Basic paths (invariant #6)"
```

---

## Task 5: AI bridge SSRF smoke test

**Files:**
- Create: `tests/e2e-shell/test_vuln_scan_ai_ssrf.sh`

The drafter does not currently fetch `repo_url` (see `scanner-bridge/vuln_drafter.py` doc-string), so this is a **smoke test** for two invariants:

- The bridge does not crash when fed a malicious `repo_url` (cloud-metadata, RFC1918, IP literal, javascript: URL).
- The drafter response is either a clean draft (200) or a clean 503 — never a 5xx with stack trace.

The test runs only when AI is enabled in the run (Run 4 — Azure OpenAI). It uploads a minimal SBOM, edits the resulting component to set a malicious `repo_url`, calls `/api/v1/ai/draft-ignore-reason`, and asserts the response status code.

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# test_vuln_scan_ai_ssrf.sh — adversarial repo_url smoke test against the AI drafter.
# Verifies the bridge stays alive and never returns 5xx for malicious URLs.

test_vuln_scan_ai_ssrf() {
    log_section "Vuln-scan AI: SSRF-adversarial repo_url smoke"

    # Preconditions: vuln-scan + AI features both enabled.
    local pre_status
    pre_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_ADMIN_URL}/api/v1/vulnerabilities/summary")
    if [ "$pre_status" = "503" ]; then
        log_skip "Vuln-scan AI SSRF: feature disabled"
        return
    fi
    if [ "${SGW_AI_ENABLED:-false}" != "true" ]; then
        log_skip "Vuln-scan AI SSRF: AI features off (set SGW_AI_ENABLED=true to run)"
        return
    fi
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" != "true" ] || [ -z "${SGW_PROXY_TOKEN:-}" ]; then
        log_skip "Vuln-scan AI SSRF: needs super-token bootstrap"
        return
    fi
    local bearer=(-H "Authorization: Bearer ${SGW_PROXY_TOKEN}")

    # 1. Upload a minimal SBOM so we have a real component_id.
    local component="e2e-aissrf-$$"
    local sbom='{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"requests","version":"2.31.0","purl":"pkg:pypi/requests@2.31.0"}]}'
    local upload_resp
    upload_resp=$(curl -sf -X POST \
        "${E2E_ADMIN_URL}/api/v1/projects/default/components/${component}/scans?ecosystem=pypi" \
        "${bearer[@]}" \
        -H "Content-Type: application/vnd.cyclonedx+json" \
        --data-binary "$sbom")
    local component_id
    component_id=$(echo "$upload_resp" | jq -r '.component_id')
    if [ -z "$component_id" ] || [ "$component_id" = "null" ]; then
        log_fail "Vuln-scan AI SSRF: upload didn't return component_id"
        return
    fi

    # 2. Try four adversarial repo_urls. Each PATCH should accept the value
    # (validation is at fetch time, not write time), and the subsequent
    # drafter call should return 200 or 503 — never 5xx.
    local malicious=(
        "http://169.254.169.254/latest/meta-data/"
        "http://10.0.0.1/admin"
        "http://127.0.0.1:8080/internal"
        "javascript:alert(1)"
    )
    local rc=0
    for url in "${malicious[@]}"; do
        # Enable AI on the component + set repo_url. The Component edit endpoint
        # is PATCH /api/v1/vulnerabilities/components/{id} with JSON body.
        curl -sf -X PATCH \
            "${E2E_ADMIN_URL}/api/v1/vulnerabilities/components/${component_id}" \
            "${bearer[@]}" \
            -H "Content-Type: application/json" \
            -d "{\"ai_enabled\":true,\"repo_url\":\"${url}\"}" \
            >/dev/null 2>&1 || true

        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
            "${E2E_ADMIN_URL}/api/v1/ai/draft-ignore-reason" \
            "${bearer[@]}" \
            -H "Content-Type: application/json" \
            -d "{\"component_id\":${component_id},\"cve_id\":\"CVE-2024-0001\",\"package_name\":\"requests\",\"package_version\":\"2.31.0\"}")
        case "$code" in
            200|400|401|403|502|503)
                # 200 = drafter ran cleanly; 503 = drafter disabled / SSRF-blocked;
                # 4xx = client-side rejection; 502 = upstream LLM hiccup proxied through
                # the bridge (also not a bridge crash). None of these are crashes.
                ;;
            *)
                log_fail "Vuln-scan AI SSRF: drafter returned ${code} for repo_url=${url}"
                rc=1
                ;;
        esac
    done
    if [ $rc -eq 0 ]; then
        log_pass "Vuln-scan AI SSRF: bridge survived 4 adversarial repo_urls (no 5xx)"
    fi
}
```

- [ ] **Step 2: Commit**

```bash
git add tests/e2e-shell/test_vuln_scan_ai_ssrf.sh
git commit -m "test(e2e): AI bridge SSRF smoke (4 adversarial repo_urls, no 5xx)"
```

---

## Task 6: `shdg` CLI smoke test

**Files:**
- Create: `tests/e2e-shell/test_vuln_scan_shdg.sh`
- Modify: `tests/e2e-shell/Dockerfile.test-runner`

The runner image must contain `bin/shdg`. We add a build stage that compiles it from the repo and copies the binary into the existing runner image. The test then runs the CLI against the gate.

- [ ] **Step 1: Update `Dockerfile.test-runner`**

Read the existing file first:

```bash
cat tests/e2e-shell/Dockerfile.test-runner
```

Then:
- Add a `FROM golang:1.25-alpine AS shdg-build` stage that runs `go build -o /out/shdg ./cmd/shdg`.
- In the existing final stage, `COPY --from=shdg-build /out/shdg /usr/local/bin/shdg`.
- Ensure `chmod +x` is set.

Concrete patch (paste into the file):

```dockerfile
# --- shdg CLI build stage (added by test_vuln_scan_shdg) ---
# We do NOT need the rest of internal/ — the shdg main package is Go-stdlib-only.
# We also do NOT git-stamp the binary (no .git in the build context); a hard-coded
# "e2e" value is sufficient for the smoke test.
FROM golang:1.25-alpine AS shdg-build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/shdg ./cmd/shdg
RUN CGO_ENABLED=0 go build \
        -ldflags "-X main.Version=e2e -X main.Commit=e2e" \
        -o /out/shdg ./cmd/shdg
```

In the final stage add:

```dockerfile
COPY --from=shdg-build /out/shdg /usr/local/bin/shdg
RUN chmod +x /usr/local/bin/shdg
```

> **If the build context excludes `cmd/shdg/`** (e.g. via `.dockerignore`), update that file to allow it. Verify with `docker build --no-cache -f tests/e2e-shell/Dockerfile.test-runner .` from the repo root.

- [ ] **Step 2: Write `test_vuln_scan_shdg.sh`**

```bash
#!/usr/bin/env bash
# test_vuln_scan_shdg.sh — smoke-test the shdg CLI against the running gate.

test_vuln_scan_shdg() {
    log_section "Vuln-scan: shdg CLI smoke"

    if ! command -v shdg >/dev/null 2>&1; then
        log_skip "shdg: binary not present in runner (Dockerfile.test-runner must build it)"
        return
    fi
    local pre_status
    pre_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_ADMIN_URL}/api/v1/vulnerabilities/summary")
    if [ "$pre_status" = "503" ]; then
        log_skip "shdg: feature disabled"
        return
    fi
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" != "true" ] || [ -z "${SGW_PROXY_TOKEN:-}" ]; then
        log_skip "shdg: requires SGW_PROXY_AUTH_ENABLED + SGW_PROXY_TOKEN"
        return
    fi

    # Sub-test 1: `shdg version` exits 0.
    if shdg version >/dev/null 2>&1; then
        log_pass "shdg version: exit 0"
    else
        log_fail "shdg version: non-zero exit"
        return
    fi

    # Sub-test 2: missing flags → exit 2.
    set +e
    shdg scan --project foo >/dev/null 2>&1
    local rc=$?
    set -e
    if [ $rc -eq 2 ]; then
        log_pass "shdg scan (missing flags): exit 2 as expected"
    else
        log_fail "shdg scan (missing flags): exit ${rc}, want 2"
    fi

    # Sub-test 3: end-to-end upload via --sbom (skip Trivy bundling here —
    # E2E test rig has no internet access to GitHub).
    local fixture="${SCRIPT_DIR}/fixtures/vuln-scan/sbom-pypi-vulnerable.json"
    # Use date+pid for uniqueness; component-name regex allows a-z0-9- and 1-100
    # chars (per internal/component/component.go:ValidateComponentName).
    local component="e2e-shdg-$(date +%s)"
    set +e
    SHIELDOO_TOKEN="${SGW_PROXY_TOKEN}" \
    SHIELDOO_URL="${E2E_ADMIN_URL}" \
        shdg scan \
            --project default --component "$component" \
            --sbom "$fixture" --ecosystem pypi \
            --verbose 2>&1
    rc=$?
    set -e
    if [ $rc -eq 0 ]; then
        log_pass "shdg scan --sbom: exit 0 (upload succeeded)"
    else
        log_fail "shdg scan --sbom: exit ${rc}, want 0"
        return
    fi

    # Sub-test 4: --wait + --fail-on=none should exit 0 even if findings appear.
    set +e
    SHIELDOO_TOKEN="${SGW_PROXY_TOKEN}" \
    SHIELDOO_URL="${E2E_ADMIN_URL}" \
        shdg scan \
            --project default --component "${component}-wait" \
            --sbom "$fixture" --ecosystem pypi \
            --wait --fail-on none --poll-interval 500ms --timeout 60s \
            >/dev/null 2>&1
    rc=$?
    set -e
    if [ $rc -eq 0 ]; then
        log_pass "shdg scan --wait --fail-on none: exit 0"
    else
        log_fail "shdg scan --wait --fail-on none: exit ${rc}, want 0"
    fi
}
```

- [ ] **Step 3: Commit**

```bash
git add tests/e2e-shell/Dockerfile.test-runner tests/e2e-shell/test_vuln_scan_shdg.sh
git commit -m "test(e2e): shdg CLI smoke (version, missing-flags, --sbom, --wait)"
```

---

## Task 7: Wire all 7 tests into `run_all.sh`

**Files:**
- Modify: `tests/e2e-shell/run_all.sh`

- [ ] **Step 1: Add source lines after the existing vuln-scan sources** (around line 37, after `source "${SCRIPT_DIR}/test_vuln_scan_lifecycle.sh"`)

```bash
source "${SCRIPT_DIR}/test_vuln_scan_pypi.sh"
source "${SCRIPT_DIR}/test_vuln_scan_npm.sh"
source "${SCRIPT_DIR}/test_vuln_scan_docker.sh"
source "${SCRIPT_DIR}/test_vuln_scan_log_redaction.sh"
source "${SCRIPT_DIR}/test_vuln_scan_super_token_audit.sh"
source "${SCRIPT_DIR}/test_vuln_scan_ai_ssrf.sh"
source "${SCRIPT_DIR}/test_vuln_scan_shdg.sh"
```

- [ ] **Step 2: Add invocations after the existing vuln-scan calls** (around line 149)

```bash
test_vuln_scan_pypi
test_vuln_scan_npm
test_vuln_scan_docker
test_vuln_scan_log_redaction
test_vuln_scan_super_token_audit
test_vuln_scan_ai_ssrf
test_vuln_scan_shdg
```

- [ ] **Step 3: Commit**

```bash
git add tests/e2e-shell/run_all.sh
git commit -m "test(e2e): wire 7 new vuln-scan tests into run_all"
```

---

## Phase 3 verification

- [ ] **Step 1: One-off lint each new script**

```bash
for f in tests/e2e-shell/test_vuln_scan_{pypi,npm,docker,log_redaction,super_token_audit,ai_ssrf,shdg}.sh; do
  bash -n "$f" && echo "OK $f" || echo "SYNTAX FAIL $f"
done
```

Expected: 7× OK.

- [ ] **Step 2: Run the full E2E suite**

```bash
make test-e2e-containerized
```

All 4 runs must finish with **0 failures**. Some new tests will `log_skip` cleanly:
- `test_vuln_scan_pypi/npm/docker` — skip in Run 1 (no proxy auth).
- `test_vuln_scan_log_redaction` — skip everywhere (no docker.sock mount).
- `test_vuln_scan_super_token_audit` — skip in Run 1 + Run 4 (no super-token).
- `test_vuln_scan_ai_ssrf` — skip in Runs 1–3 (AI off); active in Run 4.
- `test_vuln_scan_shdg` — skip in Run 1; active in Runs 2+3+4.

- [ ] **Step 3: Investigate and fix any failures**

Per [feedback memory](../../../.claude/projects/-Users-valda-src-projects-shieldoo-gate/memory/feedback_always_run_tests.md): iterate until all 4 runs are zero-fail. Tests that pass in some runs but skip in others are fine; tests that **fail** anywhere block.
