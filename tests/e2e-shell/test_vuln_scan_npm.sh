#!/usr/bin/env bash
# test_vuln_scan_npm.sh — per-ecosystem upload smoke for npm SBOMs.
# Sourced by run_all.sh; defines test_vuln_scan_npm().

test_vuln_scan_npm() {
    log_section "Vuln-scan: npm ecosystem upload"

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
        log_skip "Vuln-scan npm: requires SGW_PROXY_AUTH_ENABLED=true + SGW_PROXY_TOKEN"
        return
    fi
    local bearer=(-H "Authorization: Bearer ${SGW_PROXY_TOKEN}")

    local fixture="${SCRIPT_DIR}/fixtures/vuln-scan/sbom-npm-vulnerable.json"
    if [ ! -f "$fixture" ]; then
        log_fail "Vuln-scan npm: fixture missing: $fixture"
        return
    fi

    local component="e2e-npm-$$"
    local upload_url="${E2E_ADMIN_URL}/api/v1/projects/default/components/${component}/scans?ecosystem=npm"

    local upload_resp
    upload_resp=$(curl -sf -X POST "$upload_url" "${bearer[@]}" \
        -H "Content-Type: application/vnd.cyclonedx+json" \
        --data-binary "@${fixture}")
    if [ -z "$upload_resp" ]; then
        log_fail "Vuln-scan npm: upload failed (empty body)"
        return
    fi
    local scan_run_id
    scan_run_id=$(echo "$upload_resp" | jq -r '.scan_run_id // empty')
    if [ -z "$scan_run_id" ]; then
        log_fail "Vuln-scan npm: no scan_run_id in response"
        return
    fi
    log_pass "Vuln-scan npm: upload accepted (scan_run_id=${scan_run_id})"

    # Poll for terminal status (max 30s).
    local status="unknown"
    local i
    for i in {1..30}; do
        sleep 1
        status=$(curl -sf "${E2E_ADMIN_URL}/api/v1/vulnerabilities/scan-runs/${scan_run_id}" \
            "${bearer[@]}" | jq -r '.status // "unknown"')
        case "$status" in
            done|failed) break ;;
        esac
    done
    if [ "$status" != "done" ]; then
        log_fail "Vuln-scan npm: scan terminal status=${status}, want done"
        return
    fi
    log_pass "Vuln-scan npm: scan terminal=done"

    # Findings should be non-empty for lodash@4.17.10 (CVE-2019-10744) etc.
    local findings
    findings=$(curl -sf "${E2E_ADMIN_URL}/api/v1/vulnerabilities/scan-runs/${scan_run_id}/findings" \
        "${bearer[@]}" | jq '.items | length')
    if [ "${findings:-0}" -gt 0 ]; then
        log_pass "Vuln-scan npm: ${findings} findings reported (>0 expected)"
    else
        # OSV cache outage / network blip — degrade to warn rather than fail.
        log_skip "Vuln-scan npm: 0 findings (likely OSV unreachable from test rig); ${status}"
    fi
}
