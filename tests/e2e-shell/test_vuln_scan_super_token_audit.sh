#!/usr/bin/env bash
# test_vuln_scan_super_token_audit.sh — CLAUDE.md security invariant 6:
# the global super-token MUST emit super_token_used on both Bearer and Basic paths.

test_vuln_scan_super_token_audit() {
    log_section "Vuln-scan: super_token_used audit emission (Bearer + Basic)"

    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" != "true" ] || [ -z "${SGW_PROXY_TOKEN:-}" ]; then
        log_skip "Vuln-scan super_token_audit: requires SGW_PROXY_AUTH_ENABLED + SGW_PROXY_TOKEN"
        return
    fi

    # Helper: count super_token_used rows. The admin audit endpoint returns
    # paginatedResponse{data, page, per_page, total}, so read .total directly —
    # cleanest, doesn't depend on per_page. per_page=1 keeps the response tiny.
    _count_audit() {
        local resp
        resp=$(admin_curl -sf "${E2E_ADMIN_URL}/api/v1/audit?event_type=super_token_used&per_page=1" \
            -H "Authorization: Bearer ${SGW_PROXY_TOKEN}" 2>/dev/null) || { echo 0; return; }
        echo "$resp" | jq -r '.total // 0'
    }

    local before_bearer
    before_bearer=$(_count_audit)

    # 1. Bearer path: hit any admin endpoint with the super-token.
    admin_curl -sf -o /dev/null \
        "${E2E_ADMIN_URL}/api/v1/vulnerabilities/summary" \
        -H "Authorization: Bearer ${SGW_PROXY_TOKEN}"
    sleep 1
    local after_bearer
    after_bearer=$(_count_audit)
    if [ "$after_bearer" -gt "$before_bearer" ]; then
        log_pass "Vuln-scan super_token_audit: Bearer path emitted super_token_used (${before_bearer} -> ${after_bearer})"
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
        log_pass "Vuln-scan super_token_audit: Basic path emitted super_token_used (${after_bearer} -> ${after_basic})"
    else
        log_fail "Vuln-scan super_token_audit: Basic path did NOT emit super_token_used (count stayed ${after_bearer})"
    fi
}
