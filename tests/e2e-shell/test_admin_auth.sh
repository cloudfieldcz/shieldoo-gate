#!/usr/bin/env bash
# test_admin_auth.sh — Admin-API authentication hardening e2e tests (ADR-011).
# Sourced by run_all.sh; defines test_admin_auth(). Do NOT set -e here.
#
# Validates the CRITICAL "fail-closed admin API" fix: when proxy_auth is enabled
# (proxy-auth-only mode, no OIDC), the admin API must REJECT anonymous requests and
# only admit the global super-token presented as `Authorization: Bearer` (scope *).

test_admin_auth() {
    log_section "Admin API Authentication (fail-closed) Tests"

    # Only meaningful when proxy auth is enabled (the secured E2E pass). In the
    # open dev pass the admin API is intentionally unauthenticated.
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" != "true" ]; then
        log_skip "Admin auth tests: SGW_PROXY_AUTH_ENABLED is not true"
        return
    fi
    local global_token="${SGW_PROXY_TOKEN:-}"
    if [ -z "$global_token" ]; then
        log_skip "Admin auth tests: SGW_PROXY_TOKEN not configured"
        return
    fi

    local admin_read="${E2E_ADMIN_URL}/api/v1/audit?per_page=1"
    local status

    # 1. Health stays unauthenticated (sanity — must not be locked down).
    status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_ADMIN_URL}/api/v1/health")
    assert_eq "Admin auth: health is reachable without credentials" "200" "$status"

    # 2. Anonymous admin read → 401 (fail closed; the C1 regression guard).
    status=$(curl -s -o /dev/null -w "%{http_code}" "$admin_read")
    assert_eq "Admin auth: anonymous admin read is rejected (401)" "401" "$status"

    # 3. Anonymous admin MUTATION → rejected (401/403). Flipping policy-mode must not
    #    be possible without credentials.
    status=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
        -H "Content-Type: application/json" -d '{"mode":"permissive"}' \
        "${E2E_ADMIN_URL}/api/v1/admin/policy-mode")
    if [ "$status" = "401" ] || [ "$status" = "403" ]; then
        log_pass "Admin auth: anonymous admin mutation rejected (status ${status})"
    else
        log_fail "Admin auth: anonymous admin mutation NOT rejected (status ${status})"
    fi

    # 4. Wrong bearer token → 401.
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer not-a-real-token" "$admin_read")
    assert_eq "Admin auth: wrong bearer token is rejected (401)" "401" "$status"

    # 5. Basic auth is NOT accepted on the admin API (admin chain is Bearer/cookie only).
    local basic
    basic=$(printf "ci-bot:%s" "$global_token" | base64 -w0 2>/dev/null || \
            printf "ci-bot:%s" "$global_token" | base64)
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Basic ${basic}" "$admin_read")
    assert_eq "Admin auth: Basic auth is not accepted on the admin API (401)" "401" "$status"

    # 6. Global super-token as Bearer → admitted (scope * satisfies admin:read).
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer ${global_token}" "$admin_read")
    assert_eq "Admin auth: global token (Bearer) is admitted" "200" "$status"
}
