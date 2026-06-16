#!/usr/bin/env bash
# test_vuln_scan_negative.sh — Negative-path tests for the vuln-scan upload API.
# Covers: 401/403 (no auth / wrong scope), 415 (wrong content-type),
# 413 (oversized body), 400 (invalid SBOM). Sourced by run_all.sh.

test_vuln_scan_negative() {
    log_section "Vuln-scan: negative-path tests"

    # Pre-flight: vuln-scan must be enabled. Without it every endpoint returns
    # 503 and the matrix below is meaningless — skip cleanly.
    local pre_status
    pre_status=$(admin_curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_ADMIN_URL}/api/v1/vulnerabilities/summary")
    if [ "$pre_status" = "503" ]; then
        log_skip "Vuln-scan: feature disabled in this run, skipping all negative tests"
        return
    fi

    local upload_path="/api/v1/projects/default/components/billing-api/scans"

    # ------------------------------------------------------------------
    # 401/403: no Authorization header at all on a scope-protected route.
    # ------------------------------------------------------------------
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" = "true" ]; then
        local s_noauth
        # NOTE: plain curl (NOT admin_curl) — this case deliberately sends NO
        # credential to assert the scope-protected route rejects it.
        s_noauth=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
            "${E2E_ADMIN_URL}${upload_path}" \
            -H "Content-Type: application/vnd.cyclonedx+json" \
            --data-binary '{"bomFormat":"CycloneDX","components":[]}')
        if [ "$s_noauth" = "401" ] || [ "$s_noauth" = "403" ]; then
            log_pass "Vuln-scan: missing auth → ${s_noauth}"
        else
            log_fail "Vuln-scan: missing auth expected 401/403, got ${s_noauth}"
        fi

        # 403 with random Bearer (not the super-token, not a known PAT) — the
        # PAT lookup fails → 401, which is also acceptable here.
        local s_invalid
        # NOTE: plain curl (NOT admin_curl) — must carry ONLY the bogus Bearer so
        # the PAT lookup fails; admin_curl would prepend the valid super-token.
        s_invalid=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
            "${E2E_ADMIN_URL}${upload_path}" \
            -H "Authorization: Bearer not-a-real-token" \
            -H "Content-Type: application/vnd.cyclonedx+json" \
            --data-binary '{"bomFormat":"CycloneDX","components":[]}')
        if [ "$s_invalid" = "401" ] || [ "$s_invalid" = "403" ]; then
            log_pass "Vuln-scan: invalid Bearer → ${s_invalid}"
        else
            log_fail "Vuln-scan: invalid Bearer expected 401/403, got ${s_invalid}"
        fi
    else
        log_skip "Vuln-scan: 401/403 tests require SGW_PROXY_AUTH_ENABLED=true"
    fi

    # The body-validation tests below need a request to actually reach the
    # handler. Use the super-token Bearer (scope=*) when available; otherwise
    # the request short-circuits at RequireScope("scan:upload") with 403.
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" != "true" ] || [ -z "${SGW_PROXY_TOKEN:-}" ]; then
        log_skip "Vuln-scan: body-validation tests require SGW_PROXY_AUTH_ENABLED=true + SGW_PROXY_TOKEN"
        return
    fi
    local upload_auth=(-H "Authorization: Bearer ${SGW_PROXY_TOKEN}")
    local upload_url="${E2E_ADMIN_URL}${upload_path}"

    # ------------------------------------------------------------------
    # 415: unsupported content-type (text/plain).
    # ------------------------------------------------------------------
    local s415
    s415=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$upload_url" \
        "${upload_auth[@]}" \
        -H "Content-Type: text/plain" \
        --data-binary 'not a sbom')
    assert_eq "Vuln-scan: text/plain content-type → 415" "415" "$s415"

    # ------------------------------------------------------------------
    # 413/422: payload over max_sbom_bytes (config sets 1 MiB in E2E).
    # The handler maps ErrSBOMTooLarge → 413; downstream validators that
    # see a body truncated to the cap typically map ErrInvalidSBOM → 422.
    # Either is acceptable as "oversized was rejected".
    # ------------------------------------------------------------------
    local oversized
    oversized=$(mktemp)
    head -c $((1100 * 1024)) /dev/urandom | base64 > "$oversized"
    local s413
    s413=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$upload_url" \
        "${upload_auth[@]}" \
        -H "Content-Type: application/vnd.cyclonedx+json" \
        --data-binary "@$oversized")
    rm -f "$oversized"
    if [ "$s413" = "413" ] || [ "$s413" = "422" ]; then
        log_pass "Vuln-scan: oversized body → ${s413}"
    else
        log_fail "Vuln-scan: oversized body expected 413/422, got ${s413}"
    fi

    # ------------------------------------------------------------------
    # 422: SBOM missing bomFormat — ErrInvalidSBOM is mapped to 422 per
    # spec (Status codes: 202, 400 (component name), 401, 403, 413, 415, 422).
    # ------------------------------------------------------------------
    local s422
    s422=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$upload_url" \
        "${upload_auth[@]}" \
        -H "Content-Type: application/vnd.cyclonedx+json" \
        --data-binary '{"specVersion":"1.5","components":[]}')
    assert_eq "Vuln-scan: SBOM missing bomFormat → 422" "422" "$s422"

    # ------------------------------------------------------------------
    # 422: depth-bomb structural attack — streaming validator short-circuits.
    # ------------------------------------------------------------------
    local depth_payload
    depth_payload=$(printf '{"bomFormat":"CycloneDX",%s%s}' \
        "$(printf '"a":{%.0s' {1..40})" \
        "$(printf '}%.0s' {1..40})")
    local s422b
    s422b=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$upload_url" \
        "${upload_auth[@]}" \
        -H "Content-Type: application/vnd.cyclonedx+json" \
        --data-binary "$depth_payload")
    assert_eq "Vuln-scan: depth-bomb SBOM → 422" "422" "$s422b"

    # ------------------------------------------------------------------
    # 200/202: smallest valid SBOM is accepted (negative-control).
    # ------------------------------------------------------------------
    local s2xx
    s2xx=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$upload_url" \
        "${upload_auth[@]}" \
        -H "Content-Type: application/vnd.cyclonedx+json" \
        --data-binary '{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}')
    if [ "$s2xx" = "200" ] || [ "$s2xx" = "202" ]; then
        log_pass "Vuln-scan: minimal valid SBOM accepted (${s2xx})"
    else
        log_fail "Vuln-scan: minimal valid SBOM expected 200/202, got ${s2xx}"
    fi
}
