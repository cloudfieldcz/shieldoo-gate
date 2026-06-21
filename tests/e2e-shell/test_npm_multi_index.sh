#!/usr/bin/env bash
# test_npm_multi_index.sh — Multi-upstream-index npm e2e tests (issue #32, Phase 5).
# Sourced by run.sh / run_all.sh; defines test_npm_multi_index(). Do NOT set -e here.
#
# N1 — back-compat:    a public package still routes via the default upstream.
# N2 — scanned+cached: private package (mycompany-npm-lib) served via the gate,
#                       scanned, and cached under ecosystem npm__private
#                       (THE release gate — no scan bypass).
#   N2a  packument dist.tarball rewritten to the gate origin (NOT private-index).
#   N2b  tarball fetched back through the gate (HTTP 200).
#   N2c  artifact row exists under ecosystem npm__private (authoritative check).
# N3 — scoped-miss:    mycompany-ghost (claimed by mycompany-*, absent) → 404 + BLOCKED audit.
# N4 — fail-closed:    mycompany-npm-evil (packument tarball host foreign) → 502, no bypass.

test_npm_multi_index() {
    log_section "npm Multi-Index Tests (issue #32)"

    # -----------------------------------------------------------------------
    # N1 — Default upstream back-compat: public packument still served
    # -----------------------------------------------------------------------
    log_section "N1: default upstream back-compat (is-odd)"
    assert_http_status \
        "N1: GET /is-odd returns 200 via gate default upstream" \
        "200" \
        "${E2E_NPM_URL}/is-odd"

    # -----------------------------------------------------------------------
    # N2 — Private package: scanned+cached under npm__private
    # -----------------------------------------------------------------------
    log_section "N2: private package scanned+cached (mycompany-npm-lib)"

    local packument
    packument=$(curl -sf "${E2E_CURL_AUTH[@]}" "${E2E_NPM_URL}/mycompany-npm-lib")

    # N2a — dist.tarball rewritten to the gate origin, NOT the private index host.
    if printf '%s' "$packument" | grep -q '/mycompany-npm-lib/-/mycompany-npm-lib-1.0.0.tgz' \
        && ! printf '%s' "$packument" | grep -q 'private-index:8443'; then
        log_pass "N2a: packument dist.tarball rewritten through gate (private-index host removed)"
    else
        log_fail "N2a: packument NOT rewritten correctly"
        log_info "N2a: body was: ${packument}"
    fi

    # N2b — fetch the rewritten tarball back through the gate.
    local tarball_path
    tarball_path=$(printf '%s' "$packument" \
        | grep -oE '/mycompany-npm-lib/-/[^"]+\.tgz' | head -1)
    if [ -n "$tarball_path" ]; then
        local code
        code=$(curl -s -o /dev/null -w '%{http_code}' "${E2E_CURL_AUTH[@]}" "${E2E_NPM_URL}${tarball_path}")
        if [ "$code" = "200" ]; then
            log_pass "N2b: mycompany-npm-lib tarball fetched through gate (HTTP 200)"
        else
            log_fail "N2b: tarball fetch through gate failed (HTTP ${code})"
        fi
    else
        log_fail "N2b: could not extract rewritten tarball path from packument"
    fi

    # N2c — THE RELEASE GATE: artifact row under ecosystem npm__private.
    local private_count
    private_count=$(api_jq "/api/v1/artifacts?ecosystem=npm__private" \
        '[.data[] | select(.name | test("mycompany-npm-lib"))] | length')
    assert_gte \
        "N2c (RELEASE GATE): artifact row under ecosystem npm__private for mycompany-npm-lib" \
        1 \
        "$private_count"

    # -----------------------------------------------------------------------
    # N3 — Scoped-miss: mycompany-ghost claimed by mycompany-*, absent → 404 + audit
    # -----------------------------------------------------------------------
    log_section "N3: scoped-miss (mycompany-ghost) → 404 + BLOCKED audit"
    assert_http_status \
        "N3: GET /mycompany-ghost returns 404 (scoped-miss, no public fallback)" \
        "404" \
        "${E2E_NPM_URL}/mycompany-ghost"

    local ghost_blocked
    ghost_blocked=$(api_jq "/api/v1/audit?per_page=200&event_type=BLOCKED" \
        '[.data[] | select((.artifact_id // "") | test("npm__private:mycompany-ghost"))] | length')
    assert_gte \
        "N3: BLOCKED audit event written for npm__private:mycompany-ghost" \
        1 \
        "$ghost_blocked"

    # -----------------------------------------------------------------------
    # N4 — Fail-closed: packument with a FOREIGN tarball host → 502 (no bypass)
    # -----------------------------------------------------------------------
    log_section "N4: fail-closed on foreign tarball host (mycompany-npm-evil)"
    assert_http_status \
        "N4: GET /mycompany-npm-evil returns 502 (foreign tarball host refused, no scan bypass)" \
        "502" \
        "${E2E_NPM_URL}/mycompany-npm-evil"
}
