#!/usr/bin/env bash
# test_gomod_multi_index.sh — Multi-upstream-index Go modules e2e tests (issue #32, Phase 6).
# Sourced by run.sh / run_all.sh; defines test_gomod_multi_index(). Do NOT set -e here.
#
# M1 — back-compat:    a public module's metadata still routes via the default upstream.
# M2 — scanned+cached: private module (github.com/mycompany/lib) served via the gate,
#                       scanned, and cached under ecosystem go__private (THE release gate).
#   M2a  /@v/v1.0.0.info fan-out hit; .zip fetched back through the gate (200);
#        artifact row under go__private.
# M3 — scoped-miss:    github.com/mycompany/ghost (claimed, absent) → 404 + BLOCKED audit.
#
# NOTE: GOPROXY metadata carries no download URLs, so there is no foreign-host
# negative fixture for gomod (no rewrite surface). The scoped-miss + namespacing
# are the security assertions.

test_gomod_multi_index() {
    log_section "Go modules Multi-Index Tests (issue #32)"

    local module="github.com/mycompany/lib" version="v1.0.0"

    # -----------------------------------------------------------------------
    # M1 — Default upstream back-compat: public module metadata still served
    # -----------------------------------------------------------------------
    log_section "M1: default upstream back-compat (github.com/rs/zerolog)"
    assert_http_status \
        "M1: GET /github.com/rs/zerolog/@v/list returns 200 via gate default upstream" \
        "200" \
        "${E2E_GOMOD_URL}/github.com/rs/zerolog/@v/list"

    # -----------------------------------------------------------------------
    # M2 — Private module: scanned+cached under go__private
    # -----------------------------------------------------------------------
    log_section "M2: private module scanned+cached (${module})"

    # M2a — metadata fans out to the private index.
    assert_http_status \
        "M2a: GET /${module}/@v/${version}.info returns 200 (fan-out hit)" \
        "200" \
        "${E2E_GOMOD_URL}/${module}/@v/${version}.info"

    # Fetch the .zip back through the gate.
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' "${E2E_CURL_AUTH[@]}" "${E2E_GOMOD_URL}/${module}/@v/${version}.zip")
    if [ "$code" = "200" ]; then
        log_pass "M2a: ${module}@${version} .zip fetched through gate (HTTP 200)"
    else
        log_fail "M2a: .zip fetch through gate failed (HTTP ${code})"
    fi

    # M2a — THE RELEASE GATE: artifact row under ecosystem go__private.
    local private_count
    private_count=$(api_jq "/api/v1/artifacts?ecosystem=go__private" \
        '[.data[] | select(.name | test("mycompany/lib"))] | length')
    assert_gte \
        "M2a (RELEASE GATE): artifact row under ecosystem go__private for ${module}" \
        1 \
        "$private_count"

    # -----------------------------------------------------------------------
    # M3 — Scoped-miss: github.com/mycompany/ghost claimed, absent → 404 + audit
    # -----------------------------------------------------------------------
    log_section "M3: scoped-miss (github.com/mycompany/ghost) → 404 + BLOCKED audit"
    assert_http_status \
        "M3: GET /github.com/mycompany/ghost/@v/list returns 404 (scoped-miss, no public fallback)" \
        "404" \
        "${E2E_GOMOD_URL}/github.com/mycompany/ghost/@v/list"

    local ghost_blocked
    ghost_blocked=$(api_jq "/api/v1/audit?per_page=200&event_type=BLOCKED" \
        '[.data[] | select((.artifact_id // "") | test("go__private:github.com/mycompany/ghost"))] | length')
    assert_gte \
        "M3: BLOCKED audit event written for go__private:github.com/mycompany/ghost" \
        1 \
        "$ghost_blocked"
}
