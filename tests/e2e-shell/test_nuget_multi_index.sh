#!/usr/bin/env bash
# test_nuget_multi_index.sh — Multi-upstream-index NuGet e2e tests (issue #32, Phase 5).
# Sourced by run.sh / run_all.sh; defines test_nuget_multi_index(). Do NOT set -e here.
#
# G1 — back-compat:    a public package registration still routes via the default upstream.
# G2 — scanned+cached: private package (mycompany.nuget.lib) served via the gate,
#                       scanned, and cached under ecosystem nuget__private
#                       (THE release gate — no scan bypass).
#   G2a  registration packageContent rewritten to the gate origin (NOT private-index).
#   G2b  .nupkg fetched back through the gate (HTTP 200).
#   G2c  artifact row exists under ecosystem nuget__private (authoritative check).
# G3 — scoped-miss:    mycompany.ghost (claimed by mycompany.*, absent) → 404 + BLOCKED audit.
# G4 — fail-closed:    mycompany.nuget.evil (packageContent host foreign) → 502, no bypass.

test_nuget_multi_index() {
    log_section "NuGet Multi-Index Tests (issue #32)"

    # -----------------------------------------------------------------------
    # G1 — Default upstream back-compat: the V3 service index is served + rewritten.
    #
    # NOTE: the default api.nuget.org serves registration under its advertised
    # `registration5-gz-semver2/` base (discovered from the service index), NOT at
    # `/v3/registration/{id}/index.json` — that gate route is the multi-index
    # fan-out entry point used by extra-index feeds + the gate's own download
    # routing (proven by G2). Default registration/back-compat is exercised by the
    # full `test_nuget` (dotnet restore via the service index); here we assert the
    # service-index entry point is healthy through the gate.
    # -----------------------------------------------------------------------
    log_section "G1: default upstream back-compat (V3 service index)"
    assert_http_status \
        "G1: GET /v3/index.json returns 200 via gate default upstream" \
        "200" \
        "${E2E_NUGET_URL}/v3/index.json"

    # -----------------------------------------------------------------------
    # G2 — Private package: scanned+cached under nuget__private
    # -----------------------------------------------------------------------
    log_section "G2: private package scanned+cached (mycompany.nuget.lib)"

    local reg
    reg=$(curl -sf "${E2E_CURL_AUTH[@]}" \
        "${E2E_NUGET_URL}/v3/registration/mycompany.nuget.lib/index.json")

    # G2a — packageContent rewritten to the gate origin, NOT the private feed host.
    if printf '%s' "$reg" | grep -q '/v3-flatcontainer/mycompany.nuget.lib/1.0.0/' \
        && ! printf '%s' "$reg" | grep -q 'private-index:8443'; then
        log_pass "G2a: registration packageContent rewritten through gate (private-index host removed)"
    else
        log_fail "G2a: registration NOT rewritten correctly"
        log_info "G2a: body was: ${reg}"
    fi

    # G2b — fetch the rewritten .nupkg back through the gate.
    local nupkg_path
    nupkg_path=$(printf '%s' "$reg" \
        | grep -oE '/v3-flatcontainer/mycompany.nuget.lib/[^"]+\.nupkg' | head -1)
    if [ -n "$nupkg_path" ]; then
        local code
        code=$(curl -s -o /dev/null -w '%{http_code}' "${E2E_CURL_AUTH[@]}" "${E2E_NUGET_URL}${nupkg_path}")
        if [ "$code" = "200" ]; then
            log_pass "G2b: mycompany.nuget.lib .nupkg fetched through gate (HTTP 200)"
        else
            log_fail "G2b: .nupkg fetch through gate failed (HTTP ${code})"
        fi
    else
        log_fail "G2b: could not extract rewritten packageContent path from registration"
    fi

    # G2c — THE RELEASE GATE: artifact row under ecosystem nuget__private.
    local private_count
    private_count=$(api_jq "/api/v1/artifacts?ecosystem=nuget__private" \
        '[.data[] | select(.name | test("mycompany.nuget.lib"))] | length')
    assert_gte \
        "G2c (RELEASE GATE): artifact row under ecosystem nuget__private for mycompany.nuget.lib" \
        1 \
        "$private_count"

    # -----------------------------------------------------------------------
    # G3 — Scoped-miss: mycompany.ghost claimed by mycompany.*, absent → 404 + audit
    # -----------------------------------------------------------------------
    log_section "G3: scoped-miss (mycompany.ghost) → 404 + BLOCKED audit"
    assert_http_status \
        "G3: GET /v3/registration/mycompany.ghost/index.json returns 404 (scoped-miss)" \
        "404" \
        "${E2E_NUGET_URL}/v3/registration/mycompany.ghost/index.json"

    local ghost_blocked
    ghost_blocked=$(api_jq "/api/v1/audit?per_page=200&event_type=BLOCKED" \
        '[.data[] | select((.artifact_id // "") | test("nuget__private:mycompany.ghost"))] | length')
    assert_gte \
        "G3: BLOCKED audit event written for nuget__private:mycompany.ghost" \
        1 \
        "$ghost_blocked"

    # -----------------------------------------------------------------------
    # G4 — Fail-closed: registration with a FOREIGN packageContent host → 502
    # -----------------------------------------------------------------------
    log_section "G4: fail-closed on foreign packageContent host (mycompany.nuget.evil)"
    assert_http_status \
        "G4: GET /v3/registration/mycompany.nuget.evil/index.json returns 502 (foreign host refused)" \
        "502" \
        "${E2E_NUGET_URL}/v3/registration/mycompany.nuget.evil/index.json"
}
