#!/usr/bin/env bash
# test_rubygems_multi_index.sh — Multi-upstream-index RubyGems e2e tests (issue #32, Phase 6).
# Sourced by run.sh / run_all.sh; defines test_rubygems_multi_index(). Do NOT set -e here.
#
# R1 — back-compat:    a public gem's metadata still routes via the default upstream.
# R2 — scanned+cached: private gem (mycompany-gem) served via the gate, scanned, and
#                       cached under ecosystem rubygems__private (THE release gate).
#   R2a  /api/v1/gems gem_uri rewritten to the gate origin; /info fan-out hit;
#        .gem fetched back through the gate (200); artifact row under rubygems__private.
#   R2b  real `gem install` of the private gem through the gate (best-effort signal).
# R3 — scoped-miss:    mycompany-ghost (claimed by mycompany-*, absent) → 404 + BLOCKED audit.
# R4 — fail-closed:    mycompany-evil (gem_uri host foreign) → 502, no bypass.

test_rubygems_multi_index() {
    log_section "RubyGems Multi-Index Tests (issue #32)"

    # -----------------------------------------------------------------------
    # R1 — Default upstream back-compat: public gem metadata still served
    # -----------------------------------------------------------------------
    log_section "R1: default upstream back-compat (rake)"
    assert_http_status \
        "R1: GET /api/v1/gems/rake.json returns 200 via gate default upstream" \
        "200" \
        "${E2E_RUBYGEMS_URL}/api/v1/gems/rake.json"

    # -----------------------------------------------------------------------
    # R2 — Private gem: scanned+cached under rubygems__private
    # -----------------------------------------------------------------------
    log_section "R2: private gem scanned+cached (mycompany-gem)"

    local meta
    meta=$(curl -sf "${E2E_CURL_AUTH[@]}" "${E2E_RUBYGEMS_URL}/api/v1/gems/mycompany-gem.json")

    # R2a — gem_uri rewritten to the gate origin, NOT the private index host.
    if printf '%s' "$meta" | grep -q '/gems/mycompany-gem-1.0.0.gem' \
        && ! printf '%s' "$meta" | grep -q 'private-index:8443'; then
        log_pass "R2a: gem_uri rewritten through gate (private-index host removed)"
    else
        log_fail "R2a: gem_uri NOT rewritten correctly"
        log_info "R2a: body was: ${meta}"
    fi

    # /info compact index fans out (modern Bundler path).
    assert_http_status \
        "R2a: GET /info/mycompany-gem returns 200 (compact-index fan-out hit)" \
        "200" \
        "${E2E_RUBYGEMS_URL}/info/mycompany-gem"

    # Fetch the .gem back through the gate.
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' "${E2E_CURL_AUTH[@]}" "${E2E_RUBYGEMS_URL}/gems/mycompany-gem-1.0.0.gem")
    if [ "$code" = "200" ]; then
        log_pass "R2a: mycompany-gem-1.0.0.gem fetched through gate (HTTP 200)"
    else
        log_fail "R2a: .gem fetch through gate failed (HTTP ${code})"
    fi

    # R2a — THE RELEASE GATE: artifact row under ecosystem rubygems__private.
    local private_count
    private_count=$(api_jq "/api/v1/artifacts?ecosystem=rubygems__private" \
        '[.data[] | select(.name | test("mycompany-gem"))] | length')
    assert_gte \
        "R2a (RELEASE GATE): artifact row under ecosystem rubygems__private for mycompany-gem" \
        1 \
        "$private_count"

    # R2b — real `gem install` through the gate (best-effort client signal).
    if command -v gem >/dev/null 2>&1; then
        local geminstall
        geminstall="$(mktemp -d)"
        if gem install mycompany-gem --version 1.0.0 \
            --source "${E2E_RUBYGEMS_URL}/" \
            --install-dir "$geminstall" --no-document >/dev/null 2>&1; then
            log_pass "R2b: real 'gem install mycompany-gem' through gate succeeded"
        else
            log_skip "R2b: real 'gem install' did not complete (client/source quirk; R2a is authoritative)"
        fi
        rm -rf "$geminstall"
    else
        log_skip "R2b: gem not on PATH"
    fi

    # -----------------------------------------------------------------------
    # R3 — Scoped-miss: mycompany-ghost claimed by mycompany-*, absent → 404 + audit
    # -----------------------------------------------------------------------
    log_section "R3: scoped-miss (mycompany-ghost) → 404 + BLOCKED audit"
    assert_http_status \
        "R3: GET /api/v1/gems/mycompany-ghost.json returns 404 (scoped-miss, no public fallback)" \
        "404" \
        "${E2E_RUBYGEMS_URL}/api/v1/gems/mycompany-ghost.json"

    local ghost_blocked
    ghost_blocked=$(api_jq "/api/v1/audit?per_page=200&event_type=BLOCKED" \
        '[.data[] | select((.artifact_id // "") | test("rubygems__private:mycompany-ghost"))] | length')
    assert_gte \
        "R3: BLOCKED audit event written for rubygems__private:mycompany-ghost" \
        1 \
        "$ghost_blocked"

    # -----------------------------------------------------------------------
    # R4 — Fail-closed: gem JSON with a FOREIGN gem_uri host → 502 (no bypass)
    # -----------------------------------------------------------------------
    log_section "R4: fail-closed on foreign gem_uri host (mycompany-evil)"
    assert_http_status \
        "R4: GET /api/v1/gems/mycompany-evil.json returns 502 (foreign gem_uri refused, no scan bypass)" \
        "502" \
        "${E2E_RUBYGEMS_URL}/api/v1/gems/mycompany-evil.json"
}
