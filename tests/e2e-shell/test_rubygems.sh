#!/usr/bin/env bash
# test_rubygems.sh -- RubyGems proxy e2e tests for Shieldoo Gate
# Sourced by run.sh; defines test_rubygems(). Do NOT set -e here.

test_rubygems() {
    log_section "RubyGems Proxy Tests"

    # ------------------------------------------------------------------
    # 0. Negative test: unauthenticated request must return 401 when auth enabled
    # ------------------------------------------------------------------
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" = "true" ]; then
        local noauth_status
        noauth_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_RUBYGEMS_URL}/specs.4.8.gz")
        assert_eq "RubyGems: unauthenticated request returns 401" "401" "$noauth_status"
    fi

    # ------------------------------------------------------------------
    # 1. Specs index is accessible
    # ------------------------------------------------------------------
    assert_http_status "RubyGems: /specs.4.8.gz returns HTTP 200" \
        "200" \
        "${E2E_RUBYGEMS_URL}/specs.4.8.gz"

    # ------------------------------------------------------------------
    # 2. Gem metadata is accessible
    # ------------------------------------------------------------------
    assert_http_status "RubyGems: /api/v1/gems/rake.json returns HTTP 200" \
        "200" \
        "${E2E_RUBYGEMS_URL}/api/v1/gems/rake.json"

    # ------------------------------------------------------------------
    # 3. Download a gem through the proxy
    # ------------------------------------------------------------------
    local workdir
    workdir=$(mktemp -d)

    local gem_url="${E2E_RUBYGEMS_URL}/gems/rake-13.1.0.gem"
    if curl -sf "${E2E_CURL_AUTH[@]}" -o "${workdir}/rake-13.1.0.gem" "$gem_url"; then
        log_pass "RubyGems: gem download succeeded for rake-13.1.0.gem"
    else
        log_fail "RubyGems: gem download failed for rake-13.1.0.gem"
    fi

    rm -rf "$workdir"

    # ------------------------------------------------------------------
    # 4. Artifacts registered in API (>= 1 with ecosystem=="rubygems")
    # ------------------------------------------------------------------
    local rubygems_count
    rubygems_count=$(api_jq "/api/v1/artifacts" \
        '[.data[] | select(.ecosystem == "rubygems")] | length')
    assert_gte "RubyGems: at least 1 rubygems artifact registered in API" 1 "$rubygems_count"

    # ------------------------------------------------------------------
    # 5. Audit log has SERVED events for rubygems artifacts
    # ------------------------------------------------------------------
    local rubygems_served
    rubygems_served=$(api_jq "/api/v1/audit?per_page=200&event_type=SERVED" \
        '[.data[] | select(.artifact_id | startswith("rubygems:"))] | length')
    assert_gte "RubyGems: at least 1 SERVED audit event for rubygems artifacts" 1 "$rubygems_served"

    # ------------------------------------------------------------------
    # 6. Gate logs contain scan pipeline entries
    # ------------------------------------------------------------------
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate 2>/dev/null)

    if [[ "$gate_logs" == *"docker_logs not available"* ]]; then
        log_skip "RubyGems: gate logs inspection not available in container mode"
    elif grep -qiE "rubygems.*scan result|rubygems.*policy decision" <<< "$gate_logs"; then
        log_pass "RubyGems: gate logs contain scan pipeline entries"
    else
        log_fail "RubyGems: gate logs do not contain rubygems scan/policy entries"
    fi
}
