#!/usr/bin/env bash
# test_gomod.sh — Go module proxy e2e tests for Shieldoo Gate
# Sourced by run.sh; defines test_gomod(). Do NOT set -e here.

test_gomod() {
    log_section "Go Module Proxy Tests"

    local module="github.com/rs/zerolog"
    local version="v1.33.0"

    # ------------------------------------------------------------------
    # 1. Version list endpoint is accessible
    # ------------------------------------------------------------------
    assert_http_status "GoMod: /@v/list for ${module} returns HTTP 200" \
        "200" \
        "${E2E_GOMOD_URL}/${module}/@v/list"

    # ------------------------------------------------------------------
    # 2. Version info endpoint returns JSON
    # ------------------------------------------------------------------
    local info_resp
    info_resp=$(curl -sf "${E2E_GOMOD_URL}/${module}/@v/${version}.info")
    if echo "$info_resp" | jq -e '.Version' > /dev/null 2>&1; then
        log_pass "GoMod: .info returns valid JSON with Version field"
    else
        log_fail "GoMod: .info did not return valid JSON (response: ${info_resp})"
    fi

    # ------------------------------------------------------------------
    # 3. .mod endpoint returns go.mod content
    # ------------------------------------------------------------------
    local mod_resp
    mod_resp=$(curl -sf "${E2E_GOMOD_URL}/${module}/@v/${version}.mod")
    if echo "$mod_resp" | grep -q "^module "; then
        log_pass "GoMod: .mod returns valid go.mod content"
    else
        log_fail "GoMod: .mod did not return go.mod content"
    fi

    # ------------------------------------------------------------------
    # 4. .zip download through proxy
    # ------------------------------------------------------------------
    local workdir
    workdir=$(mktemp -d)
    local zip_path="${workdir}/module.zip"

    if curl -sf -o "$zip_path" \
        "${E2E_GOMOD_URL}/${module}/@v/${version}.zip"; then
        if file "$zip_path" | grep -qi "zip"; then
            log_pass "GoMod: downloaded .zip is a valid zip archive"
        else
            log_fail "GoMod: downloaded .zip is not a valid zip archive ($(file "$zip_path"))"
        fi
    else
        log_fail "GoMod: failed to download .zip file"
    fi

    rm -rf "$workdir"

    # ------------------------------------------------------------------
    # 5. Artifacts registered in API (>= 1 with ecosystem=="go")
    # ------------------------------------------------------------------
    local go_count
    go_count=$(api_jq "/api/v1/artifacts" \
        '[.data[] | select(.ecosystem == "go")] | length')
    assert_gte "GoMod: at least 1 go artifact registered in API" 1 "$go_count"

    # ------------------------------------------------------------------
    # 6. Audit log has SERVED events for go artifacts
    # ------------------------------------------------------------------
    local go_served
    go_served=$(api_jq "/api/v1/audit?per_page=200&event_type=SERVED" \
        '[.data[] | select(.artifact_id | startswith("go:"))] | length')
    assert_gte "GoMod: at least 1 SERVED audit event for go artifacts" 1 "$go_served"

    # ------------------------------------------------------------------
    # 7. Gate logs contain scan pipeline entries for gomod
    # ------------------------------------------------------------------
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate 2>/dev/null)

    if echo "$gate_logs" | grep -qiE "gomod.*scan result|gomod.*policy decision"; then
        log_pass "GoMod: gate logs contain scan pipeline entries"
    else
        log_fail "GoMod: gate logs do not contain gomod scan pipeline entries"
    fi
}
