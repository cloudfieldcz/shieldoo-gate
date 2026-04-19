#!/usr/bin/env bash
# test_gomod.sh — Go module proxy e2e tests for Shieldoo Gate
# Sourced by run.sh; defines test_gomod(). Do NOT set -e here.

test_gomod() {
    log_section "Go Module Proxy Tests"

    local module="github.com/rs/zerolog"
    local version="v1.33.0"

    # ------------------------------------------------------------------
    # 0. Negative test: unauthenticated request must return 401 when auth enabled
    # ------------------------------------------------------------------
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" = "true" ]; then
        local noauth_status
        noauth_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_GOMOD_URL}/${module}/@v/list")
        assert_eq "GoMod: unauthenticated request returns 401" "401" "$noauth_status"
    fi

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
    info_resp=$(curl -sf "${E2E_CURL_AUTH[@]}" "${E2E_GOMOD_URL}/${module}/@v/${version}.info")
    if echo "$info_resp" | jq -e '.Version' > /dev/null 2>&1; then
        log_pass "GoMod: .info returns valid JSON with Version field"
    else
        log_fail "GoMod: .info did not return valid JSON (response: ${info_resp})"
    fi

    # ------------------------------------------------------------------
    # 3. .mod endpoint returns go.mod content
    # ------------------------------------------------------------------
    local mod_resp
    mod_resp=$(curl -sf "${E2E_CURL_AUTH[@]}" "${E2E_GOMOD_URL}/${module}/@v/${version}.mod")
    if grep -q "^module " <<< "$mod_resp"; then
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

    if curl -sf "${E2E_CURL_AUTH[@]}" -o "$zip_path" \
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
    # 7. License detection — zerolog v1.33.0 is MIT-licensed; the gomod
    # adapter runs google/licensecheck over LICENSE-family files in the
    # module zip and persists results via TriggerAsyncLicenseWrite.
    # ------------------------------------------------------------------
    local go_artifact_id=""
    local waited=0
    while [ "$waited" -lt 30 ]; do
        go_artifact_id=$(api_jq "/api/v1/artifacts?ecosystem=go&per_page=200" \
            "[.data[] | select(.ecosystem == \"go\" and .name == \"${module}\")] | .[0].id // empty" 2>/dev/null)
        if [ -n "$go_artifact_id" ] && [ "$go_artifact_id" != "null" ]; then
            break
        fi
        sleep 1
        waited=$(( waited + 1 ))
    done

    if [ -z "$go_artifact_id" ] || [ "$go_artifact_id" = "null" ]; then
        log_fail "GoMod: could not discover ${module} artifact via admin API"
    else
        log_pass "GoMod: discovered go artifact id=${go_artifact_id}"

        # The license write is async (10s timeout goroutine). Give it time.
        sleep 5

        # Go artifact IDs contain both ':' and '/' (e.g. "go:github.com/rs/zerolog:v1.33.0").
        # Chi's {id} parameter matches a single path segment, so slashes must be
        # percent-encoded to reach handleGetArtifactLicenses.
        local encoded_id
        encoded_id=$(jq -rn --arg s "$go_artifact_id" '$s|@uri')

        local licenses_body
        licenses_body=$(curl -sf "${E2E_ADMIN_URL}/api/v1/artifacts/${encoded_id}/licenses" 2>/dev/null || true)
        if [ -z "$licenses_body" ]; then
            log_fail "GoMod: /licenses endpoint returned empty body for ${go_artifact_id}"
        else
            local has_mit
            has_mit=$(echo "$licenses_body" | jq -r '.licenses // [] | index("MIT") // empty')
            if [ -n "$has_mit" ]; then
                log_pass "GoMod: detected MIT license for ${module}"
            else
                log_fail "GoMod: MIT license not detected (body=${licenses_body})"
            fi

            local generator
            generator=$(echo "$licenses_body" | jq -r '.generator // empty')
            if [ "$generator" = "gomod-licensecheck" ]; then
                log_pass "GoMod: generator=gomod-licensecheck"
            else
                log_fail "GoMod: expected generator=gomod-licensecheck, got '${generator}'"
            fi
        fi
    fi

    # ------------------------------------------------------------------
    # 8. Gate logs contain scan pipeline entries for gomod
    # ------------------------------------------------------------------
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate 2>/dev/null)

    if [[ "$gate_logs" == *"docker_logs not available"* ]]; then
        log_skip "GoMod: gate logs inspection not available in container mode"
    elif grep -qiE "gomod.*scan result|gomod.*policy decision" <<< "$gate_logs"; then
        log_pass "GoMod: gate logs contain scan pipeline entries"
    else
        log_fail "GoMod: gate logs do not contain gomod scan pipeline entries"
    fi
}
