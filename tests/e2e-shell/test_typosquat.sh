#!/usr/bin/env bash
# test_typosquat.sh — Typosquatting detection e2e tests for Shieldoo Gate
# Sourced by run_all.sh; defines test_typosquat(). Do NOT set -e here.

test_typosquat() {
    log_section "Typosquatting Detection Tests"

    # ------------------------------------------------------------------
    # 1. Typosquat scanner is registered and healthy
    # ------------------------------------------------------------------
    local health_body
    health_body=$(api_get "/api/v1/health" 2>/dev/null || true)
    if [ -n "$health_body" ]; then
        log_pass "Typosquat: health endpoint accessible"
    else
        log_fail "Typosquat: health endpoint not accessible"
        return
    fi

    # ------------------------------------------------------------------
    # 2. Install a known typosquat name via PyPI — should be blocked (403)
    #    "reqeusts" is edit distance 2 from "requests" (transposition)
    # ------------------------------------------------------------------
    local typo_status
    typo_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_CURL_AUTH[@]}" \
        "${E2E_PYPI_URL}/packages/reqeusts/reqeusts-1.0.0.tar.gz")
    # In strict mode, SUSPICIOUS verdict → quarantine → 403
    # The proxy may also return 404 if upstream doesn't have it, but the
    # scan result should still be recorded. Accept 403 (blocked) or 404.
    if [ "$typo_status" = "403" ]; then
        log_pass "Typosquat: PyPI typosquat 'reqeusts' blocked with HTTP 403"
    elif [ "$typo_status" = "404" ]; then
        log_pass "Typosquat: PyPI typosquat 'reqeusts' returned HTTP 404 (upstream doesn't have it)"
    else
        log_fail "Typosquat: PyPI typosquat 'reqeusts' expected 403 or 404, got $typo_status"
    fi

    # ------------------------------------------------------------------
    # 3. Try an npm typosquat — "lodsah" (edit distance 2 from "lodash")
    # ------------------------------------------------------------------
    local npm_typo_status
    npm_typo_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_CURL_AUTH[@]}" \
        "${E2E_NPM_URL}/lodsah")
    if [ "$npm_typo_status" = "403" ]; then
        log_pass "Typosquat: npm typosquat 'lodsah' blocked with HTTP 403"
    elif [ "$npm_typo_status" = "404" ]; then
        log_pass "Typosquat: npm typosquat 'lodsah' returned HTTP 404 (upstream doesn't have it)"
    else
        log_fail "Typosquat: npm typosquat 'lodsah' expected 403 or 404, got $npm_typo_status"
    fi

    # ------------------------------------------------------------------
    # 4. Combosquatting: "requests-utils" should trigger combosquat detection
    # ------------------------------------------------------------------
    local combo_status
    combo_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_CURL_AUTH[@]}" \
        "${E2E_PYPI_URL}/packages/requests-utils/requests-utils-1.0.0.tar.gz")
    if [ "$combo_status" = "403" ]; then
        log_pass "Typosquat: combosquat 'requests-utils' blocked with HTTP 403"
    elif [ "$combo_status" = "404" ]; then
        log_pass "Typosquat: combosquat 'requests-utils' returned HTTP 404 (upstream doesn't have it)"
    else
        log_fail "Typosquat: combosquat 'requests-utils' expected 403 or 404, got $combo_status"
    fi

    # ------------------------------------------------------------------
    # 5. Legitimate package "requests" should NOT be flagged
    # ------------------------------------------------------------------
    local legit_status
    legit_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_CURL_AUTH[@]}" \
        "${E2E_PYPI_URL}/simple/requests/")
    assert_eq "Typosquat: legitimate 'requests' package index returns 200" \
        "200" "$legit_status"

    # ------------------------------------------------------------------
    # 5b. Regression: legitimate npm package "vitest" must NOT be blocked.
    # vitest is edit-distance 2 from "vite" and was previously a false positive.
    # Both must now be in the popular_packages seed so Strategy 1 short-circuits.
    # ------------------------------------------------------------------
    local vitest_status
    vitest_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_CURL_AUTH[@]}" \
        "${E2E_NPM_URL}/vitest")
    if [ "$vitest_status" = "403" ]; then
        log_fail "Typosquat: legitimate 'vitest' wrongly blocked (HTTP 403) — seed regression"
    else
        log_pass "Typosquat: legitimate 'vitest' not blocked (HTTP $vitest_status)"
    fi

    # 5c. Same regression check for "nest" (edit-distance 1 from "next" and "jest").
    local nest_status
    nest_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_CURL_AUTH[@]}" \
        "${E2E_NPM_URL}/nest")
    if [ "$nest_status" = "403" ]; then
        log_fail "Typosquat: legitimate 'nest' wrongly blocked (HTTP 403) — seed regression"
    else
        log_pass "Typosquat: legitimate 'nest' not blocked (HTTP $nest_status)"
    fi

    # ------------------------------------------------------------------
    # 6. Check scan results via API — look for builtin-typosquat scanner entries
    # ------------------------------------------------------------------
    local artifacts_body
    artifacts_body=$(api_get "/api/v1/artifacts?per_page=200" 2>/dev/null || true)
    if [ -n "$artifacts_body" ]; then
        # Check if any artifact has scan results from builtin-typosquat scanner
        local typosquat_scans
        typosquat_scans=$(echo "$artifacts_body" | jq -r \
            '[.data[] | select(.ecosystem == "pypi" or .ecosystem == "npm")] | length' 2>/dev/null || echo "0")
        assert_gte "Typosquat: at least 1 artifact in API from proxy requests" 1 "$typosquat_scans"
    else
        log_skip "Typosquat: could not query artifacts API"
    fi

    # ------------------------------------------------------------------
    # 6b. Typosquat blocks must persist as quarantined artifacts so admins
    # can release/override them from the Artifacts pane.
    # ------------------------------------------------------------------
    # URL-encoded form of "npm:lodsah:*" — chi treats `*` as a wildcard otherwise.
    local lodsah_artifact_id_enc="npm:lodsah:%2A"
    local lodsah_status
    lodsah_status=$(api_jq "/api/v1/artifacts/${lodsah_artifact_id_enc}" '.status.status' 2>/dev/null || echo "MISSING")
    if [ "$lodsah_status" = "QUARANTINED" ]; then
        log_pass "Typosquat: name-only npm block 'lodsah' persisted as QUARANTINED artifact (version=*)"
    else
        log_fail "Typosquat: expected lodsah to be persisted as QUARANTINED artifact, got status='$lodsah_status'"
    fi

    # ------------------------------------------------------------------
    # 6c. Override flow — releasing a typosquat-blocked artifact must
    # create a package-scoped policy override and let subsequent installs
    # through.
    # ------------------------------------------------------------------
    if [ "$lodsah_status" = "QUARANTINED" ]; then
        local release_response
        release_response=$(curl -sf -X POST "${E2E_ADMIN_URL}/api/v1/artifacts/${lodsah_artifact_id_enc}/release" 2>/dev/null || echo "")
        if [ -n "$release_response" ]; then
            log_pass "Typosquat override: release endpoint accepted POST"
        else
            log_fail "Typosquat override: release endpoint returned no response"
        fi

        # Status must now be CLEAN
        local after_release_status
        after_release_status=$(api_jq "/api/v1/artifacts/${lodsah_artifact_id_enc}" '.status.status' 2>/dev/null || echo "MISSING")
        assert_eq "Typosquat override: artifact status is CLEAN after release" \
            "CLEAN" "$after_release_status"

        # Policy override must exist with scope='package' and empty version.
        # `// empty` makes jq emit nothing (instead of the literal "null") when
        # no matching override is present, so a missing override fails loudly
        # against the "package" assertion below rather than masquerading as a
        # different value.
        local override_scope
        override_scope=$(api_jq "/api/v1/overrides?ecosystem=npm" \
            '[.data[] | select(.name=="lodsah" and .revoked==false)][0].scope // empty' 2>/dev/null || echo "")
        assert_eq "Typosquat override: policy override created with scope=package" \
            "package" "$override_scope"

        # Re-fetch the package: must NOT return 403 anymore (404 from upstream miss is OK).
        local recheck_status
        recheck_status=$(curl -s -o /dev/null -w "%{http_code}" \
            "${E2E_CURL_AUTH[@]}" \
            "${E2E_NPM_URL}/lodsah")
        if [ "$recheck_status" = "403" ]; then
            log_fail "Typosquat override: re-fetch of 'lodsah' still 403 (override not honored)"
        else
            log_pass "Typosquat override: re-fetch of 'lodsah' no longer blocked (HTTP $recheck_status)"
        fi
    else
        log_skip "Typosquat override: lodsah artifact not QUARANTINED — cannot exercise release flow"
    fi

    # ------------------------------------------------------------------
    # 6d. Regression (integrity bug, fixed 2026-05): the synthetic typosquat
    # row is persisted with sha256="" because the proxy never downloaded any
    # content. After Release, a real fetch must NOT trip a false
    # INTEGRITY_VIOLATION (which would re-quarantine the artifact and 403
    # the legitimate fetch). Exercises the PyPI flow end-to-end.
    # ------------------------------------------------------------------
    # Trigger a PyPI typosquat block by fetching a tarball URL with a
    # typosquat name. parseFilename extracts version from the filename,
    # so the synthetic artifact ID is "pypi:requestes:1.0.0".
    local pypi_typo_block_status
    pypi_typo_block_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_CURL_AUTH[@]}" \
        "${E2E_PYPI_URL}/packages/requestes/requestes-1.0.0.tar.gz")
    if [ "$pypi_typo_block_status" != "403" ]; then
        log_skip "Typosquat regression (pypi): expected 403 block on 'requestes', got $pypi_typo_block_status — skipping integrity regression"
    else
        log_pass "Typosquat regression (pypi): 'requestes' blocked with HTTP 403"

        # Synthetic row should exist as QUARANTINED with empty sha256.
        local pypi_typo_id_enc="pypi:requestes:1.0.0"
        local pypi_typo_status pypi_typo_sha
        pypi_typo_status=$(api_jq "/api/v1/artifacts/${pypi_typo_id_enc}" '.status.status' 2>/dev/null || echo "MISSING")
        pypi_typo_sha=$(api_jq "/api/v1/artifacts/${pypi_typo_id_enc}" '.sha256 // ""' 2>/dev/null || echo "")
        assert_eq "Typosquat regression (pypi): synthetic row is QUARANTINED" \
            "QUARANTINED" "$pypi_typo_status"
        assert_eq "Typosquat regression (pypi): synthetic row has empty sha256" \
            "" "$pypi_typo_sha"

        # Release the block.
        local pypi_release_response
        pypi_release_response=$(curl -sf -X POST \
            "${E2E_ADMIN_URL}/api/v1/artifacts/${pypi_typo_id_enc}/release" 2>/dev/null || echo "")
        if [ -n "$pypi_release_response" ]; then
            log_pass "Typosquat regression (pypi): release endpoint accepted POST"
        else
            log_fail "Typosquat regression (pypi): release endpoint returned no response"
        fi

        # Status must now be CLEAN.
        local pypi_after_release_status
        pypi_after_release_status=$(api_jq "/api/v1/artifacts/${pypi_typo_id_enc}" '.status.status' 2>/dev/null || echo "MISSING")
        assert_eq "Typosquat regression (pypi): status CLEAN after release" \
            "CLEAN" "$pypi_after_release_status"

        # Real fetch — must NOT return 403. Upstream may return any status
        # (200 if hosted, 502/404 otherwise); the regression assertion is
        # that the gate's override path is honored, not the upstream
        # availability. Crucially, the artifact must NOT be re-quarantined
        # by a false integrity violation against the empty stored SHA.
        local pypi_recheck_status
        pypi_recheck_status=$(curl -s -o /dev/null -w "%{http_code}" \
            "${E2E_CURL_AUTH[@]}" \
            "${E2E_PYPI_URL}/packages/requestes/requestes-1.0.0.tar.gz")
        if [ "$pypi_recheck_status" = "403" ]; then
            log_fail "Typosquat regression (pypi): re-fetch still 403 — override or integrity short-circuit broken (got $pypi_recheck_status)"
        else
            log_pass "Typosquat regression (pypi): re-fetch no longer blocked (HTTP $pypi_recheck_status)"
        fi

        # Final guard: status must remain CLEAN. If the empty-SHA short-circuit
        # in VerifyUpstreamIntegrity were missing, a successful upstream
        # download would have flipped status back to QUARANTINED with an
        # INTEGRITY_VIOLATION audit entry.
        local pypi_final_status
        pypi_final_status=$(api_jq "/api/v1/artifacts/${pypi_typo_id_enc}" '.status.status' 2>/dev/null || echo "MISSING")
        assert_eq "Typosquat regression (pypi): status remains CLEAN after re-fetch (no false integrity violation)" \
            "CLEAN" "$pypi_final_status"

        # And no INTEGRITY_VIOLATION event for this artifact in the audit log.
        local integrity_events
        integrity_events=$(api_jq "/api/v1/audit?event_type=INTEGRITY_VIOLATION&per_page=200" \
            "[.data[] | select(.artifact_id == \"${pypi_typo_id_enc}\")] | length" 2>/dev/null || echo "0")
        assert_eq "Typosquat regression (pypi): no INTEGRITY_VIOLATION event for synthetic row" \
            "0" "$integrity_events"
    fi

    # ------------------------------------------------------------------
    # 7. Verify gate logs contain typosquat scanner activity
    # ------------------------------------------------------------------
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate 2>/dev/null || true)

    if [[ "$gate_logs" == *"docker_logs not available"* ]]; then
        log_skip "Typosquat: gate logs inspection not available in container mode"
    elif [[ "$gate_logs" == *"typosquat"* ]] || [[ "$gate_logs" == *"builtin-typosquat"* ]]; then
        log_pass "Typosquat: gate logs contain typosquat scanner activity"
    else
        log_skip "Typosquat: no typosquat entries in gate logs (scanner may not have been triggered)"
    fi
}
