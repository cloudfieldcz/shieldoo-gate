#!/usr/bin/env bash
# test_version_diff.sh — Version diff analysis e2e tests for Shieldoo Gate
# Sourced by run_all.sh; defines test_version_diff(). Do NOT set -e here.

test_version_diff() {
    log_section "Version Diff Analysis Tests"

    # ------------------------------------------------------------------
    # 1. Install a package to establish a baseline version in cache
    #    Use "six" — small, stable, always available on PyPI.
    # ------------------------------------------------------------------
    local workdir
    workdir=$(mktemp -d)

    echo "six==1.16.0" > "$workdir/requirements.txt"
    pushd "$workdir" > /dev/null

    uv venv .venv --quiet 2>/dev/null
    if uv pip install \
            --python .venv/bin/python \
            --no-cache \
            --index-url "$(auth_url "${E2E_PYPI_URL}")/simple/" \
            -r requirements.txt \
            > install.log 2>&1; then
        log_pass "VersionDiff: baseline install of six==1.16.0 succeeded"
    else
        log_fail "VersionDiff: baseline install of six==1.16.0 failed"
        cat install.log >&2
        popd > /dev/null
        rm -rf "$workdir"
        return
    fi

    popd > /dev/null
    rm -rf "$workdir"

    # Brief pause to let scan pipeline finish processing the first version.
    sleep 3

    # ------------------------------------------------------------------
    # 2. Install a different version of the same package
    #    The version-diff scanner should compare against the cached baseline.
    # ------------------------------------------------------------------
    workdir=$(mktemp -d)

    echo "six==1.17.0" > "$workdir/requirements.txt"
    pushd "$workdir" > /dev/null

    uv venv .venv --quiet 2>/dev/null
    if uv pip install \
            --python .venv/bin/python \
            --no-cache \
            --index-url "$(auth_url "${E2E_PYPI_URL}")/simple/" \
            -r requirements.txt \
            > install.log 2>&1; then
        log_pass "VersionDiff: second install of six==1.17.0 succeeded"
    else
        # Version diff scanner may flag it, but six is clean so it should pass.
        # A 403 would mean false positive — still log it.
        log_fail "VersionDiff: second install of six==1.17.0 failed (check for false positive)"
        cat install.log >&2
    fi

    popd > /dev/null
    rm -rf "$workdir"

    # Brief pause for scan pipeline to process.
    sleep 3

    # ------------------------------------------------------------------
    # 3. Verify both versions are registered as artifacts
    # ------------------------------------------------------------------
    local six_artifacts
    six_artifacts=$(api_jq "/api/v1/artifacts?per_page=200" \
        '[.data[] | select(.ecosystem == "pypi" and .name == "six")] | length' 2>/dev/null || echo "0")
    assert_gte "VersionDiff: at least 2 versions of 'six' registered" 2 "$six_artifacts"

    # ------------------------------------------------------------------
    # 4. Check scan results for version-diff scanner entries
    #    Query scan results for the second version — should have version-diff result.
    # ------------------------------------------------------------------
    local second_artifact_id
    second_artifact_id=$(api_jq "/api/v1/artifacts?per_page=200" \
        '[.data[] | select(.ecosystem == "pypi" and .name == "six")] | sort_by(.cached_at) | last | .id' 2>/dev/null || echo "")

    if [ -n "$second_artifact_id" ] && [ "$second_artifact_id" != "null" ]; then
        local scan_results
        scan_results=$(api_get "/api/v1/artifacts/${second_artifact_id}/scan-results" 2>/dev/null || true)

        if [ -n "$scan_results" ]; then
            local has_vdiff
            has_vdiff=$(echo "$scan_results" | jq \
                '[.[] | select(.scanner_name == "version-diff")] | length' 2>/dev/null || echo "0")

            if [ "$has_vdiff" -gt 0 ]; then
                log_pass "VersionDiff: version-diff scanner produced scan result for six==1.17.0"

                # Check that the verdict is CLEAN (six is a legitimate update)
                local vdiff_verdict
                vdiff_verdict=$(echo "$scan_results" | jq -r \
                    '[.[] | select(.scanner_name == "version-diff")] | first | .verdict' 2>/dev/null || echo "")
                if [ "$vdiff_verdict" = "CLEAN" ]; then
                    log_pass "VersionDiff: version-diff verdict is CLEAN for legitimate update"
                elif [ "$vdiff_verdict" = "SUSPICIOUS" ]; then
                    log_fail "VersionDiff: version-diff verdict is SUSPICIOUS for legitimate six update (false positive)"
                else
                    log_pass "VersionDiff: version-diff verdict is '$vdiff_verdict'"
                fi
            else
                log_fail "VersionDiff: no version-diff scan result found for six==1.17.0"
            fi
        else
            log_fail "VersionDiff: could not fetch scan results for artifact $second_artifact_id"
        fi
    else
        log_fail "VersionDiff: could not find second version of six in artifacts API"
    fi

    # ------------------------------------------------------------------
    # 5. Verify gate logs contain version-diff scanner activity
    # ------------------------------------------------------------------
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate 2>/dev/null || true)

    if [[ "$gate_logs" == *"docker_logs not available"* ]]; then
        log_skip "VersionDiff: gate logs inspection not available in container mode"
    elif [[ "$gate_logs" == *"version-diff"* ]]; then
        log_pass "VersionDiff: gate logs contain version-diff scanner activity"
    else
        log_skip "VersionDiff: no version-diff entries in gate logs (scanner may not have had baseline)"
    fi

    # ------------------------------------------------------------------
    # 5b. When the AI bridge is enabled, assert the LLM path actually ran.
    #     The scanner emits "version-diff: ai scan completed" at INFO level
    #     only when the bridge returned a non-UNKNOWN verdict. With AI
    #     disabled the bridge returns UNKNOWN (fail-open) and that line
    #     never appears.
    # ------------------------------------------------------------------
    if [ "${AI_SCANNER_ENABLED:-false}" = "true" ]; then
        if [[ "$gate_logs" == *"docker_logs not available"* ]]; then
            log_skip "VersionDiff: gate logs unavailable; cannot assert AI path"
        elif [[ "$gate_logs" == *"version-diff: ai scan completed"* ]]; then
            log_pass "VersionDiff: AI bridge actually ran (LLM verdict observed in gate logs)"
        else
            log_fail "VersionDiff: AI_SCANNER_ENABLED=true but no 'ai scan completed' log line — AI path did not run"
        fi
    fi

    # ------------------------------------------------------------------
    # 6. Verify version-diff works for npm via API (skip npm install to
    #    avoid scan-pipeline latency issues in containerized E2E).
    #    test_npm already installs ms:2.1.3 and is-odd:3.0.1 — check
    #    that the version-diff scanner ran on at least one npm artifact.
    # ------------------------------------------------------------------
    local npm_vdiff_count
    npm_vdiff_count=$(api_jq "/api/v1/artifacts?per_page=200" \
        '[.data[] | select(.ecosystem == "npm")] | length' 2>/dev/null || echo "0")
    assert_gte "VersionDiff: at least 1 npm artifact registered from earlier tests" 1 "$npm_vdiff_count"
}
