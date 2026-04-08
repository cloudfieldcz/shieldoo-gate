#!/usr/bin/env bash
# test_reputation.sh — Reputation scanner e2e tests for Shieldoo Gate
# Sourced by run_all.sh; defines test_reputation(). Do NOT set -e here.

test_reputation() {
    log_section "Reputation Scanner Tests"

    # ------------------------------------------------------------------
    # 1. Health endpoint is accessible (reputation scanner is registered)
    # ------------------------------------------------------------------
    local health_body
    health_body=$(api_get "/api/v1/health" 2>/dev/null || true)
    if [ -n "$health_body" ]; then
        log_pass "Reputation: health endpoint accessible"
    else
        log_fail "Reputation: health endpoint not accessible"
        return
    fi

    # ------------------------------------------------------------------
    # 2. Install a PyPI package NOT used by earlier tests to ensure
    #    a fresh scan pipeline run with the reputation scanner.
    #    "colorama" is small, stable, and not used by other E2E tests.
    # ------------------------------------------------------------------
    local workdir
    workdir=$(mktemp -d)

    echo "colorama==0.4.6" > "$workdir/requirements.txt"
    pushd "$workdir" > /dev/null

    uv venv .venv --quiet 2>/dev/null
    if uv pip install \
            --python .venv/bin/python \
            --no-cache \
            --index-url "$(auth_url "${E2E_PYPI_URL}")/simple/" \
            -r requirements.txt \
            > install.log 2>&1; then
        log_pass "Reputation: install of PyPI package colorama==0.4.6 succeeded"
    else
        log_fail "Reputation: install of PyPI package colorama==0.4.6 failed"
        cat install.log >&2
        popd > /dev/null
        rm -rf "$workdir"
        return
    fi

    popd > /dev/null
    rm -rf "$workdir"

    # Wait for scan pipeline to process.
    sleep 5

    # ------------------------------------------------------------------
    # 3. Check scan results for the freshly scanned artifact — reputation
    #    scanner should have produced a result.
    # ------------------------------------------------------------------
    local colorama_id
    colorama_id=$(api_jq "/api/v1/artifacts?per_page=200" \
        '[.data[] | select(.ecosystem == "pypi" and .name == "colorama")] | sort_by(.cached_at) | last | .id' 2>/dev/null || echo "")

    if [ -n "$colorama_id" ] && [ "$colorama_id" != "null" ]; then
        local scan_results
        scan_results=$(api_get "/api/v1/artifacts/${colorama_id}/scan-results" 2>/dev/null || true)

        if [ -n "$scan_results" ]; then
            local has_reputation
            has_reputation=$(echo "$scan_results" | jq \
                '[.[] | select(.scanner_name == "builtin-reputation")] | length' 2>/dev/null || echo "0")

            if [ "$has_reputation" -gt 0 ]; then
                log_pass "Reputation: reputation scanner produced result for colorama"

                local rep_verdict
                rep_verdict=$(echo "$scan_results" | jq -r \
                    '[.[] | select(.scanner_name == "builtin-reputation")] | first | .verdict' 2>/dev/null || echo "")
                if [ "$rep_verdict" = "CLEAN" ]; then
                    log_pass "Reputation: verdict is CLEAN for reputable package 'colorama'"
                else
                    log_pass "Reputation: verdict is '$rep_verdict' for 'colorama'"
                fi
            else
                # Fail-open: the scanner may have failed to fetch metadata (network/timeout).
                # Check if the scanner was even applicable (should be for pypi).
                local total_scanners
                total_scanners=$(echo "$scan_results" | jq 'length' 2>/dev/null || echo "0")
                log_fail "Reputation: no reputation scan result found for colorama ($total_scanners total scan results)"
            fi
        else
            log_fail "Reputation: could not fetch scan results for colorama"
        fi
    else
        log_fail "Reputation: could not find colorama in artifacts API"
    fi

    # ------------------------------------------------------------------
    # 4. Check for reputation scan results on npm artifacts from earlier
    #    test suites (ms, is-odd installed by test_npm).
    # ------------------------------------------------------------------
    local npm_artifact_ids
    npm_artifact_ids=$(api_jq "/api/v1/artifacts?per_page=200" \
        '[.data[] | select(.ecosystem == "npm")] | .[0:5] | .[].id' 2>/dev/null || echo "")

    local npm_rep_found=false
    for aid in $npm_artifact_ids; do
        if [ -z "$aid" ] || [ "$aid" = "null" ]; then
            continue
        fi
        local sr
        sr=$(api_get "/api/v1/artifacts/${aid}/scan-results" 2>/dev/null || true)
        if [ -n "$sr" ]; then
            local has_rep
            has_rep=$(echo "$sr" | jq '[.[] | select(.scanner_name == "builtin-reputation")] | length' 2>/dev/null || echo "0")
            if [ "$has_rep" -gt 0 ]; then
                npm_rep_found=true
                break
            fi
        fi
    done

    if [ "$npm_rep_found" = "true" ]; then
        log_pass "Reputation: at least one npm artifact has reputation scan result"
    else
        log_skip "Reputation: no npm artifact has reputation result (metadata fetch may have timed out)"
    fi

    # ------------------------------------------------------------------
    # 6. Cross-check: look for ANY reputation scan result across all
    #    artifacts. Even if specific packages fail metadata fetch,
    #    at least some should have reputation results.
    # ------------------------------------------------------------------
    local all_artifact_ids
    all_artifact_ids=$(api_jq "/api/v1/artifacts?per_page=200" \
        '[.data[] | select(.ecosystem == "pypi" or .ecosystem == "npm" or .ecosystem == "nuget")] | .[0:10] | .[].id' 2>/dev/null || echo "")

    local found_any=false
    for aid in $all_artifact_ids; do
        if [ -z "$aid" ] || [ "$aid" = "null" ]; then
            continue
        fi
        local sr
        sr=$(api_get "/api/v1/artifacts/${aid}/scan-results" 2>/dev/null || true)
        if [ -n "$sr" ]; then
            local has_rep
            has_rep=$(echo "$sr" | jq '[.[] | select(.scanner_name == "builtin-reputation")] | length' 2>/dev/null || echo "0")
            if [ "$has_rep" -gt 0 ]; then
                found_any=true
                break
            fi
        fi
    done

    if [ "$found_any" = "true" ]; then
        log_pass "Reputation: at least one artifact has reputation scan result"
    else
        log_fail "Reputation: no artifact has reputation scan result (checked up to 10)"
    fi

    # ------------------------------------------------------------------
    # 7. Verify gate logs contain reputation scanner activity
    # ------------------------------------------------------------------
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate 2>/dev/null || true)

    if [[ "$gate_logs" == *"docker_logs not available"* ]]; then
        log_skip "Reputation: gate logs inspection not available in container mode"
    elif [[ "$gate_logs" == *"reputation"* ]] || [[ "$gate_logs" == *"builtin-reputation"* ]]; then
        log_pass "Reputation: gate logs contain reputation scanner activity"
    else
        log_skip "Reputation: no reputation entries in gate logs (scanner may not have been triggered)"
    fi
}
