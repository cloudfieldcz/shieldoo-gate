#!/usr/bin/env bash
# test_pypi.sh — PyPI proxy e2e tests for Shieldoo Gate
# Sourced by run.sh; defines test_pypi(). Do NOT set -e here.

test_pypi() {
    log_section "PyPI Proxy Tests"

    # ------------------------------------------------------------------
    # 0. Negative test: unauthenticated request must return 401 when auth enabled
    # ------------------------------------------------------------------
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" = "true" ]; then
        local noauth_status
        noauth_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_PYPI_URL}/simple/")
        assert_eq "PyPI: unauthenticated request returns 401" "401" "$noauth_status"
    fi

    # ------------------------------------------------------------------
    # 1. Simple index is accessible
    # ------------------------------------------------------------------
    assert_http_status "PyPI: /simple/ returns HTTP 200" \
        "200" \
        "${E2E_PYPI_URL}/simple/"

    # ------------------------------------------------------------------
    # 2. Package page has rewritten URLs
    # ------------------------------------------------------------------
    local six_page
    six_page=$(curl -sf "${E2E_CURL_AUTH[@]}" "${E2E_PYPI_URL}/simple/six/")

    # Use bash built-in pattern matching instead of echo|grep -q to avoid
    # SIGPIPE failures under set -o pipefail (large responses + grep -q).
    if [[ "$six_page" == *"/packages/"* ]]; then
        log_pass "PyPI: package page contains rewritten /packages/ path"
    else
        log_fail "PyPI: package page does not contain /packages/ path"
    fi

    if [[ "$six_page" == *"files.pythonhosted.org"* ]]; then
        log_fail "PyPI: package page still contains upstream 'files.pythonhosted.org' URL (not rewritten)"
    else
        log_pass "PyPI: package page does not expose upstream 'files.pythonhosted.org'"
    fi

    # ------------------------------------------------------------------
    # 3. Install packages via uv through the proxy
    # ------------------------------------------------------------------
    local workdir
    workdir=$(mktemp -d)
    cp "${SCRIPT_DIR}/fixtures/pypi/requirements.txt" "$workdir/"

    pushd "$workdir" > /dev/null

    uv venv .venv --quiet 2>/dev/null
    if uv pip install \
            --python .venv/bin/python \
            --no-cache \
            --index-url "$(auth_url "${E2E_PYPI_URL}")/simple/" \
            -r requirements.txt \
            > install.log 2>&1; then
        log_pass "PyPI: uv pip install succeeded for all fixture packages"
    else
        log_fail "PyPI: uv pip install failed (see log below)"
        cat install.log >&2
    fi

    popd > /dev/null
    rm -rf "$workdir"

    # ------------------------------------------------------------------
    # 4. Artifacts registered in API (>= 3 with ecosystem=="pypi")
    # ------------------------------------------------------------------
    local pypi_count
    pypi_count=$(api_jq "/api/v1/artifacts" \
        '[.data[] | select(.ecosystem == "pypi")] | length')
    assert_gte "PyPI: at least 3 pypi artifacts registered in API" 3 "$pypi_count"

    # ------------------------------------------------------------------
    # 5. Audit log has SERVED events for pypi artifacts
    # ------------------------------------------------------------------
    local pypi_served
    pypi_served=$(api_jq "/api/v1/audit?per_page=200&event_type=SERVED" \
        '[.data[] | select(.artifact_id | startswith("pypi:"))] | length')
    assert_gte "PyPI: at least 1 SERVED audit event for pypi artifacts" 1 "$pypi_served"

    # ------------------------------------------------------------------
    # 6. Gate logs contain scan pipeline entries
    #    (only when docker_logs can access real container logs)
    # ------------------------------------------------------------------
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate 2>/dev/null)

    if [[ "$gate_logs" == *"docker_logs not available"* ]]; then
        log_skip "PyPI: gate logs inspection not available in container mode"
    elif [[ "$gate_logs" == *"scan result"* ]] || [[ "$gate_logs" == *"policy decision"* ]]; then
        log_pass "PyPI: gate logs contain scan pipeline entries"
    else
        log_fail "PyPI: gate logs do not contain 'scan result' or 'policy decision' entries"
    fi
}
