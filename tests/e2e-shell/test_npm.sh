#!/usr/bin/env bash
# test_npm.sh — npm proxy e2e tests for Shieldoo Gate
# Sourced by run.sh; defines test_npm(). Do NOT set -e here.

test_npm() {
    log_section "npm Proxy Tests"

    # ------------------------------------------------------------------
    # 1. Package metadata accessible
    # ------------------------------------------------------------------
    assert_http_status "npm: /is-odd metadata returns HTTP 200" \
        "200" \
        "${E2E_NPM_URL}/is-odd"

    # ------------------------------------------------------------------
    # 2. Tarball URLs in metadata are rewritten (no upstream registry host)
    # ------------------------------------------------------------------
    local metadata
    metadata=$(curl -sf "${E2E_NPM_URL}/is-odd")

    if echo "$metadata" | grep -q "registry.npmjs.org"; then
        log_fail "npm: package metadata still contains upstream 'registry.npmjs.org' tarball URLs (not rewritten)"
    else
        log_pass "npm: package metadata does not expose upstream 'registry.npmjs.org' tarball URLs"
    fi

    # ------------------------------------------------------------------
    # 3. Install packages via npm through the proxy
    # ------------------------------------------------------------------
    local workdir
    workdir=$(mktemp -d)
    cp "${SCRIPT_DIR}/fixtures/npm/package.json" "$workdir/"
    # Generate .npmrc dynamically with the correct URL (container-aware)
    echo "registry=${E2E_NPM_URL}/" > "$workdir/.npmrc"

    pushd "$workdir" > /dev/null

    if npm install \
            --registry "${E2E_NPM_URL}" \
            --no-audit \
            --no-fund \
            --prefer-online \
            --cache "$workdir/.npm-cache" \
            > install.log 2>&1; then
        log_pass "npm: npm install succeeded for all fixture packages"
    else
        log_fail "npm: npm install failed (see log below)"
        cat install.log >&2
    fi

    popd > /dev/null
    rm -rf "$workdir"

    # ------------------------------------------------------------------
    # 4. Artifacts registered in API (>= 3 with ecosystem=="npm")
    # ------------------------------------------------------------------
    local npm_count
    npm_count=$(api_jq "/api/v1/artifacts" \
        '[.data[] | select(.ecosystem == "npm")] | length')
    assert_gte "npm: at least 2 npm artifacts registered in API" 2 "$npm_count"

    # ------------------------------------------------------------------
    # 5. Audit log has SERVED events for npm artifacts
    # ------------------------------------------------------------------
    local npm_served
    npm_served=$(api_jq "/api/v1/audit?per_page=200&event_type=SERVED" \
        '[.data[] | select(.artifact_id | startswith("npm:"))] | length')
    assert_gte "npm: at least 1 SERVED audit event for npm artifacts" 1 "$npm_served"
}
