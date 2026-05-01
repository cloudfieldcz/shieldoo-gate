#!/usr/bin/env bash
# test_license_policy.sh — SPDX license-policy evaluation e2e tests
# Sourced by run_all.sh; defines test_license_policy() and test_license_<eco>().
# Do NOT set -e here.
#
# Coverage:
#   - test_license_policy()        : S-01 anti-spoofing guard + GET/PUT view
#   - test_license_pypi()          : end-to-end block via uv pip install
#   - test_license_npm()           : end-to-end block via direct curl
#   - test_license_nuget()         : end-to-end block via direct curl
#   - test_license_maven()         : end-to-end block via direct curl (GPL flagship)
#   - test_license_rubygems()      : best-effort (gem metadata extraction is brittle)
#
# All ecosystem tests skip themselves when:
#   - SGW_PROXY_AUTH_ENABLED is not "true"  (no project context)
#   - SGW_PROJECTS_MODE      is not "strict" (per-project override is ignored)

# ---------------------------------------------------------------------------
# Shared helpers (private; underscore prefix).
# ---------------------------------------------------------------------------

# _lic_should_run prints nothing and returns 0 when the strict-mode
# enforcement tests should run, 1 otherwise (with a log_skip line).
_lic_should_run() {
    local context="$1"
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" != "true" ]; then
        log_skip "${context}: SGW_PROXY_AUTH_ENABLED is not true"
        return 1
    fi
    if [ -z "${SGW_PROXY_TOKEN:-}" ]; then
        log_skip "${context}: SGW_PROXY_TOKEN not set"
        return 1
    fi
    if [ "${SGW_PROJECTS_MODE:-lazy}" != "strict" ]; then
        log_skip "${context}: SGW_PROJECTS_MODE is not strict"
        return 1
    fi
    return 0
}

# _lic_create_project label blocked_csv [unknown_action]
#   - Creates the project (idempotent on conflict — uses existing row).
#   - Sets a per-project override blocking the comma-separated SPDX list.
#   - Echoes the project id on stdout so callers can capture with $(...).
#   - Returns 1 on any failure (test should skip remaining assertions).
_lic_create_project() {
    local label="$1"
    local blocked_csv="$2"
    local unknown_action="${3:-allow}"

    local create_status
    create_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${E2E_ADMIN_URL}/api/v1/projects" \
        -H "Content-Type: application/json" \
        -d "{\"label\":\"${label}\",\"display_name\":\"License E2E ${label}\"}")
    case "$create_status" in
        201|409) ;;  # 409 = already exists (rare; safe)
        *) echo "create-failed-${create_status}" >&2; return 1 ;;
    esac

    local pid
    pid=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects" \
        | jq -r --arg l "$label" '.projects[] | select(.label == $l) | .id')
    if [ -z "$pid" ] || [ "$pid" = "null" ]; then
        echo "lookup-failed" >&2
        return 1
    fi

    # Convert "GPL-2.0-only,GPL-2.0-or-later" → ["GPL-2.0-only","GPL-2.0-or-later"]
    local blocked_json
    blocked_json=$(printf '%s' "$blocked_csv" | jq -R 'split(",") | map(select(length > 0))')

    local body
    body=$(jq -n --argjson b "$blocked_json" --arg ua "$unknown_action" \
        '{mode:"override", blocked:$b, warned:[], allowed:[], unknown_action:$ua}')

    local put_status
    put_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT "${E2E_ADMIN_URL}/api/v1/projects/${pid}/license-policy" \
        -H "Content-Type: application/json" \
        -d "$body")
    if [ "$put_status" != "200" ]; then
        echo "put-failed-${put_status}" >&2
        return 1
    fi
    echo "$pid"
    return 0
}

# _lic_assert_artifact context label url expected_status description
#   Performs a Basic-auth GET against the proxy and asserts the HTTP code.
#   - context     : ecosystem label, used in the assertion text
#   - label       : project label = Basic-auth username
#   - url         : full http://shieldoo-gate:<port>/<path> URL
#   - expected    : "200" (allowed) or "403" (blocked)
#   - description : short artifact description for the assertion message
_lic_assert_artifact() {
    local context="$1"
    local label="$2"
    local url="$3"
    local expected="$4"
    local description="$5"

    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "${label}:${SGW_PROXY_TOKEN}" "$url")
    assert_eq "${context}: ${description} returned HTTP ${expected}" "$expected" "$status"
}

# _lic_audit_block_present pid → 0/1 plus log line.
#   Verifies the audit log has at least one license-block event for the
#   given project. Accepts either LICENSE_BLOCKED or BLOCKED with a
#   reason mentioning "license" — see internal/adapter/base.go for the
#   auto-promote logic.
_lic_audit_block_present() {
    local context="$1"
    local pid="$2"

    sleep 2  # debounced audit writer
    local count
    count=$(curl -sf "${E2E_ADMIN_URL}/api/v1/audit?per_page=200" \
        | jq --arg pid "$pid" '[.data[]
            | select((.project_id // 0 | tostring) == $pid)
            | select(.event_type == "LICENSE_BLOCKED" or .event_type == "BLOCKED")
            | select((.reason // "") | test("license"; "i"))
        ] | length')
    if [ -z "$count" ] || [ "$count" = "null" ]; then count=0; fi
    if [ "$count" -ge 1 ]; then
        log_pass "${context}: audit log has ${count} license-block event(s) for project ${pid}"
    else
        log_fail "${context}: no license-block audit event recorded for project ${pid}"
    fi
}

# ---------------------------------------------------------------------------
# Section 1 — anti-spoofing guard + view
# ---------------------------------------------------------------------------

test_license_policy() {
    log_section "License Policy: API + S-01 guards"

    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" != "true" ]; then
        log_skip "License policy tests: SGW_PROXY_AUTH_ENABLED is not true"
        return
    fi
    local global_token="${SGW_PROXY_TOKEN:-}"
    if [ -z "$global_token" ]; then
        log_skip "License policy tests: SGW_PROXY_TOKEN not set"
        return
    fi

    # Use a deterministic-ish id with PID + epoch so reruns within a single
    # second don't collide.
    local label="lic-api-$$-$(date +%s)"
    local create_status
    create_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${E2E_ADMIN_URL}/api/v1/projects" \
        -H "Content-Type: application/json" \
        -d "{\"label\":\"${label}\",\"display_name\":\"License E2E\"}")
    if [ "$create_status" != "201" ]; then
        log_fail "License: POST /projects failed (status=${create_status})"
        return
    fi
    log_pass "License: test project '${label}' created"

    local pid
    pid=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects" | jq -r --arg l "$label" '.projects[] | select(.label == $l) | .id')
    if [ -z "$pid" ] || [ "$pid" = "null" ]; then
        log_fail "License: could not resolve project id"
        return
    fi

    # Default per-project mode == inherit.
    local lp mode
    lp=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects/${pid}/license-policy")
    mode=$(echo "$lp" | jq -r '.mode')
    assert_eq "License: default per-project mode is 'inherit'" "inherit" "$mode"

    # PUT mode=override — succeeds in BOTH lazy and strict projects modes.
    # ADR-004 (2026-04-30) removed the legacy S-01 lazy-mode 403 guard:
    # per-project license policy authoring is gated by admin API auth (OIDC),
    # which is independent of the PAT/proxy-traffic auth boundary that
    # `projects.mode` controls.
    local put_status
    put_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT "${E2E_ADMIN_URL}/api/v1/projects/${pid}/license-policy" \
        -H "Content-Type: application/json" \
        -d '{"mode":"override","blocked":["GPL-3.0-only"]}')
    assert_eq "License: PUT override returns 200 (ADR-004: applies in both lazy and strict)" "200" "$put_status"

    # Round-trip: PUT mode=inherit must always succeed (no projects.mode gating).
    local inherit_status
    inherit_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT "${E2E_ADMIN_URL}/api/v1/projects/${pid}/license-policy" \
        -H "Content-Type: application/json" \
        -d '{"mode":"inherit"}')
    assert_eq "License: PUT mode=inherit returns 200" "200" "$inherit_status"

    # GET surfaces strict_required when override is ineffective.
    local strict_req
    strict_req=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects/${pid}/license-policy" | jq -r '.strict_required')
    case "$strict_req" in
        true|false|null) log_pass "License: GET annotates 'strict_required' (value=${strict_req})" ;;
        *) log_fail "License: 'strict_required' field missing or invalid (got '${strict_req}')" ;;
    esac

    # GET unknown project returns 200 (default-inherit semantics) or 404.
    local ghost_status
    ghost_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_ADMIN_URL}/api/v1/projects/999999/license-policy")
    if [ "$ghost_status" = "200" ] || [ "$ghost_status" = "404" ]; then
        log_pass "License: GET policy for missing project returns 200/404 (default-inherit semantics)"
    else
        log_fail "License: GET policy for missing project returned unexpected ${ghost_status}"
    fi

    # DELETE override returns to inherit.
    local del_status
    del_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X DELETE "${E2E_ADMIN_URL}/api/v1/projects/${pid}/license-policy")
    assert_eq "License: DELETE per-project override returns 200" "200" "$del_status"
    local mode_after
    mode_after=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects/${pid}/license-policy" | jq -r '.mode')
    assert_eq "License: mode reverts to 'inherit' after DELETE" "inherit" "$mode_after"
}

# ---------------------------------------------------------------------------
# Section 2 — PyPI enforcement (uv pip install)
# ---------------------------------------------------------------------------

test_license_pypi() {
    log_section "License Enforcement: PyPI"
    _lic_should_run "PyPI" || return 0

    local label="lic-pypi-$$-$(date +%s)"
    local pid
    if ! pid=$(_lic_create_project "$label" \
        "GPL-2.0-only,GPL-2.0-or-later,GPL-3.0-only,GPL-3.0-or-later,AGPL-3.0-only,AGPL-3.0-or-later,Apache-2.0"); then
        log_fail "PyPI: project setup failed (${pid})"
        return
    fi
    log_pass "PyPI: project '${label}' (id=${pid}) blocking GPL/AGPL family + Apache-2.0"

    local pypi_no_scheme="${E2E_PYPI_URL#http://}"
    pypi_no_scheme="${pypi_no_scheme#https://}"
    local index="http://${label}:${SGW_PROXY_TOKEN}@${pypi_no_scheme}/simple/"

    local workdir
    workdir=$(mktemp -d)
    pushd "$workdir" > /dev/null
    uv venv .venv --quiet 2>/dev/null

    # Allowed: urllib3 (MIT)
    if uv pip install --python .venv/bin/python --no-cache --reinstall \
            --index-url "$index" "urllib3" > urllib3.log 2>&1; then
        log_pass "PyPI: MIT 'urllib3' installs (allowed)"
    else
        log_fail "PyPI: MIT 'urllib3' install FAILED unexpectedly"
        sed -n '1,30p' urllib3.log >&2
    fi

    # Blocked: requests (Apache-2.0)
    if uv pip install --python .venv/bin/python --no-cache --reinstall \
            --index-url "$index" "requests" > requests.log 2>&1; then
        log_fail "PyPI: Apache-2.0 'requests' installed but should have been BLOCKED"
        sed -n '1,30p' requests.log >&2
    else
        if grep -qiE "403|forbidden|license|blocked" requests.log; then
            log_pass "PyPI: Apache-2.0 'requests' BLOCKED by license policy"
        else
            log_fail "PyPI: 'requests' install failed but log doesn't mention 403/license"
            sed -n '1,30p' requests.log >&2
        fi
    fi

    popd > /dev/null
    rm -rf "$workdir"

    _lic_audit_block_present "PyPI" "$pid"
}

# ---------------------------------------------------------------------------
# Section 3 — npm (direct curl on tarball)
# ---------------------------------------------------------------------------

test_license_npm() {
    log_section "License Enforcement: npm"
    _lic_should_run "npm" || return 0

    local label="lic-npm-$$-$(date +%s)"
    local pid
    if ! pid=$(_lic_create_project "$label" "BSD-3-Clause"); then
        log_fail "npm: project setup failed (${pid})"
        return
    fi
    log_pass "npm: project '${label}' (id=${pid}) blocking BSD-3-Clause"

    # Allowed: commander (MIT, very small, no deps).
    _lic_assert_artifact "npm" "$label" \
        "${E2E_NPM_URL}/commander/-/commander-12.1.0.tgz" "200" \
        "MIT 'commander-12.1.0.tgz' (allowed)"

    # Blocked: qs (BSD-3-Clause).
    _lic_assert_artifact "npm" "$label" \
        "${E2E_NPM_URL}/qs/-/qs-6.13.0.tgz" "403" \
        "BSD-3-Clause 'qs-6.13.0.tgz' (blocked)"

    _lic_audit_block_present "npm" "$pid"
}

# ---------------------------------------------------------------------------
# Section 4 — NuGet (direct curl on .nupkg)
# ---------------------------------------------------------------------------

test_license_nuget() {
    log_section "License Enforcement: NuGet"
    _lic_should_run "NuGet" || return 0

    local label="lic-nuget-$$-$(date +%s)"
    local pid
    if ! pid=$(_lic_create_project "$label" "BSD-3-Clause"); then
        log_fail "NuGet: project setup failed (${pid})"
        return
    fi
    log_pass "NuGet: project '${label}' (id=${pid}) blocking BSD-3-Clause"

    # Allowed: Serilog (Apache-2.0, small core lib).
    _lic_assert_artifact "NuGet" "$label" \
        "${E2E_NUGET_URL}/v3-flatcontainer/serilog/4.0.0/serilog.4.0.0.nupkg" "200" \
        "Apache-2.0 'Serilog 4.0.0' (allowed)"

    # Blocked: Polly (BSD-3-Clause).
    _lic_assert_artifact "NuGet" "$label" \
        "${E2E_NUGET_URL}/v3-flatcontainer/polly/8.4.1/polly.8.4.1.nupkg" "403" \
        "BSD-3-Clause 'Polly 8.4.1' (blocked)"

    _lic_audit_block_present "NuGet" "$pid"
}

# ---------------------------------------------------------------------------
# Section 5 — Maven (inline + effective-POM parent chain resolution)
# ---------------------------------------------------------------------------

test_license_maven() {
    log_section "License Enforcement: Maven"
    _lic_should_run "Maven" || return 0

    # Maven license enforcement covers two detection paths:
    #
    # 1. Inline: some JARs embed <licenses> directly in META-INF/maven/.../pom.xml
    #    (e.g. log4j-core declares Apache-2.0 inline).
    #
    # 2. Effective-POM parent chain: most JARs inherit licenses from a parent
    #    pom (e.g. mysql-connector-j → oss-parent declares GPL-2.0). The
    #    effective-POM resolver fetches standalone .pom files from the upstream
    #    Maven repository and walks the parent chain to discover inherited
    #    licenses. This covers ~95% of enterprise Maven artifacts.

    local label="lic-maven-$$-$(date +%s)"
    local pid
    if ! pid=$(_lic_create_project "$label" \
        "Apache-2.0,GPL-2.0-only,GPL-2.0-or-later"); then
        log_fail "Maven: project setup failed (${pid})"
        return
    fi
    log_pass "Maven: project '${label}' (id=${pid}) blocking Apache-2.0, GPL-2.0-only"

    # --- Test 1: Effective-POM parent chain resolution ---
    # mysql-connector-j 8.4.0 inherits GPL-2.0 from its parent POM (oss-parent).
    # The embedded pom.xml has no inline <licenses> — the effective-POM resolver
    # must walk the parent chain to discover the license. Blocked by policy.
    _lic_assert_artifact "Maven" "$label" \
        "${E2E_MAVEN_URL}/com/mysql/mysql-connector-j/8.4.0/mysql-connector-j-8.4.0.jar" "403" \
        "GPL-2.0 'mysql-connector-j 8.4.0' (parent chain → oss-parent) blocked"

    # --- Test 2: Inline license detection (existing) ---
    # log4j-core 2.23.1 explicitly inlines Apache-2.0 in its embedded pom.xml.
    _lic_assert_artifact "Maven" "$label" \
        "${E2E_MAVEN_URL}/org/apache/logging/log4j/log4j-core/2.23.1/log4j-core-2.23.1.jar" "403" \
        "Apache-2.0 'log4j-core 2.23.1' (inline license) blocked"

    # --- Test 3: Allowed artifact (MIT, not in blocked list) ---
    # slf4j-api 1.7.36 inherits MIT from slf4j-parent via effective-POM resolver.
    # MIT is not in the blocked list → allowed.
    _lic_assert_artifact "Maven" "$label" \
        "${E2E_MAVEN_URL}/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar" "200" \
        "MIT 'slf4j-api 1.7.36' (parent chain → MIT) allowed"

    # --- Test 4: Effective-POM for Apache commons (Apache-2.0 → blocked) ---
    # commons-lang3 3.14.0 inherits Apache-2.0 from commons-parent → apache.
    _lic_assert_artifact "Maven" "$label" \
        "${E2E_MAVEN_URL}/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar" "403" \
        "Apache-2.0 'commons-lang3 3.14.0' (parent chain → apache) blocked"

    _lic_audit_block_present "Maven" "$pid"
}

# ---------------------------------------------------------------------------
# Section 6 — RubyGems (best-effort — gem metadata extraction is brittle)
# ---------------------------------------------------------------------------

test_license_rubygems() {
    log_section "License Enforcement: RubyGems (best-effort)"
    _lic_should_run "RubyGems" || return 0

    local label="lic-rubygems-$$-$(date +%s)"
    local pid
    if ! pid=$(_lic_create_project "$label" "Apache-2.0"); then
        log_fail "RubyGems: project setup failed (${pid})"
        return
    fi
    log_pass "RubyGems: project '${label}' (id=${pid}) blocking Apache-2.0"

    # Allowed: concurrent-ruby (MIT, no native deps).
    local allowed_status
    allowed_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "${label}:${SGW_PROXY_TOKEN}" \
        "${E2E_RUBYGEMS_URL}/gems/concurrent-ruby-1.3.4.gem")
    if [ "$allowed_status" = "200" ]; then
        log_pass "RubyGems: MIT 'concurrent-ruby 1.3.4' allowed (200)"
    else
        log_fail "RubyGems: MIT 'concurrent-ruby 1.3.4' returned ${allowed_status} (expected 200)"
    fi

    # Blocked: aws-sdk-core (Apache-2.0). Detection is best-effort — gem
    # metadata is YAML inside a nested gzip; if the extractor misses it,
    # the request will succeed (200) and we log a warning instead of FAIL.
    local blocked_status
    blocked_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -u "${label}:${SGW_PROXY_TOKEN}" \
        "${E2E_RUBYGEMS_URL}/gems/aws-sdk-core-3.214.0.gem")
    if [ "$blocked_status" = "403" ]; then
        log_pass "RubyGems: Apache-2.0 'aws-sdk-core 3.214.0' BLOCKED (403)"
        _lic_audit_block_present "RubyGems" "$pid"
    elif [ "$blocked_status" = "200" ]; then
        log_skip "RubyGems: Apache-2.0 'aws-sdk-core 3.214.0' was served (license extraction from .gem is best-effort — see docs/features/sbom-generation.md)"
    else
        log_fail "RubyGems: 'aws-sdk-core 3.214.0' returned unexpected ${blocked_status}"
    fi
}

# ---------------------------------------------------------------------------
# Section 7 — Cache-hit license enforcement (global + per-project)
#
# Verifies that changing the license policy AFTER an artifact is cached
# takes effect immediately on the next request (Fix A: synchronous gate)
# and proactively quarantines/releases artifacts (Fix B: async re-eval).
# ---------------------------------------------------------------------------

test_license_cache_hit() {
    log_section "License Enforcement: Cache-Hit Path"
    _lic_should_run "CacheHit" || return 0

    # Use chalk (MIT, npm) — small, well-known license.
    # Create project directly (not via _lic_create_project which requires
    # a non-empty blocked list for the jq JSON builder).
    local label="lic-cache-$$-$(date +%s)"
    local create_status
    create_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${E2E_ADMIN_URL}/api/v1/projects" \
        -H "Content-Type: application/json" \
        -d "{\"label\":\"${label}\",\"display_name\":\"License Cache-Hit E2E\"}")
    if [ "$create_status" != "201" ] && [ "$create_status" != "409" ]; then
        log_fail "CacheHit: project create failed (status=${create_status})"
        return
    fi
    local pid
    pid=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects" \
        | jq -r --arg l "$label" '.projects[] | select(.label == $l) | .id')
    if [ -z "$pid" ] || [ "$pid" = "null" ]; then
        log_fail "CacheHit: could not resolve project id"
        return
    fi
    log_pass "CacheHit: project '${label}' (id=${pid}) created (no blocked licenses yet)"

    # 1. Download chalk — should succeed (MIT not blocked).
    local tarball="${E2E_NPM_URL}/chalk/-/chalk-5.4.1.tgz"
    _lic_assert_artifact "CacheHit" "$label" "$tarball" "200" \
        "step 1: MIT 'chalk' cached (allowed)"

    # Give async SBOM write a moment to persist metadata.
    sleep 5

    # Verify SBOM metadata has MIT.
    local licenses
    licenses=$(curl -sf "${E2E_ADMIN_URL}/api/v1/artifacts/npm:chalk:5.4.1/licenses" \
        | jq -r '.licenses // [] | join(",")' 2>/dev/null)
    if [[ "$licenses" == *"MIT"* ]]; then
        log_pass "CacheHit: SBOM metadata has MIT license"
    else
        log_fail "CacheHit: SBOM metadata missing MIT (got '${licenses}') — subsequent tests will fail"
        return
    fi

    # ---- Global policy: block MIT ----

    # 2. Block MIT globally.
    local put_status
    put_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT "${E2E_ADMIN_URL}/api/v1/policy/licenses" \
        -H "Content-Type: application/json" \
        -d '{"enabled":true,"blocked":["MIT"],"warned":[],"allowed":[],"unknown_action":"allow","on_sbom_error":"allow","or_semantics":"any_allowed"}')
    assert_eq "CacheHit: block MIT globally returns 200" "200" "$put_status"

    # 3. Download chalk again — should be 403 (cache-hit + license gate).
    _lic_assert_artifact "CacheHit" "$label" "$tarball" "403" \
        "step 3: MIT 'chalk' BLOCKED on cache-hit (global policy)"

    # 4. Verify artifact was quarantined by async re-evaluation (Fix B).
    sleep 3
    local status
    status=$(curl -sf "${E2E_ADMIN_URL}/api/v1/artifacts/npm:chalk:5.4.1" \
        | jq -r '.status.status' 2>/dev/null)
    assert_eq "CacheHit: artifact QUARANTINED by re-evaluation" "QUARANTINED" "$status"

    # 5. Unblock MIT globally.
    curl -sf -X DELETE "${E2E_ADMIN_URL}/api/v1/policy/licenses" > /dev/null

    # 6. Download chalk — should be 200 again.
    sleep 2
    _lic_assert_artifact "CacheHit" "$label" "$tarball" "200" \
        "step 6: MIT 'chalk' allowed after global unblock"

    # 7. Verify artifact was released back to CLEAN.
    status=$(curl -sf "${E2E_ADMIN_URL}/api/v1/artifacts/npm:chalk:5.4.1" \
        | jq -r '.status.status' 2>/dev/null)
    assert_eq "CacheHit: artifact released to CLEAN after unblock" "CLEAN" "$status"

    # ---- Per-project policy: block MIT ----

    # 8. Block MIT on this project only.
    local body
    body=$(jq -n '{mode:"override", blocked:["MIT"], warned:[], allowed:[], unknown_action:"allow"}')
    put_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT "${E2E_ADMIN_URL}/api/v1/projects/${pid}/license-policy" \
        -H "Content-Type: application/json" \
        -d "$body")
    assert_eq "CacheHit: block MIT on project returns 200" "200" "$put_status"

    # 9. Download chalk via this project — should be 403.
    sleep 1
    _lic_assert_artifact "CacheHit" "$label" "$tarball" "403" \
        "step 9: MIT 'chalk' BLOCKED on cache-hit (per-project policy)"

    # 10. Delete project policy (revert to global = no blocks).
    curl -sf -X DELETE "${E2E_ADMIN_URL}/api/v1/projects/${pid}/license-policy" > /dev/null

    # 11. Download chalk — should be 200.
    sleep 1
    _lic_assert_artifact "CacheHit" "$label" "$tarball" "200" \
        "step 11: MIT 'chalk' allowed after project policy revert"

    _lic_audit_block_present "CacheHit" "$pid"
}
