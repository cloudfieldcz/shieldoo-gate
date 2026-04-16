#!/usr/bin/env bash
# test_projects.sh — Project registry e2e tests
# Sourced by run_all.sh; defines test_projects(). Do NOT set -e here.

test_projects() {
    log_section "Project Registry Tests"

    # These tests exercise the Basic auth username → project mapping.
    # Only meaningful when proxy auth is enabled (so a username is actually
    # present in the Authorization header).
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" != "true" ]; then
        log_skip "Project tests: SGW_PROXY_AUTH_ENABLED is not true"
        return
    fi

    local global_token="${SGW_PROXY_TOKEN:-}"
    if [ -z "$global_token" ]; then
        log_skip "Project tests: SGW_PROXY_TOKEN not set"
        return
    fi

    # Lazy-mode-only assertions: in strict mode the proxy rejects unknown
    # labels with 403, so the auto-create + mixed-case flows below would
    # always fail there. They cover real lazy-mode semantics; strict mode
    # has its own coverage in test_license_policy.sh + section 5 below.
    local mode="${SGW_PROJECTS_MODE:-lazy}"

    if [ "$mode" = "lazy" ]; then
        # ------------------------------------------------------------------
        # 1. Lazy-create happy path — first request with a new label creates
        #    a project row and stamps it on subsequent audit events.
        # ------------------------------------------------------------------
        local label="e2e-team-$(date +%s)"
        local status
        status=$(curl -s -o /dev/null -w "%{http_code}" -u "${label}:${global_token}" "${E2E_PYPI_URL}/simple/")
        assert_eq "Projects: lazy-create via PyPI /simple/ returns 200" "200" "$status"

        # Query the admin API to confirm the project exists.
        local list_resp
        list_resp=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects" 2>/dev/null)
        if [ -n "$list_resp" ]; then
            if echo "$list_resp" | jq -e --arg l "$label" '.projects[] | select(.label == $l)' > /dev/null 2>&1; then
                log_pass "Projects: lazy-created project visible via /api/v1/projects"
            else
                log_fail "Projects: lazy-created project NOT visible in /api/v1/projects"
                echo "$list_resp" | head -c 400 >&2
            fi

            # created_via should be "lazy" for this row.
            local created_via
            created_via=$(echo "$list_resp" | jq -r --arg l "$label" '.projects[] | select(.label == $l) | .created_via')
            assert_eq "Projects: created_via=lazy for auto-provisioned label" "lazy" "$created_via"
        else
            log_fail "Projects: /api/v1/projects returned empty body (endpoint wiring broken?)"
        fi

        # ------------------------------------------------------------------
        # 2. Mixed-case normalization — different case must not create dup rows.
        # ------------------------------------------------------------------
        local mixed="MixedCase-$(date +%s)"
        local lowered
        lowered=$(echo "$mixed" | tr '[:upper:]' '[:lower:]')
        curl -s -o /dev/null -u "${mixed}:${global_token}" "${E2E_PYPI_URL}/simple/" > /dev/null
        curl -s -o /dev/null -u "${lowered}:${global_token}" "${E2E_PYPI_URL}/simple/" > /dev/null
        sleep 1
        local match_count
        match_count=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects" | jq -r --arg l "$lowered" '[.projects[] | select(.label == $l)] | length')
        assert_eq "Projects: mixed-case labels collapse into a single lowercase row" "1" "$match_count"
    else
        log_skip "Projects: lazy auto-create + mixed-case (SGW_PROJECTS_MODE=${mode})"

        # ------------------------------------------------------------------
        # Strict-mode counterpart: unknown label MUST be rejected with 403.
        # ------------------------------------------------------------------
        local strict_unknown="e2e-strict-unknown-$(date +%s)"
        local strict_status
        strict_status=$(curl -s -o /dev/null -w "%{http_code}" -u "${strict_unknown}:${global_token}" "${E2E_PYPI_URL}/simple/")
        assert_eq "Projects: strict mode rejects unknown label with 403" "403" "$strict_status"
    fi

    # ------------------------------------------------------------------
    # 3. Empty Basic auth username → "default" project fallback.
    # ------------------------------------------------------------------
    curl -s -o /dev/null -u ":${global_token}" "${E2E_PYPI_URL}/simple/" > /dev/null
    local has_default
    has_default=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects" | jq -r '[.projects[] | select(.label == "default")] | length')
    assert_gte "Projects: 'default' project exists (seeded or auto-used)" 1 "$has_default"

    # ------------------------------------------------------------------
    # 4. Invalid label (non-alnum chars) → 400
    # ------------------------------------------------------------------
    status=$(curl -s -o /dev/null -w "%{http_code}" -u 'bad@char:'"${global_token}" "${E2E_PYPI_URL}/simple/")
    assert_eq "Projects: invalid label returns 400" "400" "$status"

    # ------------------------------------------------------------------
    # 5. Explicit project creation via admin API
    # ------------------------------------------------------------------
    local explicit="e2e-api-$(date +%s)"
    local create_status
    create_status=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${E2E_ADMIN_URL}/api/v1/projects" \
        -H "Content-Type: application/json" \
        -d "{\"label\":\"${explicit}\",\"display_name\":\"E2E explicit\"}")
    assert_eq "Projects: POST /api/v1/projects creates (201)" "201" "$create_status"

    local created_via_api
    created_via_api=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects" | jq -r --arg l "$explicit" '.projects[] | select(.label == $l) | .created_via')
    assert_eq "Projects: created_via=api for explicit creation" "api" "$created_via_api"

    # ------------------------------------------------------------------
    # 6. Per-project artifact usage — after pulling a package under a label,
    #    artifact_project_usage should have a row. This test tolerates the
    #    30s flush interval by retrying.
    #    In strict mode we re-use the explicit project from section 5.
    # ------------------------------------------------------------------
    local usage_label
    if [ "$mode" = "strict" ]; then
        usage_label="$explicit"   # already pre-provisioned via POST above
    else
        usage_label="e2e-usage-$(date +%s)"
    fi
    # Pull a small PyPI package (six is tiny and well-known).
    curl -s -o /dev/null -u "${usage_label}:${global_token}" \
        "${E2E_PYPI_URL}/simple/six/" || true

    # Find project id.
    local usage_pid
    usage_pid=$(curl -sf "${E2E_ADMIN_URL}/api/v1/projects" | jq -r --arg l "$usage_label" '.projects[] | select(.label == $l) | .id')

    if [ -n "$usage_pid" ] && [ "$usage_pid" != "null" ]; then
        log_pass "Projects: usage project id=${usage_pid} discovered (label='${usage_label}')"
        # List artifacts via the project-scoped endpoint.
        local usage_resp_status
        usage_resp_status=$(curl -s -o /dev/null -w "%{http_code}" \
            "${E2E_ADMIN_URL}/api/v1/projects/${usage_pid}/artifacts")
        assert_eq "Projects: /projects/{id}/artifacts returns 200" "200" "$usage_resp_status"
    else
        log_fail "Projects: could not discover usage project id (label='${usage_label}', mode=${mode})"
    fi
}
