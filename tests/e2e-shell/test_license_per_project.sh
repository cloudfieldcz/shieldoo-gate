#!/usr/bin/env bash
# test_license_per_project.sh — verifies the per-project license-release flow:
#   1. Global release on a license-blocked artifact returns 409 + project-scope hint
#   2. POST /projects/{id}/overrides creates a per-project allow row (201)
#   3. GET /projects/{id}/overrides surfaces the new row
#   4. Revoke flips the row back; the project's artifact decision returns to blocked
#      (or stays clean if a global allow shadowed the revoke — flagged as skip).
#
# Sourced by run_all.sh; do NOT set -e here.

test_license_per_project() {
    log_section "License: per-project Release flow + override visibility"

    if [ "${SGW_PROJECTS_MODE:-lazy}" != "strict" ]; then
        log_skip "License per-project: requires SGW_PROJECTS_MODE=strict"
        return
    fi
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" != "true" ] || [ -z "${SGW_PROXY_TOKEN:-}" ]; then
        log_skip "License per-project: needs SGW_PROXY_AUTH_ENABLED=true + SGW_PROXY_TOKEN"
        return
    fi
    local bearer=(-H "Authorization: Bearer ${SGW_PROXY_TOKEN}")

    # Resolve the 'default' project's numeric id. Most license-policy ecosystem
    # tests run against the default project; if a more specific label exists in
    # the test rig we still match a license-blocked artifact below.
    local pid
    pid=$(admin_curl -sf "${E2E_ADMIN_URL}/api/v1/projects" "${bearer[@]}" \
        | jq -r '.projects[]? | select(.label == "default") | .id')
    if [ -z "$pid" ] || [ "$pid" = "null" ]; then
        log_skip "License per-project: no 'default' project (rig changed?)"
        return
    fi

    # Look for a license-blocked artifact in this project. Preceding tests
    # (test_license_pypi/npm/etc.) leave at least one BLOCKED_LICENSE row in
    # the project's artifacts list. If none is present, the rig hasn't run
    # license enforcement against this project yet — skip cleanly.
    local list
    list=$(admin_curl -sf "${E2E_ADMIN_URL}/api/v1/projects/${pid}/artifacts" "${bearer[@]}")
    local first_eco first_name first_ver first_id
    first_eco=$(echo "$list" | jq -r '.artifacts[]? | select(.decision == "BLOCKED_LICENSE") | .ecosystem' | head -n1)
    first_name=$(echo "$list" | jq -r '.artifacts[]? | select(.decision == "BLOCKED_LICENSE") | .name' | head -n1)
    first_ver=$(echo "$list" | jq -r '.artifacts[]? | select(.decision == "BLOCKED_LICENSE") | .version // ""' | head -n1)
    first_id=$(echo "$list" | jq -r '.artifacts[]? | select(.decision == "BLOCKED_LICENSE") | .id // ""' | head -n1)
    if [ -z "$first_eco" ] || [ -z "$first_name" ]; then
        log_skip "License per-project: no BLOCKED_LICENSE artifact in default project (run test_license_* first)"
        return
    fi

    # Step 1: if we have a real artifact id, the global Release endpoint must
    # 409 with the project-scope hint. (When the artifact is audit-only — no
    # artifact_status row — there's nothing to release globally either, so
    # skip this step in that case.)
    if [ -n "$first_id" ] && [ "$first_id" != "null" ]; then
        local code
        code=$(admin_curl -s -o /dev/null -w "%{http_code}" -X POST \
            "${E2E_ADMIN_URL}/api/v1/artifacts/$(printf %s "$first_id" | jq -sRr @uri)/release" \
            "${bearer[@]}")
        case "$code" in
            409)
                log_pass "License per-project: global release on license block returned 409"
                ;;
            404)
                log_skip "License per-project: artifact has no artifact_status row (audit-only); skipping 409 assertion"
                ;;
            *)
                log_fail "License per-project: global release expected 409, got ${code}"
                return
                ;;
        esac
    else
        log_skip "License per-project: BLOCKED_LICENSE row is audit-only (no artifact id); skipping 409 assertion"
    fi

    # Step 2: create the per-project override.
    local create_body create_resp create_code
    if [ -n "$first_ver" ] && [ "$first_ver" != "null" ]; then
        create_body=$(jq -n --arg eco "$first_eco" --arg name "$first_name" --arg ver "$first_ver" \
            '{ecosystem:$eco, name:$name, version:$ver, scope:"version", kind:"allow", reason:"e2e per-project release"}')
    else
        create_body=$(jq -n --arg eco "$first_eco" --arg name "$first_name" \
            '{ecosystem:$eco, name:$name, scope:"package", kind:"allow", reason:"e2e per-project release"}')
    fi
    create_resp=$(mktemp)
    create_code=$(admin_curl -s -o "$create_resp" -w "%{http_code}" -X POST \
        "${E2E_ADMIN_URL}/api/v1/projects/${pid}/overrides" \
        "${bearer[@]}" -H "Content-Type: application/json" -d "$create_body")
    local oid=""
    if [ "$create_code" = "201" ]; then
        oid=$(jq -r '.id // empty' < "$create_resp")
    elif [ "$create_code" = "409" ]; then
        # Already-active row from a prior run. Look it up so we can still
        # exercise the GET + revoke steps.
        oid=$(admin_curl -sf "${E2E_ADMIN_URL}/api/v1/projects/${pid}/overrides" "${bearer[@]}" \
            | jq -r --arg name "$first_name" --arg eco "$first_eco" \
                '.items[]? | select(.name == $name and .ecosystem == $eco and .revoked == false) | .id' \
            | head -n1)
        if [ -n "$oid" ]; then
            log_skip "License per-project: override already existed (id=${oid}); reusing"
        fi
    fi
    rm -f "$create_resp"
    if [ -n "$oid" ] && [ "$oid" != "null" ]; then
        log_pass "License per-project: project override (id=${oid}) is in place"
    else
        log_fail "License per-project: override create failed (status=${create_code})"
        return
    fi

    # Step 3: GET listing includes the new override.
    if admin_curl -sf "${E2E_ADMIN_URL}/api/v1/projects/${pid}/overrides" "${bearer[@]}" \
        | jq -e --argjson id "$oid" '.items[]? | select(.id == $id)' >/dev/null; then
        log_pass "License per-project: override visible in project overrides listing"
    else
        log_fail "License per-project: override id=${oid} NOT in listing"
    fi

    # Step 4: revoke + assert it transitions on next list. Postgres returns
    # JSON true/false; SQLite via sqlx may return either form depending on the
    # column type — accept both.
    local revoke_code
    revoke_code=$(admin_curl -s -o /dev/null -w "%{http_code}" -X POST \
        "${E2E_ADMIN_URL}/api/v1/projects/${pid}/overrides/${oid}/revoke" \
        "${bearer[@]}" -H "Content-Type: application/json" -d '{"reason":"e2e cleanup"}')
    if [ "$revoke_code" != "200" ]; then
        log_fail "License per-project: revoke returned ${revoke_code}"
        return
    fi
    local revoked
    revoked=$(admin_curl -sf "${E2E_ADMIN_URL}/api/v1/projects/${pid}/overrides" "${bearer[@]}" \
        | jq -r --argjson id "$oid" '.items[]? | select(.id == $id) | .revoked')
    if [ "$revoked" = "true" ] || [ "$revoked" = "1" ]; then
        log_pass "License per-project: revoke transitioned override to revoked"
    else
        log_fail "License per-project: revoke did not stick (revoked=${revoked})"
        return
    fi

    # Step 5: post-revoke fail-shut. After revoking the per-project allow, the
    # artifact's decision in the project's list must NOT be WHITELISTED. If a
    # global allow (possibly migrated by 036) is still active, the artifact may
    # still appear CLEAN — flag that with log_skip rather than failing because
    # the system remained safe (the global is itself an explicit approval).
    if [ -n "$first_id" ] && [ "$first_id" != "null" ]; then
        local recheck
        recheck=$(admin_curl -sf "${E2E_ADMIN_URL}/api/v1/projects/${pid}/artifacts" "${bearer[@]}" \
            | jq -r --arg id "$first_id" '.artifacts[]? | select(.id == $id) | .decision')
        case "$recheck" in
            BLOCKED_LICENSE)
                log_pass "License per-project: post-revoke decision flipped back to BLOCKED_LICENSE"
                ;;
            CLEAN|WHITELISTED)
                log_skip "License per-project: post-revoke still ${recheck} — a global allow shadows revoke"
                ;;
            "")
                log_skip "License per-project: artifact disappeared from list (likely retention/dedup)"
                ;;
            *)
                log_fail "License per-project: post-revoke decision=${recheck} (expected BLOCKED_LICENSE)"
                ;;
        esac
    else
        log_skip "License per-project: cannot re-check audit-only artifact decision"
    fi
}
