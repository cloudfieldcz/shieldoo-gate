#!/usr/bin/env bash
# test_proxy_auth.sh — Proxy API key authentication e2e tests
# Sourced by run_all.sh; defines test_proxy_auth(). Do NOT set -e here.

test_proxy_auth() {
    log_section "Proxy Authentication Tests"

    # These tests only run when proxy auth is enabled (SGW_PROXY_AUTH_ENABLED=true).
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" != "true" ]; then
        log_skip "Proxy auth tests: SGW_PROXY_AUTH_ENABLED is not true"
        return
    fi

    local global_token="${SGW_PROXY_TOKEN:-}"

    # ------------------------------------------------------------------
    # 1. Unauthenticated request → 401
    # ------------------------------------------------------------------
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_PYPI_URL}/simple/")
    assert_eq "Proxy auth: unauthenticated PyPI request returns 401" "401" "$status"

    # ------------------------------------------------------------------
    # 2. Wrong token → 401
    # ------------------------------------------------------------------
    status=$(curl -s -o /dev/null -w "%{http_code}" -u "user:wrong-token" "${E2E_PYPI_URL}/simple/")
    assert_eq "Proxy auth: wrong token returns 401" "401" "$status"

    # ------------------------------------------------------------------
    # 3. Global token → 200 (if configured)
    # ------------------------------------------------------------------
    if [ -n "$global_token" ]; then
        status=$(curl -s -o /dev/null -w "%{http_code}" -u "ci-bot:${global_token}" "${E2E_PYPI_URL}/simple/")
        assert_eq "Proxy auth: global token allows PyPI access" "200" "$status"

        # Also test npm
        status=$(curl -s -o /dev/null -w "%{http_code}" -u "ci-bot:${global_token}" "${E2E_NPM_URL}/chalk")
        assert_eq "Proxy auth: global token allows npm access" "200" "$status"
    else
        log_skip "Proxy auth: global token not configured, skipping global token tests"
    fi

    # ------------------------------------------------------------------
    # 4. Create PAT via admin API (if admin API has API key endpoints)
    # ------------------------------------------------------------------
    local create_resp
    create_resp=$(curl -sf -X POST "${E2E_ADMIN_URL}/api/v1/api-keys" \
        -H "Content-Type: application/json" \
        -d '{"name":"e2e-test-key"}' 2>/dev/null) || true

    if [ -n "$create_resp" ]; then
        local pat_token
        pat_token=$(echo "$create_resp" | jq -r '.token // empty')

        if [ -n "$pat_token" ]; then
            log_pass "Proxy auth: created PAT via admin API"

            # 5. Use PAT to access PyPI → 200
            status=$(curl -s -o /dev/null -w "%{http_code}" -u "e2e:${pat_token}" "${E2E_PYPI_URL}/simple/")
            assert_eq "Proxy auth: PAT allows PyPI access" "200" "$status"

            # 6. Install package with PAT via uv
            local workdir
            workdir=$(mktemp -d)
            pushd "$workdir" > /dev/null

            uv venv .venv --quiet 2>/dev/null
            if uv pip install \
                    --python .venv/bin/python \
                    --no-cache \
                    --index-url "http://e2e:${pat_token}@${E2E_PYPI_URL#http://}/simple/" \
                    six \
                    > install.log 2>&1; then
                log_pass "Proxy auth: uv pip install with PAT succeeded"
            else
                log_fail "Proxy auth: uv pip install with PAT failed"
                cat install.log >&2
            fi

            popd > /dev/null
            rm -rf "$workdir"

            # 7. Revoke PAT
            local pat_id
            pat_id=$(echo "$create_resp" | jq -r '.id // empty')
            if [ -n "$pat_id" ]; then
                local revoke_status
                revoke_status=$(curl -s -o /dev/null -w "%{http_code}" -X DELETE \
                    "${E2E_ADMIN_URL}/api/v1/api-keys/${pat_id}")
                assert_eq "Proxy auth: revoke PAT returns 204" "204" "$revoke_status"

                # 8. Revoked PAT → 401
                status=$(curl -s -o /dev/null -w "%{http_code}" -u "e2e:${pat_token}" "${E2E_PYPI_URL}/simple/")
                assert_eq "Proxy auth: revoked PAT returns 401" "401" "$status"
            fi
        else
            log_skip "Proxy auth: PAT token empty in response, skipping PAT tests"
        fi
    else
        log_skip "Proxy auth: admin API key endpoints not available (auth not enabled?)"
    fi

    # ------------------------------------------------------------------
    # 9. Docker auth (if global token available)
    # ------------------------------------------------------------------
    if [ -n "$global_token" ]; then
        status=$(curl -s -o /dev/null -w "%{http_code}" -u "ci-bot:${global_token}" "${E2E_DOCKER_URL}/v2/")
        # Docker /v2/ should return 200 or 401 with WWW-Authenticate
        if [ "$status" = "200" ] || [ "$status" = "401" ]; then
            log_pass "Proxy auth: Docker /v2/ endpoint responds (status: ${status})"
        else
            log_fail "Proxy auth: Docker /v2/ unexpected status: ${status}"
        fi
    fi

    # ------------------------------------------------------------------
    # 10. Verify WWW-Authenticate header on 401
    # ------------------------------------------------------------------
    local www_auth
    www_auth=$(curl -s -D - -o /dev/null "${E2E_PYPI_URL}/simple/" | grep -i "WWW-Authenticate" || true)
    if [[ "$www_auth" == *"Basic"* ]]; then
        log_pass "Proxy auth: 401 includes WWW-Authenticate: Basic header"
    else
        log_fail "Proxy auth: 401 missing WWW-Authenticate: Basic header"
    fi
}
