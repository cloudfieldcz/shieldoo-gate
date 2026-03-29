#!/usr/bin/env bash
# test_docker.sh — Basic Docker/OCI proxy smoke tests for Shieldoo Gate
# Sourced by run.sh; defines test_docker(). Do NOT set -e here.
#
# This file provides minimal smoke tests for the Docker adapter.
# Comprehensive Docker registry tests (multi-upstream, push, sync, tag API,
# scan pipeline) are in test_docker_registry.sh.

test_docker() {
    log_section "Docker/OCI Proxy Smoke Tests"

    # ------------------------------------------------------------------
    # 0. Negative test: unauthenticated request must return 401 when auth enabled
    # ------------------------------------------------------------------
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" = "true" ]; then
        local noauth_status
        noauth_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_DOCKER_URL}/v2/")
        assert_eq "Docker: unauthenticated request returns 401" "401" "$noauth_status"
    fi

    # ------------------------------------------------------------------
    # 1. OCI v2 version check — validates the Docker adapter is alive
    # ------------------------------------------------------------------
    local v2_status
    v2_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "${E2E_DOCKER_URL}/v2/")
    # Docker registries return 200 or 401 — both indicate the proxy is working.
    if [ "$v2_status" = "200" ] || [ "$v2_status" = "401" ]; then
        log_pass "Docker: /v2/ returns HTTP ${v2_status} (proxy alive)"
    else
        log_fail "Docker: /v2/ returns HTTP ${v2_status} (expected 200 or 401)"
    fi

    # ------------------------------------------------------------------
    # 2. Version header is present
    # ------------------------------------------------------------------
    local v2_header
    v2_header=$(curl -s -D - -o /dev/null "${E2E_CURL_AUTH[@]}" "${E2E_DOCKER_URL}/v2/" | grep -i "Docker-Distribution-API-Version")
    if [[ "$v2_header" == *"registry/2.0"* ]]; then
        log_pass "Docker: /v2/ includes Docker-Distribution-API-Version header"
    else
        log_fail "Docker: /v2/ missing Docker-Distribution-API-Version header"
    fi
}
