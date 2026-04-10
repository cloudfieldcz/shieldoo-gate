#!/usr/bin/env bash
# helpers.sh — Shared utilities for Shieldoo Gate e2e shell tests
# DO NOT set -euo pipefail here; this file is sourced by callers that manage it.

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Test counters
# ---------------------------------------------------------------------------
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# ---------------------------------------------------------------------------
# Port and URL exports
# ---------------------------------------------------------------------------
# When running on the host, tests use localhost + mapped ports.
# When running inside the test-runner container (docker-compose), the SGW_*
# environment variables override these with container-internal URLs.
# ---------------------------------------------------------------------------
export E2E_PYPI_PORT=15010
export E2E_NPM_PORT=14873
export E2E_NUGET_PORT=15001
export E2E_DOCKER_PORT="${SGW_DOCKER_PORT:-15002}"
export E2E_MAVEN_PORT=18085
export E2E_ADMIN_PORT=18080
export E2E_PUSH_REGISTRY_PORT=15003
export E2E_RUBYGEMS_PORT=18086
export E2E_GOMOD_PORT=18087

export E2E_PYPI_URL="${SGW_PYPI_URL:-http://localhost:${E2E_PYPI_PORT}}"
export E2E_NPM_URL="${SGW_NPM_URL:-http://localhost:${E2E_NPM_PORT}}"
export E2E_NUGET_URL="${SGW_NUGET_URL:-http://localhost:${E2E_NUGET_PORT}}"
export E2E_DOCKER_URL="${SGW_DOCKER_URL:-http://localhost:${E2E_DOCKER_PORT}}"
export E2E_MAVEN_URL="${SGW_MAVEN_URL:-http://localhost:${E2E_MAVEN_PORT}}"
export E2E_ADMIN_URL="${SGW_ADMIN_URL:-http://localhost:${E2E_ADMIN_PORT}}"
export E2E_PUSH_REGISTRY_URL="${SGW_PUSH_REGISTRY_URL:-http://localhost:${E2E_PUSH_REGISTRY_PORT}}"
export E2E_RUBYGEMS_URL="${SGW_RUBYGEMS_URL:-http://localhost:${E2E_RUBYGEMS_PORT}}"
export E2E_GOMOD_URL="${SGW_GOMOD_URL:-http://localhost:${E2E_GOMOD_PORT}}"

# Docker registry host for crane (host:port, no scheme).
# In container: shieldoo-gate:5002; on host: localhost:15002.
if [ -n "${SGW_DOCKER_URL:-}" ]; then
    # Strip http:// prefix to get host:port for crane
    export E2E_DOCKER_REGISTRY_HOST="${SGW_DOCKER_URL#http://}"
else
    export E2E_DOCKER_REGISTRY_HOST="localhost:${E2E_DOCKER_PORT}"
fi

# ---------------------------------------------------------------------------
# Proxy auth configuration
# ---------------------------------------------------------------------------
# When SGW_PROXY_AUTH_ENABLED=true, all proxy requests must include Basic Auth.
# E2E_CURL_AUTH is a bash array used with curl: curl "${E2E_CURL_AUTH[@]}" ...
# E2E_AUTH_USERINFO is "user:pass@" prefix for embedding in URLs (uv, npm).
E2E_CURL_AUTH=()
E2E_AUTH_USERINFO=""
if [ "${SGW_PROXY_AUTH_ENABLED:-false}" = "true" ] && [ -n "${SGW_PROXY_TOKEN:-}" ]; then
    E2E_CURL_AUTH=(-u "ci-bot:${SGW_PROXY_TOKEN}")
    E2E_AUTH_USERINFO="ci-bot:${SGW_PROXY_TOKEN}@"
fi

# auth_url "http://host:port" → "http://ci-bot:token@host:port" (when auth enabled)
auth_url() {
    local url="$1"
    if [ -n "$E2E_AUTH_USERINFO" ]; then
        echo "${url//:\/\//:\/\/${E2E_AUTH_USERINFO}}"
    else
        echo "$url"
    fi
}

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log_info() {
    printf "${CYAN}[INFO]${NC}  %s\n" "$*"
}

log_pass() {
    TESTS_PASSED=$(( TESTS_PASSED + 1 ))
    printf "${GREEN}[PASS]${NC}  %s\n" "$*"
}

log_fail() {
    TESTS_FAILED=$(( TESTS_FAILED + 1 ))
    printf "${RED}[FAIL]${NC}  %s\n" "$*"
}

log_skip() {
    TESTS_SKIPPED=$(( TESTS_SKIPPED + 1 ))
    printf "${YELLOW}[SKIP]${NC}  %s\n" "$*"
}

log_section() {
    printf "\n${CYAN}=== %s ===${NC}\n" "$*"
}

# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

# assert_eq "description" "expected" "actual"
assert_eq() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    if [ "$expected" = "$actual" ]; then
        log_pass "$desc"
    else
        log_fail "$desc (expected='${expected}' actual='${actual}')"
    fi
}

# assert_contains "description" "needle" "haystack"
assert_contains() {
    local desc="$1"
    local needle="$2"
    local haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        log_pass "$desc"
    else
        log_fail "$desc (needle='${needle}' not found in haystack)"
    fi
}

# assert_gte "description" expected actual  (actual >= expected, integers)
assert_gte() {
    local desc="$1"
    local expected="$2"
    local actual="$3"
    if [ "$actual" -ge "$expected" ] 2>/dev/null; then
        log_pass "$desc"
    else
        log_fail "$desc (expected>=${expected} actual=${actual})"
    fi
}

# assert_http_status "description" expected_status url
assert_http_status() {
    local desc="$1"
    local expected_status="$2"
    local url="$3"
    local actual_status
    actual_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$url")
    assert_eq "$desc" "$expected_status" "$actual_status"
}

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

# api_get path — GET from Admin API, outputs response body (fails on HTTP error)
api_get() {
    local path="$1"
    curl -sf "${E2E_ADMIN_URL}${path}"
}

# api_jq path jq_filter — api_get + jq filter
api_jq() {
    local path="$1"
    local filter="$2"
    api_get "$path" | jq -r "$filter"
}

# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

# docker_logs service_name — tail compose logs for a service
docker_logs() {
    local service="$1"
    docker compose -f "${COMPOSE_FILE}" logs "$service"
}

# ---------------------------------------------------------------------------
# Readiness check
# ---------------------------------------------------------------------------

# wait_for_ready [max_seconds] — polls /api/v1/health until 200, default 120s
wait_for_ready() {
    local max_seconds="${1:-120}"
    local interval=2
    local elapsed=0
    local health_url="${E2E_ADMIN_URL}/api/v1/health"

    log_info "Waiting for shieldoo-gate to be ready (max ${max_seconds}s)..."
    while [ "$elapsed" -lt "$max_seconds" ]; do
        if curl -sf "$health_url" > /dev/null 2>&1; then
            log_info "shieldoo-gate is ready (${elapsed}s elapsed)"
            return 0
        fi
        sleep "$interval"
        elapsed=$(( elapsed + interval ))
    done

    log_fail "shieldoo-gate did not become ready within ${max_seconds}s"
    return 1
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

# print_summary — prints pass/fail/skip counts, returns 1 if any failures
print_summary() {
    local total=$(( TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED ))
    printf "\n${CYAN}--- Test Summary ---${NC}\n"
    printf "  Total:   %d\n" "$total"
    printf "  ${GREEN}Passed:  %d${NC}\n" "$TESTS_PASSED"
    printf "  ${RED}Failed:  %d${NC}\n" "$TESTS_FAILED"
    printf "  ${YELLOW}Skipped: %d${NC}\n" "$TESTS_SKIPPED"
    printf "\n"

    if [ "$TESTS_FAILED" -gt 0 ]; then
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# Database access (for integrity e2e tests)
# ---------------------------------------------------------------------------
# db_exec runs SQL against the test database.
# Only works in PostgreSQL passes (Run 2/3). Returns 1 in SQLite passes.
db_exec() {
    local sql="$1"
    if [ "${SGW_DATABASE_BACKEND:-sqlite}" = "postgres" ]; then
        PGPASSWORD=shieldoo_e2e_pass psql -h postgres -U shieldoo -d shieldoo_e2e -tAc "$sql" 2>/dev/null
    else
        return 1
    fi
}

# db_available returns 0 if the test-runner can manipulate the DB directly.
db_available() {
    [ "${SGW_DATABASE_BACKEND:-sqlite}" = "postgres" ] && db_exec "SELECT 1" >/dev/null 2>&1
}
