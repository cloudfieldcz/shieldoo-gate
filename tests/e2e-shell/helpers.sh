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
export E2E_PYPI_PORT=15010
export E2E_NPM_PORT=14873
export E2E_NUGET_PORT=15001
export E2E_ADMIN_PORT=18080

export E2E_PYPI_URL="http://localhost:${E2E_PYPI_PORT}"
export E2E_NPM_URL="http://localhost:${E2E_NPM_PORT}"
export E2E_NUGET_URL="http://localhost:${E2E_NUGET_PORT}"
export E2E_ADMIN_URL="http://localhost:${E2E_ADMIN_PORT}"

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
    actual_status=$(curl -s -o /dev/null -w "%{http_code}" "$url")
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
