#!/usr/bin/env bash
# run_all.sh — Containerized E2E test orchestrator for Shieldoo Gate
#
# Runs ALL E2E test suites sequentially inside the test-runner container.
# Exits with non-zero on any test failure.
#
# This script is the ENTRYPOINT for docker-compose test-runner service.
# It can also be run directly on the host if all tools are installed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source helpers (sets up URLs, logging, assertions)
source "${SCRIPT_DIR}/helpers.sh"

# Source all test files (defines test_* functions)
source "${SCRIPT_DIR}/test_pypi.sh"
source "${SCRIPT_DIR}/test_npm.sh"
source "${SCRIPT_DIR}/test_nuget.sh"
source "${SCRIPT_DIR}/test_docker.sh"
source "${SCRIPT_DIR}/test_docker_registry.sh"
source "${SCRIPT_DIR}/test_maven.sh"
source "${SCRIPT_DIR}/test_rubygems.sh"
source "${SCRIPT_DIR}/test_gomod.sh"
source "${SCRIPT_DIR}/test_api.sh"
source "${SCRIPT_DIR}/test_proxy_auth.sh"
source "${SCRIPT_DIR}/test_policy_tiers.sh"
source "${SCRIPT_DIR}/test_typosquat.sh"
source "${SCRIPT_DIR}/test_version_diff.sh"
source "${SCRIPT_DIR}/test_reputation.sh"
source "${SCRIPT_DIR}/test_integrity.sh"

_run_label=""
if [ "${SGW_PROXY_AUTH_ENABLED:-false}" = "true" ]; then
    _run_label=" [auth enabled]"
fi
echo "=== Shieldoo Gate E2E Test Suite (containerized)${_run_label} ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# When running inside docker-compose, COMPOSE_FILE is not set (no docker CLI needed).
# The docker_logs helper requires COMPOSE_FILE; make it a no-op in container mode.
if [ -z "${COMPOSE_FILE:-}" ]; then
    # In container mode, read logs from the shared log file instead of docker compose.
    # Brief sleep allows volume-shared file content to become visible across containers.
    docker_logs() {
        local log_file="/var/log/shieldoo-gate/gate.log"
        if [ -f "$log_file" ]; then
            sleep 1
            cat "$log_file"
        else
            echo "(docker_logs not available inside container — skipping log inspection)"
        fi
    }
fi

# Wait for shieldoo-gate to be ready (in-container the URL comes from env vars)
log_section "Shieldoo Gate E2E Test Suite"
log_info "Waiting for shieldoo-gate readiness..."

MAX_WAIT=120
ELAPSED=0
HEALTH_URL="${E2E_ADMIN_URL}/api/v1/health"
while [ "$ELAPSED" -lt "$MAX_WAIT" ]; do
    if curl -sf "$HEALTH_URL" > /dev/null 2>&1; then
        log_info "shieldoo-gate is ready (${ELAPSED}s elapsed)"
        break
    fi
    sleep 2
    ELAPSED=$(( ELAPSED + 2 ))
done

if [ "$ELAPSED" -ge "$MAX_WAIT" ]; then
    log_fail "shieldoo-gate did not become ready within ${MAX_WAIT}s"
    exit 1
fi

# ---------------------------------------------------------------------------
# Backend verification (pass 2/3: ensure production-like backends are used)
# ---------------------------------------------------------------------------
if [ "${SGW_CACHE_BACKEND:-}" = "s3" ] || [ "${SGW_CACHE_BACKEND:-}" = "azure_blob" ]; then
    log_section "Backend Verification (${SGW_CACHE_BACKEND})"
    GATE_LOG="/var/log/shieldoo-gate/gate.log"
    if [ -f "$GATE_LOG" ]; then
        if [ "${SGW_CACHE_BACKEND}" = "s3" ]; then
            if grep -q "s3 cache store initialized" "$GATE_LOG"; then
                log_pass "S3 cache backend active (MinIO)"
            else
                log_fail "S3 cache backend NOT detected in logs — may have fallen back to local"
            fi
        elif [ "${SGW_CACHE_BACKEND}" = "azure_blob" ]; then
            if grep -q "azure blob cache store initialized" "$GATE_LOG"; then
                log_pass "Azure Blob cache backend active (Azurite)"
            else
                log_fail "Azure Blob cache backend NOT detected in logs — may have fallen back to local"
            fi
        fi
        if grep -q "postgres connection pool configured" "$GATE_LOG"; then
            log_pass "PostgreSQL backend active"
        else
            log_fail "PostgreSQL backend NOT detected in logs — may have fallen back to SQLite"
        fi
    else
        log_info "Gate log not available — skipping backend verification"
    fi
fi

# ---------------------------------------------------------------------------
# Run all test suites
# ---------------------------------------------------------------------------
test_pypi
test_npm
test_nuget
test_docker
test_docker_registry
test_maven
test_rubygems
test_gomod
test_api
test_proxy_auth
test_policy_tiers
test_typosquat
test_version_diff
test_reputation
test_integrity

# ---------------------------------------------------------------------------
# Summary and exit code
# ---------------------------------------------------------------------------
print_summary
