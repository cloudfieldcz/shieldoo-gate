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

echo "=== Shieldoo Gate E2E Test Suite (containerized) ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo ""

# When running inside docker-compose, COMPOSE_FILE is not set (no docker CLI needed).
# The docker_logs helper requires COMPOSE_FILE; make it a no-op in container mode.
if [ -z "${COMPOSE_FILE:-}" ]; then
    # Override docker_logs to cat container stdout instead of using docker compose
    docker_logs() {
        echo "(docker_logs not available inside container — skipping log inspection)"
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

# ---------------------------------------------------------------------------
# Summary and exit code
# ---------------------------------------------------------------------------
print_summary
