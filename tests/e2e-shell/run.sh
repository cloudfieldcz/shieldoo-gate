#!/usr/bin/env bash
# run.sh — E2E shell test suite for Shieldoo Gate
#
# Usage: ./tests/e2e-shell/run.sh [--no-build] [--keep]
#   --no-build  Skip docker compose build (use existing images)
#   --keep      Don't tear down stack after tests (for debugging)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.e2e.yml"

export SCRIPT_DIR COMPOSE_FILE

# Parse args
NO_BUILD=false
KEEP_STACK=false
for arg in "$@"; do
    case "$arg" in
        --no-build) NO_BUILD=true ;;
        --keep)     KEEP_STACK=true ;;
    esac
done

# Source helpers and test files
source "${SCRIPT_DIR}/helpers.sh"
source "${SCRIPT_DIR}/test_pypi.sh"
source "${SCRIPT_DIR}/test_npm.sh"
source "${SCRIPT_DIR}/test_nuget.sh"
source "${SCRIPT_DIR}/test_docker.sh"
source "${SCRIPT_DIR}/test_api.sh"

check_prereqs() {
    local missing=()
    for cmd in docker curl jq uv node npm; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Missing required tools: ${missing[*]}"
        echo "Install them and retry."
        exit 1
    fi
    if ! docker compose version &>/dev/null; then
        echo "docker compose plugin not available"
        exit 1
    fi
}

cleanup() {
    if [[ "$KEEP_STACK" == "true" ]]; then
        log_info "Stack kept running (--keep). Tear down with:"
        log_info "  docker compose -f ${COMPOSE_FILE} down -v"
        return
    fi
    log_info "Tearing down e2e stack..."
    docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans 2>/dev/null || true
}

main() {
    log_section "Shieldoo Gate — E2E Shell Tests"
    check_prereqs

    # Register cleanup trap early (before any containers start)
    trap cleanup EXIT

    # 1. Clean slate
    log_info "Cleaning previous e2e state..."
    docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans 2>/dev/null || true

    # 2. Build (unless --no-build)
    if [[ "$NO_BUILD" == "false" ]]; then
        log_info "Building images..."
        if ! docker compose -f "${COMPOSE_FILE}" build 2>&1; then
            log_fail "Docker build failed"
            exit 1
        fi
    fi

    # 3. Start stack
    log_info "Starting e2e stack..."
    if ! docker compose -f "${COMPOSE_FILE}" up -d 2>&1; then
        log_fail "Docker compose up failed"
        exit 1
    fi

    # 4. Wait for health
    if ! wait_for_ready 120; then
        log_fail "Stack failed to start"
        docker compose -f "${COMPOSE_FILE}" logs 2>&1 | tail -50
        exit 1
    fi

    # 5. Run test suites
    test_pypi
    test_npm
    test_nuget
    test_docker
    test_api

    # 6. Summary
    print_summary
}

main "$@"
