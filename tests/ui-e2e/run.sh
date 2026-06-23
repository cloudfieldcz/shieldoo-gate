#!/usr/bin/env bash
# run.sh — standalone UI test suite runner for the Shieldoo Gate admin UI.
#
# This suite is INTENTIONALLY separate from the shell e2e harness
# (tests/e2e-shell/run_all.sh). It brings up its OWN fresh gate (open / no-auth
# mode, empty DB) so visual-regression snapshots are deterministic, then runs
# the Playwright suite (ui/e2e) inside the PINNED Playwright container so dev
# (macOS) and CI (Linux) render byte-identically.
#
# Usage:
#   tests/ui-e2e/run.sh            # verify against committed baselines
#   tests/ui-e2e/run.sh --update   # regenerate baselines (after intentional UI changes)
#   tests/ui-e2e/run.sh --keep     # leave the gate stack running afterwards
#
# Baselines live in ui/e2e/__screenshots__ and are committed. They MUST only be
# regenerated via this script (the pinned container) — see docs/development/ui-e2e.md.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/tests/e2e-shell/docker-compose.e2e.yml"

# docker compose project is named "shieldoo-e2e" (see docker-compose.e2e.yml),
# so its bridge network is "shieldoo-e2e_proxy-net". The gate is reachable on it
# as the compose service DNS name shieldoo-gate:8080.
COMPOSE_NETWORK="shieldoo-e2e_proxy-net"
GATE_INTERNAL_URL="http://shieldoo-gate:8080"
GATE_HOST_HEALTH="http://localhost:18080/api/v1/health"

# Pinned Playwright image (digest-pinned per CLAUDE.md). The tag MUST match the
# @playwright/test version in ui/package.json (1.61.0) — bump both together.
PW_IMAGE="mcr.microsoft.com/playwright:v1.61.0-jammy@sha256:264136758e43332108f6420f82c47f639f619ca65301065ceade677763f477ec"

UPDATE_ARG=""
KEEP_STACK=false
for arg in "$@"; do
  case "$arg" in
    --update) UPDATE_ARG="--update-snapshots" ;;
    --keep)   KEEP_STACK=true ;;
    *) echo "unknown arg: $arg" >&2; exit 2 ;;
  esac
done

cleanup() {
  if [ "${KEEP_STACK}" = "true" ]; then
    echo "ui-e2e: leaving gate stack running (--keep). Tear down with:"
    echo "  docker compose -f ${COMPOSE_FILE} down -v --remove-orphans"
    return
  fi
  echo "ui-e2e: tearing down gate stack..."
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

echo "=== ui-e2e: building + starting a fresh open-mode gate ==="
docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans 2>/dev/null || true
docker compose -f "${COMPOSE_FILE}" build shieldoo-gate scanner-bridge
docker compose -f "${COMPOSE_FILE}" up -d shieldoo-gate

echo "=== ui-e2e: waiting for gate readiness ==="
for _ in $(seq 1 60); do
  if curl -sf "${GATE_HOST_HEALTH}" >/dev/null 2>&1; then
    echo "ui-e2e: gate ready"
    break
  fi
  sleep 2
done
curl -sf "${GATE_HOST_HEALTH}" >/dev/null 2>&1 || { echo "ui-e2e: gate did not become ready" >&2; exit 1; }

echo "=== ui-e2e: running Playwright in the pinned container ==="
# Anonymous volume on node_modules so the container's Linux install never
# clobbers the host's node_modules. CI=1 enables retry + html report.
docker run --rm \
  --network "${COMPOSE_NETWORK}" \
  -v "${REPO_ROOT}/ui:/work" -v /work/node_modules \
  -w /work \
  -e PLAYWRIGHT_BASE_URL="${GATE_INTERNAL_URL}" \
  -e CI=1 \
  "${PW_IMAGE}" \
  bash -lc "npm ci && npx playwright test ${UPDATE_ARG}"
