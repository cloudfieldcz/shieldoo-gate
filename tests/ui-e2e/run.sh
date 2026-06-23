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
# The gate stack is the shell-e2e compose, overlaid with a UI-specific override
# that swaps in a creds-free config (AI scanners downgraded to best_effort).
# Relative volume paths in both files resolve against the FIRST -f file's dir
# (tests/e2e-shell), so the override's ../e2e-shell/config.ui.yaml lands correctly.
COMPOSE_BASE="${REPO_ROOT}/tests/e2e-shell/docker-compose.e2e.yml"
COMPOSE_OVERRIDE="${SCRIPT_DIR}/docker-compose.ui.yml"
COMPOSE=(-f "${COMPOSE_BASE}" -f "${COMPOSE_OVERRIDE}")
SRC_CONFIG="${REPO_ROOT}/tests/e2e-shell/config.e2e.yaml"
UI_CONFIG="${REPO_ROOT}/tests/e2e-shell/config.ui.yaml"

# docker compose project is named "shieldoo-e2e" (see docker-compose.e2e.yml),
# so its bridge network is "shieldoo-e2e_proxy-net". The gate is reachable on it
# as the compose service DNS name shieldoo-gate:8080.
COMPOSE_NETWORK="shieldoo-e2e_proxy-net"
GATE_INTERNAL_URL="http://shieldoo-gate:8080"
GATE_HOST_HEALTH="http://localhost:18080/api/v1/health"

# Pinned Playwright image (digest-pinned per CLAUDE.md). This is the AMD64
# manifest digest specifically: pinning the per-arch digest fixes the rendering
# architecture so baselines are portable — an Apple-Silicon (arm64) dev machine
# pulls and runs this same amd64 image under emulation, byte-identical to the
# amd64 CI runner. (The gate compose pins linux/amd64 for the same reason.)
# The tag MUST match the @playwright/test version in ui/package.json (1.61.0);
# bump tag + amd64 digest + package.json together.
PW_IMAGE="mcr.microsoft.com/playwright:v1.61.0-jammy@sha256:19298da4a542f9823673f35f64690518abae7cb07ec925fcf4383b89e2766341"

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
    echo "  docker compose ${COMPOSE[*]} down -v --remove-orphans"
    return
  fi
  echo "ui-e2e: tearing down gate stack..."
  docker compose "${COMPOSE[@]}" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# Derive the creds-free UI config from the shell-e2e config: downgrade the
# AI-backed scanners to best_effort so the gate boots without Azure OpenAI
# credentials. Regenerated every run so it tracks config.e2e.yaml; git-ignored.
echo "=== ui-e2e: deriving creds-free config (config.ui.yaml) ==="
sed -E 's/(ai-scanner|version-diff): "required"/\1: "best_effort"/' "${SRC_CONFIG}" > "${UI_CONFIG}"

echo "=== ui-e2e: building + starting a fresh open-mode gate ==="
docker compose "${COMPOSE[@]}" down -v --remove-orphans 2>/dev/null || true
docker compose "${COMPOSE[@]}" build shieldoo-gate scanner-bridge
docker compose "${COMPOSE[@]}" up -d shieldoo-gate

echo "=== ui-e2e: waiting for gate readiness ==="
# Generous budget: a cold runner downloads the Trivy vuln DB and warms other
# scanners on first boot, which can take a few minutes (locally the caches are
# already warm and it is ~15s). 150 × 2s = 5 min.
for _ in $(seq 1 150); do
  if curl -sf "${GATE_HOST_HEALTH}" >/dev/null 2>&1; then
    echo "ui-e2e: gate ready"
    break
  fi
  sleep 2
done
if ! curl -sf "${GATE_HOST_HEALTH}" >/dev/null 2>&1; then
  echo "ui-e2e: gate did not become ready — dumping gate logs:" >&2
  docker compose "${COMPOSE[@]}" logs --tail=120 shieldoo-gate >&2 || true
  exit 1
fi

echo "=== ui-e2e: running Playwright in the pinned container ==="
# Architecture is pinned via the amd64 image digest above (PW_IMAGE), not a
# --platform flag — the two conflict ("cannot overwrite digest").
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
