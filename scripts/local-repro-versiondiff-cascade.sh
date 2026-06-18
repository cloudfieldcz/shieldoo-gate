#!/usr/bin/env bash
# Local reproduction of the version-diff required-scanner breaker cascade.
#
# Fires the UI's full npm dependency tree at the LOCAL gate (docker compose)
# with high concurrency. With version-diff marked `required` in
# docker/config.yaml and a COLD gate cache, the burst trips version-diff's
# circuit breaker, which cascades to the engine per-scanner breaker and fails
# every component closed with 503 "scanner unavailable".
#
# Prereqs:
#   docker compose -f docker/docker-compose.yml up -d --build   # gate on :4873
#   gate cache must be COLD (fresh volumes, or `docker volume rm` the cache)
#   the host npm cache is BYPASSED via a throwaway --cache dir below, otherwise
#   npm serves tarballs locally and never hits the gate.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGISTRY="${REGISTRY:-http://localhost:4873/}"
WORK="$(mktemp -d /tmp/sgw-repro.XXXXXX)"
NPM_CACHE="$(mktemp -d /tmp/sgw-npm-cache.XXXXXX)"

echo ">> work dir:   $WORK"
echo ">> npm cache:  $NPM_CACHE (throwaway — bypasses host ~/.npm)"
echo ">> registry:   $REGISTRY"

cp "$REPO_ROOT/ui/package.json" "$REPO_ROOT/ui/package-lock.json" "$WORK/"
cd "$WORK"

echo ">> running npm ci against the local gate (cold cache forces fresh scans)..."
# --prefer-online + throwaway cache => every tarball is fetched THROUGH the gate.
npm ci \
  --registry "$REGISTRY" \
  --cache "$NPM_CACHE" \
  --prefer-online \
  --no-audit --no-fund \
  --fetch-retries 0 \
  --loglevel http
status=$?

echo
echo "============================================================"
if [ $status -eq 0 ]; then
  echo "RESULT: npm ci SUCCEEDED (exit 0) — no cascade (fix works / not reproduced)"
else
  echo "RESULT: npm ci FAILED (exit $status) — check for 503 'scanner unavailable' above (cascade reproduced)"
fi
echo "Inspect gate breaker state:"
echo "  docker compose -f docker/docker-compose.yml exec -T shieldoo-gate wget -qO- http://localhost:8080/metrics | grep circuit_breaker_state"
echo "============================================================"

rm -rf "$WORK" "$NPM_CACHE"
exit $status
