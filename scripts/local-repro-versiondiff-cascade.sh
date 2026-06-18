#!/usr/bin/env bash
# Faithful local reproduction of the version-diff `required`-scanner breaker
# cascade. See docs/scanners/version-diff.md ("Reproducing the breaker cascade
# locally") and docker/docker-compose.local-repro.yml for the why.
#
# The cascade (metric-confirmed on prod):
#   1. Under a concurrent burst, version-diff's previous-version DB lookup
#      (internal/scanner/versiondiff/scanner.go:157) waits on an exhausted pool /
#      contended postgres → context.DeadlineExceeded → ErrKindRetryable.
#   2. 5 retryable errors open the engine per-scanner breaker (engine.go:76,
#      newScanCircuit(5, 1m)).
#   3. The open breaker fast-fails EVERY subsequent scan with `overload` →
#      policy ActionRetryLater → 503 "scanner unavailable".
#
# Why the OLD cold-cache `npm ci` script did NOT reproduce it:
#   - Cold DB → every package first-seen → sql.ErrNoRows → version-diff returns
#     CLEAN, never engaging its failure path. Prod cascaded because its DB had
#     version history (predecessors existed).
#   - sqlite WAL hides lock contention; amd64-on-arm emulation serializes.
#
# This harness flips all three (postgres + native arch + SEEDED predecessors)
# and drives a high-concurrency burst of *target* versions whose predecessor is
# already cached, so version-diff actually reaches its DB-lookup + bridge path.
#
# Phases:
#   0. bring up the local-repro stack (postgres, native arch) — unless SKIP_UP=1
#   1. SEED   — download the predecessor of every locked version in
#               ui/package-lock.json through the gate (caches each CLEAN +
#               records a DB version row for version-diff to diff against)
#   2. NPM CI — run a real `npm ci` of ui/ through the gate; every locked version
#               pulled now engages version-diff under npm's concurrent fan-out
#   3. OBSERVE — dump breaker state + scanner error counters, count 503s
#
# Env knobs:
#   SKIP_UP=1        reuse a stack already running (skip build + up)
#   CONCURRENCY=128  parallelism — seed xargs width AND npm ci --maxsockets
#   SGW_DB_POOL=5    gate postgres pool size (passed to the override; lower = bites faster)
#   BRIDGE_CPUS=2    scanner-bridge CPU cap (passed to the override; slower scans = more contention)
#   SGW_MAX_SCANS=32 engine max_concurrent_scans (passed to the override)
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

REGISTRY="${REGISTRY:-http://localhost:4873}"
ADMIN="${ADMIN:-http://localhost:8080}"
CONCURRENCY="${CONCURRENCY:-128}"
ROUNDS="${ROUNDS:-1}"

# Native arch is essential — emulation serializes and hides the concurrency.
export SGW_PLATFORM=""
COMPOSE=(docker compose -f docker/docker-compose.yml -f docker/docker-compose.local-repro.yml)

# The reproduction drives a real `npm ci` of the shieldoo-gate frontend
# (ui/package-lock.json, ~200 packages) THROUGH the gate — exactly what the
# release CI does against prod. Phase 1 seeds the predecessor of each locked
# version first, so the npm ci in phase 2 engages version-diff on every package.

log() { printf '\n\033[1;36m>> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }

require() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }; }
require jq
require curl

# ---------------------------------------------------------------------------
# Phase 0 — bring up the local-repro stack
# ---------------------------------------------------------------------------
if [ "${SKIP_UP:-0}" != "1" ]; then
  if [ ! -f docker/.env ]; then
    warn "docker/.env missing — seeding AI_SCANNER_* from .deploy/.env (gitignored)"
    if [ -f .deploy/.env ]; then
      { grep -E '^AI_SCANNER_' .deploy/.env | grep -v '^AI_SCANNER_ENABLED='; \
        echo "AI_SCANNER_ENABLED=true"; } > docker/.env
    else
      warn ".deploy/.env not found — bridge will run WITHOUT Azure creds (cascade harder to trigger)"
      echo "AI_SCANNER_ENABLED=false" > docker/.env
    fi
  fi
  log "building + starting local-repro stack (postgres + native arch)..."
  "${COMPOSE[@]}" up -d --build
else
  log "SKIP_UP=1 — reusing the running stack"
fi

log "waiting for the gate npm endpoint to answer..."
for _ in $(seq 1 60); do
  if curl -fsS -o /dev/null "$REGISTRY/lodash" 2>/dev/null; then break; fi
  sleep 2
done
curl -fsS -o /dev/null "$REGISTRY/lodash" || { echo "gate not reachable at $REGISTRY" >&2; exit 1; }

# predecessor_url <pkg> <lockedVer> -> gate tarball URL of the published stable
# version immediately BELOW <lockedVer> (empty if none / locked is the oldest).
# We seed this predecessor so that when `npm ci` later pulls <lockedVer>,
# version-diff has exactly one prior cached version to diff against.
predecessor_url() {
  local pkg="$1" locked="$2" packument stable pred
  packument="$(curl -fsS "$REGISTRY/$pkg" 2>/dev/null)" || return 0
  # stable versions only (exclude prereleases like 1.2.3-rc.1) — filter in jq to
  # avoid grep '-' ambiguity under ugrep.
  stable="$(jq -r '.versions | keys[] | select(test("-")|not)' <<<"$packument" 2>/dev/null)"
  [ -z "$stable" ] && return 0
  pred="$(printf '%s\n%s\n' "$stable" "$locked" | sort -V -u \
            | awk -v t="$locked" '$0==t{print prev; exit} {prev=$0}')"
  [ -z "$pred" ] && return 0
  jq -r --arg v "$pred" '.versions[$v].dist.tarball // empty' <<<"$packument" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Phase 1 — SEED predecessors of the LOCKED versions
# ---------------------------------------------------------------------------
log "PHASE 1 — resolving + seeding predecessors for the UI dependency tree..."
SEED_URLS="$(mktemp /tmp/sgw-seed-urls.XXXXXX)"
# name<TAB>lockedVersion for every node_modules entry in the lockfile.
jq -r '.packages | to_entries[]
       | select(.key|startswith("node_modules/"))
       | select(.key|sub("^node_modules/";"")|contains("node_modules/")|not)
       | "\(.key|sub("^node_modules/";""))\t\(.value.version)"' \
   "$REPO_ROOT/ui/package-lock.json" 2>/dev/null \
| while IFS=$'\t' read -r name locked; do
    [ -z "$name" ] || [ -z "$locked" ] && continue
    url="$(predecessor_url "$name" "$locked")"
    [ -n "$url" ] && echo "$url"
  done | sort -u > "$SEED_URLS"

seed_count=$(wc -l <"$SEED_URLS" | tr -d ' ')
log "resolved $seed_count predecessor tarballs — downloading through the gate ($CONCURRENCY-wide)..."
# Distinct artifacts → the per-artifact lock does not serialize them; this warms
# the cache + DB version history. version-diff stays cheap here (predecessors
# have no predecessor of their own → CLEAN), but guarddog/ai still scan each.
xargs -P "$CONCURRENCY" -I{} curl -s -o /dev/null {} < "$SEED_URLS"
rm -f "$SEED_URLS"
log "predecessors seeded; letting async cache/DB writes settle..."
sleep 5

# ---------------------------------------------------------------------------
# Phase 2 — npm ci the shieldoo-gate frontend THROUGH the gate (prod-faithful)
# ---------------------------------------------------------------------------
# This is exactly what the release CI does: `npm ci` of ui/ through the prod
# gate. Now that predecessors are cached, every locked version that gets pulled
# engages version-diff (locked vs seeded predecessor) under npm's concurrent
# fan-out — the load shape that cascaded on prod.
log "PHASE 2 — npm ci of ui/ through the gate (maxsockets=$CONCURRENCY)..."
require npm
WORK="$(mktemp -d /tmp/sgw-npmci.XXXXXX)"
NPM_CACHE="$(mktemp -d /tmp/sgw-npm-cache.XXXXXX)"   # throwaway → bypass host ~/.npm
NPM_LOG="$(mktemp /tmp/sgw-npmci.XXXXXX.log)"
cp "$REPO_ROOT/ui/package.json" "$REPO_ROOT/ui/package-lock.json" "$WORK/"
(
  cd "$WORK"
  npm ci \
    --registry "$REGISTRY/" \
    --cache "$NPM_CACHE" \
    --prefer-online \
    --maxsockets "$CONCURRENCY" \
    --no-audit --no-fund \
    --fetch-retries 0 \
    --loglevel http 2>&1
) | tee "$NPM_LOG"
npm_status=${PIPESTATUS[0]}

# ---------------------------------------------------------------------------
# Phase 3 — OBSERVE
# ---------------------------------------------------------------------------
log "PHASE 3 — results"
n503=$(grep -c "fetch GET 503\|503 .*scanner unavailable\|status 503" "$NPM_LOG" 2>/dev/null || true)
echo "   npm ci exit code:          $npm_status (0 = all served, non-zero = some request failed)"
echo "   503 'scanner unavailable': $n503   <-- > 0 means the cascade reproduced"
rm -rf "$WORK" "$NPM_CACHE" "$NPM_LOG"

echo
log "engine breaker + scanner error counters (admin /metrics):"
curl -fsS "$ADMIN/metrics" 2>/dev/null \
  | grep -E 'shieldoo_gate_circuit_breaker_state\{|shieldoo_gate_scanner_errors_total\{|scan_error_mode_applied' \
  | sed 's/^/   /' \
  || warn "could not read $ADMIN/metrics"

echo
echo "============================================================"
if [ "$n503" -gt 0 ] || [ "$npm_status" -ne 0 ]; then
  echo "RESULT: CASCADE LIKELY REPRODUCED — npm ci failed and/or saw 503 'scanner unavailable'."
  echo "        Confirm circuit_breaker_state{scanner=\"version-diff\"}=1 above."
else
  echo "RESULT: npm ci succeeded, no 503s — cascade NOT reproduced this run."
  echo "        Push harder: SGW_DB_POOL=5 ./scripts/local-repro-versiondiff-cascade.sh SKIP_UP=1,"
  echo "        raise CONCURRENCY (maxsockets), or confirm AI creds are set (a slow LLM call holds"
  echo "        the scan — and its DB connection — open long enough for the small pool to starve)."
fi
echo "Manual breaker check:"
echo "  curl -s $ADMIN/metrics | grep circuit_breaker_state"
echo "Tear down:  ${COMPOSE[*]} down -v"
echo "============================================================"
exit 0
