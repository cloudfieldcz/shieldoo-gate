#!/usr/bin/env bash
# test_oversized_artifact.sh — Oversized-artifact (terminal scanner error) e2e tests.
# Sourced by run_all.sh; defines test_oversized_artifact(). Do NOT set -e here.
#
# Regression cover for the PROD incident where every fetch of
# opencv-contrib-python 4.10.0.84 returned HTTP 503 forever:
#
#   1. version-diff is criticality "required" (config.e2e.yaml, mirroring PROD).
#   2. Its compressed-size guard (max_artifact_size_mb: 50) returns a TERMINAL
#      scanner error for artifacts it can never ship to the bridge.
#   3. The guard sits AFTER the previous-version lookup, so it only fires once a
#      sibling distribution of the same package is already cached — a first-seen
#      oversized package exits CLEAN before reaching it.
#   4. The policy engine used to map every required-scanner error to retry_later
#      (503 + Retry-After), so clients were told to come back for a verdict that
#      was structurally predetermined. pip retried forever and the gate
#      re-downloaded ~68 MB and re-ran the whole scanner suite on every attempt.
#
# Terminal errors must now fail closed as a definitive 403 BLOCKED. The size-evasion
# guard ("pad the package past the limit to skip the diff") stays shut; operators
# unblock deliberately via a policy override or by raising max_artifact_size_mb.
#
# NOTE ON COST: this suite pulls two real multi-MB wheels from pypi.org (~130 MB
# total) because version-diff only declares EcosystemPyPI and therefore never runs
# on the local private-index fixtures (those are cached as pypi__private). The
# oversized path cannot be reproduced without a genuine >50 MB artifact.

# The seed and target MUST be two distributions of the SAME package so that the
# target finds a predecessor and falls through to the size guard. Both opencv
# wheels are well over the 50 MB cap.
OVERSIZED_PKG="opencv-contrib-python"
OVERSIZED_SEED_VERSION="4.9.0.80"
OVERSIZED_TARGET_VERSION="4.10.0.84"

# oversized_wheel_url pkg version — resolve a downloadable href for the given
# version from the gate's PEP 503 simple page. Echoes an absolute gate URL, or
# nothing when no matching href is present.
oversized_wheel_url() {
    local pkg="$1" version="$2" page href
    page=$(curl -sf "${E2E_CURL_AUTH[@]}" "${E2E_PYPI_URL}/simple/${pkg}/" 2>/dev/null) || return 0

    # Prefer a manylinux x86_64 wheel (deterministic, always >50 MB for opencv);
    # fall back to any href carrying the exact version string.
    href=$(printf '%s' "$page" \
        | grep -oE 'href="[^"]+"' \
        | sed -e 's/^href="//' -e 's/"$//' \
        | grep -F "${pkg//-/_}-${version}-" \
        | grep -E 'manylinux.*x86_64\.whl' \
        | head -1)
    if [ -z "$href" ]; then
        href=$(printf '%s' "$page" \
            | grep -oE 'href="[^"]+"' \
            | sed -e 's/^href="//' -e 's/"$//' \
            | grep -F "${version}" \
            | head -1)
    fi
    [ -n "$href" ] || return 0

    # Strip any PEP 503 #sha256=… fragment, then absolutise relative hrefs.
    href="${href%%#*}"
    case "$href" in
        http://*|https://*) printf '%s' "$href" ;;
        /*)                 printf '%s%s' "${E2E_PYPI_URL}" "$href" ;;
        *)                  printf '%s/simple/%s/%s' "${E2E_PYPI_URL}" "$pkg" "$href" ;;
    esac
}

test_oversized_artifact() {
    log_section "Oversized Artifact / Terminal Scanner Error Tests"

    # The terminal path only exists when version-diff is enabled AND criticality
    # "required" (config.e2e.yaml sets both, mirroring PROD). There is no admin
    # endpoint exposing scanner criticality, so this suite is outcome-gated
    # instead: a served (200) target means the guard never fired and the run is
    # reported as non-conclusive rather than as a pass or a failure.

    # -----------------------------------------------------------------------
    # 1. Seed a predecessor. A first-seen oversized package has no previous
    #    version, so version-diff returns CLEAN before the size guard and the
    #    artifact is served normally. This step must therefore SUCCEED — it is
    #    also the control proving oversized artifacts are not blocked outright.
    # -----------------------------------------------------------------------
    local seed_url
    seed_url=$(oversized_wheel_url "$OVERSIZED_PKG" "$OVERSIZED_SEED_VERSION")
    if [ -z "$seed_url" ]; then
        log_skip "Oversized: no ${OVERSIZED_PKG} ${OVERSIZED_SEED_VERSION} wheel href on simple page — upstream layout changed"
        return
    fi

    local seed_code
    seed_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 600 \
        "${E2E_CURL_AUTH[@]}" "$seed_url")
    if [ "$seed_code" = "200" ]; then
        log_pass "Oversized: first-seen oversized wheel (${OVERSIZED_SEED_VERSION}) served — no predecessor, size guard not reached"
    else
        log_fail "Oversized: seed wheel ${OVERSIZED_SEED_VERSION} returned HTTP ${seed_code} (expected 200) — cannot establish predecessor"
        return
    fi

    # Let the scan pipeline commit the seed's artifact_status row: the
    # predecessor lookup only matches status CLEAN or SUSPICIOUS.
    sleep 5

    # -----------------------------------------------------------------------
    # 2. THE REGRESSION GATE: with a predecessor cached, the oversized target
    #    hits the terminal size guard. It must be a definitive 403, never a 503.
    # -----------------------------------------------------------------------
    local target_url
    target_url=$(oversized_wheel_url "$OVERSIZED_PKG" "$OVERSIZED_TARGET_VERSION")
    if [ -z "$target_url" ]; then
        log_skip "Oversized: no ${OVERSIZED_PKG} ${OVERSIZED_TARGET_VERSION} wheel href on simple page — upstream layout changed"
        return
    fi

    local target_code
    target_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 600 \
        "${E2E_CURL_AUTH[@]}" "$target_url")

    case "$target_code" in
        503)
            log_fail "Oversized: ${OVERSIZED_TARGET_VERSION} returned HTTP 503 — terminal scanner error mapped to retry_later (the PROD regression: retrying can never clear it)"
            ;;
        403)
            log_pass "Oversized: ${OVERSIZED_TARGET_VERSION} returned HTTP 403 — terminal scanner error fails closed as a definitive block"
            ;;
        200)
            # Served means the size guard never fired. Either the predecessor
            # was not visible yet, or the artifact is under the configured cap —
            # both make this run non-conclusive rather than a proven regression.
            log_skip "Oversized: ${OVERSIZED_TARGET_VERSION} served (HTTP 200) — size guard did not fire (no predecessor yet, or artifact under max_artifact_size_mb)"
            ;;
        *)
            log_fail "Oversized: ${OVERSIZED_TARGET_VERSION} returned unexpected HTTP ${target_code} (expected 403)"
            ;;
    esac

    # -----------------------------------------------------------------------
    # 3. Retrying must be idempotent: the same request stays 403 rather than
    #    oscillating into 503. This is what distinguishes "permanent" from
    #    "transient" for the client.
    # -----------------------------------------------------------------------
    if [ "$target_code" = "403" ]; then
        local retry_code
        retry_code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 600 \
            "${E2E_CURL_AUTH[@]}" "$target_url")
        assert_eq "Oversized: retry of a permanently unscannable artifact stays 403" "403" "$retry_code"
    fi

    # -----------------------------------------------------------------------
    # 4. The outage must never be silent: a SCAN_UNAVAILABLE audit row is
    #    required, and its metadata must classify the failure as terminal with
    #    the block mode actually applied.
    # -----------------------------------------------------------------------
    local unavailable_rows
    unavailable_rows=$(api_get "/api/v1/audit?per_page=200&event_type=SCAN_UNAVAILABLE" 2>/dev/null || true)

    if [ -z "$unavailable_rows" ]; then
        log_skip "Oversized: could not read SCAN_UNAVAILABLE audit rows"
        return
    fi

    local terminal_count
    terminal_count=$(printf '%s' "$unavailable_rows" \
        | jq '[.data[]? | select((.metadata_json // "") | contains("\"kind\":\"terminal\""))] | length' \
        2>/dev/null || echo "0")

    if [ "$terminal_count" -gt 0 ]; then
        log_pass "Oversized: SCAN_UNAVAILABLE audit row records kind=terminal (${terminal_count} row(s))"

        local block_mode_count
        block_mode_count=$(printf '%s' "$unavailable_rows" \
            | jq '[.data[]? | select(((.metadata_json // "") | contains("\"kind\":\"terminal\"")) and ((.metadata_json // "") | contains("\"mode\":\"block\"")))] | length' \
            2>/dev/null || echo "0")
        assert_gte "Oversized: terminal SCAN_UNAVAILABLE row records the applied mode as 'block'" 1 "$block_mode_count"
    elif [ "$target_code" = "403" ]; then
        log_fail "Oversized: artifact was blocked but no SCAN_UNAVAILABLE row with kind=terminal was written — outage is silent"
    else
        log_skip "Oversized: no terminal SCAN_UNAVAILABLE rows (size guard did not fire this run)"
    fi
}
