#!/usr/bin/env bash
# test_pypi_multi_index.sh — Multi-upstream-index PyPI e2e tests for Shieldoo Gate
# Sourced by run.sh / run_all.sh; defines test_pypi_multi_index(). Do NOT set -e here.
#
# Validates multi-index behaviour end-to-end through the gate (issue #32).
#
# S1 — back-compat:    normal public package still routes via default upstream.
# S2 — scanned+cached: private unscoped package (mycompany-lib) is served via
#                       /ext-packages/private/…, scanned, and cached under
#                       ecosystem pypi__private (THE release gate — no bypass).
#   S2a  simple page contains /ext-packages/private/ rewritten href.
#   S2b  tarball fetched through the gate (HTTP 200, non-empty body).
#   S2c  artifact row exists under ecosystem pypi__private (authoritative check).
# S3 — scoped:          acme-widget (claimed by corp via acme-*) routes to corp index.
# S4 — scoped-miss:     acme-ghost (claimed by corp but absent) → 404 + BLOCKED audit.
# S5 — SSRF fail-closed: /ext-packages/ghost/… → 404 before any upstream request.

test_pypi_multi_index() {
    log_section "PyPI Multi-Index Tests (issue #32)"

    # -----------------------------------------------------------------------
    # S1 — Default upstream back-compat: public package still works
    # -----------------------------------------------------------------------
    log_section "S1: default upstream back-compat (requests)"

    local s1_workdir
    s1_workdir=$(mktemp -d)
    pushd "$s1_workdir" > /dev/null || { log_fail "S1: could not enter workdir"; return; }

    uv venv .venv --quiet 2>/dev/null
    if uv pip install \
            --python .venv/bin/python \
            --no-deps \
            --no-cache \
            --index-url "$(auth_url "${E2E_PYPI_URL}")/simple/" \
            requests \
            > install.log 2>&1; then
        log_pass "S1: requests installed via gate default upstream"
    else
        log_fail "S1: requests install failed (see log below)"
        cat install.log >&2
    fi

    popd > /dev/null || true
    rm -rf "$s1_workdir"

    # -----------------------------------------------------------------------
    # S2 — Private unscoped package: scanned+cached under pypi__private
    #
    # mycompany-lib exists only on the private index (not on pypi.org).
    # The gate must:
    #   1. Rewrite the simple-page hrefs to /ext-packages/private/…  (S2a)
    #   2. Serve the tarball through /ext-packages/private/…           (S2b)
    #   3. Create an artifact row under ecosystem pypi__private        (S2c ← hard gate)
    #
    # S2b uses a deterministic curl-fetch of the rewritten href so a uv build
    # quirk (sdist missing [build-system]) cannot block the scan+cache proof.
    # S2c is the authoritative release-gate assertion: if it fails, a private
    # artifact reached the client without scanning — full scan bypass.
    # -----------------------------------------------------------------------
    log_section "S2: private unscoped package scanned+cached (mycompany-lib)"

    # S2a — simple page contains /ext-packages/private/ rewritten href
    local mycompany_simple_page
    mycompany_simple_page=$(curl -sf "${E2E_CURL_AUTH[@]}" \
        "${E2E_PYPI_URL}/simple/mycompany-lib/")

    if [[ "$mycompany_simple_page" == *"/ext-packages/private/"* ]]; then
        log_pass "S2a: simple page for mycompany-lib contains /ext-packages/private/ (URL rewritten)"
    else
        log_fail "S2a: simple page for mycompany-lib does NOT contain /ext-packages/private/ href"
        log_info "S2a: page body was: ${mycompany_simple_page}"
    fi

    # S2b — extract the rewritten tarball URL and fetch it through the gate
    # The href in the simple page is a relative /ext-packages/private/… path,
    # so we prefix it with the gate's base URL.
    local tarball_path
    tarball_path=$(printf '%s' "$mycompany_simple_page" \
        | grep -oE '/ext-packages/private/[^"'\''> ]+' \
        | head -1)

    if [ -n "$tarball_path" ]; then
        # Assert on the HTTP status (not the body) — capturing a gzip tarball into a
        # shell var trips bash's "ignored null byte" warning and proves nothing extra.
        local tarball_code
        tarball_code=$(curl -s -o /dev/null -w '%{http_code}' "${E2E_CURL_AUTH[@]}" "${E2E_PYPI_URL}${tarball_path}")
        if [ "$tarball_code" = "200" ]; then
            log_pass "S2b: mycompany-lib tarball fetched through gate (/ext-packages/private/…)"
        else
            log_fail "S2b: failed to fetch mycompany-lib tarball through gate (HTTP ${tarball_code})"
        fi
    else
        log_fail "S2b: could not extract /ext-packages/private/… href from simple page"
    fi

    # Also attempt a real uv install as a client-signal (optional — build failures
    # are NOT a gate failure here; S2c is the authoritative proof).
    local s2_workdir
    s2_workdir=$(mktemp -d)
    pushd "$s2_workdir" > /dev/null || { log_fail "S2: could not enter workdir"; return; }

    uv venv .venv --quiet 2>/dev/null
    # NOTE: uv fetches the sdist THEN tries to build metadata. The fetch triggers
    # the gate's download→scan→cache pipeline (S2c proof). If build fails (the
    # sdist has no [build-system]), that is a uv quirk, not a gate failure.
    if uv pip install \
            --python .venv/bin/python \
            --no-deps \
            --no-cache \
            --index-url "$(auth_url "${E2E_PYPI_URL}")/simple/" \
            mycompany-lib \
            > install.log 2>&1; then
        log_pass "S2: uv pip install of mycompany-lib succeeded (full client signal)"
    else
        # Build may fail due to missing [build-system]; the gate did its job if
        # the tarball was fetched (proven by S2b) and cached (proven by S2c).
        log_info "S2: uv pip install of mycompany-lib did not complete (likely sdist build quirk, not a gate failure)"
        log_info "S2: this is non-fatal — S2b (fetch) and S2c (scan+cache) are the authoritative checks"
    fi

    popd > /dev/null || true
    rm -rf "$s2_workdir"

    # S2c — THE RELEASE GATE: artifact row must exist under ecosystem pypi__private
    # This is the proof that no bypass occurred: the gate scanned and cached the
    # artifact before serving it to the client. Without this check a metadata-rewrite
    # miss would silently forward the private artifact un-scanned (worst-case bypass).
    local private_count
    private_count=$(api_jq "/api/v1/artifacts?ecosystem=pypi__private" \
        '[.data[] | select(.name | test("mycompany-lib"))] | length')

    assert_gte \
        "S2c (RELEASE GATE): artifact row under ecosystem pypi__private for mycompany-lib" \
        1 \
        "$private_count"

    # S2c diagnostics: the gate persists the artifact row SYNCHRONOUSLY before
    # serving (persistArtifact → http.ServeFile), so when S2b returned 200 the row
    # must already exist. If assert_gte above failed, this is NOT a timing race —
    # it means the private artifact was served without being scanned/cached (a
    # scan BYPASS). Emit extra audit diagnostics to localise the failure; do NOT
    # soften the verdict — assert_gte has already recorded the failure.
    if [ "${private_count:-0}" -lt 1 ] 2>/dev/null; then
        local private_served
        private_served=$(api_jq "/api/v1/audit?per_page=200&event_type=SERVED" \
            '[.data[] | select((.artifact_id // "") | test("pypi__private"))] | length')
        if [ "${private_served:-0}" -ge 1 ] 2>/dev/null; then
            log_fail "S2c-diagnostic: a SERVED audit row for pypi__private exists but NO artifact row — scan+cache did not complete (BYPASS)"
        else
            log_fail "S2c-diagnostic: no SERVED audit row for pypi__private either — private artifact never reached the scan pipeline (BYPASS)"
        fi
    fi

    # -----------------------------------------------------------------------
    # S3 — Scoped package: acme-widget claimed by corp index (acme-*)
    # -----------------------------------------------------------------------
    log_section "S3: scoped package via corp index (acme-widget)"

    # The simple page must contain /ext-packages/corp/ hrefs.
    local acme_simple_page
    acme_simple_page=$(curl -sf "${E2E_CURL_AUTH[@]}" \
        "${E2E_PYPI_URL}/simple/acme-widget/")

    if [[ "$acme_simple_page" == *"/ext-packages/corp/"* ]]; then
        log_pass "S3a: simple page for acme-widget contains /ext-packages/corp/ (scoped routing confirmed)"
    else
        log_fail "S3a: simple page for acme-widget does NOT contain /ext-packages/corp/ href"
        log_info "S3a: page body was: ${acme_simple_page}"
    fi

    # Fetch the tarball through the gate's /ext-packages/corp/… route.
    local acme_tarball_path
    acme_tarball_path=$(printf '%s' "$acme_simple_page" \
        | grep -oE '/ext-packages/corp/[^"'\''> ]+' \
        | head -1)

    if [ -n "$acme_tarball_path" ]; then
        local acme_tarball_code
        acme_tarball_code=$(curl -s -o /dev/null -w '%{http_code}' "${E2E_CURL_AUTH[@]}" "${E2E_PYPI_URL}${acme_tarball_path}")
        if [ "$acme_tarball_code" = "200" ]; then
            log_pass "S3b: acme-widget tarball fetched through gate (/ext-packages/corp/…)"
        else
            log_fail "S3b: failed to fetch acme-widget tarball through gate (HTTP ${acme_tarball_code})"
        fi
    else
        log_fail "S3b: could not extract /ext-packages/corp/… href from acme-widget simple page"
    fi

    # Also attempt a uv install as client signal (build failures are non-fatal here too).
    local s3_workdir
    s3_workdir=$(mktemp -d)
    pushd "$s3_workdir" > /dev/null || { log_fail "S3: could not enter workdir"; return; }

    uv venv .venv --quiet 2>/dev/null
    if uv pip install \
            --python .venv/bin/python \
            --no-deps \
            --no-cache \
            --index-url "$(auth_url "${E2E_PYPI_URL}")/simple/" \
            acme-widget \
            > install.log 2>&1; then
        log_pass "S3: uv pip install of acme-widget succeeded (full client signal)"
    else
        log_info "S3: uv pip install of acme-widget did not complete (likely sdist build quirk, not a gate failure)"
        log_info "S3: S3a (simple page) and S3b (tarball fetch) are the authoritative checks"
    fi

    popd > /dev/null || true
    rm -rf "$s3_workdir"

    # -----------------------------------------------------------------------
    # S4 — Scoped-miss: acme-ghost matches acme-* (claimed by corp), absent on
    #      private index → 404, no public fallback, and audited as BLOCKED.
    #
    # The action (GET /simple/acme-ghost/) must happen before the audit assertion.
    # -----------------------------------------------------------------------
    log_section "S4: scoped-miss (acme-ghost) → 404 + BLOCKED audit"

    # Trigger the 404 first (writes the BLOCKED audit row).
    assert_http_status \
        "S4: /simple/acme-ghost/ returns 404 (scoped-miss, no public fallback)" \
        "404" \
        "${E2E_PYPI_URL}/simple/acme-ghost/"

    # Now verify the BLOCKED audit event was written.
    local ghost_blocked
    ghost_blocked=$(api_jq "/api/v1/audit?per_page=200&event_type=BLOCKED" \
        '[.data[] | select((.artifact_id // "") | test("pypi__corp:acme-ghost"))] | length')

    assert_gte \
        "S4: BLOCKED audit event written for pypi__corp:acme-ghost (scoped-miss audited)" \
        1 \
        "$ghost_blocked"

    # -----------------------------------------------------------------------
    # S5 — SSRF fail-closed: forged extra-index name returns 404 immediately
    #      without making any upstream request.
    # -----------------------------------------------------------------------
    log_section "S5: SSRF fail-closed (forged index name → 404)"

    assert_http_status \
        "S5: /ext-packages/ghost/whatever-1.0.tar.gz returns 404 (unknown index name rejected)" \
        "404" \
        "${E2E_PYPI_URL}/ext-packages/ghost/whatever-1.0.tar.gz"
}
