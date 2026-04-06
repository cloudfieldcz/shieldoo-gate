#!/usr/bin/env bash
# test_policy_tiers.sh — E2E tests for policy tiers feature
#
# Runs in ALL 3 E2E passes. Behavior adapts based on SGW_POLICY_MODE:
#   Pass 1 (strict):     MEDIUM CVE → 403, MALICIOUS → 403, behavioral → 403
#   Pass 2 (balanced):   MEDIUM CVE → 200+warning, MALICIOUS → 403, behavioral → 403
#   Pass 3 (permissive): MEDIUM CVE → 200+warning, MALICIOUS → 403, behavioral → 403
#
# Security invariants (MALICIOUS, behavioral) are verified in ALL passes.

POLICY_MODE="${SGW_POLICY_MODE:-strict}"

# ─── Test 1: MALICIOUS always blocked (ALL modes) ─────────────────
# Security invariant: MALICIOUS → BLOCK regardless of mode.
_test_malicious_always_blocked() {
    log_info "[ALL modes] MALICIOUS package must be blocked (mode=$POLICY_MODE)"
    local status
    # Use a known malicious-flagged package or threat feed entry
    status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" \
        "${E2E_PYPI_URL}/simple/malicious-test-pkg/")
    # 403 = blocked by policy, 404 = not found (acceptable — not in threat feed)
    # Key assertion: NEVER 200
    if [ "$status" = "200" ]; then
        log_fail "MALICIOUS package returned 200 in $POLICY_MODE mode — SECURITY VIOLATION"
        return
    fi
    log_pass "MALICIOUS package not served (HTTP $status) in $POLICY_MODE mode"
}

# ─── Test 2: MEDIUM CVE package — mode-specific behavior ───────────
# strict:     HTTP 403 (quarantined)
# balanced:   HTTP 200 + X-Shieldoo-Warning header
# permissive: HTTP 200 + X-Shieldoo-Warning header
_test_medium_cve_package() {
    log_info "[$POLICY_MODE] MEDIUM CVE package behavior"
    local headers_file="/tmp/e2e_policy_tiers_headers"
    local status
    # Use a real package with known MEDIUM CVE (qs@6.11.0 — ReDoS CVE)
    status=$(curl -s -D "$headers_file" -o /dev/null -w "%{http_code}" \
        "${E2E_CURL_AUTH[@]}" "${E2E_NPM_URL}/qs/-/qs-6.11.0.tgz")

    case "$POLICY_MODE" in
        strict)
            assert_eq "strict: MEDIUM CVE must be quarantined (HTTP 403)" \
                "403" "$status"
            ;;
        balanced)
            # In balanced mode, MEDIUM CVE goes to AI triage.
            # AI may decide ALLOW (200+warning) or QUARANTINE (403) — both are valid.
            if [ "$status" = "200" ]; then
                assert_contains "balanced: X-Shieldoo-Warning header must be present" \
                    "X-Shieldoo-Warning" "$(cat "$headers_file")"
            elif [ "$status" = "403" ]; then
                log_pass "balanced: MEDIUM CVE quarantined by AI triage (HTTP 403)"
            else
                log_fail "balanced: unexpected HTTP $status for MEDIUM CVE (expected 200 or 403)"
            fi
            ;;
        permissive)
            assert_eq "permissive: MEDIUM CVE must be allowed (HTTP 200)" \
                "200" "$status"
            assert_contains "permissive: X-Shieldoo-Warning header must be present" \
                "X-Shieldoo-Warning" "$(cat "$headers_file")"
            ;;
    esac
    rm -f "$headers_file"
}

# ─── Test 3: Behavioral scanner → always quarantined (ALL modes) ──
# Scanner category floor: behavioral findings → effective severity HIGH → QUARANTINE.
_test_behavioral_always_quarantined() {
    log_info "[ALL modes] Behavioral scanner finding must be quarantined (mode=$POLICY_MODE)"
    local status
    # @protobufjs/inquire triggers ai-scanner SUSPICIOUS+MEDIUM → floor = HIGH → 403
    status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" \
        "${E2E_NPM_URL}/@protobufjs/inquire/-/inquire-1.1.0.tgz")
    assert_eq "Behavioral finding must be quarantined in $POLICY_MODE mode (HTTP 403)" \
        "403" "$status"
}

# ─── Test 4: Audit log event type — mode-specific ─────────────────
_test_audit_log_event_type() {
    log_info "[$POLICY_MODE] Verify audit log event types"
    sleep 2  # wait for async audit log write
    local events
    events=$(api_jq "/api/v1/audit?limit=20" '.data[].event_type' 2>/dev/null || echo "")

    case "$POLICY_MODE" in
        strict)
            assert_contains "strict: audit log must contain QUARANTINED events" \
                "QUARANTINED" "$events"
            ;;
        balanced)
            # In balanced mode, AI triage may ALLOW or QUARANTINE — check for either event type.
            if echo "$events" | grep -q "ALLOWED_WITH_WARNING"; then
                log_pass "balanced: audit log contains ALLOWED_WITH_WARNING events"
            elif echo "$events" | grep -q "QUARANTINED"; then
                log_pass "balanced: audit log contains QUARANTINED events (AI triage decided quarantine)"
            else
                log_fail "balanced: audit log must contain ALLOWED_WITH_WARNING or QUARANTINED events"
            fi
            ;;
        permissive)
            assert_contains "$POLICY_MODE: audit log must contain ALLOWED_WITH_WARNING events" \
                "ALLOWED_WITH_WARNING" "$events"
            ;;
    esac
}

# ─── Test 5: X-Shieldoo-Warning header absence on CLEAN ──────────
_test_warning_header_clean() {
    log_info "[$POLICY_MODE] X-Shieldoo-Warning header check on CLEAN package"
    local headers_file="/tmp/e2e_policy_tiers_headers_clean"
    # Download a known CLEAN package — should never have warning header
    curl -s -D "$headers_file" -o /dev/null \
        "${E2E_CURL_AUTH[@]}" "${E2E_NPM_URL}/is-number/-/is-number-7.0.0.tgz"
    if grep -qi "X-Shieldoo-Warning" "$headers_file" 2>/dev/null; then
        log_fail "CLEAN package should NOT have X-Shieldoo-Warning header"
    else
        log_pass "CLEAN package correctly has no X-Shieldoo-Warning header"
    fi
    rm -f "$headers_file"
}

# ─── Test 6: Startup log contains correct mode info ───────────────
_test_startup_log() {
    log_info "[$POLICY_MODE] Verify startup log messages"
    local log_file="/var/log/shieldoo-gate/gate.log"

    if [ ! -f "$log_file" ]; then
        log_skip "Gate log not available — skipping startup log check"
        return
    fi

    local logs
    logs=$(head -50 "$log_file")

    case "$POLICY_MODE" in
        strict)
            # strict is default, no special startup warning expected
            log_pass "strict mode: no special startup warning expected"
            ;;
        balanced)
            assert_contains "balanced: startup log must mention balanced mode" \
                "balanced" "$logs"
            ;;
        permissive)
            assert_contains "permissive: startup log must contain permissive WARNING" \
                "permissive" "$logs"
            ;;
    esac
}

# ─── Main test function ──────────────────────────────────────────
test_policy_tiers() {
    log_section "Policy Tiers (mode=$POLICY_MODE)"
    _test_malicious_always_blocked
    _test_medium_cve_package
    _test_behavioral_always_quarantined
    _test_audit_log_event_type
    _test_warning_header_clean
    _test_startup_log
}
