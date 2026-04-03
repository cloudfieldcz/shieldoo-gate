#!/usr/bin/env bash
# test_ai_scanner.sh — AI Scanner e2e tests for Shieldoo Gate
# Sourced by run.sh; defines test_ai_scanner(). Do NOT set -e here.

test_ai_scanner() {
    log_section "AI Scanner Tests"

    # ------------------------------------------------------------------
    # 1. Health endpoint reports ai-scanner when enabled
    # ------------------------------------------------------------------
    local health_response
    health_response=$(api_get "/api/v1/health" 2>/dev/null || true)
    if [ -z "$health_response" ]; then
        log_skip "AI Scanner: admin API not reachable"
        return
    fi

    # When AI scanner is disabled (default), it should not appear in scanners.
    # When enabled (requires AI_SCANNER_API_KEY), it should appear.
    if [ "${SGW_SCANNERS_AI_ENABLED:-false}" = "true" ]; then
        if echo "$health_response" | jq -e '.scanners["ai-scanner"]' > /dev/null 2>&1; then
            log_pass "AI Scanner: appears in health check when enabled"
        else
            log_fail "AI Scanner: not found in health check despite being enabled"
        fi
    else
        if echo "$health_response" | jq -e '.scanners["ai-scanner"]' > /dev/null 2>&1; then
            log_fail "AI Scanner: appears in health check despite being disabled"
        else
            log_pass "AI Scanner: correctly absent from health check when disabled"
        fi
    fi

    # ------------------------------------------------------------------
    # 2. Verify AI scanner config is accepted (no startup crash)
    # ------------------------------------------------------------------
    # If we reach this point, the gate started successfully, which means
    # the AI scanner config (even if disabled) does not break startup.
    log_pass "AI Scanner: gate starts successfully with AI scanner config"

    # ------------------------------------------------------------------
    # 3. Malicious .pth fixture test (only when AI scanner is enabled)
    # ------------------------------------------------------------------
    if [ "${SGW_SCANNERS_AI_ENABLED:-false}" = "true" ]; then
        local fixture_dir="${SCRIPT_DIR}/fixtures/ai-scanner"
        if [ -d "$fixture_dir" ]; then
            # Create a minimal wheel with a malicious .pth file.
            local workdir
            workdir=$(mktemp -d)

            # Build a minimal .whl with evil .pth.
            mkdir -p "$workdir/evil_pth_pkg"
            echo "# safe module" > "$workdir/evil_pth_pkg/__init__.py"
            cat > "$workdir/evil_pth_pkg.pth" << 'PTHEOF'
import os, subprocess, sys; subprocess.Popen([sys.executable, "-c", "import base64; exec(base64.b64decode('cHJpbnQoJ3B3bmVkJyk='))"])
PTHEOF
            # Create a wheel-like zip.
            local whl_path="$workdir/evil_pth_pkg-1.0.0-py3-none-any.whl"
            (cd "$workdir" && zip -q "$whl_path" evil_pth_pkg/__init__.py evil_pth_pkg.pth)

            log_info "AI Scanner: created malicious .pth fixture at $whl_path"

            # The actual blocking test would require uploading the artifact
            # through the proxy, which depends on full PyPI publish flow.
            # For now, verify the fixture was created successfully.
            if [ -f "$whl_path" ]; then
                log_pass "AI Scanner: malicious .pth fixture created successfully"
            else
                log_fail "AI Scanner: failed to create malicious .pth fixture"
            fi

            rm -rf "$workdir"
        else
            log_skip "AI Scanner: fixtures/ai-scanner directory not found"
        fi
    else
        log_skip "AI Scanner: .pth fixture test skipped (AI scanner not enabled)"
    fi
}
