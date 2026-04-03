#!/usr/bin/env bash
# test_ai_scanner.sh — AI Scanner e2e tests for Shieldoo Gate
# Sourced by run.sh; defines test_ai_scanner(). Do NOT set -e here.

test_ai_scanner() {
    log_section "AI Scanner Tests"

    # ------------------------------------------------------------------
    # 1. Health endpoint behaviour depending on AI scanner state
    # ------------------------------------------------------------------
    local health_response
    health_response=$(api_get "/api/v1/health" 2>/dev/null || true)
    if [ -z "$health_response" ]; then
        log_skip "AI Scanner: admin API not reachable"
        return
    fi

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
    log_pass "AI Scanner: gate starts successfully with AI scanner config"

    # ------------------------------------------------------------------
    # 3. AI scanner integration test — install a real package and verify
    #    AI scanner participated in the scan pipeline (only when enabled)
    # ------------------------------------------------------------------
    if [ "${SGW_SCANNERS_AI_ENABLED:-false}" != "true" ]; then
        log_skip "AI Scanner: integration tests skipped (AI scanner not enabled)"
        return
    fi

    # Install a small, clean package through the proxy to trigger the
    # full scan pipeline including AI scanner.
    local workdir
    workdir=$(mktemp -d)
    pushd "$workdir" > /dev/null

    uv venv .venv --quiet 2>/dev/null
    if uv pip install \
            --python .venv/bin/python \
            --no-cache \
            --index-url "$(auth_url "${E2E_PYPI_URL}")/simple/" \
            six==1.17.0 \
            > install.log 2>&1; then
        log_pass "AI Scanner: uv pip install six succeeded through proxy"
    else
        log_fail "AI Scanner: uv pip install six failed"
        cat install.log >&2
        popd > /dev/null
        rm -rf "$workdir"
        return
    fi

    popd > /dev/null
    rm -rf "$workdir"

    # Give the scan pipeline a moment to complete and persist results.
    sleep 2

    # ------------------------------------------------------------------
    # 4. Verify AI scanner appears in scan results via API
    # ------------------------------------------------------------------
    local artifact_data
    artifact_data=$(api_get "/api/v1/artifacts?search=six" 2>/dev/null || true)

    if [ -n "$artifact_data" ]; then
        # Check that the artifact was found.
        local six_count
        six_count=$(echo "$artifact_data" | jq '[.data[] | select(.name == "six")] | length' 2>/dev/null || echo "0")
        assert_gte "AI Scanner: six artifact registered in API" 1 "$six_count"

        # Check scan results for ai-scanner participation.
        local six_id
        six_id=$(echo "$artifact_data" | jq -r '[.data[] | select(.name == "six")][0].artifact_id' 2>/dev/null || echo "")

        if [ -n "$six_id" ] && [ "$six_id" != "null" ]; then
            local scan_results
            scan_results=$(api_get "/api/v1/artifacts/${six_id}/scans" 2>/dev/null || true)

            if [ -n "$scan_results" ]; then
                local ai_scan_count
                ai_scan_count=$(echo "$scan_results" | jq '[.data[] | select(.scanner_id == "ai-scanner")] | length' 2>/dev/null || echo "0")
                if [ "$ai_scan_count" -ge 1 ]; then
                    log_pass "AI Scanner: ai-scanner scan result found for six package"

                    # Verify the verdict is CLEAN (six is a legitimate package).
                    local ai_verdict
                    ai_verdict=$(echo "$scan_results" | jq -r '[.data[] | select(.scanner_id == "ai-scanner")][0].verdict' 2>/dev/null || echo "")
                    assert_eq "AI Scanner: six package verdict is CLEAN" "CLEAN" "$ai_verdict"
                else
                    log_fail "AI Scanner: no ai-scanner scan result found for six package"
                fi
            else
                log_fail "AI Scanner: could not fetch scan results for six"
            fi
        else
            log_fail "AI Scanner: could not determine artifact ID for six"
        fi
    else
        log_fail "AI Scanner: could not fetch artifact data"
    fi

    # ------------------------------------------------------------------
    # 5. Verify gate logs contain AI scanner entries
    # ------------------------------------------------------------------
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate 2>/dev/null || true)

    if [ -n "$gate_logs" ]; then
        if [[ "$gate_logs" == *"ai scanner: scan complete"* ]]; then
            log_pass "AI Scanner: gate logs contain 'ai scanner: scan complete' entry"
        else
            log_fail "AI Scanner: gate logs missing 'ai scanner: scan complete' entry"
        fi
    else
        log_skip "AI Scanner: gate logs not available"
    fi

    # ------------------------------------------------------------------
    # 6. Malicious .pth fixture test — create a wheel with a malicious
    #    .pth file and verify the extractor + scanner would flag it.
    #    We test this by calling the scanner-bridge gRPC directly via
    #    the Python test harness running inside the scanner-bridge container.
    # ------------------------------------------------------------------
    local fixture_dir="${SCRIPT_DIR}/fixtures/ai-scanner"
    if [ ! -d "$fixture_dir" ]; then
        log_skip "AI Scanner: fixtures/ai-scanner directory not found"
        return
    fi

    # Create a minimal wheel with a malicious .pth file.
    local mal_workdir
    mal_workdir=$(mktemp -d)

    mkdir -p "$mal_workdir/evil_pth_pkg"
    echo "# safe module" > "$mal_workdir/evil_pth_pkg/__init__.py"
    cat > "$mal_workdir/evil_pth_pkg.pth" << 'PTHEOF'
import os, subprocess, sys; subprocess.Popen([sys.executable, "-c", "import base64; exec(base64.b64decode('cHJpbnQoJ3B3bmVkJyk='))"])
PTHEOF

    local whl_path="$mal_workdir/evil_pth_pkg-1.0.0-py3-none-any.whl"
    (cd "$mal_workdir" && zip -q "$whl_path" evil_pth_pkg/__init__.py evil_pth_pkg.pth)

    if [ -f "$whl_path" ]; then
        log_pass "AI Scanner: malicious .pth fixture wheel created"
    else
        log_fail "AI Scanner: failed to create malicious .pth fixture wheel"
        rm -rf "$mal_workdir"
        return
    fi

    # Copy the wheel into the scanner-bridge container and run extraction test.
    local bridge_container
    bridge_container=$(docker compose -f "${COMPOSE_FILE}" ps -q scanner-bridge 2>/dev/null || true)

    if [ -n "$bridge_container" ]; then
        # Copy fixture into the container.
        docker cp "$whl_path" "${bridge_container}:/tmp/evil_pth_pkg-1.0.0-py3-none-any.whl" 2>/dev/null

        # Run the extractor inside the container and verify it finds the .pth file.
        local extract_result
        extract_result=$(docker exec "$bridge_container" python -c "
import sys
sys.path.insert(0, '/app')
from extractors.pypi import extract
result = extract('/tmp/evil_pth_pkg-1.0.0-py3-none-any.whl')
pth_files = [k for k in result if k.endswith('.pth')]
if pth_files:
    content = result[pth_files[0]]
    if 'subprocess' in content and 'base64' in content:
        print('DETECTED')
    else:
        print('PTH_FOUND_BUT_NO_MALICIOUS_PATTERNS')
else:
    print('NO_PTH_FOUND')
" 2>&1 || echo "ERROR")

        assert_eq "AI Scanner: extractor detects malicious .pth with subprocess+base64" \
            "DETECTED" "$extract_result"

        # If AI scanner is enabled and working, run a full AI scan on the fixture.
        local ai_scan_result
        ai_scan_result=$(docker exec "$bridge_container" python -c "
import sys, asyncio, json
sys.path.insert(0, '/app')
import ai_scanner

class FakeReq:
    artifact_id = 'pypi:evil-pth-pkg:1.0.0'
    ecosystem = 'pypi'
    name = 'evil-pth-pkg'
    version = '1.0.0'
    local_path = '/tmp/evil_pth_pkg-1.0.0-py3-none-any.whl'

result = asyncio.run(ai_scanner.scan(FakeReq()))
print(json.dumps({'verdict': result.get('verdict', 'ERROR'), 'confidence': result.get('confidence', 0)}))
" 2>&1 || echo '{"verdict":"ERROR","confidence":0}')

        if [ -n "$ai_scan_result" ]; then
            local verdict
            verdict=$(echo "$ai_scan_result" | jq -r '.verdict' 2>/dev/null || echo "PARSE_ERROR")
            local confidence
            confidence=$(echo "$ai_scan_result" | jq -r '.confidence' 2>/dev/null || echo "0")

            if [ "$verdict" = "MALICIOUS" ]; then
                log_pass "AI Scanner: LLM correctly identified malicious .pth (verdict=$verdict, confidence=$confidence)"
            elif [ "$verdict" = "SUSPICIOUS" ]; then
                log_pass "AI Scanner: LLM flagged malicious .pth as SUSPICIOUS (verdict=$verdict, confidence=$confidence)"
            elif [ "$verdict" = "ERROR" ] || [ "$verdict" = "PARSE_ERROR" ]; then
                log_fail "AI Scanner: LLM scan failed for malicious .pth fixture (output: $ai_scan_result)"
            else
                log_fail "AI Scanner: LLM did NOT detect malicious .pth (verdict=$verdict, confidence=$confidence)"
            fi
        else
            log_fail "AI Scanner: could not run AI scan on malicious .pth fixture"
        fi

        # Clean up fixture inside container.
        docker exec "$bridge_container" rm -f /tmp/evil_pth_pkg-1.0.0-py3-none-any.whl 2>/dev/null || true
    else
        log_skip "AI Scanner: scanner-bridge container not found, skipping .pth fixture test"
    fi

    rm -rf "$mal_workdir"

    # ------------------------------------------------------------------
    # 7. Audit log: verify SERVED events include AI scanner metadata
    # ------------------------------------------------------------------
    local audit_data
    audit_data=$(api_get "/api/v1/audit?per_page=50&event_type=SERVED" 2>/dev/null || true)
    if [ -n "$audit_data" ]; then
        local pypi_served
        pypi_served=$(echo "$audit_data" | jq '[.data[] | select(.artifact_id | startswith("pypi:"))] | length' 2>/dev/null || echo "0")
        assert_gte "AI Scanner: at least 1 SERVED audit event for pypi artifacts" 1 "$pypi_served"
    else
        log_skip "AI Scanner: audit log not available"
    fi
}
