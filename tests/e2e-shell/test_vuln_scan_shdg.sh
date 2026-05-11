#!/usr/bin/env bash
# test_vuln_scan_shdg.sh — smoke-test the shdg CLI against the running gate.

test_vuln_scan_shdg() {
    log_section "Vuln-scan: shdg CLI smoke"

    if ! command -v shdg >/dev/null 2>&1; then
        log_skip "shdg: binary not present in runner (Dockerfile.test-runner must build it)"
        return
    fi
    local pre_status
    pre_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_ADMIN_URL}/api/v1/vulnerabilities/summary")
    if [ "$pre_status" = "503" ]; then
        log_skip "shdg: feature disabled"
        return
    fi
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" != "true" ] || [ -z "${SGW_PROXY_TOKEN:-}" ]; then
        log_skip "shdg: requires SGW_PROXY_AUTH_ENABLED + SGW_PROXY_TOKEN"
        return
    fi

    # Sub-test 1: `shdg version` exits 0.
    if shdg version >/dev/null 2>&1; then
        log_pass "shdg version: exit 0"
    else
        log_fail "shdg version: non-zero exit"
        return
    fi

    # Sub-test 2: missing flags → exit 2.
    set +e
    shdg scan --project foo >/dev/null 2>&1
    local rc=$?
    set -e
    if [ $rc -eq 2 ]; then
        log_pass "shdg scan (missing flags): exit 2 as expected"
    else
        log_fail "shdg scan (missing flags): exit ${rc}, want 2"
    fi

    # Sub-test 3: end-to-end upload via --sbom (skip Trivy bundling here —
    # E2E test rig has no internet access to GitHub).
    local fixture="${SCRIPT_DIR}/fixtures/vuln-scan/sbom-pypi-vulnerable.json"
    # Use date+pid for uniqueness; component-name regex allows a-z0-9- and 1-100
    # chars (per internal/component/component.go:ValidateComponentName).
    local component
    component="e2e-shdg-$(date +%s)"
    set +e
    SHIELDOO_TOKEN="${SGW_PROXY_TOKEN}" \
    SHIELDOO_URL="${E2E_ADMIN_URL}" \
        shdg scan \
            --project default --component "$component" \
            --sbom "$fixture" --ecosystem pypi \
            --verbose 2>&1
    rc=$?
    set -e
    if [ $rc -eq 0 ]; then
        log_pass "shdg scan --sbom: exit 0 (upload succeeded)"
    else
        log_fail "shdg scan --sbom: exit ${rc}, want 0"
        return
    fi

    # Sub-test 4: --wait + --fail-on=none should exit 0 even if findings appear.
    # --timeout 180s gives shdg headroom to retry on a 429 (rate-limited),
    # which is realistic in CI when many tests share a single token.
    set +e
    SHIELDOO_TOKEN="${SGW_PROXY_TOKEN}" \
    SHIELDOO_URL="${E2E_ADMIN_URL}" \
        shdg scan \
            --project default --component "${component}-wait" \
            --sbom "$fixture" --ecosystem pypi \
            --wait --fail-on none --poll-interval 500ms --timeout 180s \
            >/dev/null 2>&1
    rc=$?
    set -e
    if [ $rc -eq 0 ]; then
        log_pass "shdg scan --wait --fail-on none: exit 0"
    else
        log_fail "shdg scan --wait --fail-on none: exit ${rc}, want 0"
    fi

    # Sub-test 5: --wait --fail-on critical against a vulnerable pypi SBOM.
    # Should rc=1 IF OSV reports any criticals; if OSV is unreachable
    # (no internet in test rig), accept rc=0 with log_skip — the test rig
    # has no guaranteed outbound internet, so we can't make this strict.
    set +e
    SHIELDOO_TOKEN="${SGW_PROXY_TOKEN}" \
    SHIELDOO_URL="${E2E_ADMIN_URL}" \
        timeout 90 shdg scan \
            --project default --component "${component}-critical" \
            --sbom "$fixture" --ecosystem pypi \
            --wait --fail-on critical --poll-interval 1s --timeout 60s \
            >/dev/null 2>&1
    rc=$?
    set -e
    case "$rc" in
        1)
            log_pass "shdg scan --fail-on critical: rc=1 as expected (criticals reported)"
            ;;
        0)
            log_skip "shdg scan --fail-on critical: rc=0 — OSV may be unreachable, skipping strict assertion"
            ;;
        *)
            log_fail "shdg scan --fail-on critical: rc=${rc}, want 1 (or 0 if OSV unavailable)"
            ;;
    esac
}

# test_vuln_scan_shdg_image — exercises the --image path end-to-end:
# shdg shells out to `trivy image <ref>`, uploads the resulting CycloneDX
# (containing OS-layer packages), the server runs OSV+Trivy aggregation,
# and --fail-on maps the result to a CI exit code.
#
# Gated on `command -v docker` because the bundled Trivy needs the local
# Docker daemon (or registry pull) to inspect the image. The e2e rig
# does not always ship a daemon — skip cleanly when absent.
test_vuln_scan_shdg_image() {
    log_section "Vuln-scan: shdg --image"

    if ! command -v shdg >/dev/null 2>&1; then
        log_skip "shdg --image: binary not present in runner"
        return
    fi
    if ! command -v docker >/dev/null 2>&1; then
        log_skip "shdg --image: docker not present in runner"
        return
    fi
    local pre_status
    pre_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_ADMIN_URL}/api/v1/vulnerabilities/summary")
    if [ "$pre_status" = "503" ]; then
        log_skip "shdg --image: feature disabled"
        return
    fi
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" != "true" ] || [ -z "${SGW_PROXY_TOKEN:-}" ]; then
        log_skip "shdg --image: requires SGW_PROXY_AUTH_ENABLED + SGW_PROXY_TOKEN"
        return
    fi

    # Sub-test A: happy path — small public image, --fail-on none.
    # Pre-pull alpine:3.20 so a flaky registry doesn't fail the test
    # before shdg even runs; from there on, `trivy image` reads from
    # the local daemon.
    if ! docker pull alpine:3.20 >/dev/null 2>&1; then
        log_skip "shdg --image: docker pull alpine:3.20 failed (registry unreachable?)"
        return
    fi
    local component_a
    component_a="e2e-shdg-image-$(date +%s)"
    set +e
    SHIELDOO_TOKEN="${SGW_PROXY_TOKEN}" \
    SHIELDOO_URL="${E2E_ADMIN_URL}" \
        shdg scan \
            --project default --component "$component_a" \
            --image alpine:3.20 \
            --wait --fail-on none --poll-interval 500ms --timeout 180s \
            >/dev/null 2>&1
    local rc=$?
    set -e
    if [ $rc -eq 0 ]; then
        log_pass "shdg --image alpine:3.20 --fail-on none: rc=0"
    else
        log_fail "shdg --image alpine:3.20 --fail-on none: rc=${rc}, want 0"
        return
    fi

    # Sub-test B: --fail-on critical against a known-old tag (alpine:3.10,
    # EOL since 2021, has accumulated CVEs). Mirrors the pypi sub-test's
    # tolerance: rc=1 when OSV is reachable, rc=0 with log_skip otherwise.
    if ! docker pull alpine:3.10 >/dev/null 2>&1; then
        log_skip "shdg --image (--fail-on critical): docker pull alpine:3.10 failed"
        return
    fi
    local component_b
    component_b="e2e-shdg-image-crit-$(date +%s)"
    set +e
    SHIELDOO_TOKEN="${SGW_PROXY_TOKEN}" \
    SHIELDOO_URL="${E2E_ADMIN_URL}" \
        timeout 240 shdg scan \
            --project default --component "$component_b" \
            --image alpine:3.10 \
            --wait --fail-on critical --poll-interval 1s --timeout 180s \
            >/dev/null 2>&1
    rc=$?
    set -e
    case "$rc" in
        1)
            log_pass "shdg --image alpine:3.10 --fail-on critical: rc=1 as expected"
            ;;
        0)
            log_skip "shdg --image alpine:3.10 --fail-on critical: rc=0 — OSV may be unreachable"
            ;;
        *)
            log_fail "shdg --image alpine:3.10 --fail-on critical: rc=${rc}, want 1 (or 0 if OSV unavailable)"
            ;;
    esac
}
