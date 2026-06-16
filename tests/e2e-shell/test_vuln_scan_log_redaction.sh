#!/usr/bin/env bash
# test_vuln_scan_log_redaction.sh — verify the gate's structured log scrubs
# Authorization headers / Bearer tokens. Sends a request with a marker token
# and greps the gate's stdout/stderr for any leak.

test_vuln_scan_log_redaction() {
    log_section "Vuln-scan: log redaction (no Authorization in gate logs)"

    local pre_status
    pre_status=$(admin_curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_ADMIN_URL}/api/v1/vulnerabilities/summary")
    if [ "$pre_status" = "503" ]; then
        log_skip "Vuln-scan log_redaction: feature disabled"
        return
    fi

    # We need access to the gate container's logs. In the runner the gate is
    # named "shieldoo-gate" by docker-compose.e2e.yml.
    local marker
    marker="LEAK-CANARY-$(date +%s%N)"

    # Send a request with the canary as the bearer. We don't care about the
    # response body — just that the redactor processed the request.
    admin_curl -s -o /dev/null -X GET "${E2E_ADMIN_URL}/api/v1/vulnerabilities/summary" \
        -H "Authorization: Bearer ${marker}" >/dev/null

    # Give the log line time to land.
    sleep 1

    # Inspect logs from inside the docker network. The runner has a docker
    # client mounted, but to avoid a privilege escalation we instead read the
    # log file we control: the gate writes to stdout, captured by docker. The
    # test container can curl docker via /var/run/docker.sock IF mounted. If
    # neither is available, skip with a clear message.
    if [ ! -S /var/run/docker.sock ]; then
        log_skip "Vuln-scan log_redaction: docker.sock not mounted in runner"
        return
    fi
    local logs
    logs=$(curl --silent --unix-socket /var/run/docker.sock \
        "http://localhost/containers/shieldoo-gate/logs?stdout=1&stderr=1&tail=200" 2>/dev/null \
        | tr -d '\000-\010\013\014\016-\037' || true)
    if [ -z "$logs" ]; then
        log_skip "Vuln-scan log_redaction: gate logs unreadable"
        return
    fi
    if grep -q "$marker" <<<"$logs"; then
        log_fail "Vuln-scan log_redaction: bearer token marker LEAKED into gate logs"
        return
    fi
    if grep -Eqi 'authorization":?\s*"bearer' <<<"$logs"; then
        log_fail "Vuln-scan log_redaction: 'Authorization: Bearer' literal present in logs"
        return
    fi
    log_pass "Vuln-scan log_redaction: no bearer / Authorization in gate logs"
}
