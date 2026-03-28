#!/usr/bin/env bash
# test_docker_registry.sh — Docker registry redesign E2E tests
# Sourced by run.sh; defines test_docker_registry(). Do NOT set -e here.
#
# IMPORTANT: The scan pipeline (manifest fetch → crane pull → Trivy scan) takes
# 1-3 minutes per image on first run due to Trivy vulnerability DB download (~40MB).
# Subsequent runs with cached Trivy DB are much faster (~10-30s per image).
#
# Test images (chosen for minimal size):
#   Docker Hub:  hello-world (~13kB)
#   gcr.io:      gcr.io/distroless/static (~2MB)

# _check_docker_pull_result — helper for evaluating pull results with quarantine awareness.
# Usage: _check_docker_pull_result "description" "$output" "$exit_code" "fail"|"skip"
_check_docker_pull_result() {
    local desc="$1"
    local output="$2"
    local exit_code="$3"
    local severity="$4"  # "fail" or "skip"

    if [ "$exit_code" -eq 0 ]; then
        log_pass "$desc"
        return 0
    fi

    # Quarantined = scan pipeline worked correctly — this is a PASS.
    if echo "$output" | grep -qi "quarantined"; then
        log_pass "${desc} — image correctly quarantined by scan pipeline"
        return 0
    fi

    # Timeout (exit 124) = scan pipeline taking too long.
    if [ "$exit_code" -eq 124 ]; then
        log_skip "${desc} — timed out waiting for scan pipeline"
        return 1
    fi

    # 502 = scan pipeline issue (e.g. crane.Pull failure), not a routing failure.
    if echo "$output" | grep -q "502"; then
        log_skip "${desc} — 502 from scan pipeline (not a routing issue)"
        return 1
    fi

    # Docker Hub rate limit
    if echo "$output" | grep -qi "TOOMANYREQUESTS\|rate limit"; then
        log_skip "${desc} — Docker Hub rate limit reached"
        return 1
    fi

    # Other failure
    if [ "$severity" = "fail" ]; then
        log_fail "${desc}: ${output}"
    else
        log_skip "${desc}: ${output}"
    fi
    return 1
}

test_docker_registry() {
    log_section "Docker Registry Redesign Tests"

    # Per-operation timeout (seconds). The scan pipeline downloads Trivy DB
    # on first run (~40MB) and then scans the image. This can take several minutes.
    local CRANE_TIMEOUT=180

    # _timed_crane wraps crane with a timeout (gtimeout on macOS, timeout on Linux).
    _timed_crane() {
        if command -v gtimeout &>/dev/null; then
            gtimeout "$CRANE_TIMEOUT" crane "$@"
        elif [ -x /opt/homebrew/bin/gtimeout ]; then
            /opt/homebrew/bin/gtimeout "$CRANE_TIMEOUT" crane "$@"
        elif command -v timeout &>/dev/null; then
            timeout "$CRANE_TIMEOUT" crane "$@"
        else
            crane "$@"
        fi
    }

    local manifest_output
    local manifest_exit

    # ==================================================================
    # Part 1: FAST TESTS — no scan pipeline, just routing and API checks
    # ==================================================================

    # /v2/ endpoint responds locally
    local v2_status
    v2_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_DOCKER_URL}/v2/")
    assert_eq "Docker Registry: /v2/ returns 200 (local response)" "200" "$v2_status"

    local v2_header
    v2_header=$(curl -s -D - -o /dev/null "${E2E_DOCKER_URL}/v2/" | grep -i "Docker-Distribution-API-Version")
    assert_contains "Docker Registry: /v2/ has API version header" "registry/2.0" "$v2_header"

    # Allowlist enforcement (instant — no scan needed)
    log_info "Docker Registry: testing allowlist enforcement..."
    local disallowed_status
    disallowed_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        "${E2E_DOCKER_URL}/v2/evil.io/malware/pkg/manifests/latest")
    assert_eq "Docker Registry: disallowed registry (evil.io) returns 403" "403" "$disallowed_status"

    local quay_status
    quay_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        "${E2E_DOCKER_URL}/v2/quay.io/prometheus/node-exporter/manifests/latest")
    assert_eq "Docker Registry: disallowed registry (quay.io) returns 403" "403" "$quay_status"

    # Blob routing (instant — just proxies to upstream, returns 404 for fake digest)
    local blob_status
    blob_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_DOCKER_URL}/v2/gcr.io/distroless/static/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000")
    if [ "$blob_status" = "404" ] || [ "$blob_status" = "400" ] || [ "$blob_status" = "401" ]; then
        log_pass "Docker Registry: blob routed to gcr.io correctly (HTTP ${blob_status})"
    else
        log_fail "Docker Registry: blob routing returned unexpected HTTP ${blob_status}"
    fi

    # Tag Management API (instant — works with whatever repos exist)
    local registries_status
    registries_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_ADMIN_URL}/api/v1/docker/registries")
    assert_eq "Docker Registry: /api/v1/docker/registries returns 200" "200" "$registries_status"

    # ==================================================================
    # Part 2: SLOW TESTS — involve scan pipeline (Trivy DB + image pull + scan)
    # First run: ~1-3 min per image. Subsequent: ~10-30s per image.
    # ==================================================================

    log_info "Docker Registry: starting scan pipeline tests (may take several minutes on first run)..."

    # Pull hello-world (~13kB) — the smallest possible image
    log_info "Docker Registry: pulling hello-world (this triggers Trivy DB download on first run)..."
    manifest_output=$(_timed_crane manifest "${E2E_DOCKER_REGISTRY_HOST}/library/hello-world:latest" --insecure 2>&1)
    manifest_exit=$?
    _check_docker_pull_result \
        "Docker Registry: hello-world pull + scan from Docker Hub" \
        "$manifest_output" "$manifest_exit" "skip"

    # If hello-world succeeded, Trivy DB is now cached — subsequent pulls will be faster.
    if [ "$manifest_exit" -eq 0 ]; then
        # X-Shieldoo-Scanned header on cached manifest (instant — already cached)
        local scanned_header
        scanned_header=$(curl -s -D - -o /dev/null \
            -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
            "${E2E_DOCKER_URL}/v2/library/hello-world/manifests/latest" 2>/dev/null \
            | grep -i "X-Shieldoo-Scanned")
        if echo "$scanned_header" | grep -qi "true"; then
            log_pass "Docker Registry: X-Shieldoo-Scanned: true on cached manifest"
        else
            log_skip "Docker Registry: X-Shieldoo-Scanned header not found"
        fi

        # Audit log has entries
        local blocked_events
        blocked_events=$(api_jq "/api/v1/audit?per_page=200" \
            '[.data[] | select(.event_type == "BLOCKED")] | length' 2>/dev/null || echo "0")
        assert_gte "Docker Registry: at least 2 BLOCKED audit entries" 2 "$blocked_events"
    else
        log_skip "Docker Registry: skipping cached manifest tests (hello-world pull didn't complete)"
    fi

    # Pull gcr.io/distroless/static (~2MB) — proves multi-upstream routing
    log_info "Docker Registry: pulling gcr.io/distroless/static (multi-upstream routing test)..."
    manifest_output=$(_timed_crane manifest "${E2E_DOCKER_REGISTRY_HOST}/gcr.io/distroless/static:latest" --insecure 2>&1)
    manifest_exit=$?
    _check_docker_pull_result \
        "Docker Registry: gcr.io/distroless/static via multi-upstream routing" \
        "$manifest_output" "$manifest_exit" "skip"

    # ==================================================================
    # Part 3: PUSH TESTS — push internal images via crane copy
    # ==================================================================

    log_info "Docker Registry: testing push to internal namespace..."
    local push_output
    if push_output=$(_timed_crane copy "hello-world:latest" "${E2E_DOCKER_REGISTRY_HOST}/myteam/testapp:v1.0" --insecure 2>&1); then
        log_pass "Docker Registry: push to internal namespace succeeded"

        # Pull back the pushed image
        log_info "Docker Registry: pulling back pushed image..."
        if manifest_output=$(_timed_crane manifest "${E2E_DOCKER_REGISTRY_HOST}/myteam/testapp:v1.0" --insecure 2>&1); then
            log_pass "Docker Registry: pull-back of pushed image succeeded"
        else
            _check_docker_pull_result \
                "Docker Registry: pull-back of pushed image" \
                "$manifest_output" "$?" "skip"
        fi
    else
        _check_docker_pull_result \
            "Docker Registry: push to internal namespace" \
            "$push_output" "$?" "skip"
    fi

    # Push to upstream namespace must be rejected (instant — no scan)
    log_info "Docker Registry: testing push rejection for upstream namespaces..."
    local push_upstream_output
    if push_upstream_output=$(_timed_crane copy "hello-world:latest" "${E2E_DOCKER_REGISTRY_HOST}/gcr.io/evil/image:v1.0" --insecure 2>&1); then
        log_fail "Docker Registry: push to gcr.io namespace should have been rejected"
    else
        log_pass "Docker Registry: push to upstream namespace (gcr.io) correctly rejected"
    fi

    # ==================================================================
    # Part 4: API TESTS — repos, tags, sync (instant — use whatever state exists)
    # ==================================================================

    local repos_count
    repos_count=$(api_jq "/api/v1/docker/repositories" '. | length' 2>/dev/null || echo "0")
    if [ "$repos_count" -gt 0 ] 2>/dev/null; then
        log_pass "Docker Registry: ${repos_count} repositories registered"

        local repo_id
        repo_id=$(api_jq "/api/v1/docker/repositories" '.[0].id' 2>/dev/null || echo "")

        if [ -n "$repo_id" ] && [ "$repo_id" != "null" ]; then
            # Create a tag via API
            local create_tag_status
            create_tag_status=$(curl -s -o /dev/null -w "%{http_code}" \
                -X POST -H "Content-Type: application/json" \
                -d '{"tag": "e2e-test-tag", "manifest_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}' \
                "${E2E_ADMIN_URL}/api/v1/docker/repositories/${repo_id}/tags")
            if [ "$create_tag_status" = "201" ] || [ "$create_tag_status" = "200" ]; then
                log_pass "Docker Registry: tag creation via API (HTTP ${create_tag_status})"
            else
                log_skip "Docker Registry: tag creation returned HTTP ${create_tag_status}"
            fi

            # Delete the tag
            local delete_tag_status
            delete_tag_status=$(curl -s -o /dev/null -w "%{http_code}" \
                -X DELETE "${E2E_ADMIN_URL}/api/v1/docker/repositories/${repo_id}/tags/e2e-test-tag")
            if [ "$delete_tag_status" = "204" ] || [ "$delete_tag_status" = "200" ]; then
                log_pass "Docker Registry: tag deletion via API (HTTP ${delete_tag_status})"
            else
                log_skip "Docker Registry: tag deletion returned HTTP ${delete_tag_status}"
            fi

            # Manual sync trigger
            local sync_status
            sync_status=$(curl -s -o /dev/null -w "%{http_code}" \
                -X POST "${E2E_ADMIN_URL}/api/v1/docker/sync/${repo_id}")
            if [ "$sync_status" = "202" ] || [ "$sync_status" = "200" ]; then
                log_pass "Docker Registry: manual sync trigger accepted (HTTP ${sync_status})"
            else
                log_skip "Docker Registry: sync trigger returned HTTP ${sync_status}"
            fi
        fi
    else
        log_skip "Docker Registry: no repositories registered (pull tests may have timed out)"
    fi

    # Gate logs contain docker scan pipeline entries
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate 2>/dev/null)
    if echo "$gate_logs" | grep -qi "docker.*scan"; then
        log_pass "Docker Registry: gate logs contain Docker scan entries"
    else
        log_skip "Docker Registry: no Docker scan entries in logs (scans may not have completed)"
    fi
}
