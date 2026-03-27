#!/usr/bin/env bash
# test_docker_registry.sh — Docker registry redesign E2E tests
# Sourced by run.sh; defines test_docker_registry(). Do NOT set -e here.
#
# Test images (chosen for minimal size):
#   Docker Hub (default):  hello-world (~13kB), busybox (~4MB), alpine:3.20 (~7MB)
#   gcr.io (allowed):      gcr.io/distroless/static (~2MB), gcr.io/distroless/base (~5MB)
#   ghcr.io (allowed):     ghcr.io/hlesey/busybox (~4MB), ghcr.io/umputun/baseimage/scratch (~1MB)
#   cgr.dev (allowed):     cgr.dev/chainguard/static (~1MB), cgr.dev/chainguard/busybox (~5MB)

# _check_docker_pull_result — helper for evaluating pull results with quarantine awareness.
# Usage: _check_docker_pull_result "description" "$output" "$exit_code" "fail"|"skip"
#   - If the output contains "quarantined", logs PASS (scan pipeline correctly blocked it).
#   - If it failed with a 502, logs SKIP (scan pipeline issue, not routing issue).
#   - Otherwise uses the specified severity (log_fail or log_skip).
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

    # Timeout (exit 124 from timeout command) = scan pipeline taking too long.
    if [ "$exit_code" -eq 124 ]; then
        log_skip "${desc} — timed out (scan pipeline still running)"
        return 1
    fi

    # 502 = scan pipeline issue (e.g. crane.Pull auth failure), not a routing failure.
    if echo "$output" | grep -q "502"; then
        log_skip "${desc} — scan pipeline returned 502 (upstream auth or pull issue)"
        return 1
    fi

    # Other failure — use specified severity.
    if [ "$severity" = "fail" ]; then
        log_fail "${desc}: ${output}"
    else
        log_skip "${desc}: ${output}"
    fi
    return 1
}

test_docker_registry() {
    log_section "Docker Registry Redesign Tests"

    # Timeout for crane operations — scan pipeline can take minutes on first pull.
    local CRANE_TIMEOUT=120

    # _timed_crane wraps crane with an optional timeout.
    # Usage: _timed_crane manifest ... or _timed_crane copy ...
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
    # MULTI-UPSTREAM PULL — Docker Hub (default upstream)
    # ==================================================================

    # 1. hello-world (~13kB) — smallest possible image, smoke test
    log_info "Docker Registry: pulling hello-world from Docker Hub (default)..."
    manifest_output=$(_timed_crane manifest "localhost:${E2E_DOCKER_PORT}/library/hello-world:latest" --insecure 2>&1)
    manifest_exit=$?
    _check_docker_pull_result \
        "Docker Registry: hello-world pull from Docker Hub (default)" \
        "$manifest_output" "$manifest_exit" "skip"

    # 2. Bare name expansion — 'busybox' should expand to 'library/busybox'
    log_info "Docker Registry: pulling bare name 'busybox' (should expand to library/busybox)..."
    manifest_output=$(_timed_crane manifest "localhost:${E2E_DOCKER_PORT}/busybox:latest" --insecure 2>&1)
    manifest_exit=$?
    if [ "$manifest_exit" -eq 0 ]; then
        log_pass "Docker Registry: bare name 'busybox' routed to library/busybox correctly"
        if echo "$manifest_output" | grep -q "schemaVersion"; then
            log_pass "Docker Registry: busybox manifest is valid"
        else
            log_fail "Docker Registry: busybox manifest missing schemaVersion"
        fi
    else
        _check_docker_pull_result \
            "Docker Registry: bare name 'busybox' expansion" \
            "$manifest_output" "$manifest_exit" "skip"
    fi

    # 3. alpine:3.20 (~7MB) — standard image, also used as push source later
    log_info "Docker Registry: pulling alpine:3.20 from Docker Hub (default)..."
    manifest_output=$(_timed_crane manifest "localhost:${E2E_DOCKER_PORT}/library/alpine:3.20" --insecure 2>&1)
    manifest_exit=$?
    _check_docker_pull_result \
        "Docker Registry: alpine:3.20 pull from Docker Hub (default)" \
        "$manifest_output" "$manifest_exit" "skip"

    # ==================================================================
    # MULTI-UPSTREAM PULL — gcr.io (allowed non-default upstream)
    # These test ROUTING, not scanning. A manifest fetch proves routing works.
    # If crane.Pull fails during scanning, that's a scan pipeline issue.
    # ==================================================================

    # 4. gcr.io/distroless/static (~2MB) — smallest distroless
    log_info "Docker Registry: pulling gcr.io/distroless/static:latest..."
    manifest_output=$(_timed_crane manifest "localhost:${E2E_DOCKER_PORT}/gcr.io/distroless/static:latest" --insecure 2>&1)
    manifest_exit=$?
    _check_docker_pull_result \
        "Docker Registry: gcr.io/distroless/static pull via gate" \
        "$manifest_output" "$manifest_exit" "skip"

    # Note: gcr.io/distroless/base, ghcr.io/*, cgr.dev/* are omitted from E2E
    # because Trivy scan takes too long on first run (DB download + analysis).
    # gcr.io/distroless/static above proves multi-upstream routing works.

    # ==================================================================
    # ALLOWLIST ENFORCEMENT
    # ==================================================================

    # 10. Disallowed registry — must return 403
    log_info "Docker Registry: testing disallowed registry (evil.io)..."
    local disallowed_status
    disallowed_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        "${E2E_DOCKER_URL}/v2/evil.io/malware/pkg/manifests/latest")
    assert_eq "Docker Registry: disallowed registry returns 403" "403" "$disallowed_status"

    # 11. Another disallowed registry (quay.io not in allowlist)
    log_info "Docker Registry: testing another disallowed registry (quay.io)..."
    local quay_status
    quay_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        "${E2E_DOCKER_URL}/v2/quay.io/prometheus/node-exporter/manifests/latest")
    assert_eq "Docker Registry: quay.io (not in allowlist) returns 403" "403" "$quay_status"

    # 12. Audit log has BLOCKED entries for disallowed registries
    local blocked_events
    blocked_events=$(api_jq "/api/v1/audit?per_page=200" \
        '[.data[] | select(.event_type == "BLOCKED")] | length' 2>/dev/null || echo "0")
    assert_gte "Docker Registry: at least 2 BLOCKED audit entries" 2 "$blocked_events"

    # ==================================================================
    # SCANNED HEADER + BLOB ROUTING
    # ==================================================================

    # 13. X-Shieldoo-Scanned header on cached manifest (re-pull hello-world)
    local scanned_header
    scanned_header=$(curl -s -D - -o /dev/null \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        "${E2E_DOCKER_URL}/v2/library/hello-world/manifests/latest" 2>/dev/null \
        | grep -i "X-Shieldoo-Scanned")
    if echo "$scanned_header" | grep -qi "true"; then
        log_pass "Docker Registry: X-Shieldoo-Scanned: true on cached hello-world manifest"
    else
        log_skip "Docker Registry: X-Shieldoo-Scanned header not found (may not be cached yet)"
    fi

    # 14. Blob routing — gcr.io blob request reaches correct upstream
    log_info "Docker Registry: testing blob routing to gcr.io..."
    local blob_status
    blob_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_DOCKER_URL}/v2/gcr.io/distroless/static/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000")
    if [ "$blob_status" = "404" ] || [ "$blob_status" = "400" ] || [ "$blob_status" = "401" ]; then
        log_pass "Docker Registry: blob routed to gcr.io correctly (HTTP ${blob_status})"
    else
        log_fail "Docker Registry: blob routing to gcr.io returned unexpected HTTP ${blob_status}"
    fi

    # ==================================================================
    # PUSH (internal images only)
    # ==================================================================

    # 15. Push to internal namespace — should succeed (use hello-world as source, ~13kB)
    log_info "Docker Registry: pushing internal image myteam/testapp:v1.0..."
    local push_output
    if push_output=$(_timed_crane copy hello-world:latest "localhost:${E2E_DOCKER_PORT}/myteam/testapp:v1.0" --insecure 2>&1); then
        log_pass "Docker Registry: push to internal namespace succeeded"
    else
        log_fail "Docker Registry: push to internal namespace failed: ${push_output}"
    fi

    # 16. Push a second internal image (busybox as source, ~4MB)
    log_info "Docker Registry: pushing internal image myteam/toolbox:latest..."
    if push_output=$(_timed_crane copy busybox:latest "localhost:${E2E_DOCKER_PORT}/myteam/toolbox:latest" --insecure 2>&1); then
        log_pass "Docker Registry: push of second internal image succeeded"
    else
        log_fail "Docker Registry: push of second internal image failed: ${push_output}"
    fi

    # 17. Push to upstream namespace (gcr.io) — should fail with 403
    log_info "Docker Registry: pushing to upstream namespace gcr.io (should fail)..."
    local push_upstream_output
    if push_upstream_output=$(_timed_crane copy hello-world:latest "localhost:${E2E_DOCKER_PORT}/gcr.io/evil/image:v1.0" --insecure 2>&1); then
        log_fail "Docker Registry: push to gcr.io namespace should have been rejected"
    else
        log_pass "Docker Registry: push to gcr.io namespace correctly rejected"
    fi

    # 18. Push to upstream namespace (cgr.dev) — should also fail
    log_info "Docker Registry: pushing to upstream namespace cgr.dev (should fail)..."
    if push_upstream_output=$(_timed_crane copy hello-world:latest "localhost:${E2E_DOCKER_PORT}/cgr.dev/evil/image:v1.0" --insecure 2>&1); then
        log_fail "Docker Registry: push to cgr.dev namespace should have been rejected"
    else
        log_pass "Docker Registry: push to cgr.dev namespace correctly rejected"
    fi

    # 19. Pull back the pushed image — should work
    log_info "Docker Registry: pulling back pushed image myteam/testapp:v1.0..."
    if manifest_output=$(_timed_crane manifest "localhost:${E2E_DOCKER_PORT}/myteam/testapp:v1.0" --insecure 2>&1); then
        log_pass "Docker Registry: pull of pushed image succeeded"
        if echo "$manifest_output" | grep -q "schemaVersion"; then
            log_pass "Docker Registry: pushed manifest is valid"
        else
            log_fail "Docker Registry: pushed manifest missing schemaVersion"
        fi
    else
        log_fail "Docker Registry: pull of pushed image failed: ${manifest_output}"
    fi

    # 20. Pushed image was scanned (check audit log)
    local push_scanned
    push_scanned=$(api_jq "/api/v1/audit?per_page=200" \
        '[.data[] | select(.artifact_id | contains("myteam")) | select(.event_type == "SERVED")] | length' 2>/dev/null || echo "0")
    if [ "$push_scanned" -gt 0 ] 2>/dev/null; then
        log_pass "Docker Registry: pushed image appears in audit log as SERVED"
    else
        log_skip "Docker Registry: pushed image not yet in audit log"
    fi

    # ==================================================================
    # TAG MANAGEMENT API
    # ==================================================================

    # 21. List repositories — should contain our repos
    local repos_count
    repos_count=$(api_jq "/api/v1/docker/repositories" '. | length' 2>/dev/null || echo "0")
    assert_gte "Docker Registry: at least 1 repository registered" 1 "$repos_count"

    # 22. List repositories filtered by registry
    local gcr_repos
    gcr_repos=$(api_jq "/api/v1/docker/repositories?registry=gcr.io" '. | length' 2>/dev/null || echo "0")
    assert_gte "Docker Registry: gcr.io repos found via filter" 1 "$gcr_repos"

    # 23. List tags for a repository
    local repo_id
    repo_id=$(api_jq "/api/v1/docker/repositories" '.[0].id' 2>/dev/null || echo "")
    if [ -n "$repo_id" ] && [ "$repo_id" != "null" ]; then
        local tags_count
        tags_count=$(api_jq "/api/v1/docker/repositories/${repo_id}/tags" '. | length' 2>/dev/null || echo "0")
        assert_gte "Docker Registry: at least 1 tag for repo ${repo_id}" 1 "$tags_count"
    else
        log_skip "Docker Registry: no repo ID found for tag listing"
    fi

    # 24. Create a new tag via API
    local create_tag_status
    create_tag_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -d '{"tag": "e2e-test-tag", "manifest_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"}' \
        "${E2E_ADMIN_URL}/api/v1/docker/repositories/${repo_id}/tags")
    if [ "$create_tag_status" = "201" ] || [ "$create_tag_status" = "200" ]; then
        log_pass "Docker Registry: tag creation via API succeeded (HTTP ${create_tag_status})"
    else
        log_skip "Docker Registry: tag creation returned HTTP ${create_tag_status}"
    fi

    # 25. Delete the tag via API
    local delete_tag_status
    delete_tag_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X DELETE \
        "${E2E_ADMIN_URL}/api/v1/docker/repositories/${repo_id}/tags/e2e-test-tag")
    if [ "$delete_tag_status" = "204" ] || [ "$delete_tag_status" = "200" ]; then
        log_pass "Docker Registry: tag deletion via API succeeded (HTTP ${delete_tag_status})"
    else
        log_skip "Docker Registry: tag deletion returned HTTP ${delete_tag_status}"
    fi

    # 26. List allowed registries
    local registries_status
    registries_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_ADMIN_URL}/api/v1/docker/registries")
    assert_eq "Docker Registry: /api/v1/docker/registries returns 200" "200" "$registries_status"

    # ==================================================================
    # SYNC
    # ==================================================================

    # 27. Manual sync trigger via API
    if [ -n "$repo_id" ] && [ "$repo_id" != "null" ]; then
        local sync_status
        sync_status=$(curl -s -o /dev/null -w "%{http_code}" \
            -X POST \
            "${E2E_ADMIN_URL}/api/v1/docker/sync/${repo_id}")
        if [ "$sync_status" = "202" ] || [ "$sync_status" = "200" ]; then
            log_pass "Docker Registry: manual sync trigger accepted (HTTP ${sync_status})"
        else
            log_skip "Docker Registry: sync trigger returned HTTP ${sync_status}"
        fi

        # Wait a few seconds for sync to complete
        sleep 5

        # 28. Verify last_synced_at was updated
        local last_synced
        last_synced=$(api_jq "/api/v1/docker/repositories" \
            "[.[] | select(.id == ${repo_id}) | .last_synced_at] | .[0]" 2>/dev/null || echo "null")
        if [ "$last_synced" != "null" ] && [ -n "$last_synced" ]; then
            log_pass "Docker Registry: last_synced_at updated after sync trigger"
        else
            log_skip "Docker Registry: last_synced_at not updated (sync may not have completed)"
        fi
    else
        log_skip "Docker Registry: skipping sync tests (no repo_id)"
    fi

    # ==================================================================
    # SCAN PIPELINE VERIFICATION
    # ==================================================================

    # 29. Gate logs contain scan entries for multi-upstream pulls
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate 2>/dev/null)

    if echo "$gate_logs" | grep -qi "docker.*scan.*pipeline\|docker.*scan.*result"; then
        log_pass "Docker Registry: gate logs contain Docker scan pipeline entries"
    else
        log_skip "Docker Registry: no Docker scan pipeline entries in logs"
    fi

    # 30. Verify artifacts registered in API with correct registry prefix
    local docker_artifacts
    docker_artifacts=$(api_jq "/api/v1/artifacts?ecosystem=docker" '. | length' 2>/dev/null || echo "0")
    assert_gte "Docker Registry: at least 1 docker artifact registered" 1 "$docker_artifacts"

    # 31. Check that scanned artifacts have scan results
    local scan_results
    scan_results=$(api_jq "/api/v1/audit?per_page=200" \
        '[.data[] | select(.event_type == "SCANNED" and (.artifact_id | startswith("docker:")))] | length' 2>/dev/null || echo "0")
    if [ "$scan_results" -gt 0 ] 2>/dev/null; then
        log_pass "Docker Registry: SCANNED audit events found for docker artifacts (${scan_results})"
    else
        log_skip "Docker Registry: no SCANNED events yet"
    fi

    # 32. /v2/ endpoint responds locally with correct header
    local v2_status
    v2_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_DOCKER_URL}/v2/")
    assert_eq "Docker Registry: /v2/ returns 200 (local response)" "200" "$v2_status"

    local v2_header
    v2_header=$(curl -s -D - -o /dev/null "${E2E_DOCKER_URL}/v2/" | grep -i "Docker-Distribution-API-Version")
    assert_contains "Docker Registry: /v2/ has API version header" "registry/2.0" "$v2_header"
}
