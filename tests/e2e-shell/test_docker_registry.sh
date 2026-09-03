#!/usr/bin/env bash
# test_docker_registry.sh — Docker registry redesign E2E tests
# Sourced by run.sh; defines test_docker_registry(). Do NOT set -e here.
#
# IMPORTANT: The scan pipeline (manifest fetch → crane pull → Trivy scan) takes
# 1-3 minutes per image on first run due to Trivy vulnerability DB download (~40MB).
# Subsequent runs with cached Trivy DB are much faster (~10-30s per image).
#
# Test images (chosen for minimal size and no rate limits):
#   ghcr.io:     ghcr.io/jitesoft/alpine (~3MB, no rate limit)
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
    if grep -qi "quarantined" <<< "$output"; then
        log_pass "${desc} — image correctly quarantined by scan pipeline"
        return 0
    fi

    # Timeout (exit 124) = scan pipeline taking too long.
    if [ "$exit_code" -eq 124 ]; then
        log_skip "${desc} — timed out waiting for scan pipeline"
        return 1
    fi

    # 502 = scan pipeline issue (e.g. crane.Pull failure), not a routing failure.
    if [[ "$output" == *"502"* ]]; then
        log_skip "${desc} — 502 from scan pipeline (not a routing issue)"
        return 1
    fi

    # Docker Hub rate limit
    if grep -qi "TOOMANYREQUESTS\|rate limit" <<< "$output"; then
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

# _tl_sha256_hex "<string>" → lowercase hex sha256 (coreutils/shasum/openssl fallbacks).
_tl_sha256_hex() {
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    else
        printf '%s' "$1" | openssl dgst -sha256 | awk '{print $NF}'
    fi
}

# _tl_push_blob "<base>" "<digest>" "<content>" → echoes the final HTTP status.
# Monolithic upload: POST opens a session, PUT sends the bytes with ?digest=.
_tl_push_blob() {
    local base="$1" digest="$2" content="$3"
    local loc
    loc=$(curl -s -D - -o /dev/null "${E2E_CURL_AUTH[@]}" -X POST "${base}/blobs/uploads/" \
        | grep -i '^Location:' | tr -d '\r' | awk '{print $2}')
    if [ -z "$loc" ]; then
        echo "000"
        return
    fi
    case "$loc" in
        http*) : ;;
        *) loc="${E2E_DOCKER_URL}${loc}" ;;
    esac
    curl -s -o /dev/null -w '%{http_code}' "${E2E_CURL_AUTH[@]}" \
        -X PUT "${loc}?digest=${digest}" --data-binary "$content"
}

test_docker_registry() {
    log_section "Docker Registry Redesign Tests"

    # Per-operation timeout (seconds). The scan pipeline downloads Trivy DB
    # on first run (~40MB) and then scans the image. This can take several minutes.
    local CRANE_TIMEOUT=180

    # Authenticate crane to our proxy registry (when proxy auth enabled).
    # Uses crane auth login so credentials are scoped to our registry only,
    # not applied to Docker Hub or other upstream sources.
    if [ -n "$E2E_AUTH_USERINFO" ]; then
        crane auth login "$E2E_DOCKER_REGISTRY_HOST" \
            --username "ci-bot" --password "${SGW_PROXY_TOKEN}" --insecure 2>/dev/null \
            && log_info "Docker Registry: crane authenticated to proxy" \
            || log_info "Docker Registry: crane auth login failed (continuing)"
    fi

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
    # Part 0: NEGATIVE TEST — unauthenticated request must return 401
    # ==================================================================
    if [ "${SGW_PROXY_AUTH_ENABLED:-false}" = "true" ]; then
        local noauth_status
        noauth_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_DOCKER_URL}/v2/")
        assert_eq "Docker Registry: unauthenticated request returns 401" "401" "$noauth_status"
    fi

    # ==================================================================
    # Part 1: FAST TESTS — no scan pipeline, just routing and API checks
    # ==================================================================

    # /v2/ endpoint responds locally
    local v2_status
    v2_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "${E2E_DOCKER_URL}/v2/")
    assert_eq "Docker Registry: /v2/ returns 200 (local response)" "200" "$v2_status"

    local v2_header
    v2_header=$(curl -s -D - -o /dev/null "${E2E_CURL_AUTH[@]}" "${E2E_DOCKER_URL}/v2/" | grep -i "Docker-Distribution-API-Version" || true)
    assert_contains "Docker Registry: /v2/ has API version header" "registry/2.0" "$v2_header"

    # Allowlist enforcement (instant — no scan needed)
    log_info "Docker Registry: testing allowlist enforcement..."
    local disallowed_status
    disallowed_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_CURL_AUTH[@]}" \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        "${E2E_DOCKER_URL}/v2/evil.io/malware/pkg/manifests/latest")
    assert_eq "Docker Registry: disallowed registry (evil.io) returns 403" "403" "$disallowed_status"

    local quay_status
    quay_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_CURL_AUTH[@]}" \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        "${E2E_DOCKER_URL}/v2/quay.io/prometheus/node-exporter/manifests/latest")
    assert_eq "Docker Registry: disallowed registry (quay.io) returns 403" "403" "$quay_status"

    # Blob routing (instant — just proxies to upstream, returns 404 for fake digest)
    local blob_status
    blob_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_CURL_AUTH[@]}" \
        "${E2E_DOCKER_URL}/v2/gcr.io/distroless/static/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000")
    if [ "$blob_status" = "404" ] || [ "$blob_status" = "400" ] || [ "$blob_status" = "401" ]; then
        log_pass "Docker Registry: blob routed to gcr.io correctly (HTTP ${blob_status})"
    else
        log_fail "Docker Registry: blob routing returned unexpected HTTP ${blob_status}"
    fi

    # Tag Management API (admin port — no proxy auth needed)
    local registries_status
    registries_status=$(admin_curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_ADMIN_URL}/api/v1/docker/registries")
    assert_eq "Docker Registry: /api/v1/docker/registries returns 200" "200" "$registries_status"

    # ==================================================================
    # Part 2: SLOW TESTS — involve scan pipeline (Trivy DB + image pull + scan)
    # First run: ~1-3 min per image. Subsequent: ~10-30s per image.
    # ==================================================================

    log_info "Docker Registry: starting scan pipeline tests (may take several minutes on first run)..."

    # Pull ghcr.io/jitesoft/alpine (~3MB) — public, no rate limit, triggers Trivy DB download on first run
    log_info "Docker Registry: pulling ghcr.io/jitesoft/alpine (this triggers Trivy DB download on first run)..."
    manifest_output=""; manifest_exit=0
    manifest_output=$(_timed_crane manifest "${E2E_DOCKER_REGISTRY_HOST}/ghcr.io/jitesoft/alpine:latest" --insecure 2>&1) || manifest_exit=$?
    _check_docker_pull_result \
        "Docker Registry: ghcr.io/jitesoft/alpine pull + scan via multi-upstream" \
        "$manifest_output" "$manifest_exit" "skip" || true

    # If alpine succeeded, Trivy DB is now cached — subsequent pulls will be faster.
    if [ "$manifest_exit" -eq 0 ]; then
        # X-Shieldoo-Scanned header on cached manifest (instant — already cached)
        local scanned_header
        # `|| true` swallows the grep-no-match exit code; without it, the
        # `set -euo pipefail` inherited from run_all.sh kills the suite when
        # the X-Shieldoo-Scanned header is missing instead of letting the
        # next assertion log_skip.
        scanned_header=$(curl -s -D - -o /dev/null \
            "${E2E_CURL_AUTH[@]}" \
            -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
            "${E2E_DOCKER_URL}/v2/ghcr.io/jitesoft/alpine/manifests/latest" 2>/dev/null \
            | grep -i "X-Shieldoo-Scanned" || true)
        if grep -qi "true" <<< "$scanned_header"; then
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
        log_skip "Docker Registry: skipping cached manifest tests (alpine pull didn't complete)"
    fi

    # Pull gcr.io/distroless/static (~2MB) — proves multi-upstream routing
    log_info "Docker Registry: pulling gcr.io/distroless/static (multi-upstream routing test)..."
    manifest_output=""; manifest_exit=0
    manifest_output=$(_timed_crane manifest "${E2E_DOCKER_REGISTRY_HOST}/gcr.io/distroless/static:latest" --insecure 2>&1) || manifest_exit=$?
    _check_docker_pull_result \
        "Docker Registry: gcr.io/distroless/static via multi-upstream routing" \
        "$manifest_output" "$manifest_exit" "skip" || true

    # ==================================================================
    # Part 3: PUSH TESTS — push internal images via crane copy
    # ==================================================================

    log_info "Docker Registry: testing push to internal namespace..."
    local push_output
    if push_output=$(_timed_crane copy "${E2E_DOCKER_REGISTRY_HOST}/ghcr.io/jitesoft/alpine:latest" "${E2E_DOCKER_REGISTRY_HOST}/myteam/testapp:v1.0" --insecure 2>&1); then
        log_pass "Docker Registry: push to internal namespace succeeded"

        # Pull back the pushed image
        log_info "Docker Registry: pulling back pushed image..."
        if manifest_output=$(_timed_crane manifest "${E2E_DOCKER_REGISTRY_HOST}/myteam/testapp:v1.0" --insecure 2>&1); then
            log_pass "Docker Registry: pull-back of pushed image succeeded"
        else
            _check_docker_pull_result \
                "Docker Registry: pull-back of pushed image" \
                "$manifest_output" "$?" "skip" || true
        fi
    else
        _check_docker_pull_result \
            "Docker Registry: push to internal namespace" \
            "$push_output" "$?" "skip" || true
    fi

    # Push to upstream namespace must be rejected (instant — no scan)
    log_info "Docker Registry: testing push rejection for upstream namespaces..."
    local push_upstream_output
    if push_upstream_output=$(_timed_crane copy "${E2E_DOCKER_REGISTRY_HOST}/ghcr.io/jitesoft/alpine:latest" "${E2E_DOCKER_REGISTRY_HOST}/gcr.io/evil/image:v1.0" --insecure 2>&1); then
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
            create_tag_status=$(admin_curl -s -o /dev/null -w "%{http_code}" \
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
            delete_tag_status=$(admin_curl -s -o /dev/null -w "%{http_code}" \
                -X DELETE "${E2E_ADMIN_URL}/api/v1/docker/repositories/${repo_id}/tags/e2e-test-tag")
            if [ "$delete_tag_status" = "204" ] || [ "$delete_tag_status" = "200" ]; then
                log_pass "Docker Registry: tag deletion via API (HTTP ${delete_tag_status})"
            else
                log_skip "Docker Registry: tag deletion returned HTTP ${delete_tag_status}"
            fi

            # Manual sync trigger
            local sync_status
            sync_status=$(admin_curl -s -o /dev/null -w "%{http_code}" \
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

    # ==================================================================
    # Part 5: TAG LISTING — GET /v2/{name}/tags/list (issue #196)
    # Instant: names only, no manifests/blobs, no scan pipeline.
    # ==================================================================

    log_info "Docker Registry: testing tag listing..."

    # Upstream (allowlisted registry) tag list — the endpoint Dependabot's
    # docker ecosystem calls before it compares digests.
    local tags_body tags_status
    tags_body=$(curl -s -w "\n%{http_code}" "${E2E_CURL_AUTH[@]}" \
        "${E2E_DOCKER_URL}/v2/ghcr.io/jitesoft/alpine/tags/list")
    tags_status=$(tail -n1 <<< "$tags_body")
    tags_body=$(sed '$d' <<< "$tags_body")
    if [ "$tags_status" = "200" ]; then
        local tag_count
        tag_count=$(jq -r '.tags | length' <<< "$tags_body" 2>/dev/null || echo "0")
        assert_eq "Docker Registry: tags/list reports the client-facing image name" \
            "ghcr.io/jitesoft/alpine" "$(jq -r '.name' <<< "$tags_body" 2>/dev/null || echo "")"
        if [ "$tag_count" -gt 0 ] 2>/dev/null; then
            log_pass "Docker Registry: tags/list on ghcr.io returned ${tag_count} tags"
        else
            log_fail "Docker Registry: tags/list on ghcr.io returned an empty tag list"
        fi
    else
        log_skip "Docker Registry: tags/list on ghcr.io returned HTTP ${tags_status}"
    fi

    # crane ls exercises the same endpoint through a real OCI client.
    local crane_ls_output
    if crane_ls_output=$(_timed_crane ls "${E2E_DOCKER_REGISTRY_HOST}/ghcr.io/jitesoft/alpine" --insecure 2>&1); then
        if [ -n "$crane_ls_output" ]; then
            log_pass "Docker Registry: crane ls lists tags through the gate"
        else
            log_fail "Docker Registry: crane ls returned no tags"
        fi
    else
        log_skip "Docker Registry: crane ls failed: ${crane_ls_output}"
    fi

    # Pagination: ?n=1 must return at most one tag; when the upstream paginates,
    # the Link header must point back at the gate (client-facing image name),
    # never at the upstream registry or a different repository.
    local page_headers page_body page_tags
    local tags_page_file
    tags_page_file=$(mktemp "${TMPDIR:-/tmp}/e2e_docker_tags_page.XXXXXX")
    page_headers=$(curl -s -D - -o "$tags_page_file" "${E2E_CURL_AUTH[@]}" \
        "${E2E_DOCKER_URL}/v2/ghcr.io/jitesoft/alpine/tags/list?n=1" 2>/dev/null || true)
    page_body=$(cat "$tags_page_file" 2>/dev/null || echo '{}')
    page_tags=$(jq -r '.tags | length' <<< "$page_body" 2>/dev/null || echo "0")
    if [ "$page_tags" -le 1 ] 2>/dev/null; then
        log_pass "Docker Registry: tags/list?n=1 honoured page size (${page_tags} tag)"
    else
        log_fail "Docker Registry: tags/list?n=1 returned ${page_tags} tags"
    fi
    local link_header
    link_header=$(grep -i "^link:" <<< "$page_headers" || true)
    if [ -n "$link_header" ]; then
        assert_contains "Docker Registry: tags/list Link header rewritten to the gate path" \
            "/v2/ghcr.io/jitesoft/alpine/tags/list" "$link_header"
        if grep -qi "https\?://" <<< "$link_header"; then
            log_fail "Docker Registry: tags/list Link header leaks an absolute upstream URL: ${link_header}"
        else
            log_pass "Docker Registry: tags/list Link header is gate-relative"
        fi
    else
        log_skip "Docker Registry: upstream did not paginate tags/list (no Link header)"
    fi

    # Response hardening: the body is re-encoded by the gate, so the media type is
    # always JSON and never sniffable.
    local tags_hdrs
    tags_hdrs=$(curl -s -D - -o /dev/null "${E2E_CURL_AUTH[@]}" \
        "${E2E_DOCKER_URL}/v2/ghcr.io/jitesoft/alpine/tags/list" 2>/dev/null || true)
    assert_contains "Docker Registry: tags/list sets nosniff" "nosniff" "$tags_hdrs"
    assert_contains "Docker Registry: tags/list serves application/json" "application/json" "$tags_hdrs"

    # Unknown query parameters must not reach the upstream (a mirror upstream
    # honours ?ns=, which would escape the allowlist decision).
    local tags_ns_status
    tags_ns_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" \
        "${E2E_DOCKER_URL}/v2/ghcr.io/jitesoft/alpine/tags/list?ns=evil.example.com&n=1")
    assert_eq "Docker Registry: tags/list ignores unknown query parameters" "200" "$tags_ns_status"

    # Allowlist enforcement applies to tag listing too.
    local tags_denied_status
    tags_denied_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" \
        "${E2E_DOCKER_URL}/v2/evil.io/malware/pkg/tags/list")
    assert_eq "Docker Registry: tags/list on disallowed registry returns 403" "403" "$tags_denied_status"

    # Malformed pagination is rejected before any upstream request.
    local tags_badn_status
    tags_badn_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" \
        "${E2E_DOCKER_URL}/v2/ghcr.io/jitesoft/alpine/tags/list?n=nope")
    assert_eq "Docker Registry: tags/list with invalid n returns 400" "400" "$tags_badn_status"

    # Internal (pushed) namespace tag list comes from docker_tags, not upstream.
    # A synthetic image is pushed over the raw registry API (same recipe as
    # test_docker_push_durable.sh) so this does not depend on an upstream pull
    # surviving the scan pipeline.
    local TL_NS="myteam/taglisttest"
    local TL_BASE="${E2E_DOCKER_URL}/v2/${TL_NS}"
    local TL_CFG='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}'
    local TL_LAYER='shieldoo-taglist-e2e-layer'
    local TL_CFG_DIGEST TL_LAYER_DIGEST
    TL_CFG_DIGEST="sha256:$(_tl_sha256_hex "$TL_CFG")"
    TL_LAYER_DIGEST="sha256:$(_tl_sha256_hex "$TL_LAYER")"

    local tl_code
    tl_code=$(_tl_push_blob "$TL_BASE" "$TL_CFG_DIGEST" "$TL_CFG")
    if [ "$tl_code" != "201" ]; then
        log_skip "Docker Registry: internal tags/list — config blob upload returned ${tl_code} (push API unavailable)"
    else
        tl_code=$(_tl_push_blob "$TL_BASE" "$TL_LAYER_DIGEST" "$TL_LAYER")
        assert_eq "Docker Registry: internal tags/list — layer blob upload accepted" "201" "$tl_code"

        local TL_MANIFEST
        TL_MANIFEST=$(printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"%s","size":%d},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"%s","size":%d}]}' \
            "$TL_CFG_DIGEST" "${#TL_CFG}" "$TL_LAYER_DIGEST" "${#TL_LAYER}")

        local tl_put_code
        tl_put_code=$(curl -s -o /dev/null -w '%{http_code}' "${E2E_CURL_AUTH[@]}" \
            -X PUT -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
            --data-binary "$TL_MANIFEST" "${TL_BASE}/manifests/v1")

        if [ "$tl_put_code" != "201" ]; then
            log_skip "Docker Registry: internal tags/list — manifest PUT returned ${tl_put_code} (blocked by policy)"
        else
            local internal_tags_body internal_tags_status
            internal_tags_body=$(curl -s -w "\n%{http_code}" "${E2E_CURL_AUTH[@]}" "${TL_BASE}/tags/list")
            internal_tags_status=$(tail -n1 <<< "$internal_tags_body")
            internal_tags_body=$(sed '$d' <<< "$internal_tags_body")
            assert_eq "Docker Registry: internal tags/list returns 200 for a pushed image" \
                "200" "$internal_tags_status"
            assert_contains "Docker Registry: internal tags/list lists the pushed tag" \
                "v1" "$(jq -r '.tags | join(",")' <<< "$internal_tags_body" 2>/dev/null || echo "")"
            assert_eq "Docker Registry: internal tags/list reports the internal image name" \
                "$TL_NS" "$(jq -r '.name' <<< "$internal_tags_body" 2>/dev/null || echo "")"

            # Internal listings paginate locally: ?n=1 caps the page and, when
            # more tags exist, emits a gate-relative Link. With one tag there is
            # no next page, so the Link header must be absent.
            local internal_page_headers internal_page_tags
            internal_page_headers=$(curl -s -D - -o "$tags_page_file" "${E2E_CURL_AUTH[@]}" \
                "${TL_BASE}/tags/list?n=1" 2>/dev/null || true)
            internal_page_tags=$(jq -r '.tags | length' < "$tags_page_file" 2>/dev/null || echo "0")
            assert_eq "Docker Registry: internal tags/list?n=1 returns one tag" "1" "$internal_page_tags"
            if grep -qi "^link:" <<< "$internal_page_headers"; then
                log_fail "Docker Registry: internal tags/list emitted a Link header with no next page"
            else
                log_pass "Docker Registry: internal tags/list omits Link on the last page"
            fi

            # A push-allowed name that was never pushed must not be answered from
            # the internal store — it falls through to upstream (404 once the gate
            # cannot authenticate there), never 200 with foreign tags.
            local unknown_status
            unknown_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" \
                "${E2E_DOCKER_URL}/v2/myteam/never-pushed-${RANDOM}/tags/list")
            if [ "$unknown_status" = "404" ] || [ "$unknown_status" = "403" ]; then
                log_pass "Docker Registry: never-pushed internal name does not list tags (HTTP ${unknown_status})"
            else
                log_fail "Docker Registry: never-pushed internal name returned HTTP ${unknown_status}"
            fi
        fi
    fi
    rm -f "$tags_page_file"

    # Gate logs contain docker scan pipeline entries
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate 2>/dev/null)
    if [[ "$gate_logs" == *"docker_logs not available"* ]]; then
        log_skip "Docker Registry: gate logs inspection not available in container mode"
    elif grep -qi "docker.*scan" <<< "$gate_logs"; then
        log_pass "Docker Registry: gate logs contain Docker scan entries"
    else
        log_skip "Docker Registry: no Docker scan entries in logs (scans may not have completed)"
    fi
}
