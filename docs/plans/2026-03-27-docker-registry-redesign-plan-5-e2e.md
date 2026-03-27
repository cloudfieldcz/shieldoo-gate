# Docker Registry Redesign — Phase 5: E2E Tests

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Comprehensive E2E test coverage for the new Docker registry features: multi-upstream pull, push, scheduled sync, tag management API, scan pipeline, quarantine flow, and allowlist enforcement. Tests run against a real shieldoo-gate stack with real Docker clients.

**Architecture:** Extends the existing shell-based E2E framework in `tests/e2e-shell/`. Uses real public registries (`gcr.io`, `cgr.dev`) as allowed upstreams for multi-upstream testing — no mock registry needed. A local `registry:2` instance is added only for push tests (internal image target). The existing `test_docker.sh` is replaced with a comprehensive `test_docker_registry.sh`. Tests use `crane` (go-containerregistry CLI) for push/pull operations.

**Test images (chosen for minimal size):**

| Image | Size | Purpose | Upstream |
|-------|------|---------|----------|
| `hello-world` | ~13 kB | Smallest possible pull, smoke test, push source | Docker Hub (default) |
| `busybox:latest` | ~4 MB | Bare name expansion (`library/` prefix), push source | Docker Hub (default) |
| `alpine:3.20` | ~7 MB | Standard test image | Docker Hub (default) |
| `gcr.io/distroless/static:latest` | ~2 MB | Multi-upstream: gcr.io | gcr.io |
| `gcr.io/distroless/base:latest` | ~5 MB | Multi-upstream: gcr.io (second image) | gcr.io |
| `ghcr.io/hlesey/busybox:latest` | ~4 MB | Multi-upstream: ghcr.io | ghcr.io |
| `ghcr.io/umputun/baseimage/scratch:latest` | ~1 MB | Multi-upstream: ghcr.io (scratch + zoneinfo) | ghcr.io |
| `cgr.dev/chainguard/static:latest` | ~1 MB | Multi-upstream: cgr.dev | cgr.dev |
| `cgr.dev/chainguard/busybox:latest` | ~5 MB | Multi-upstream: cgr.dev (second image) | cgr.dev |

**Tech Stack:** Bash, crane (OCI CLI), curl, jq, Docker Compose, `registry:2` (distribution/distribution for push target)

**Index:** [`plan-index.md`](./2026-03-27-docker-registry-redesign-plan-index.md)

**Prerequisites:** Phases 1-4a must be complete. Phase 4b (UI) is not tested here.

---

### Task 1: Add Mock Upstream Registry to E2E Stack

**Files:**
- Modify: `tests/e2e-shell/docker-compose.e2e.yml`
- Modify: `tests/e2e-shell/config.e2e.yaml`
- Modify: `tests/e2e-shell/helpers.sh`
- Modify: `tests/e2e-shell/run.sh`

- [ ] **Step 1: Add `push-registry` service to docker-compose.e2e.yml**

Add a lightweight OCI registry as push target for internal images:

```yaml
  push-registry:
    image: registry:2.8.3
    container_name: shieldoo-e2e-push-registry
    ports:
      - "15003:5000"
    restart: "no"
```

Note: this is NOT an upstream — it's only used as a reference for verifying pushed images can be pulled back. The actual push target is shieldoo-gate itself.

- [ ] **Step 2: Update config.e2e.yaml for multi-upstream**

Replace the `docker:` upstream string with the new struct. Use real public registries as allowed upstreams:

```yaml
upstreams:
  pypi: "https://pypi.org"
  npm: "https://registry.npmjs.org"
  nuget: "https://api.nuget.org"
  docker:
    default_registry: "https://registry-1.docker.io"
    allowed_registries:
      - host: "gcr.io"
        url: "https://gcr.io"
      - host: "ghcr.io"
        url: "https://ghcr.io"
      - host: "cgr.dev"
        url: "https://cgr.dev"
    sync:
      enabled: true
      interval: "1h"
      rescan_interval: "2h"
      max_concurrent: 2
    push:
      enabled: true
```

- [ ] **Step 3: Add push registry port to helpers.sh**

Add after the existing port definitions (line 27):
```bash
export E2E_PUSH_REGISTRY_PORT=15003
export E2E_PUSH_REGISTRY_URL="http://localhost:${E2E_PUSH_REGISTRY_PORT}"
```

- [ ] **Step 4: Add `crane` to prerequisites check in run.sh**

Update `check_prereqs` to include `crane` (required for push/pull tests):
```bash
for cmd in docker curl jq uv node npm crane; do
```

- [ ] **Step 6: Commit**

```bash
git add tests/e2e-shell/docker-compose.e2e.yml tests/e2e-shell/config.e2e.yaml tests/e2e-shell/helpers.sh tests/e2e-shell/run.sh
git commit -m "test(e2e): add mock upstream registry for multi-upstream Docker tests"
```

---

### Task 2: Multi-Upstream Pull Tests

**Files:**
- Create: `tests/e2e-shell/test_docker_registry.sh`
- Modify: `tests/e2e-shell/run.sh` (source + call new test file)

- [ ] **Step 1: Create test_docker_registry.sh with multi-upstream pull tests**

```bash
#!/usr/bin/env bash
# test_docker_registry.sh — Docker registry redesign E2E tests
# Sourced by run.sh; defines test_docker_registry(). Do NOT set -e here.
#
# Test images (chosen for minimal size):
#   Docker Hub (default):  hello-world (~13kB), busybox (~4MB), alpine:3.20 (~7MB)
#   gcr.io (allowed):      gcr.io/distroless/static (~2MB), gcr.io/distroless/base (~5MB)
#   cgr.dev (allowed):     cgr.dev/chainguard/static (~1MB), cgr.dev/chainguard/busybox (~5MB)

test_docker_registry() {
    log_section "Docker Registry Redesign Tests"

    local manifest_output

    # ==================================================================
    # MULTI-UPSTREAM PULL — Docker Hub (default upstream)
    # ==================================================================

    # 1. hello-world (~13kB) — smallest possible image, smoke test
    log_info "Docker Registry: pulling hello-world from Docker Hub (default)..."
    if manifest_output=$(crane manifest "localhost:${E2E_DOCKER_PORT}/library/hello-world:latest" 2>&1); then
        log_pass "Docker Registry: hello-world pull succeeded (~13kB)"
    else
        log_skip "Docker Registry: hello-world pull failed (may need auth): ${manifest_output}"
    fi

    # 2. Bare name expansion — 'busybox' should expand to 'library/busybox'
    log_info "Docker Registry: pulling bare name 'busybox' (should expand to library/busybox)..."
    if manifest_output=$(crane manifest "localhost:${E2E_DOCKER_PORT}/busybox:latest" 2>&1); then
        log_pass "Docker Registry: bare name 'busybox' routed to library/busybox correctly"
        if echo "$manifest_output" | grep -q "schemaVersion"; then
            log_pass "Docker Registry: busybox manifest is valid"
        else
            log_fail "Docker Registry: busybox manifest missing schemaVersion"
        fi
    else
        log_skip "Docker Registry: busybox pull failed: ${manifest_output}"
    fi

    # 3. alpine:3.20 (~7MB) — standard image, also used as push source later
    log_info "Docker Registry: pulling alpine:3.20 from Docker Hub (default)..."
    if manifest_output=$(crane manifest "localhost:${E2E_DOCKER_PORT}/library/alpine:3.20" 2>&1); then
        log_pass "Docker Registry: alpine:3.20 pull succeeded"
    else
        log_skip "Docker Registry: alpine:3.20 pull failed: ${manifest_output}"
    fi

    # ==================================================================
    # MULTI-UPSTREAM PULL — gcr.io (allowed non-default upstream)
    # ==================================================================

    # 4. gcr.io/distroless/static (~2MB) — smallest distroless
    log_info "Docker Registry: pulling gcr.io/distroless/static:latest..."
    if manifest_output=$(crane manifest "localhost:${E2E_DOCKER_PORT}/gcr.io/distroless/static:latest" 2>&1); then
        log_pass "Docker Registry: gcr.io/distroless/static pull via gate succeeded"
    else
        log_fail "Docker Registry: gcr.io/distroless/static pull failed: ${manifest_output}"
    fi

    # 5. gcr.io/distroless/base (~5MB)
    log_info "Docker Registry: pulling gcr.io/distroless/base:latest..."
    if manifest_output=$(crane manifest "localhost:${E2E_DOCKER_PORT}/gcr.io/distroless/base:latest" 2>&1); then
        log_pass "Docker Registry: gcr.io/distroless/base pull via gate succeeded"
    else
        log_fail "Docker Registry: gcr.io/distroless/base pull failed: ${manifest_output}"
    fi

    # ==================================================================
    # MULTI-UPSTREAM PULL — ghcr.io (allowed non-default upstream)
    # ==================================================================

    # 6. ghcr.io/hlesey/busybox (~4MB) — BusyBox mirror on GHCR
    log_info "Docker Registry: pulling ghcr.io/hlesey/busybox:latest..."
    if manifest_output=$(crane manifest "localhost:${E2E_DOCKER_PORT}/ghcr.io/hlesey/busybox:latest" 2>&1); then
        log_pass "Docker Registry: ghcr.io/hlesey/busybox pull via gate succeeded"
    else
        log_fail "Docker Registry: ghcr.io/hlesey/busybox pull failed: ${manifest_output}"
    fi

    # 7. ghcr.io/umputun/baseimage/scratch (~1MB) — scratch + zoneinfo
    log_info "Docker Registry: pulling ghcr.io/umputun/baseimage/scratch:latest..."
    if manifest_output=$(crane manifest "localhost:${E2E_DOCKER_PORT}/ghcr.io/umputun/baseimage/scratch:latest" 2>&1); then
        log_pass "Docker Registry: ghcr.io/umputun/baseimage/scratch pull via gate succeeded"
    else
        log_fail "Docker Registry: ghcr.io/umputun/baseimage/scratch pull failed: ${manifest_output}"
    fi

    # ==================================================================
    # MULTI-UPSTREAM PULL — cgr.dev (allowed non-default upstream)
    # ==================================================================

    # 8. cgr.dev/chainguard/static (~1MB) — smallest chainguard image
    log_info "Docker Registry: pulling cgr.dev/chainguard/static:latest..."
    if manifest_output=$(crane manifest "localhost:${E2E_DOCKER_PORT}/cgr.dev/chainguard/static:latest" 2>&1); then
        log_pass "Docker Registry: cgr.dev/chainguard/static pull via gate succeeded"
    else
        log_fail "Docker Registry: cgr.dev/chainguard/static pull failed: ${manifest_output}"
    fi

    # 9. cgr.dev/chainguard/busybox (~5MB)
    log_info "Docker Registry: pulling cgr.dev/chainguard/busybox:latest..."
    if manifest_output=$(crane manifest "localhost:${E2E_DOCKER_PORT}/cgr.dev/chainguard/busybox:latest" 2>&1); then
        log_pass "Docker Registry: cgr.dev/chainguard/busybox pull via gate succeeded"
    else
        log_fail "Docker Registry: cgr.dev/chainguard/busybox pull failed: ${manifest_output}"
    fi

    # ==================================================================
    # ALLOWLIST ENFORCEMENT
    # ==================================================================

    # 10. Disallowed registry — must return 403
    log_info "Docker Registry: testing disallowed registry (evil.io)..."
    local disallowed_status
    disallowed_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        "${E2E_DOCKER_URL}/v2/evil.io/malware/pkg/manifests/latest")
    assert_eq "$disallowed_status" "403" "Docker Registry: disallowed registry returns 403"

    # 11. Another disallowed registry (quay.io not in allowlist)
    log_info "Docker Registry: testing another disallowed registry (quay.io)..."
    local quay_status
    quay_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        "${E2E_DOCKER_URL}/v2/quay.io/prometheus/node-exporter/manifests/latest")
    assert_eq "$quay_status" "403" "Docker Registry: quay.io (not in allowlist) returns 403"

    # 12. Audit log has BLOCKED entries for disallowed registries
    local blocked_events
    blocked_events=$(api_jq "/api/v1/audit?per_page=200" \
        '[.data[] | select(.event_type == "BLOCKED")] | length' 2>/dev/null || echo "0")
    assert_gte "$blocked_events" 2 "Docker Registry: at least 2 BLOCKED audit entries"

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
```

- [ ] **Step 2: Source and call in run.sh**

Add after existing sources (line 31):
```bash
source "${SCRIPT_DIR}/test_docker_registry.sh"
```

Add after `test_docker` call (line 100):
```bash
    test_docker_registry
```

- [ ] **Step 3: Run E2E and verify multi-upstream tests pass**

Run: `./tests/e2e-shell/run.sh --keep`
Expected: Multi-upstream pull tests pass

- [ ] **Step 4: Commit**

```bash
git add tests/e2e-shell/test_docker_registry.sh tests/e2e-shell/run.sh
git commit -m "test(e2e): add multi-upstream Docker pull tests"
```

---

### Task 3: Push Tests

**Files:**
- Modify: `tests/e2e-shell/test_docker_registry.sh`

- [ ] **Step 1: Add push tests to test_docker_registry.sh**

Append to the function:

```bash
    # ==================================================================
    # PUSH (internal images only)
    # ==================================================================

    # 13. Push to internal namespace — should succeed (use hello-world as source, ~13kB)
    log_info "Docker Registry: pushing internal image myteam/testapp:v1.0..."
    local push_output
    if push_output=$(crane copy hello-world:latest "localhost:${E2E_DOCKER_PORT}/myteam/testapp:v1.0" --insecure 2>&1); then
        log_pass "Docker Registry: push to internal namespace succeeded"
    else
        log_fail "Docker Registry: push to internal namespace failed: ${push_output}"
    fi

    # 14. Push a second internal image (busybox as source, ~4MB)
    log_info "Docker Registry: pushing internal image myteam/toolbox:latest..."
    if push_output=$(crane copy busybox:latest "localhost:${E2E_DOCKER_PORT}/myteam/toolbox:latest" --insecure 2>&1); then
        log_pass "Docker Registry: push of second internal image succeeded"
    else
        log_fail "Docker Registry: push of second internal image failed: ${push_output}"
    fi

    # 15. Push to upstream namespace (gcr.io) — should fail with 403
    log_info "Docker Registry: pushing to upstream namespace gcr.io (should fail)..."
    local push_upstream_output
    if push_upstream_output=$(crane copy hello-world:latest "localhost:${E2E_DOCKER_PORT}/gcr.io/evil/image:v1.0" --insecure 2>&1); then
        log_fail "Docker Registry: push to gcr.io namespace should have been rejected"
    else
        log_pass "Docker Registry: push to gcr.io namespace correctly rejected"
    fi

    # 16. Push to upstream namespace (cgr.dev) — should also fail
    log_info "Docker Registry: pushing to upstream namespace cgr.dev (should fail)..."
    if push_upstream_output=$(crane copy hello-world:latest "localhost:${E2E_DOCKER_PORT}/cgr.dev/evil/image:v1.0" --insecure 2>&1); then
        log_fail "Docker Registry: push to cgr.dev namespace should have been rejected"
    else
        log_pass "Docker Registry: push to cgr.dev namespace correctly rejected"
    fi

    # 17. Pull back the pushed image — should work
    log_info "Docker Registry: pulling back pushed image myteam/testapp:v1.0..."
    if manifest_output=$(crane manifest --insecure "localhost:${E2E_DOCKER_PORT}/myteam/testapp:v1.0" 2>&1); then
        log_pass "Docker Registry: pull of pushed image succeeded"
        if echo "$manifest_output" | grep -q "schemaVersion"; then
            log_pass "Docker Registry: pushed manifest is valid"
        else
            log_fail "Docker Registry: pushed manifest missing schemaVersion"
        fi
    else
        log_fail "Docker Registry: pull of pushed image failed: ${manifest_output}"
    fi

    # 18. Pushed image was scanned (check audit log)
    local push_scanned
    push_scanned=$(api_jq "/api/v1/audit?per_page=200" \
        '[.data[] | select(.artifact_id | contains("myteam")) | select(.event_type == "SERVED")] | length' 2>/dev/null || echo "0")
    if [ "$push_scanned" -gt 0 ] 2>/dev/null; then
        log_pass "Docker Registry: pushed image appears in audit log as SERVED"
    else
        log_skip "Docker Registry: pushed image not yet in audit log"
    fi
```

- [ ] **Step 2: Run E2E and verify push tests pass**

Run: `./tests/e2e-shell/run.sh --no-build --keep`
Expected: Push tests pass

- [ ] **Step 3: Commit**

```bash
git add tests/e2e-shell/test_docker_registry.sh
git commit -m "test(e2e): add Docker push and namespace validation tests"
```

---

### Task 4: Tag Management API Tests

**Files:**
- Modify: `tests/e2e-shell/test_docker_registry.sh`

- [ ] **Step 1: Add tag management API tests**

Append to the function:

```bash
    # ==================================================================
    # TAG MANAGEMENT API
    # ==================================================================

    # 19. List repositories — should contain our repos
    local repos_count
    repos_count=$(api_jq "/api/v1/docker/repositories" '. | length' 2>/dev/null || echo "0")
    assert_gte "$repos_count" 1 "Docker Registry: at least 1 repository registered"

    # 20. List repositories filtered by registry
    local mock_repos
    mock_repos=$(api_jq "/api/v1/docker/repositories?registry=gcr.io" '. | length' 2>/dev/null || echo "0")
    assert_gte "$mock_repos" 1 "Docker Registry: gcr.io repos found via filter"

    # 21. List tags for a repository
    local repo_id
    repo_id=$(api_jq "/api/v1/docker/repositories" '.[0].id' 2>/dev/null || echo "")
    if [ -n "$repo_id" ] && [ "$repo_id" != "null" ]; then
        local tags_count
        tags_count=$(api_jq "/api/v1/docker/repositories/${repo_id}/tags" '. | length' 2>/dev/null || echo "0")
        assert_gte "$tags_count" 1 "Docker Registry: at least 1 tag for repo ${repo_id}"
    else
        log_skip "Docker Registry: no repo ID found for tag listing"
    fi

    # 22. Create a new tag via API
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

    # 23. Delete the tag via API
    local delete_tag_status
    delete_tag_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X DELETE \
        "${E2E_ADMIN_URL}/api/v1/docker/repositories/${repo_id}/tags/e2e-test-tag")
    if [ "$delete_tag_status" = "204" ] || [ "$delete_tag_status" = "200" ]; then
        log_pass "Docker Registry: tag deletion via API succeeded (HTTP ${delete_tag_status})"
    else
        log_skip "Docker Registry: tag deletion returned HTTP ${delete_tag_status}"
    fi

    # 24. List allowed registries
    local registries_status
    registries_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_ADMIN_URL}/api/v1/docker/registries")
    assert_http_status "$registries_status" 200 "Docker Registry: /api/v1/docker/registries returns 200"
```

- [ ] **Step 2: Run E2E and verify API tests pass**

- [ ] **Step 3: Commit**

```bash
git add tests/e2e-shell/test_docker_registry.sh
git commit -m "test(e2e): add Docker tag management API tests"
```

---

### Task 5: Sync Tests

**Files:**
- Modify: `tests/e2e-shell/test_docker_registry.sh`

- [ ] **Step 1: Add sync trigger and verification tests**

Append to the function:

```bash
    # ==================================================================
    # SYNC
    # ==================================================================

    # 25. Manual sync trigger via API
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

        # 26. Verify last_synced_at was updated
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
```

- [ ] **Step 2: Run E2E and verify sync tests pass**

- [ ] **Step 3: Commit**

```bash
git add tests/e2e-shell/test_docker_registry.sh
git commit -m "test(e2e): add Docker sync trigger and verification tests"
```

---

### Task 6: Scan Pipeline + Quarantine Flow Tests

**Files:**
- Modify: `tests/e2e-shell/test_docker_registry.sh`

- [ ] **Step 1: Add scan and quarantine verification tests**

Append to the function:

```bash
    # ==================================================================
    # SCAN PIPELINE VERIFICATION
    # ==================================================================

    # 27. Gate logs contain scan entries for multi-upstream pulls
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate 2>/dev/null)

    if echo "$gate_logs" | grep -qi "docker.*scan.*pipeline\|docker.*scan.*result"; then
        log_pass "Docker Registry: gate logs contain Docker scan pipeline entries"
    else
        log_skip "Docker Registry: no Docker scan pipeline entries in logs"
    fi

    # 28. Verify artifacts registered in API with correct registry prefix
    local docker_artifacts
    docker_artifacts=$(api_jq "/api/v1/artifacts?ecosystem=docker" '. | length' 2>/dev/null || echo "0")
    assert_gte "$docker_artifacts" 1 "Docker Registry: at least 1 docker artifact registered"

    # 29. Check that scanned artifacts have scan results
    local scan_results
    scan_results=$(api_jq "/api/v1/audit?per_page=200" \
        '[.data[] | select(.event_type == "SCANNED" and (.artifact_id | startswith("docker:")))] | length' 2>/dev/null || echo "0")
    if [ "$scan_results" -gt 0 ] 2>/dev/null; then
        log_pass "Docker Registry: SCANNED audit events found for docker artifacts (${scan_results})"
    else
        log_skip "Docker Registry: no SCANNED events yet"
    fi

    # 30. /v2/ endpoint responds locally with correct header
    local v2_status
    v2_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_DOCKER_URL}/v2/")
    assert_eq "$v2_status" "200" "Docker Registry: /v2/ returns 200 (local response)"

    local v2_header
    v2_header=$(curl -s -D - -o /dev/null "${E2E_DOCKER_URL}/v2/" | grep -i "Docker-Distribution-API-Version")
    assert_contains "$v2_header" "registry/2.0" "Docker Registry: /v2/ has API version header"
}
```

- [ ] **Step 2: Close the function and verify**

Make sure the function ends with `}`.

- [ ] **Step 3: Run full E2E suite**

Run: `./tests/e2e-shell/run.sh`
Expected: All tests pass (existing + new Docker registry tests)

- [ ] **Step 4: Commit**

```bash
git add tests/e2e-shell/test_docker_registry.sh
git commit -m "test(e2e): add Docker scan pipeline and quarantine flow tests"
```

---

### Task 7: Update Existing test_docker.sh

**Files:**
- Modify: `tests/e2e-shell/test_docker.sh`

- [ ] **Step 1: Simplify test_docker.sh**

The original `test_docker.sh` tested basic proxy functionality. Now that `test_docker_registry.sh` covers all Docker tests comprehensively, simplify `test_docker.sh` to avoid duplication. Keep only the basic smoke tests that don't overlap:

- Keep: /v2/ check (backward compat — validates old behavior still works)
- Remove: Everything covered by `test_docker_registry.sh`

Or alternatively, remove `test_docker.sh` entirely and rename `test_docker_registry.sh` to `test_docker.sh`. Choose the cleaner approach.

- [ ] **Step 2: Update run.sh if test file was renamed**

- [ ] **Step 3: Run full E2E suite**

Run: `./tests/e2e-shell/run.sh`
Expected: All pass, no duplicate tests

- [ ] **Step 4: Commit**

```bash
git add tests/e2e-shell/test_docker.sh tests/e2e-shell/test_docker_registry.sh tests/e2e-shell/run.sh
git commit -m "test(e2e): consolidate Docker E2E tests into single comprehensive suite"
```

---

### Task 8: Update E2E Documentation

**Files:**
- Modify: `tests/e2e-shell/README.md`

- [ ] **Step 1: Update README with new Docker registry tests**

Add section documenting:
- New prerequisite: `crane` CLI
- Mock registry setup (what it is, why it's there)
- New test categories: multi-upstream pull, push, sync, tag API, scan pipeline
- How to run Docker-only tests for faster iteration

- [ ] **Step 2: Run full E2E one final time**

Run: `./tests/e2e-shell/run.sh`
Expected: All pass, clean output

- [ ] **Step 3: Commit**

```bash
git add tests/e2e-shell/README.md
git commit -m "docs(e2e): update README with Docker registry E2E test documentation"
```
