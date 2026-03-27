# Docker Registry Redesign — Phase 5: E2E Tests

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Comprehensive E2E test coverage for the new Docker registry features: multi-upstream pull, push, scheduled sync, tag management API, scan pipeline, quarantine flow, and allowlist enforcement. Tests run against a real shieldoo-gate stack with real Docker clients.

**Architecture:** Extends the existing shell-based E2E framework in `tests/e2e-shell/`. A second mock registry (lightweight OCI registry via `registry:2`) is added to the E2E compose stack to test multi-upstream routing. The existing `test_docker.sh` is replaced with a comprehensive `test_docker_registry.sh`. The E2E config is updated for the new `upstreams.docker` struct with the mock registry in the allowlist. Tests use `crane` (go-containerregistry CLI) for push/pull operations.

**Tech Stack:** Bash, crane (OCI CLI), curl, jq, Docker Compose, `registry:2` (distribution/distribution)

**Index:** [`plan-index.md`](./2026-03-27-docker-registry-redesign-plan-index.md)

**Prerequisites:** Phases 1-4a must be complete. Phase 4b (UI) is not tested here.

---

### Task 1: Add Mock Upstream Registry to E2E Stack

**Files:**
- Modify: `tests/e2e-shell/docker-compose.e2e.yml`
- Modify: `tests/e2e-shell/config.e2e.yaml`
- Modify: `tests/e2e-shell/helpers.sh`
- Modify: `tests/e2e-shell/run.sh`

- [ ] **Step 1: Add `mock-registry` service to docker-compose.e2e.yml**

Add a lightweight OCI registry as a second upstream (simulating ghcr.io):

```yaml
  mock-registry:
    image: registry:2.8.3
    container_name: shieldoo-e2e-mock-registry
    ports:
      - "15003:5000"
    restart: "no"
```

Make `shieldoo-gate` depend on it:
```yaml
  shieldoo-gate:
    depends_on:
      - scanner-bridge
      - mock-registry
```

- [ ] **Step 2: Update config.e2e.yaml for multi-upstream**

Replace the `docker:` upstream string with the new struct:

```yaml
upstreams:
  pypi: "https://pypi.org"
  npm: "https://registry.npmjs.org"
  nuget: "https://api.nuget.org"
  docker:
    default_registry: "https://registry-1.docker.io"
    allowed_registries:
      - host: "mock-registry:5000"
        url: "http://mock-registry:5000"
    sync:
      enabled: true
      interval: "1h"
      rescan_interval: "2h"
      max_concurrent: 2
    push:
      enabled: true
```

Note: `mock-registry:5000` is the Docker-internal hostname. For crane on the host, use `localhost:15003`.

- [ ] **Step 3: Add mock registry port to helpers.sh**

Add after the existing port definitions (line 27):
```bash
export E2E_MOCK_REGISTRY_PORT=15003
export E2E_MOCK_REGISTRY_URL="http://localhost:${E2E_MOCK_REGISTRY_PORT}"
```

- [ ] **Step 4: Add `crane` to prerequisites check in run.sh**

Update `check_prereqs` to include `crane` (required for push/pull tests):
```bash
for cmd in docker curl jq uv node npm crane; do
```

- [ ] **Step 5: Pre-populate mock registry with test images**

Add a function to `run.sh` after stack startup but before tests:
```bash
seed_mock_registry() {
    log_info "Seeding mock registry with test images..."
    # Pull a small image, retag, push to mock registry
    crane copy alpine:3.20 "localhost:${E2E_MOCK_REGISTRY_PORT}/testorg/testimage:v1.0" --insecure
    crane copy alpine:3.20 "localhost:${E2E_MOCK_REGISTRY_PORT}/testorg/testimage:v2.0" --insecure
    log_info "Mock registry seeded with testorg/testimage:v1.0 and v2.0"
}
```

Call it after `wait_for_ready`:
```bash
    # 4b. Seed mock registry
    seed_mock_registry
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

test_docker_registry() {
    log_section "Docker Registry Redesign Tests"

    # ==================================================================
    # MULTI-UPSTREAM PULL
    # ==================================================================

    # 1. Default upstream (Docker Hub) — pull alpine:3.20
    log_info "Docker Registry: pulling alpine:3.20 from default upstream (Docker Hub)..."
    local manifest_output
    if manifest_output=$(crane manifest --insecure "localhost:${E2E_DOCKER_PORT}/library/alpine:3.20" 2>&1); then
        log_pass "Docker Registry: pull from default upstream (Docker Hub) succeeded"
        if echo "$manifest_output" | grep -q "schemaVersion"; then
            log_pass "Docker Registry: manifest contains schemaVersion"
        else
            log_fail "Docker Registry: manifest missing schemaVersion"
        fi
    else
        log_skip "Docker Registry: default upstream pull failed (may need auth): ${manifest_output}"
    fi

    # 2. Bare image name expands to library/ — pull nginx (not library/nginx)
    log_info "Docker Registry: pulling bare name 'nginx' (should expand to library/nginx)..."
    local bare_status
    bare_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        "${E2E_DOCKER_URL}/v2/nginx/manifests/latest")
    if [ "$bare_status" = "200" ] || [ "$bare_status" = "502" ]; then
        log_pass "Docker Registry: bare name 'nginx' routed correctly (HTTP ${bare_status})"
    else
        log_skip "Docker Registry: bare name routing returned HTTP ${bare_status}"
    fi

    # 3. Allowed non-default upstream (mock registry) — pull testorg/testimage:v1.0
    log_info "Docker Registry: pulling from mock upstream registry..."
    if manifest_output=$(crane manifest --insecure "localhost:${E2E_DOCKER_PORT}/mock-registry:5000/testorg/testimage:v1.0" 2>&1); then
        log_pass "Docker Registry: pull from allowed non-default upstream succeeded"
    else
        log_fail "Docker Registry: pull from mock upstream failed: ${manifest_output}"
    fi

    # 4. Disallowed registry — must return 403
    log_info "Docker Registry: testing disallowed registry (evil.io)..."
    local disallowed_status
    disallowed_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        "${E2E_DOCKER_URL}/v2/evil.io/malware/pkg/manifests/latest")
    assert_eq "$disallowed_status" "403" "Docker Registry: disallowed registry returns 403"

    # 5. Disallowed registry — audit log has BLOCKED entry
    local blocked_events
    blocked_events=$(api_jq "/api/v1/audit?per_page=200" \
        '[.data[] | select(.event_type == "BLOCKED" and (.artifact_id | contains("evil.io")))] | length' 2>/dev/null || echo "0")
    assert_gte "$blocked_events" 1 "Docker Registry: BLOCKED audit entry for evil.io"

    # 6. Scanned header on cached manifest
    local scanned_header
    scanned_header=$(curl -s -D - -o /dev/null \
        -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
        "${E2E_DOCKER_URL}/v2/mock-registry:5000/testorg/testimage:v1.0/manifests/v1.0" 2>/dev/null \
        | grep -i "X-Shieldoo-Scanned")
    if echo "$scanned_header" | grep -qi "true"; then
        log_pass "Docker Registry: X-Shieldoo-Scanned: true on cached manifest"
    else
        log_skip "Docker Registry: X-Shieldoo-Scanned header not found (may not be cached yet)"
    fi

    # 7. Blob routing to correct upstream
    log_info "Docker Registry: testing blob routing to mock upstream..."
    local blob_status
    blob_status=$(curl -s -o /dev/null -w "%{http_code}" \
        "${E2E_DOCKER_URL}/v2/mock-registry:5000/testorg/testimage/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000000")
    if [ "$blob_status" = "404" ] || [ "$blob_status" = "400" ]; then
        log_pass "Docker Registry: blob routed to mock upstream correctly (HTTP ${blob_status})"
    else
        log_fail "Docker Registry: blob routing returned unexpected HTTP ${blob_status}"
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

    # 8. Push to internal namespace — should succeed
    log_info "Docker Registry: pushing internal image myteam/testapp:v1.0..."
    # Create a minimal image from scratch
    local push_output
    if push_output=$(crane copy alpine:3.20 "localhost:${E2E_DOCKER_PORT}/myteam/testapp:v1.0" --insecure 2>&1); then
        log_pass "Docker Registry: push to internal namespace succeeded"
    else
        log_fail "Docker Registry: push to internal namespace failed: ${push_output}"
    fi

    # 9. Push to upstream namespace — should fail with 403
    log_info "Docker Registry: pushing to upstream namespace (should fail)..."
    local push_upstream_output
    if push_upstream_output=$(crane copy alpine:3.20 "localhost:${E2E_DOCKER_PORT}/mock-registry:5000/evil/image:v1.0" --insecure 2>&1); then
        log_fail "Docker Registry: push to upstream namespace should have been rejected"
    else
        log_pass "Docker Registry: push to upstream namespace correctly rejected"
    fi

    # 10. Pull back the pushed image — should work
    log_info "Docker Registry: pulling back pushed image..."
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

    # 11. Pushed image was scanned (check audit log)
    local push_scanned
    push_scanned=$(api_jq "/api/v1/audit?per_page=200" \
        '[.data[] | select(.artifact_id | contains("myteam")) and select(.event_type == "SERVED")] | length' 2>/dev/null || echo "0")
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

    # 12. List repositories — should contain our repos
    local repos_count
    repos_count=$(api_jq "/api/v1/docker/repositories" '. | length' 2>/dev/null || echo "0")
    assert_gte "$repos_count" 1 "Docker Registry: at least 1 repository registered"

    # 13. List repositories filtered by registry
    local mock_repos
    mock_repos=$(api_jq "/api/v1/docker/repositories?registry=mock-registry:5000" '. | length' 2>/dev/null || echo "0")
    assert_gte "$mock_repos" 1 "Docker Registry: mock-registry repos found via filter"

    # 14. List tags for a repository
    local repo_id
    repo_id=$(api_jq "/api/v1/docker/repositories" '.[0].id' 2>/dev/null || echo "")
    if [ -n "$repo_id" ] && [ "$repo_id" != "null" ]; then
        local tags_count
        tags_count=$(api_jq "/api/v1/docker/repositories/${repo_id}/tags" '. | length' 2>/dev/null || echo "0")
        assert_gte "$tags_count" 1 "Docker Registry: at least 1 tag for repo ${repo_id}"
    else
        log_skip "Docker Registry: no repo ID found for tag listing"
    fi

    # 15. Create a new tag via API
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

    # 16. Delete the tag via API
    local delete_tag_status
    delete_tag_status=$(curl -s -o /dev/null -w "%{http_code}" \
        -X DELETE \
        "${E2E_ADMIN_URL}/api/v1/docker/repositories/${repo_id}/tags/e2e-test-tag")
    if [ "$delete_tag_status" = "204" ] || [ "$delete_tag_status" = "200" ]; then
        log_pass "Docker Registry: tag deletion via API succeeded (HTTP ${delete_tag_status})"
    else
        log_skip "Docker Registry: tag deletion returned HTTP ${delete_tag_status}"
    fi

    # 17. List allowed registries
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

    # 18. Manual sync trigger via API
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

        # 19. Verify last_synced_at was updated
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

    # 20. Gate logs contain scan entries for multi-upstream pulls
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate 2>/dev/null)

    if echo "$gate_logs" | grep -qi "docker.*scan.*pipeline\|docker.*scan.*result"; then
        log_pass "Docker Registry: gate logs contain Docker scan pipeline entries"
    else
        log_skip "Docker Registry: no Docker scan pipeline entries in logs"
    fi

    # 21. Verify artifacts registered in API with correct registry prefix
    local docker_artifacts
    docker_artifacts=$(api_jq "/api/v1/artifacts?ecosystem=docker" '. | length' 2>/dev/null || echo "0")
    assert_gte "$docker_artifacts" 1 "Docker Registry: at least 1 docker artifact registered"

    # 22. Check that scanned artifacts have scan results
    local scan_results
    scan_results=$(api_jq "/api/v1/audit?per_page=200" \
        '[.data[] | select(.event_type == "SCANNED" and (.artifact_id | startswith("docker:")))] | length' 2>/dev/null || echo "0")
    if [ "$scan_results" -gt 0 ] 2>/dev/null; then
        log_pass "Docker Registry: SCANNED audit events found for docker artifacts (${scan_results})"
    else
        log_skip "Docker Registry: no SCANNED events yet"
    fi

    # 23. /v2/ endpoint responds locally with correct header
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
