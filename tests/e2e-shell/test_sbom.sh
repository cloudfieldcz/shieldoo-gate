#!/usr/bin/env bash
# test_sbom.sh — CycloneDX SBOM generation e2e tests
# Sourced by run_all.sh; defines test_sbom(). Do NOT set -e here.

test_sbom() {
    log_section "SBOM Generation Tests"

    # Azure SDK v1.6.4 negotiates x-ms-version=2026-02-06 which Azurite 3.34
    # rejects (400 API version). PutBlob fails, but since v1.3 the SBOM writer
    # persists metadata anyway (blob_path=""). The /licenses endpoint works;
    # only the /sbom blob endpoint returns an error. We flag this so the blob
    # assertions can be skipped below while still testing license metadata.
    local azure_blob_skip=false
    if [ "${SGW_CACHE_BACKEND:-}" = "azure_blob" ]; then
        azure_blob_skip=true
        log_info "SBOM: Azure backend detected — blob assertions will be skipped (Azurite version mismatch), license metadata still tested"
    fi

    # Pull a small, deterministic PyPI package so Trivy generates an SBOM.
    local workdir
    workdir=$(mktemp -d)
    pushd "$workdir" > /dev/null

    # Install 'six' — small single-file package with a well-known license.
    local install_url
    if [ -n "$E2E_AUTH_USERINFO" ]; then
        install_url="http://${E2E_AUTH_USERINFO}${E2E_PYPI_URL#http://}/simple/"
    else
        install_url="${E2E_PYPI_URL}/simple/"
    fi

    uv venv .venv --quiet 2>/dev/null || true
    if ! uv pip install \
            --python .venv/bin/python \
            --no-cache \
            --index-url "$install_url" \
            six \
            > install.log 2>&1; then
        log_fail "SBOM: uv pip install six failed — cannot exercise SBOM path"
        cat install.log >&2
        popd > /dev/null
        return
    fi
    log_pass "SBOM: installed 'six' through the proxy"

    popd > /dev/null

    # ------------------------------------------------------------------
    # Give the async SBOM writer a moment to persist the blob + metadata.
    # ------------------------------------------------------------------
    local artifact_id=""
    local waited=0
    local max_wait=30
    while [ "$waited" -lt "$max_wait" ]; do
        artifact_id=$(curl -sf "${E2E_ADMIN_URL}/api/v1/artifacts?ecosystem=pypi&name=six&limit=5" \
            | jq -r '.data // .artifacts // [] | .[0].id // empty' 2>/dev/null)
        if [ -n "$artifact_id" ] && [ "$artifact_id" != "null" ]; then
            break
        fi
        sleep 1
        waited=$(( waited + 1 ))
    done

    if [ -z "$artifact_id" ] || [ "$artifact_id" = "null" ]; then
        log_fail "SBOM: could not discover 'six' artifact via admin API (waited ${max_wait}s)"
        return
    fi
    log_pass "SBOM: discovered artifact id=${artifact_id}"

    # Wait a bit more for the async SBOM write goroutine.
    sleep 5

    # ------------------------------------------------------------------
    # 1. GET /api/v1/artifacts/{id}/sbom returns CycloneDX JSON
    #    (skipped on Azure backend — blob write fails due to Azurite mismatch)
    # ------------------------------------------------------------------
    if [ "$azure_blob_skip" = true ]; then
        log_skip "SBOM: /sbom blob endpoint — skipped on Azure backend (Azurite version mismatch)"
    else
        local sbom_body
        sbom_body=$(curl -sf -H "Accept: application/vnd.cyclonedx+json" \
            "${E2E_ADMIN_URL}/api/v1/artifacts/${artifact_id}/sbom" 2>/dev/null || true)

        if [ -z "$sbom_body" ]; then
            log_fail "SBOM: /sbom endpoint returned empty body (async write did not land in time?)"
            return
        fi

        local bom_format
        bom_format=$(echo "$sbom_body" | jq -r '.bomFormat // empty' 2>/dev/null)
        assert_eq "SBOM: bomFormat=CycloneDX" "CycloneDX" "$bom_format"

        local spec_version
        spec_version=$(echo "$sbom_body" | jq -r '.specVersion // empty' 2>/dev/null)
        if [[ "$spec_version" =~ ^1\.[0-9]+$ ]]; then
            log_pass "SBOM: specVersion looks like CycloneDX 1.x (${spec_version})"
        else
            log_fail "SBOM: unexpected specVersion '${spec_version}'"
        fi

        # Path sanitization — internal cache paths MUST NOT leak.
        if echo "$sbom_body" | grep -q '/var/cache/shieldoo-gate'; then
            log_fail "SBOM: blob contains '/var/cache/shieldoo-gate' (path sanitization broken)"
        else
            log_pass "SBOM: internal cache paths sanitized out of blob"
        fi
    fi

    # ------------------------------------------------------------------
    # 3. GET /api/v1/artifacts/{id}/licenses returns SPDX IDs
    # ------------------------------------------------------------------
    local licenses_body
    licenses_body=$(curl -sf "${E2E_ADMIN_URL}/api/v1/artifacts/${artifact_id}/licenses" 2>/dev/null || true)
    if [ -z "$licenses_body" ]; then
        log_fail "SBOM: /licenses endpoint returned empty body"
        return
    fi

    # Dependency-less Python wheels (like 'six') legitimately produce 0
    # components in CycloneDX — Trivy only lists dependencies, not the artifact
    # itself. The check below is a presence check (numeric field), not a value
    # threshold.
    local component_count
    component_count=$(echo "$licenses_body" | jq -r '.component_count // -1')
    if [ "$component_count" != "-1" ] && [ "$component_count" -ge 0 ] 2>/dev/null; then
        log_pass "SBOM: component_count is present and numeric (=${component_count})"
    else
        log_fail "SBOM: component_count field missing or invalid"
    fi

    local generator
    generator=$(echo "$licenses_body" | jq -r '.generator // empty')
    if [[ "$generator" == trivy* ]]; then
        log_pass "SBOM: generator=${generator}"
    elif [ -n "$generator" ] && [ "$generator" != "unknown" ]; then
        # Some Trivy versions omit metadata.tools for filesystem scans — accept
        # any non-empty, non-"unknown" generator string.
        log_pass "SBOM: generator=${generator} (non-empty)"
    else
        log_fail "SBOM: generator is missing or 'unknown' (got '${generator}')"
    fi
}
