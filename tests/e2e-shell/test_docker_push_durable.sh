#!/usr/bin/env bash
# test_docker_push_durable.sh — durable push-blob storage + quarantine gating (ADR-009).
# Sourced by run_all.sh; defines test_docker_push_durable(). Do NOT set -e here.
#
# HARNESS NOTE: the e2e suite runs INSIDE the test-runner container, which cannot
# `docker compose restart` or `exec` the gate container. So two behaviors from the
# Phase 4 plan are intentionally NOT driven from shell here:
#   - "pushed image survives a gate process restart" — the restart can't be issued
#     from inside the runner;
#   - the `-migrate-push-blobs` one-shot — needs `exec` into the gate container.
# Both are covered by Go unit tests (internal/adapter/docker: serve_hardening_test.go,
# migrate_blobs_test.go) and the operator runbook in docs/adapters.md.
#
# This test drives the gate's OWN registry push API over HTTP (no upstream image,
# so it is deterministic — no rate limits, no CVE-verdict dependency). It proves,
# against the configured backend (object store in the S3/Azurite passes):
#   1. a pushed internal image's blob is servable by digest (served from the durable
#      backend, not /tmp);
#   2. an unreferenced blob under a KNOWN internal repo returns 404 — never a
#      fall-through to the upstream registry;
#   3. once every manifest referencing a blob is quarantined, that blob stops being
#      servable by digest — the serveInternalBlob quarantine gate (ADR-009).
# Step 3 needs deterministic DB access, so it runs only in the PostgreSQL passes
# (which are exactly the durable-backend passes: S3 + Azurite).

# _sha256_hex "<string>" → lowercase hex sha256 (busybox/coreutils/openssl fallbacks).
_sha256_hex() {
    if command -v sha256sum >/dev/null 2>&1; then
        printf '%s' "$1" | sha256sum | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
    else
        printf '%s' "$1" | openssl dgst -sha256 | awk '{print $NF}'
    fi
}

# _push_blob "<base>" "<digest>" "<content>" → echoes the final HTTP status.
# Monolithic upload: POST to open a session, then PUT the bytes with ?digest=.
_push_blob() {
    local base="$1" digest="$2" content="$3"
    local loc
    loc=$(curl -s -D - -o /dev/null "${E2E_CURL_AUTH[@]}" -X POST "${base}/blobs/uploads/" \
        | grep -i '^Location:' | tr -d '\r' | awk '{print $2}')
    if [ -z "$loc" ]; then
        echo "000"
        return
    fi
    # Location is a path (/v2/.../blobs/uploads/<uuid>); make it absolute.
    case "$loc" in
        http*) : ;;
        *) loc="${E2E_DOCKER_URL}${loc}" ;;
    esac
    curl -s -o /dev/null -w '%{http_code}' "${E2E_CURL_AUTH[@]}" \
        -X PUT "${loc}?digest=${digest}" --data-binary "$content"
}

test_docker_push_durable() {
    log_section "Docker Push — durable blob storage + quarantine gating (ADR-009)"

    local NS="myteam/durabletest"
    local BASE="${E2E_DOCKER_URL}/v2/${NS}"

    # --- Build a tiny, self-contained image (config + one layer) ---------------
    local CFG='{"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}}'
    local LAYER='shieldoo-durable-e2e-layer'
    local CFG_DIGEST LAYER_DIGEST
    CFG_DIGEST="sha256:$(_sha256_hex "$CFG")"
    LAYER_DIGEST="sha256:$(_sha256_hex "$LAYER")"

    local code
    code=$(_push_blob "$BASE" "$CFG_DIGEST" "$CFG")
    if [ "$code" != "201" ]; then
        log_skip "Docker Push durable: config blob upload returned ${code} (push API unavailable) — skipping"
        return 0
    fi
    code=$(_push_blob "$BASE" "$LAYER_DIGEST" "$LAYER")
    assert_eq "Docker Push durable: layer blob upload accepted" "201" "$code"

    # Manifest referencing the two blobs.
    local MANIFEST
    MANIFEST=$(printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"%s","size":%d},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"%s","size":%d}]}' \
        "$CFG_DIGEST" "${#CFG}" "$LAYER_DIGEST" "${#LAYER}")

    local mput_code
    mput_code=$(curl -s -o /dev/null -w '%{http_code}' "${E2E_CURL_AUTH[@]}" \
        -X PUT -H "Content-Type: application/vnd.oci.image.manifest.v1+json" \
        --data-binary "$MANIFEST" "${BASE}/manifests/v1")

    if [ "$mput_code" = "403" ]; then
        # Manifest was blocked/quarantined by policy → its uploaded layers must NOT
        # be servable by digest (the security property still holds on the deny path).
        local blocked_code
        blocked_code=$(curl -s -o /dev/null -w '%{http_code}' "${E2E_CURL_AUTH[@]}" "${BASE}/blobs/${LAYER_DIGEST}")
        if [ "$blocked_code" = "404" ] || [ "$blocked_code" = "403" ]; then
            log_pass "Docker Push durable: blocked-manifest layer not servable by digest (HTTP ${blocked_code})"
        else
            log_fail "Docker Push durable: blocked-manifest layer GET returned ${blocked_code}, expected 404/403"
        fi
        return 0
    fi
    if [ "$mput_code" != "201" ]; then
        log_fail "Docker Push durable: manifest PUT returned ${mput_code}, expected 201 or 403"
        return 0
    fi
    log_pass "Docker Push durable: pushed synthetic image → ${NS}:v1 (manifest stored)"

    # (1) The layer blob is servable by digest from the durable backend.
    assert_http_status "Docker Push durable: layer blob servable by digest (durable serve)" "200" "${BASE}/blobs/${LAYER_DIGEST}"

    # (2) An unreferenced blob under this KNOWN internal repo must 404 (no fall-through).
    local fake_digest="sha256:0000000000000000000000000000000000000000000000000000000000000000"
    assert_http_status "Docker Push durable: unreferenced blob in known internal repo returns 404 (no upstream fall-through)" "404" "${BASE}/blobs/${fake_digest}"

    # (3) Quarantine gating — needs deterministic DB access (PostgreSQL passes).
    if ! db_available; then
        log_skip "Docker Push durable: quarantine-gating check requires a PostgreSQL/durable-backend pass — skipping"
        return 0
    fi
    # Quarantine EVERY manifest that references the layer, then it must stop serving.
    db_exec "UPDATE artifact_status SET status='QUARANTINED', quarantine_reason='e2e durable blob', quarantined_at=NOW() WHERE artifact_id IN (SELECT manifest_artifact_id FROM docker_blob_refs WHERE blob_digest = '${LAYER_DIGEST}')" >/dev/null 2>&1

    local post_code
    post_code=$(curl -s -o /dev/null -w '%{http_code}' "${E2E_CURL_AUTH[@]}" "${BASE}/blobs/${LAYER_DIGEST}")
    if [ "$post_code" = "404" ] || [ "$post_code" = "403" ]; then
        log_pass "Docker Push durable: blob NOT servable after quarantine (HTTP ${post_code}; quarantine gate holds)"
    else
        log_fail "Docker Push durable: quarantined image blob GET returned ${post_code}, expected 404/403 (quarantine bypass or upstream fall-through)"
    fi
}
