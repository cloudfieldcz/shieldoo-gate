#!/usr/bin/env bash
# test_integrity.sh — SHA256 integrity verification e2e tests for Shieldoo Gate
# Sourced by run_all.sh; defines test_integrity(). Do NOT set -e here.
#
# These tests require direct database access (PostgreSQL passes only).
# Individual tests are automatically skipped in SQLite passes.

test_integrity() {
    log_section "SHA256 Integrity Verification Tests"

    # ---------------------------------------------------------------------------
    # Scenario 1: Download clean package -> tamper SHA256 in DB -> re-download -> 403
    # ---------------------------------------------------------------------------
    if ! db_available; then
        log_skip "integrity: cache tamper -> 403 on re-download (npm) — requires PostgreSQL"
    else
        local desc="integrity: cache tamper -> 403 on re-download (npm)"

        # 1. Download a clean npm package (populates cache + DB).
        local pkg="is-number"
        local ver="7.0.0"
        local tarball_url="${E2E_NPM_URL}/${pkg}/-/${pkg}-${ver}.tgz"
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
        if [ "$http_code" != "200" ]; then
            log_fail "$desc — initial download failed (HTTP $http_code)"
        else
            local artifact_id="npm:${pkg}:${ver}"

            # 2. Wait for async operations and verify CLEAN.
            sleep 2
            local status
            status=$(db_exec "SELECT status FROM artifact_status WHERE artifact_id = '${artifact_id}'")
            if [ "$status" != "CLEAN" ]; then
                log_fail "$desc — expected CLEAN status after download, got: '$status'"
            else
                # 3. Tamper SHA256 in DB.
                db_exec "UPDATE artifacts SET sha256 = '0000000000000000000000000000000000000000000000000000000000000000' WHERE id = '${artifact_id}'"

                # 4. Re-download — should get 403 (integrity violation).
                http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
                assert_eq "$desc — re-download returns 403" "403" "$http_code"

                # 5. Verify artifact was auto-quarantined.
                status=$(db_exec "SELECT status FROM artifact_status WHERE artifact_id = '${artifact_id}'")
                assert_eq "$desc — auto-quarantine" "QUARANTINED" "$status"

                # 6. Verify INTEGRITY_VIOLATION audit event.
                local event
                event=$(db_exec "SELECT event_type FROM audit_log WHERE artifact_id = '${artifact_id}' AND event_type = 'INTEGRITY_VIOLATION' ORDER BY id DESC LIMIT 1")
                assert_eq "$desc — INTEGRITY_VIOLATION audit event" "INTEGRITY_VIOLATION" "$event"

                # 7. Cleanup: delete artifact.
                curl -s -X DELETE "${E2E_CURL_AUTH[@]}" "${E2E_ADMIN_URL}/api/v1/artifacts/${artifact_id}" > /dev/null
            fi
        fi
    fi

    # ---------------------------------------------------------------------------
    # Scenario 2: Download -> quarantine via DB -> verify blocked ->
    #             release via DB -> tamper SHA256 -> rescan -> verify quarantine
    #
    # Requires both PostgreSQL (for DB manipulation) AND a working cache backend.
    # Azurite (Run 3) has known API version incompatibility that breaks cache.Get()
    # during rescan, causing the artifact to stay in PENDING_SCAN.
    # ---------------------------------------------------------------------------
    if ! db_available; then
        log_skip "integrity: quarantine -> override -> tamper -> rescan -> re-quarantine — requires PostgreSQL"
    elif [ "${SGW_CACHE_BACKEND:-local}" = "azure_blob" ]; then
        log_skip "integrity: quarantine -> override -> tamper -> rescan -> re-quarantine — skipped on Azurite (known API version incompatibility)"
    else
        local desc="integrity: quarantine -> override -> tamper -> rescan -> re-quarantine"

        # Use a unique package not used by other tests.
        local pkg="color-name"
        local ver="1.1.4"
        local tarball_url="${E2E_NPM_URL}/${pkg}/-/${pkg}-${ver}.tgz"
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
        if [ "$http_code" != "200" ]; then
            log_fail "$desc — initial download failed (HTTP $http_code)"
        else
            local artifact_id="npm:${pkg}:${ver}"
            sleep 2

            # 2. Quarantine directly via DB (avoids potential API/rebind issues).
            db_exec "UPDATE artifact_status SET status = 'QUARANTINED', quarantine_reason = 'integrity e2e test', quarantined_at = NOW() WHERE artifact_id = '${artifact_id}'"

            # 3. Verify status is QUARANTINED in DB.
            local status
            status=$(db_exec "SELECT status FROM artifact_status WHERE artifact_id = '${artifact_id}'")
            assert_eq "$desc — quarantine via DB" "QUARANTINED" "$status"

            # 4. Verify download is blocked (403).
            http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
            assert_eq "$desc — blocked while quarantined" "403" "$http_code"

            # 5. Release directly via DB.
            db_exec "UPDATE artifact_status SET status = 'CLEAN', released_at = NOW() WHERE artifact_id = '${artifact_id}'"

            # 6. Verify download works again (200).
            http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
            assert_eq "$desc — download after release" "200" "$http_code"

            # 7. Tamper SHA256 in DB.
            db_exec "UPDATE artifacts SET sha256 = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' WHERE id = '${artifact_id}'"

            # 8. Trigger rescan via API.
            http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" \
                -X POST "${E2E_ADMIN_URL}/api/v1/artifacts/${artifact_id}/rescan")
            assert_eq "$desc — rescan API" "202" "$http_code"

            # 9. Wait for rescan scheduler to process.
            sleep 15

            # 10. Verify artifact is quarantined again.
            status=$(db_exec "SELECT status FROM artifact_status WHERE artifact_id = '${artifact_id}'")
            assert_eq "$desc — re-quarantined after tampered rescan" "QUARANTINED" "$status"

            # 11. Verify INTEGRITY_VIOLATION audit event from rescan.
            local event
            event=$(db_exec "SELECT event_type FROM audit_log WHERE artifact_id = '${artifact_id}' AND event_type = 'INTEGRITY_VIOLATION' ORDER BY id DESC LIMIT 1")
            assert_eq "$desc — rescan INTEGRITY_VIOLATION audit" "INTEGRITY_VIOLATION" "$event"

            # 12. Cleanup: delete artifact.
            curl -s -X DELETE "${E2E_CURL_AUTH[@]}" "${E2E_ADMIN_URL}/api/v1/artifacts/${artifact_id}" > /dev/null
        fi
    fi

    # ---------------------------------------------------------------------------
    # Scenario 3: After integrity violation -> delete artifact -> re-fetch -> OK
    # ---------------------------------------------------------------------------
    if ! db_available; then
        log_skip "integrity: delete after violation -> fresh re-fetch succeeds — requires PostgreSQL"
    else
        local desc="integrity: delete after violation -> fresh re-fetch succeeds"

        # 1. Download a clean package.
        local pkg="picomatch"
        local ver="4.0.2"
        local tarball_url="${E2E_NPM_URL}/${pkg}/-/${pkg}-${ver}.tgz"
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
        if [ "$http_code" != "200" ]; then
            log_fail "$desc — initial download failed (HTTP $http_code)"
        else
            local artifact_id="npm:${pkg}:${ver}"
            sleep 2

            # 2. Tamper SHA256.
            db_exec "UPDATE artifacts SET sha256 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' WHERE id = '${artifact_id}'"

            # 3. Re-download -> 403 (integrity violation).
            http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
            assert_eq "$desc — blocked after tamper" "403" "$http_code"

            # 4. Delete artifact via API.
            http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" \
                -X DELETE "${E2E_ADMIN_URL}/api/v1/artifacts/${artifact_id}")
            assert_eq "$desc — delete API" "200" "$http_code"

            # 5. Re-fetch — should download fresh from upstream, scan, and serve (200).
            http_code=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_CURL_AUTH[@]}" "$tarball_url")
            assert_eq "$desc — fresh download after delete" "200" "$http_code"

            # 6. Verify artifact is CLEAN again.
            sleep 2
            local status
            status=$(db_exec "SELECT status FROM artifact_status WHERE artifact_id = '${artifact_id}'")
            assert_eq "$desc — clean after re-fetch" "CLEAN" "$status"
        fi
    fi
}
