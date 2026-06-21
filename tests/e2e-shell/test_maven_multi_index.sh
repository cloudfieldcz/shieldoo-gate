#!/usr/bin/env bash
# test_maven_multi_index.sh — Multi-upstream-index Maven e2e tests (issue #32, Phase 7).
# Sourced by run.sh / run_all.sh; defines test_maven_multi_index(). Do NOT set -e here.
#
# MV1 — back-compat:    a public coordinate's metadata still routes via the default upstream.
# MV2 — scanned+cached: private artifact (com.mycompany:lib) served via the gate,
#                        scanned, and cached under ecosystem maven__private (THE release gate).
#   MV2a  POM fan-out hit; .jar fetched back through the gate (200);
#         artifact row under maven__private.
# MV3 — scoped-miss:    com.mycompany:ghost (claimed, absent) → 404 + BLOCKED audit.
#
# NOTE: Maven embeds no download URLs in metadata (clients construct artifact URLs
# from the coordinate), so there is no foreign-host negative fixture for Maven
# (no rewrite surface). The scoped-miss + namespacing are the security assertions.

test_maven_multi_index() {
    log_section "Maven Multi-Index Tests (issue #32)"

    local group_path="com/mycompany/lib" version="1.0.0"

    # -----------------------------------------------------------------------
    # MV1 — Default upstream back-compat: public coordinate metadata still served
    # -----------------------------------------------------------------------
    log_section "MV1: default upstream back-compat (org.apache.commons:commons-lang3)"
    assert_http_status \
        "MV1: GET /org/apache/commons/commons-lang3/maven-metadata.xml returns 200 via gate default upstream" \
        "200" \
        "${E2E_MAVEN_URL}/org/apache/commons/commons-lang3/maven-metadata.xml"

    # -----------------------------------------------------------------------
    # MV2 — Private artifact: scanned+cached under maven__private
    # -----------------------------------------------------------------------
    log_section "MV2: private artifact scanned+cached (com.mycompany:lib)"

    # MV2a — POM fans out to the private index (verbatim relay).
    assert_http_status \
        "MV2a: GET /${group_path}/${version}/lib-${version}.pom returns 200 (fan-out hit)" \
        "200" \
        "${E2E_MAVEN_URL}/${group_path}/${version}/lib-${version}.pom"

    # Fetch the .jar back through the gate (scanned download route).
    local code
    code=$(curl -s -o /dev/null -w '%{http_code}' "${E2E_CURL_AUTH[@]}" "${E2E_MAVEN_URL}/${group_path}/${version}/lib-${version}.jar")
    if [ "$code" = "200" ]; then
        log_pass "MV2a: com.mycompany:lib:${version} .jar fetched through gate (HTTP 200)"
    else
        log_fail "MV2a: .jar fetch through gate failed (HTTP ${code})"
    fi

    # MV2a — THE RELEASE GATE: artifact row under ecosystem maven__private.
    local private_count
    private_count=$(api_jq "/api/v1/artifacts?ecosystem=maven__private" \
        '[.data[] | select(.name | test("com.mycompany:lib"))] | length')
    assert_gte \
        "MV2a (RELEASE GATE): artifact row under ecosystem maven__private for com.mycompany:lib" \
        1 \
        "$private_count"

    # -----------------------------------------------------------------------
    # MV3 — Scoped-miss: com.mycompany:ghost claimed, absent → 404 + BLOCKED audit
    # -----------------------------------------------------------------------
    log_section "MV3: scoped-miss (com.mycompany:ghost) → 404 + BLOCKED audit"
    assert_http_status \
        "MV3: GET /com/mycompany/ghost/maven-metadata.xml returns 404 (scoped-miss, no public fallback)" \
        "404" \
        "${E2E_MAVEN_URL}/com/mycompany/ghost/maven-metadata.xml"

    local ghost_blocked
    ghost_blocked=$(api_jq "/api/v1/audit?per_page=200&event_type=BLOCKED" \
        '[.data[] | select((.artifact_id // "") | test("maven__private:com.mycompany:ghost"))] | length')
    assert_gte \
        "MV3: BLOCKED audit event written for maven__private:com.mycompany:ghost" \
        1 \
        "$ghost_blocked"
}
