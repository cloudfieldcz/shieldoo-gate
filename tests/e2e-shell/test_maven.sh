#!/usr/bin/env bash
# test_maven.sh — Maven proxy e2e tests for Shieldoo Gate
# Sourced by run.sh; defines test_maven(). Do NOT set -e here.

test_maven() {
    log_section "Maven Proxy Tests"

    # ------------------------------------------------------------------
    # 1. Maven metadata endpoint is accessible
    # ------------------------------------------------------------------
    assert_http_status "Maven: metadata for commons-lang3 returns HTTP 200" \
        "200" \
        "${E2E_MAVEN_URL}/org/apache/commons/commons-lang3/maven-metadata.xml"

    # ------------------------------------------------------------------
    # 2. POM file is downloadable
    # ------------------------------------------------------------------
    assert_http_status "Maven: POM for commons-lang3 3.14.0 returns HTTP 200" \
        "200" \
        "${E2E_MAVEN_URL}/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom"

    # ------------------------------------------------------------------
    # 3. JAR file is downloadable
    # ------------------------------------------------------------------
    assert_http_status "Maven: JAR for commons-lang3 3.14.0 returns HTTP 200" \
        "200" \
        "${E2E_MAVEN_URL}/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar"

    # ------------------------------------------------------------------
    # 4. Downloaded JAR is a valid zip (JARs are zip archives)
    # ------------------------------------------------------------------
    local workdir
    workdir=$(mktemp -d)
    local jar_path="${workdir}/commons-lang3-3.14.0.jar"

    if curl -sf -o "$jar_path" \
        "${E2E_MAVEN_URL}/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar"; then
        if file "$jar_path" | grep -qi "zip\|jar\|java"; then
            log_pass "Maven: downloaded JAR is a valid archive"
        else
            log_fail "Maven: downloaded JAR is not a valid archive ($(file "$jar_path"))"
        fi
    else
        log_fail "Maven: failed to download JAR file"
    fi

    rm -rf "$workdir"

    # ------------------------------------------------------------------
    # 5. Artifacts registered in API (>= 1 with ecosystem=="maven")
    # ------------------------------------------------------------------
    local maven_count
    maven_count=$(api_jq "/api/v1/artifacts" \
        '[.data[] | select(.ecosystem == "maven")] | length')
    assert_gte "Maven: at least 1 maven artifact registered in API" 1 "$maven_count"

    # ------------------------------------------------------------------
    # 6. Audit log has SERVED events for maven artifacts
    # ------------------------------------------------------------------
    local maven_served
    maven_served=$(api_jq "/api/v1/audit?per_page=200&event_type=SERVED" \
        '[.data[] | select(.artifact_id | startswith("maven:"))] | length')
    assert_gte "Maven: at least 1 SERVED audit event for maven artifacts" 1 "$maven_served"

    # ------------------------------------------------------------------
    # 7. Gate logs contain scan pipeline entries for maven
    # ------------------------------------------------------------------
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate 2>/dev/null)

    if echo "$gate_logs" | grep -qiE "scan result|policy decision"; then
        log_pass "Maven: gate logs contain scan pipeline entries"
    else
        log_fail "Maven: gate logs do not contain 'scan result' or 'policy decision' entries"
    fi
}
