#!/usr/bin/env bash
# test_api.sh — Admin API e2e tests for Shieldoo Gate
# Sourced by run.sh; defines test_api(). Do NOT set -e here.

test_api() {
    log_section "Admin API Tests"

    # ------------------------------------------------------------------
    # 1. Health endpoint returns {"status":"ok"}
    # ------------------------------------------------------------------
    local health_status
    health_status=$(api_jq "/api/v1/health" '.status')
    assert_eq "API: /health returns {\"status\":\"ok\"}" "ok" "$health_status"

    # ------------------------------------------------------------------
    # 2. Stats summary: total_artifacts > 0, total_served > 0
    # ------------------------------------------------------------------
    local total_artifacts total_served
    total_artifacts=$(api_jq "/api/v1/stats/summary" '.total_artifacts')
    total_served=$(api_jq "/api/v1/stats/summary" '.total_served')
    assert_gte "API: stats total_artifacts > 0" 1 "$total_artifacts"
    assert_gte "API: stats total_served > 0" 1 "$total_served"

    # ------------------------------------------------------------------
    # 3. Stats by_period has 7 daily buckets
    # ------------------------------------------------------------------
    local period_count
    period_count=$(api_jq "/api/v1/stats/summary" '.by_period | keys | length')
    assert_gte "API: stats by_period has at least 7 daily buckets" 7 "$period_count"

    # ------------------------------------------------------------------
    # 4. Today's bucket has served > 0
    # ------------------------------------------------------------------
    local today today_served
    today=$(date -u +%Y-%m-%d)
    today_served=$(api_jq "/api/v1/stats/summary" ".by_period[\"${today}\"].served // 0")
    assert_gte "API: today's stats bucket (${today}) has served > 0" 1 "$today_served"

    # ------------------------------------------------------------------
    # 5. Stats total_artifacts matches /artifacts total
    # ------------------------------------------------------------------
    local artifacts_total stats_total
    artifacts_total=$(api_jq "/api/v1/artifacts" '.total')
    stats_total=$(api_jq "/api/v1/stats/summary" '.total_artifacts')
    assert_eq "API: stats total_artifacts matches /artifacts total" \
        "$stats_total" "$artifacts_total"

    # ------------------------------------------------------------------
    # 6. Audit log has entries (length > 0)
    # ------------------------------------------------------------------
    local audit_count
    audit_count=$(api_jq "/api/v1/audit?per_page=200" '.data | length')
    assert_gte "API: audit log has at least 1 entry" 1 "$audit_count"

    # ------------------------------------------------------------------
    # 7. Metrics endpoint returns 200 and contains go_goroutines
    # ------------------------------------------------------------------
    assert_http_status "API: /metrics returns HTTP 200" \
        "200" \
        "${E2E_ADMIN_URL}/metrics"

    local metrics_body
    metrics_body=$(curl -sf "${E2E_ADMIN_URL}/metrics")
    assert_contains "API: /metrics contains 'go_goroutines'" \
        "go_goroutines" \
        "$metrics_body"
}
