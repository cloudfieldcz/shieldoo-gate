#!/usr/bin/env bash
# test_nuget.sh — NuGet proxy e2e tests for Shieldoo Gate
# Sourced by run.sh; defines test_nuget(). Do NOT set -e here.

test_nuget() {
    log_section "NuGet Proxy Tests"

    # ------------------------------------------------------------------
    # 1. Skip if dotnet is not available
    # ------------------------------------------------------------------
    if ! command -v dotnet > /dev/null 2>&1; then
        log_skip "NuGet: dotnet CLI not found — skipping all NuGet tests"
        return 0
    fi

    # ------------------------------------------------------------------
    # 2. Service index accessible
    # ------------------------------------------------------------------
    assert_http_status "NuGet: /v3/index.json returns HTTP 200" \
        "200" \
        "${E2E_NUGET_URL}/v3/index.json"

    # ------------------------------------------------------------------
    # 3. Restore packages via dotnet through the proxy
    # ------------------------------------------------------------------
    local workdir
    workdir=$(mktemp -d)
    cp "${SCRIPT_DIR}/fixtures/nuget/E2ETest.csproj" "$workdir/"
    cp "${SCRIPT_DIR}/fixtures/nuget/nuget.config" "$workdir/"

    # Create minimal Program.cs so the project is valid
    mkdir -p "$workdir"
    cat > "$workdir/Program.cs" <<'EOF'
using Newtonsoft.Json;
Console.WriteLine(JsonConvert.SerializeObject(new { status = "ok" }));
EOF

    pushd "$workdir" > /dev/null

    if dotnet restore \
            --no-cache \
            --force \
            --configfile nuget.config \
            --packages "$workdir/packages" \
            > restore.log 2>&1; then
        log_pass "NuGet: dotnet restore succeeded for all fixture packages"
    else
        log_fail "NuGet: dotnet restore failed (see log below)"
        cat restore.log >&2
    fi

    popd > /dev/null
    rm -rf "$workdir"

    # ------------------------------------------------------------------
    # 4. Artifacts registered in API (>= 2 with ecosystem=="nuget")
    # ------------------------------------------------------------------
    local nuget_count
    nuget_count=$(api_jq "/api/v1/artifacts" \
        '[.data[] | select(.ecosystem == "nuget")] | length')
    assert_gte "NuGet: at least 1 nuget artifact registered in API" 1 "$nuget_count"

    # ------------------------------------------------------------------
    # 5. Audit log has SERVED events for nuget artifacts
    # ------------------------------------------------------------------
    local nuget_served
    nuget_served=$(api_jq "/api/v1/audit?per_page=200&event_type=SERVED" \
        '[.data[] | select(.artifact_id | startswith("nuget:"))] | length')
    assert_gte "NuGet: at least 1 SERVED audit event for nuget artifacts" 1 "$nuget_served"
}
