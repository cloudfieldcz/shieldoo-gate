# E2E Shell Script Test Suite

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Self-contained bash-based E2E test suite that spins up an isolated Shieldoo Gate stack on non-conflicting ports, installs packages through all three proxies (PyPI, npm, NuGet), and validates artifacts, audit logs, scan results, and dashboard stats via the Admin API.

**Architecture:** A single `tests/e2e-shell/run.sh` orchestration script plus per-ecosystem test functions. The suite uses its own `docker-compose.e2e.yml` (different host ports, own volumes) so it never touches the dev environment. Each run starts clean (`docker compose down -v`). Test projects live alongside the script with more dependencies than the simple examples. Assertions are done via `curl` + `jq` against the Admin API.

**Tech Stack:** Bash, Docker Compose, curl, jq, uv (Python), npm (Node.js), dotnet CLI (.NET)

---

## File Structure

```
tests/e2e-shell/
├── run.sh                        # Main orchestration script (executable)
├── docker-compose.e2e.yml        # Isolated stack: different ports + own volumes
├── config.e2e.yaml               # Gate config for e2e (matches internal ports)
├── helpers.sh                    # Shared assertion/utility functions
├── test_pypi.sh                  # PyPI test functions
├── test_npm.sh                   # npm test functions
├── test_nuget.sh                 # NuGet test functions
├── test_api.sh                   # Admin API / dashboard stats validation
├── fixtures/
│   ├── pypi/
│   │   └── requirements.txt      # 3+ PyPI packages (requests, flask, click)
│   ├── npm/
│   │   ├── package.json          # 3+ npm packages (chalk, lodash, is-odd)
│   │   └── .npmrc                # Points to e2e npm port
│   └── nuget/
│       ├── E2ETest.csproj        # 2+ NuGet packages (Newtonsoft.Json, Dapper)
│       └── nuget.config          # Points to e2e NuGet port
└── README.md                     # How to run, prerequisites, what it tests
```

## Port Mapping (E2E-isolated)

| Service | Dev Port | E2E Host Port | Internal Port |
|---------|----------|---------------|---------------|
| PyPI    | 5010     | **15010**     | 5000          |
| npm     | 4873     | **14873**     | 4873          |
| NuGet   | 5001     | **15001**     | 5001          |
| Docker  | 5002     | **15002**     | 5002          |
| Admin   | 8080     | **18080**     | 8080          |

## Prerequisites

The following CLI tools must be available on the host:
- `docker` and `docker compose`
- `curl` and `jq`
- `uv` (Python package manager)
- `node` and `npm`
- `dotnet` (optional — NuGet tests skip if missing)

## Known Issues to Fix Before Tests Will Pass

### npm adapter: tarball URL rewriting (same bug as PyPI had)

The npm adapter's `proxyUpstream` for package metadata returns upstream tarball URLs like `https://registry.npmjs.org/chalk/-/chalk-5.4.1.tgz`. The npm client follows these URLs directly, **bypassing the proxy's scan pipeline**. The adapter needs to rewrite tarball URLs in metadata responses to point back through the proxy (e.g., `http://localhost:PORT/chalk/-/chalk-5.4.1.tgz`).

**Files to modify:** `internal/adapter/npm/npm.go` — add URL rewriting in `handlePackageMetadata` (and scoped variant), similar to `pypi.proxyUpstreamRewrite`.

### NuGet adapter: check if same issue exists

The NuGet adapter proxies the V3 service index and registration. Need to verify whether `packageBaseAddress` URLs in the service index point to upstream or to the proxy. If upstream, the flat-container downloads bypass scanning.

**Files to check:** `internal/adapter/nuget/nuget.go` — `handleServiceIndex` and `handleRegistration`.

---

## Task 1: Create helpers.sh — shared test utilities

**Files:**
- Create: `tests/e2e-shell/helpers.sh`

- [ ] **Step 1: Write helpers.sh**

```bash
#!/usr/bin/env bash
# helpers.sh — shared assertion and utility functions for e2e tests

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# E2E ports (must match docker-compose.e2e.yml)
export E2E_PYPI_PORT=15010
export E2E_NPM_PORT=14873
export E2E_NUGET_PORT=15001
export E2E_ADMIN_PORT=18080

export E2E_PYPI_URL="http://localhost:${E2E_PYPI_PORT}"
export E2E_NPM_URL="http://localhost:${E2E_NPM_PORT}"
export E2E_NUGET_URL="http://localhost:${E2E_NUGET_PORT}"
export E2E_ADMIN_URL="http://localhost:${E2E_ADMIN_PORT}"

log_info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC}  $*"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; TESTS_FAILED=$((TESTS_FAILED + 1)); }
log_skip()  { echo -e "${YELLOW}[SKIP]${NC}  $*"; TESTS_SKIPPED=$((TESTS_SKIPPED + 1)); }
log_section() { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

# assert_eq "description" "expected" "actual"
assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        log_pass "$desc"
    else
        log_fail "$desc (expected: '$expected', got: '$actual')"
    fi
}

# assert_contains "description" "needle" "haystack"
assert_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        log_pass "$desc"
    else
        log_fail "$desc (expected to contain: '$needle')"
    fi
}

# assert_gte "description" expected actual — actual >= expected (integers)
assert_gte() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$actual" -ge "$expected" ]]; then
        log_pass "$desc"
    else
        log_fail "$desc (expected >= $expected, got: $actual)"
    fi
}

# assert_http_status "description" expected_status url
assert_http_status() {
    local desc="$1" expected="$2" url="$3"
    local status
    status=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
    assert_eq "$desc" "$expected" "$status"
}

# api_get path — returns JSON body from Admin API
api_get() {
    curl -sf "${E2E_ADMIN_URL}/api/v1$1" 2>/dev/null || echo "{}"
}

# api_jq path jq_filter — returns jq-filtered value from Admin API
api_jq() {
    api_get "$1" | jq -r "$2" 2>/dev/null || echo ""
}

# docker_logs service_name — returns docker compose logs for a service
docker_logs() {
    docker compose -f "${COMPOSE_FILE}" logs "$1" 2>/dev/null
}

# wait_for_ready — polls health endpoint until ready or timeout
wait_for_ready() {
    local max_wait="${1:-120}"
    local elapsed=0
    log_info "Waiting for stack to be ready (max ${max_wait}s)..."
    while [[ $elapsed -lt $max_wait ]]; do
        if curl -sf "${E2E_ADMIN_URL}/api/v1/health" >/dev/null 2>&1; then
            log_info "Stack ready after ${elapsed}s"
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    log_fail "Stack not ready after ${max_wait}s"
    return 1
}

# print_summary — prints test results and exits with appropriate code
print_summary() {
    echo ""
    log_section "Test Summary"
    echo -e "  ${GREEN}Passed:${NC}  $TESTS_PASSED"
    echo -e "  ${RED}Failed:${NC}  $TESTS_FAILED"
    echo -e "  ${YELLOW}Skipped:${NC} $TESTS_SKIPPED"
    echo ""
    if [[ $TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}SOME TESTS FAILED${NC}"
        return 1
    else
        echo -e "${GREEN}ALL TESTS PASSED${NC}"
        return 0
    fi
}
```

---

## Task 2: Create e2e Docker Compose and config

**Files:**
- Create: `tests/e2e-shell/docker-compose.e2e.yml`
- Create: `tests/e2e-shell/config.e2e.yaml`

- [ ] **Step 1: Write docker-compose.e2e.yml**

Uses the same build context as dev but different host ports and separate named volumes (prefixed `e2e-`). Project name `shieldoo-e2e` ensures full isolation.

```yaml
name: shieldoo-e2e

services:
  shieldoo-gate:
    build:
      context: ../..
      dockerfile: docker/Dockerfile
    platform: linux/amd64
    depends_on:
      scanner-bridge:
        condition: service_started
    ports:
      - "15010:5000"
      - "14873:4873"
      - "15001:5001"
      - "15002:5002"
      - "18080:8080"
    volumes:
      - e2e-bridge-socket:/tmp
      - e2e-gate-data:/var/lib/shieldoo-gate
      - e2e-gate-cache:/var/cache/shieldoo-gate
      - e2e-trivy-cache:/var/cache/trivy
      - ./config.e2e.yaml:/etc/shieldoo-gate/config.yaml:ro
    environment:
      SGW_SCANNERS_GUARDDOG_BRIDGE_SOCKET: /tmp/shieldoo-bridge.sock
    restart: "no"

  scanner-bridge:
    build:
      context: ../../scanner-bridge
      dockerfile: Dockerfile
    platform: linux/amd64
    volumes:
      - e2e-bridge-socket:/tmp
    environment:
      BRIDGE_SOCKET: /tmp/shieldoo-bridge.sock
    restart: "no"

volumes:
  e2e-bridge-socket:
  e2e-gate-data:
  e2e-gate-cache:
  e2e-trivy-cache:
```

- [ ] **Step 2: Write config.e2e.yaml**

Same as dev config but with no allowlist entries (we want to test the full scan pipeline without bypasses) and threat feed disabled (avoids flaky TLS errors).

```yaml
server:
  host: "0.0.0.0"

ports:
  pypi: 5000
  npm: 4873
  nuget: 5001
  docker: 5002
  admin: 8080

upstreams:
  pypi: "https://pypi.org"
  npm: "https://registry.npmjs.org"
  nuget: "https://api.nuget.org"
  docker: "https://registry-1.docker.io"

cache:
  backend: "local"
  local:
    path: "/var/cache/shieldoo-gate"
    max_size_gb: 10
  ttl:
    pypi: "168h"
    npm: "168h"
    nuget: "168h"
    docker: "720h"

database:
  backend: "sqlite"
  sqlite:
    path: "/var/lib/shieldoo-gate/gate.db"

scanners:
  parallel: true
  timeout: "120s"
  guarddog:
    enabled: true
    bridge_socket: "/tmp/shieldoo-bridge.sock"
  trivy:
    enabled: true
    binary: "trivy"
    cache_dir: "/var/cache/trivy"
  osv:
    enabled: true
    api_url: "https://api.osv.dev"

policy:
  block_if_verdict: "MALICIOUS"
  quarantine_if_verdict: "SUSPICIOUS"
  minimum_confidence: 0.7
  allowlist: []

threat_feed:
  enabled: false

log:
  level: "debug"
  format: "json"
```

---

## Task 3: Create test fixtures — PyPI, npm, NuGet projects

**Files:**
- Create: `tests/e2e-shell/fixtures/pypi/requirements.txt`
- Create: `tests/e2e-shell/fixtures/npm/package.json`
- Create: `tests/e2e-shell/fixtures/npm/.npmrc`
- Create: `tests/e2e-shell/fixtures/nuget/E2ETest.csproj`
- Create: `tests/e2e-shell/fixtures/nuget/nuget.config`

- [ ] **Step 1: Write PyPI requirements.txt**

Three well-known packages with pinned versions:

```
six==1.17.0
idna==3.11
certifi==2026.2.25
```

(Using small, stable packages without heavy transitive deps to keep test fast.)

- [ ] **Step 2: Write npm package.json**

```json
{
  "name": "shieldoo-e2e-npm",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "is-odd": "3.0.1",
    "is-number": "7.0.0",
    "ms": "2.1.3"
  }
}
```

- [ ] **Step 3: Write npm .npmrc**

```
registry=http://localhost:14873/
```

- [ ] **Step 4: Write NuGet E2ETest.csproj**

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Dapper" Version="2.1.35" />
  </ItemGroup>
</Project>
```

- [ ] **Step 5: Write NuGet nuget.config**

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="shieldoo-e2e" value="http://localhost:15001/v3/index.json" />
  </packageSources>
</configuration>
```

---

## Task 4: Write test_pypi.sh

**Files:**
- Create: `tests/e2e-shell/test_pypi.sh`

- [ ] **Step 1: Write test_pypi.sh**

```bash
#!/usr/bin/env bash
# test_pypi.sh — PyPI proxy e2e tests

test_pypi() {
    log_section "PyPI Proxy Tests"

    local workdir
    workdir=$(mktemp -d)
    trap "rm -rf '$workdir'" RETURN

    # Copy fixture
    cp "${SCRIPT_DIR}/fixtures/pypi/requirements.txt" "$workdir/"

    # Test 1: Simple index is accessible
    assert_http_status "PyPI simple index returns 200" "200" \
        "${E2E_PYPI_URL}/simple/"

    # Test 2: Package page returns 200 and has rewritten URLs
    local pkg_page
    pkg_page=$(curl -sf "${E2E_PYPI_URL}/simple/six/" 2>/dev/null || echo "")
    assert_contains "PyPI package page contains download links" "six-" "$pkg_page"
    assert_contains "PyPI download URLs rewritten to /packages/" "/packages/" "$pkg_page"

    # Verify no upstream URLs leak through
    if echo "$pkg_page" | grep -q "files.pythonhosted.org"; then
        log_fail "PyPI package page still contains upstream URLs (URL rewriting broken)"
    else
        log_pass "PyPI package page URLs properly rewritten"
    fi

    # Test 3: Install packages via proxy
    log_info "Installing PyPI packages via proxy..."
    (
        cd "$workdir"
        uv venv .venv --quiet 2>/dev/null
        # shellcheck source=/dev/null
        source .venv/bin/activate
        if uv pip install --no-cache --index-url "${E2E_PYPI_URL}/simple/" \
            -r requirements.txt --quiet 2>/dev/null; then
            log_pass "PyPI install succeeded (3 packages)"
        else
            log_fail "PyPI install failed"
            return
        fi
        deactivate 2>/dev/null || true
    )

    # Test 4: Artifacts visible in API
    local pypi_count
    pypi_count=$(api_get "/artifacts" | jq '[.data[] | select(.ecosystem == "pypi")] | length')
    assert_gte "PyPI artifacts registered (>= 3)" 3 "$pypi_count"

    # Test 5: Audit log has SERVED events for pypi artifacts
    local served_count
    served_count=$(api_get "/audit" | jq '[.data[] | select(.event_type == "SERVED" and (.artifact_id | startswith("pypi:")))] | length')
    assert_gte "PyPI SERVED audit events (>= 3)" 3 "$served_count"

    # Test 6: Scan results exist for each artifact
    local artifacts
    artifacts=$(api_get "/artifacts" | jq -r '.data[] | select(.ecosystem == "pypi") | .name + ":" + .version')
    for art_key in $artifacts; do
        local art_id="pypi:${art_key}"
        local scan_count
        scan_count=$(api_get "/artifacts/$(jq -Rr @uri <<<"$art_id")/scan-results" \
            | jq 'if type == "array" then length else .data // [] | length end' 2>/dev/null || echo "0")
        if [[ "$scan_count" -gt 0 ]]; then
            log_pass "Scan results exist for $art_id ($scan_count scanners)"
        else
            log_fail "No scan results for $art_id"
        fi
    done

    # Test 7: Check gate logs for scan pipeline messages
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate)
    if echo "$gate_logs" | grep -q '"message":"starting scan pipeline".*pypi:'; then
        log_pass "Gate logs contain scan pipeline entries for PyPI"
    elif echo "$gate_logs" | grep -q '"message":"scan result"'; then
        log_pass "Gate logs contain scan result entries"
    else
        log_fail "Gate logs missing scan pipeline entries for PyPI"
    fi
}
```

---

## Task 5: Write test_npm.sh

**Files:**
- Create: `tests/e2e-shell/test_npm.sh`

- [ ] **Step 1: Write test_npm.sh**

```bash
#!/usr/bin/env bash
# test_npm.sh — npm proxy e2e tests

test_npm() {
    log_section "npm Proxy Tests"

    local workdir
    workdir=$(mktemp -d)
    trap "rm -rf '$workdir'" RETURN

    # Copy fixtures
    cp "${SCRIPT_DIR}/fixtures/npm/package.json" "$workdir/"
    cp "${SCRIPT_DIR}/fixtures/npm/.npmrc" "$workdir/"

    # Test 1: Package metadata is accessible
    local meta_status
    meta_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_NPM_URL}/is-odd" 2>/dev/null)
    assert_eq "npm package metadata returns 200" "200" "$meta_status"

    # Test 2: Install packages via proxy
    log_info "Installing npm packages via proxy..."
    (
        cd "$workdir"
        if npm install --registry "${E2E_NPM_URL}" --no-audit --no-fund \
            --loglevel=error 2>/dev/null; then
            log_pass "npm install succeeded (3 packages)"
        else
            log_fail "npm install failed"
            return
        fi
    )

    # Test 3: Artifacts visible in API
    local npm_count
    npm_count=$(api_get "/artifacts" | jq '[.data[] | select(.ecosystem == "npm")] | length')
    assert_gte "npm artifacts registered (>= 3)" 3 "$npm_count"

    # Test 4: Audit log has SERVED events
    local served_count
    served_count=$(api_get "/audit" | jq '[.data[] | select(.event_type == "SERVED" and (.artifact_id | startswith("npm:")))] | length')
    assert_gte "npm SERVED audit events (>= 3)" 3 "$served_count"

    # Test 5: Gate logs contain npm scan entries
    local gate_logs
    gate_logs=$(docker_logs shieldoo-gate)
    if echo "$gate_logs" | grep -q 'npm:'; then
        log_pass "Gate logs contain npm entries"
    else
        log_fail "Gate logs missing npm entries"
    fi
}
```

---

## Task 6: Write test_nuget.sh

**Files:**
- Create: `tests/e2e-shell/test_nuget.sh`

- [ ] **Step 1: Write test_nuget.sh**

```bash
#!/usr/bin/env bash
# test_nuget.sh — NuGet proxy e2e tests

test_nuget() {
    log_section "NuGet Proxy Tests"

    # Check if dotnet is available
    if ! command -v dotnet &>/dev/null; then
        log_skip "dotnet not found — skipping NuGet tests"
        return
    fi

    local workdir
    workdir=$(mktemp -d)
    trap "rm -rf '$workdir'" RETURN

    # Copy fixtures
    cp "${SCRIPT_DIR}/fixtures/nuget/E2ETest.csproj" "$workdir/"
    cp "${SCRIPT_DIR}/fixtures/nuget/nuget.config" "$workdir/"
    # Minimal Program.cs so dotnet restore works
    cat > "$workdir/Program.cs" << 'CSEOF'
class Program { static void Main() {} }
CSEOF

    # Test 1: Service index accessible
    assert_http_status "NuGet service index returns 200" "200" \
        "${E2E_NUGET_URL}/v3/index.json"

    # Test 2: Restore packages via proxy
    log_info "Restoring NuGet packages via proxy..."
    (
        cd "$workdir"
        if dotnet restore --no-cache --force 2>/dev/null; then
            log_pass "NuGet restore succeeded (2 packages)"
        else
            log_fail "NuGet restore failed"
            return
        fi
    )

    # Test 3: Artifacts visible in API
    local nuget_count
    nuget_count=$(api_get "/artifacts" | jq '[.data[] | select(.ecosystem == "nuget")] | length')
    assert_gte "NuGet artifacts registered (>= 2)" 2 "$nuget_count"

    # Test 4: Audit log has SERVED events
    local served_count
    served_count=$(api_get "/audit" | jq '[.data[] | select(.event_type == "SERVED" and (.artifact_id | startswith("nuget:")))] | length')
    assert_gte "NuGet SERVED audit events (>= 2)" 2 "$served_count"
}
```

---

## Task 7: Write test_api.sh — Admin API and dashboard stats

**Files:**
- Create: `tests/e2e-shell/test_api.sh`

- [ ] **Step 1: Write test_api.sh**

```bash
#!/usr/bin/env bash
# test_api.sh — Admin API and dashboard stats validation

test_api() {
    log_section "Admin API Tests"

    # Test 1: Health endpoint
    local health
    health=$(api_get "/health")
    assert_eq "Health status is ok" "ok" "$(echo "$health" | jq -r '.status')"

    # Test 2: Stats summary — totals match reality
    local stats
    stats=$(api_get "/stats/summary")

    local total_artifacts
    total_artifacts=$(echo "$stats" | jq '.total_artifacts')
    assert_gte "Stats: total_artifacts > 0" 1 "$total_artifacts"

    local total_served
    total_served=$(echo "$stats" | jq '.total_served')
    assert_gte "Stats: total_served > 0" 1 "$total_served"

    # Test 3: Stats by_period has 7 daily buckets
    local period_count
    period_count=$(echo "$stats" | jq '.by_period | keys | length')
    assert_eq "Stats: by_period has 7 days" "7" "$period_count"

    # Test 4: Today's bucket has served events
    local today
    today=$(date -u +%Y-%m-%d)
    local today_served
    today_served=$(echo "$stats" | jq --arg d "$today" '.by_period[$d].served // 0')
    assert_gte "Stats: today served > 0" 1 "$today_served"

    # Test 5: Stats total_artifacts matches actual artifact count
    local actual_count
    actual_count=$(api_get "/artifacts" | jq '.total')
    assert_eq "Stats total_artifacts matches /artifacts total" "$actual_count" "$total_artifacts"

    # Test 6: Audit log endpoint returns data
    local audit
    audit=$(api_get "/audit")
    local audit_count
    audit_count=$(echo "$audit" | jq '.data | length')
    assert_gte "Audit log has entries" 1 "$audit_count"

    # Test 7: Metrics endpoint returns prometheus format
    local metrics_status
    metrics_status=$(curl -s -o /dev/null -w "%{http_code}" "${E2E_ADMIN_URL}/metrics")
    assert_eq "Metrics endpoint returns 200" "200" "$metrics_status"

    local metrics_body
    metrics_body=$(curl -sf "${E2E_ADMIN_URL}/metrics" 2>/dev/null || echo "")
    assert_contains "Metrics contain Go runtime info" "go_goroutines" "$metrics_body"
}
```

---

## Task 8: Write run.sh — main orchestrator

**Files:**
- Create: `tests/e2e-shell/run.sh`

- [ ] **Step 1: Write run.sh**

```bash
#!/usr/bin/env bash
# run.sh — E2E shell test suite for Shieldoo Gate
#
# Usage: ./tests/e2e-shell/run.sh [--no-build] [--keep]
#   --no-build  Skip docker compose build (use existing images)
#   --keep      Don't tear down stack after tests (for debugging)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.e2e.yml"

export SCRIPT_DIR COMPOSE_FILE

# Parse args
NO_BUILD=false
KEEP_STACK=false
for arg in "$@"; do
    case "$arg" in
        --no-build) NO_BUILD=true ;;
        --keep)     KEEP_STACK=true ;;
    esac
done

# Source helpers and test files
source "${SCRIPT_DIR}/helpers.sh"
source "${SCRIPT_DIR}/test_pypi.sh"
source "${SCRIPT_DIR}/test_npm.sh"
source "${SCRIPT_DIR}/test_nuget.sh"
source "${SCRIPT_DIR}/test_api.sh"

# Check prerequisites
check_prereqs() {
    local missing=()
    for cmd in docker curl jq uv node npm; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "Missing required tools: ${missing[*]}"
        echo "Install them and retry."
        exit 1
    fi
    # docker compose plugin check
    if ! docker compose version &>/dev/null; then
        echo "docker compose plugin not available"
        exit 1
    fi
}

# Teardown: always clean up on exit (unless --keep)
cleanup() {
    if [[ "$KEEP_STACK" == "true" ]]; then
        log_info "Stack kept running (--keep). Tear down with:"
        log_info "  docker compose -f ${COMPOSE_FILE} down -v"
        return
    fi
    log_info "Tearing down e2e stack..."
    docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans 2>/dev/null || true
}

main() {
    log_section "Shieldoo Gate — E2E Shell Tests"
    check_prereqs

    # 1. Clean slate
    log_info "Cleaning previous e2e state..."
    docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans 2>/dev/null || true

    # 2. Build (unless --no-build)
    if [[ "$NO_BUILD" == "false" ]]; then
        log_info "Building images..."
        docker compose -f "${COMPOSE_FILE}" build --quiet 2>&1 || {
            log_fail "Docker build failed"
            exit 1
        }
    fi

    # 3. Start stack
    log_info "Starting e2e stack..."
    docker compose -f "${COMPOSE_FILE}" up -d 2>&1 || {
        log_fail "Docker compose up failed"
        exit 1
    }

    # Register cleanup trap
    trap cleanup EXIT

    # 4. Wait for health
    if ! wait_for_ready 120; then
        log_fail "Stack failed to start"
        docker compose -f "${COMPOSE_FILE}" logs 2>&1 | tail -50
        exit 1
    fi

    # 5. Run test suites
    test_pypi
    test_npm
    test_nuget
    test_api

    # 6. Summary
    print_summary
}

main "$@"
```

- [ ] **Step 2: Make run.sh executable**

```bash
chmod +x tests/e2e-shell/run.sh
```

---

## Task 9: Write README.md for the test suite

**Files:**
- Create: `tests/e2e-shell/README.md`

- [ ] **Step 1: Write README**

Brief doc explaining what the suite does, how to run it, and the `--no-build` / `--keep` flags.

---

## Task 10: Fix npm adapter URL rewriting

**Files:**
- Modify: `internal/adapter/npm/npm.go`
- Modify: `internal/adapter/npm/npm_test.go`

This is the same class of bug we fixed in the PyPI adapter. The npm metadata responses contain tarball URLs pointing to `https://registry.npmjs.org/...`. The npm client follows these URLs directly, bypassing the proxy.

- [ ] **Step 1: Add URL rewriting for npm metadata**

In `handlePackageMetadata` and `handleScopedMetadata`, replace `proxyUpstream` with a rewriting variant that replaces `https://registry.npmjs.org/` with a relative `/` prefix in the response body. This is simpler than PyPI because npm metadata is JSON, so we can do a string replacement on the `tarball` URL field.

The rewrite should replace the upstream URL prefix (from config) in any `"tarball":"https://registry.npmjs.org/..."` with `"tarball":"http://{request.Host}/..."`.

- [ ] **Step 2: Write test for URL rewriting**
- [ ] **Step 3: Verify npm test suite passes**

---

## Task 11: Verify NuGet adapter and fix if needed

**Files:**
- Check: `internal/adapter/nuget/nuget.go`

- [ ] **Step 1: Check if NuGet has the same URL bypass issue**

Verify what the service index and registration endpoints return. If package download URLs point to upstream (`api.nuget.org`), apply the same rewriting fix.

- [ ] **Step 2: Fix if needed, write test**

---

## Task 12: Run full test suite and fix any failures

- [ ] **Step 1: Run `./tests/e2e-shell/run.sh` end to end**
- [ ] **Step 2: Fix any failing assertions**
- [ ] **Step 3: Run again to confirm all green**
- [ ] **Step 4: Commit**

```bash
git add tests/e2e-shell/
git commit -m "test(e2e): add shell-based e2e test suite with isolated Docker Compose"
```
