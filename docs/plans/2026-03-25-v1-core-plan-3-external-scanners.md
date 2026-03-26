# Shieldoo Gate v1.0 Core — Phase 3: External Scanners (GuardDog, Trivy, OSV)

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate three external scanning tools — GuardDog (via Python gRPC bridge), Trivy (subprocess), and OSV (HTTP API) — each implementing the `Scanner` interface.

**Architecture:** GuardDog requires a Python sidecar process communicating via gRPC over Unix socket. Trivy runs as a subprocess with JSON output parsing. OSV is a pure HTTP client against `api.osv.dev`. All three follow fail-open design: errors return `VerdictClean` + logged error.

**Tech Stack:** Go 1.25+, gRPC (protobuf), Python 3.12+ (GuardDog bridge), `os/exec` (Trivy subprocess), `net/http` (OSV client), testify

**Index:** [`plan-index.md`](./2026-03-25-v1-core-plan-index.md)

---

### Task 1: gRPC Proto Definition + Code Generation

**Files:**
- Create: `scanner-bridge/proto/scanner.proto`
- Create: `internal/scanner/guarddog/proto/` (generated)
- Modify: `Makefile` (add `proto` target)

- [ ] **Step 1: Create proto file**

The proto is defined in `docs/initial-analyse.md` section 4.7.

```protobuf
// scanner-bridge/proto/scanner.proto
syntax = "proto3";
package scanner;

option go_package = "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto";

service ScannerBridge {
    rpc ScanArtifact(ScanRequest) returns (ScanResponse);
    rpc HealthCheck(HealthRequest) returns (HealthResponse);
}

message ScanRequest {
    string artifact_path = 1;
    string ecosystem = 2;
    string package_name = 3;
    string version = 4;
}

message ScanResponse {
    string verdict = 1;
    float confidence = 2;
    repeated Finding findings = 3;
    string scanner_version = 4;
    int64 duration_ms = 5;
}

message Finding {
    string severity = 1;
    string category = 2;
    string description = 3;
    string location = 4;
    repeated string iocs = 5;
}

message HealthRequest {}

message HealthResponse {
    bool healthy = 1;
    string version = 2;
}
```

- [ ] **Step 2: Add proto and gRPC dependencies**

```bash
go get google.golang.org/grpc@latest
go get google.golang.org/protobuf@latest
```

- [ ] **Step 3: Add `proto` target to Makefile**

Append to `Makefile`:

```makefile
proto:
	protoc --go_out=internal/scanner/guarddog/proto \
		--go_opt=paths=source_relative \
		--go-grpc_out=internal/scanner/guarddog/proto \
		--go-grpc_opt=paths=source_relative \
		-I scanner-bridge/proto \
		scanner-bridge/proto/scanner.proto
```

Note: The executor needs `protoc`, `protoc-gen-go`, and `protoc-gen-go-grpc` installed. If not available, the generated files can be committed directly.

- [ ] **Step 4: Generate Go code**

Run: `make proto`
Expected: Files created at `internal/scanner/guarddog/proto/scanner.pb.go` and `scanner_grpc.pb.go`.

If `protoc` is not available, create the generated files manually or install:
```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

- [ ] **Step 5: Commit**

```bash
git add scanner-bridge/proto/ internal/scanner/guarddog/proto/ Makefile go.mod go.sum
git commit -m "feat(scanner): add gRPC proto definition and generated Go code for scanner bridge"
```

---

### Task 2: GuardDog Go gRPC Client

**Files:**
- Create: `internal/scanner/guarddog/guarddog.go`
- Test: `internal/scanner/guarddog/guarddog_test.go`

- [ ] **Step 1: Write tests**

```go
// internal/scanner/guarddog/guarddog_test.go
package guarddog

import (
    "context"
    "net"
    "os"
    "path/filepath"
    "testing"

    pb "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto"
    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

// mockBridgeServer implements the gRPC ScannerBridge service for testing
type mockBridgeServer struct {
    pb.UnimplementedScannerBridgeServer
    scanFn   func(*pb.ScanRequest) *pb.ScanResponse
    healthFn func() *pb.HealthResponse
}

func (s *mockBridgeServer) ScanArtifact(_ context.Context, req *pb.ScanRequest) (*pb.ScanResponse, error) {
    return s.scanFn(req), nil
}

func (s *mockBridgeServer) HealthCheck(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
    return s.healthFn(), nil
}

func startMockBridge(t *testing.T, server *mockBridgeServer) string {
    t.Helper()
    sockPath := filepath.Join(t.TempDir(), "test.sock")
    lis, err := net.Listen("unix", sockPath)
    require.NoError(t, err)

    grpcServer := grpc.NewServer()
    pb.RegisterScannerBridgeServer(grpcServer, server)

    go func() {
        _ = grpcServer.Serve(lis)
    }()
    t.Cleanup(func() {
        grpcServer.Stop()
    })

    return sockPath
}

func TestGuardDogScanner_CleanArtifact_ReturnsClean(t *testing.T) {
    sock := startMockBridge(t, &mockBridgeServer{
        scanFn: func(req *pb.ScanRequest) *pb.ScanResponse {
            return &pb.ScanResponse{
                Verdict:        "CLEAN",
                Confidence:     1.0,
                ScannerVersion: "0.1.17",
                DurationMs:     100,
            }
        },
        healthFn: func() *pb.HealthResponse {
            return &pb.HealthResponse{Healthy: true, Version: "0.1.17"}
        },
    })

    s, err := NewGuardDogScanner(sock)
    require.NoError(t, err)
    defer s.Close()

    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        LocalPath: "/tmp/test.whl",
        Name:      "test-pkg",
        Version:   "1.0.0",
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestGuardDogScanner_MaliciousArtifact_ReturnsMalicious(t *testing.T) {
    sock := startMockBridge(t, &mockBridgeServer{
        scanFn: func(req *pb.ScanRequest) *pb.ScanResponse {
            return &pb.ScanResponse{
                Verdict:    "MALICIOUS",
                Confidence: 0.95,
                Findings: []*pb.Finding{{
                    Severity:    "CRITICAL",
                    Category:    "exfiltration",
                    Description: "Package exfiltrates SSH keys",
                    Iocs:        []string{"models.litellm.cloud"},
                }},
                ScannerVersion: "0.1.17",
                DurationMs:     200,
            }
        },
        healthFn: func() *pb.HealthResponse {
            return &pb.HealthResponse{Healthy: true, Version: "0.1.17"}
        },
    })

    s, err := NewGuardDogScanner(sock)
    require.NoError(t, err)
    defer s.Close()

    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        LocalPath: "/tmp/evil.whl",
        Name:      "evil-pkg",
        Version:   "1.0.0",
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictMalicious, result.Verdict)
    assert.NotEmpty(t, result.Findings)
}

func TestGuardDogScanner_SupportedEcosystems(t *testing.T) {
    // Cannot create without a running bridge, test the static method
    eco := (&GuardDogScanner{}).SupportedEcosystems()
    assert.Contains(t, eco, scanner.EcosystemPyPI)
    assert.Contains(t, eco, scanner.EcosystemNPM)
    assert.NotContains(t, eco, scanner.EcosystemDocker)
}

func TestGuardDogScanner_HealthCheck_Healthy(t *testing.T) {
    sock := startMockBridge(t, &mockBridgeServer{
        scanFn: func(_ *pb.ScanRequest) *pb.ScanResponse {
            return &pb.ScanResponse{Verdict: "CLEAN"}
        },
        healthFn: func() *pb.HealthResponse {
            return &pb.HealthResponse{Healthy: true, Version: "0.1.17"}
        },
    })

    s, err := NewGuardDogScanner(sock)
    require.NoError(t, err)
    defer s.Close()

    err = s.HealthCheck(context.Background())
    assert.NoError(t, err)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/guarddog/ -v`
Expected: FAIL — `NewGuardDogScanner` not defined.

- [ ] **Step 3: Implement GuardDog scanner**

```go
// internal/scanner/guarddog/guarddog.go
package guarddog

import (
    "context"
    "fmt"
    "time"

    pb "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto"
    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

type GuardDogScanner struct {
    conn   *grpc.ClientConn
    client pb.ScannerBridgeClient
}

func NewGuardDogScanner(socketPath string) (*GuardDogScanner, error) {
    conn, err := grpc.NewClient(
        "unix://"+socketPath,
        grpc.WithTransportCredentials(insecure.NewCredentials()),
    )
    if err != nil {
        return nil, fmt.Errorf("guarddog: connecting to bridge at %s: %w", socketPath, err)
    }
    return &GuardDogScanner{
        conn:   conn,
        client: pb.NewScannerBridgeClient(conn),
    }, nil
}

func (s *GuardDogScanner) Close() error {
    return s.conn.Close()
}

func (s *GuardDogScanner) Name() string    { return "guarddog" }
func (s *GuardDogScanner) Version() string { return "0.1.17" }
func (s *GuardDogScanner) SupportedEcosystems() []scanner.Ecosystem {
    return []scanner.Ecosystem{scanner.EcosystemPyPI, scanner.EcosystemNPM}
}

func (s *GuardDogScanner) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
    resp, err := s.client.ScanArtifact(ctx, &pb.ScanRequest{
        ArtifactPath: artifact.LocalPath,
        Ecosystem:    string(artifact.Ecosystem),
        PackageName:  artifact.Name,
        Version:      artifact.Version,
    })
    if err != nil {
        return scanner.ScanResult{
            Verdict:   scanner.VerdictClean,
            ScannerID: s.Name(),
            Error:     fmt.Errorf("guarddog: scanning %s: %w", artifact.ID, err),
        }, nil
    }

    var findings []scanner.Finding
    for _, f := range resp.Findings {
        findings = append(findings, scanner.Finding{
            Severity:    scanner.Severity(f.Severity),
            Category:    f.Category,
            Description: f.Description,
            Location:    f.Location,
            IoCs:        f.Iocs,
        })
    }

    return scanner.ScanResult{
        Verdict:    scanner.Verdict(resp.Verdict),
        Confidence: resp.Confidence,
        Findings:   findings,
        ScannerID:  s.Name(),
        Duration:   time.Duration(resp.DurationMs) * time.Millisecond,
    }, nil
}

func (s *GuardDogScanner) HealthCheck(ctx context.Context) error {
    resp, err := s.client.HealthCheck(ctx, &pb.HealthRequest{})
    if err != nil {
        return fmt.Errorf("guarddog: health check: %w", err)
    }
    if !resp.Healthy {
        return fmt.Errorf("guarddog: bridge reports unhealthy")
    }
    return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scanner/guarddog/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/guarddog/guarddog.go internal/scanner/guarddog/guarddog_test.go
git commit -m "feat(scanner): add GuardDog gRPC client for Python scanner bridge"
```

---

### Task 3: Python Scanner Bridge (GuardDog gRPC Server)

**Files:**
- Create: `scanner-bridge/main.py`
- Create: `scanner-bridge/requirements.txt`
- Create: `scanner-bridge/Dockerfile`

- [ ] **Step 1: Create requirements.txt with pinned hashes**

```
# scanner-bridge/requirements.txt
# ALL dependencies pinned with == — NEVER use floating specifiers
guarddog==0.1.17
grpcio==1.62.0
grpcio-tools==1.62.0
protobuf==4.25.3
```

Note: Actual hash values (`--hash=sha256:...`) must be generated at implementation time using `pip hash`. The pinned versions above are placeholders — executor should run `pip download` and compute hashes.

- [ ] **Step 2: Create the gRPC server**

```python
# scanner-bridge/main.py
"""GuardDog scanner bridge — gRPC server for Shieldoo Gate."""

import logging
import os
import sys
import time
from concurrent import futures

import grpc

# Generated proto imports (generate with: python -m grpc_tools.protoc ...)
import proto.scanner_pb2 as scanner_pb2
import proto.scanner_pb2_grpc as scanner_pb2_grpc

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

GUARDDOG_VERSION = "0.1.17"


class ScannerBridgeServicer(scanner_pb2_grpc.ScannerBridgeServicer):
    def __init__(self):
        try:
            from guarddog import PypiPackageScanner, NpmPackageScanner
            self.pypi_scanner = PypiPackageScanner()
            self.npm_scanner = NpmPackageScanner()
            logger.info("GuardDog scanners initialized")
        except ImportError:
            logger.error("GuardDog not installed")
            raise

    def ScanArtifact(self, request, context):
        start = time.time()
        try:
            if request.ecosystem == "pypi":
                results = self.pypi_scanner.scan_local(request.artifact_path)
            elif request.ecosystem == "npm":
                results = self.npm_scanner.scan_local(request.artifact_path)
            else:
                return scanner_pb2.ScanResponse(
                    verdict="CLEAN",
                    confidence=1.0,
                    scanner_version=GUARDDOG_VERSION,
                    duration_ms=int((time.time() - start) * 1000),
                )

            findings = []
            verdict = "CLEAN"
            confidence = 1.0

            if results:
                for rule_name, matches in results.items():
                    severity = "HIGH"
                    findings.append(scanner_pb2.Finding(
                        severity=severity,
                        category=rule_name,
                        description=f"GuardDog rule {rule_name} matched",
                        location=request.artifact_path,
                    ))
                if findings:
                    verdict = "MALICIOUS"
                    confidence = 0.95

            duration_ms = int((time.time() - start) * 1000)
            return scanner_pb2.ScanResponse(
                verdict=verdict,
                confidence=confidence,
                findings=findings,
                scanner_version=GUARDDOG_VERSION,
                duration_ms=duration_ms,
            )

        except Exception as e:
            logger.error("Scan error: %s", e)
            duration_ms = int((time.time() - start) * 1000)
            return scanner_pb2.ScanResponse(
                verdict="CLEAN",
                confidence=0.0,
                scanner_version=GUARDDOG_VERSION,
                duration_ms=duration_ms,
            )

    def HealthCheck(self, request, context):
        return scanner_pb2.HealthResponse(
            healthy=True,
            version=GUARDDOG_VERSION,
        )


def serve():
    socket_path = os.environ.get("BRIDGE_SOCKET", "/tmp/shieldoo-bridge.sock")

    # Clean up stale socket
    if os.path.exists(socket_path):
        os.unlink(socket_path)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    scanner_pb2_grpc.add_ScannerBridgeServicer_to_server(
        ScannerBridgeServicer(), server
    )
    server.add_insecure_port(f"unix:{socket_path}")
    server.start()
    logger.info("Scanner bridge listening on %s", socket_path)
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
```

- [ ] **Step 3: Create Dockerfile**

```dockerfile
# scanner-bridge/Dockerfile
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY proto/ proto/
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. proto/scanner.proto

COPY main.py .

ENV BRIDGE_SOCKET=/tmp/shieldoo-bridge.sock

CMD ["python", "main.py"]
```

- [ ] **Step 4: Commit**

```bash
git add scanner-bridge/
git commit -m "feat(scanner): add Python GuardDog scanner bridge with gRPC server"
```

---

### Task 4: Trivy Subprocess Wrapper

**Files:**
- Create: `internal/scanner/trivy/trivy.go`
- Test: `internal/scanner/trivy/trivy_test.go`

Runs `trivy` binary as a subprocess, parses JSON output.

- [ ] **Step 1: Write tests**

```go
// internal/scanner/trivy/trivy_test.go
package trivy

import (
    "context"
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestTrivyScanner_ParseOutput_CleanResult(t *testing.T) {
    output := `{"Results":[]}`
    result := parseOutput([]byte(output))
    assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestTrivyScanner_ParseOutput_WithVulnerabilities(t *testing.T) {
    output := `{
        "Results": [{
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2024-1234",
                "Severity": "HIGH",
                "Title": "Test vulnerability",
                "PkgName": "test-pkg"
            }]
        }]
    }`
    result := parseOutput([]byte(output))
    assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
    assert.Len(t, result.Findings, 1)
    assert.Equal(t, "CVE-2024-1234", result.Findings[0].Category)
}

func TestTrivyScanner_ParseOutput_CriticalVuln(t *testing.T) {
    output := `{
        "Results": [{
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2024-9999",
                "Severity": "CRITICAL",
                "Title": "Critical RCE",
                "PkgName": "evil"
            }]
        }]
    }`
    result := parseOutput([]byte(output))
    assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
    assert.Equal(t, scanner.SeverityCritical, result.Findings[0].Severity)
}

func TestTrivyScanner_SupportedEcosystems(t *testing.T) {
    s := &TrivyScanner{}
    eco := s.SupportedEcosystems()
    assert.Contains(t, eco, scanner.EcosystemDocker)
    assert.Contains(t, eco, scanner.EcosystemPyPI)
    assert.Contains(t, eco, scanner.EcosystemNPM)
    assert.Contains(t, eco, scanner.EcosystemNuGet)
}

func TestTrivyScanner_HealthCheck_BinaryNotFound(t *testing.T) {
    s := NewTrivyScanner("/nonexistent/trivy", t.TempDir(), 30*time.Second)
    err := s.HealthCheck(context.Background())
    assert.Error(t, err)
}

// Compile-time interface check
var _ scanner.Scanner = (*TrivyScanner)(nil)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/trivy/ -v`
Expected: FAIL

- [ ] **Step 3: Implement Trivy scanner**

```go
// internal/scanner/trivy/trivy.go
package trivy

import (
    "context"
    "encoding/json"
    "fmt"
    "os/exec"
    "time"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

type TrivyScanner struct {
    binaryPath string
    cacheDir   string
    timeout    time.Duration
}

func NewTrivyScanner(binaryPath, cacheDir string, timeout time.Duration) *TrivyScanner {
    return &TrivyScanner{
        binaryPath: binaryPath,
        cacheDir:   cacheDir,
        timeout:    timeout,
    }
}

func (s *TrivyScanner) Name() string    { return "trivy" }
func (s *TrivyScanner) Version() string { return "0.50.0" }
func (s *TrivyScanner) SupportedEcosystems() []scanner.Ecosystem {
    return []scanner.Ecosystem{scanner.EcosystemDocker, scanner.EcosystemPyPI, scanner.EcosystemNPM, scanner.EcosystemNuGet}
}

func (s *TrivyScanner) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
    scanCtx, cancel := context.WithTimeout(ctx, s.timeout)
    defer cancel()

    var args []string
    switch artifact.Ecosystem {
    case scanner.EcosystemDocker:
        args = []string{"image", "--input", artifact.LocalPath, "--format", "json", "--cache-dir", s.cacheDir}
    default:
        args = []string{"fs", artifact.LocalPath, "--format", "json", "--cache-dir", s.cacheDir}
    }

    cmd := exec.CommandContext(scanCtx, s.binaryPath, args...)
    output, err := cmd.Output()
    if err != nil {
        // Trivy exits non-zero when vulnerabilities are found — that's expected
        if exitErr, ok := err.(*exec.ExitError); ok && len(output) > 0 {
            _ = exitErr // expected behavior
        } else {
            return scanner.ScanResult{
                Verdict:   scanner.VerdictClean,
                ScannerID: s.Name(),
                Error:     fmt.Errorf("trivy: executing scan on %s: %w", artifact.ID, err),
            }, nil
        }
    }

    result := parseOutput(output)
    result.ScannerID = s.Name()
    return result, nil
}

func (s *TrivyScanner) HealthCheck(ctx context.Context) error {
    cmd := exec.CommandContext(ctx, s.binaryPath, "version")
    if err := cmd.Run(); err != nil {
        return fmt.Errorf("trivy: health check failed: %w", err)
    }
    return nil
}

type trivyOutput struct {
    Results []trivyResult `json:"Results"`
}

type trivyResult struct {
    Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyVuln struct {
    VulnerabilityID string `json:"VulnerabilityID"`
    Severity        string `json:"Severity"`
    Title           string `json:"Title"`
    PkgName         string `json:"PkgName"`
}

func parseOutput(data []byte) scanner.ScanResult {
    var out trivyOutput
    if err := json.Unmarshal(data, &out); err != nil {
        return scanner.ScanResult{Verdict: scanner.VerdictClean, Error: err}
    }

    var findings []scanner.Finding
    for _, r := range out.Results {
        for _, v := range r.Vulnerabilities {
            findings = append(findings, scanner.Finding{
                Severity:    mapSeverity(v.Severity),
                Category:    v.VulnerabilityID,
                Description: v.Title,
                Location:    v.PkgName,
            })
        }
    }

    if len(findings) == 0 {
        return scanner.ScanResult{Verdict: scanner.VerdictClean, Confidence: 1.0}
    }

    return scanner.ScanResult{
        Verdict:    scanner.VerdictSuspicious,
        Confidence: 0.9,
        Findings:   findings,
    }
}

func mapSeverity(s string) scanner.Severity {
    switch s {
    case "CRITICAL":
        return scanner.SeverityCritical
    case "HIGH":
        return scanner.SeverityHigh
    case "MEDIUM":
        return scanner.SeverityMedium
    case "LOW":
        return scanner.SeverityLow
    default:
        return scanner.SeverityInfo
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scanner/trivy/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/trivy/
git commit -m "feat(scanner): add Trivy subprocess wrapper with JSON output parsing"
```

---

### Task 5: OSV API Client

**Files:**
- Create: `internal/scanner/osv/osv.go`
- Test: `internal/scanner/osv/osv_test.go`

HTTP client for `api.osv.dev` — queries known vulnerabilities by package name and version.

- [ ] **Step 1: Write tests**

```go
// internal/scanner/osv/osv_test.go
package osv

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestOSVScanner_KnownVulnerability_ReturnsSuspicious(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        resp := osvResponse{
            Vulns: []osvVuln{{
                ID:       "GHSA-1234-5678",
                Summary:  "Test vulnerability",
                Severity: []osvSeverity{{Type: "CVSS_V3", Score: "7.5"}},
            }},
        }
        json.NewEncoder(w).Encode(resp)
    }))
    defer server.Close()

    s := NewOSVScanner(server.URL, 30*time.Second)
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        Name:      "vulnerable-pkg",
        Version:   "1.0.0",
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
    assert.Len(t, result.Findings, 1)
}

func TestOSVScanner_NoVulnerabilities_ReturnsClean(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        json.NewEncoder(w).Encode(osvResponse{Vulns: nil})
    }))
    defer server.Close()

    s := NewOSVScanner(server.URL, 30*time.Second)
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemNPM,
        Name:      "clean-pkg",
        Version:   "2.0.0",
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestOSVScanner_APIError_FailsOpen(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusInternalServerError)
    }))
    defer server.Close()

    s := NewOSVScanner(server.URL, 30*time.Second)
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        Name:      "any-pkg",
        Version:   "1.0.0",
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictClean, result.Verdict)
    assert.NotNil(t, result.Error)
}

func TestOSVScanner_SupportedEcosystems(t *testing.T) {
    s := NewOSVScanner("", 0)
    eco := s.SupportedEcosystems()
    assert.Contains(t, eco, scanner.EcosystemPyPI)
    assert.Contains(t, eco, scanner.EcosystemNPM)
    assert.Contains(t, eco, scanner.EcosystemNuGet)
    assert.NotContains(t, eco, scanner.EcosystemDocker)
}

// Compile-time interface check
var _ scanner.Scanner = (*OSVScanner)(nil)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/osv/ -v`
Expected: FAIL

- [ ] **Step 3: Implement OSV scanner**

```go
// internal/scanner/osv/osv.go
package osv

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

type OSVScanner struct {
    apiURL     string
    httpClient *http.Client
}

func NewOSVScanner(apiURL string, timeout time.Duration) *OSVScanner {
    return &OSVScanner{
        apiURL: apiURL,
        httpClient: &http.Client{
            Timeout: timeout,
        },
    }
}

func (s *OSVScanner) Name() string    { return "osv" }
func (s *OSVScanner) Version() string { return "1.0.0" }
func (s *OSVScanner) SupportedEcosystems() []scanner.Ecosystem {
    return []scanner.Ecosystem{scanner.EcosystemPyPI, scanner.EcosystemNPM, scanner.EcosystemNuGet}
}

func (s *OSVScanner) HealthCheck(ctx context.Context) error {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.apiURL, nil)
    if err != nil {
        return fmt.Errorf("osv: creating health request: %w", err)
    }
    resp, err := s.httpClient.Do(req)
    if err != nil {
        return fmt.Errorf("osv: health check: %w", err)
    }
    resp.Body.Close()
    return nil
}

func (s *OSVScanner) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
    ecosystem := mapEcosystem(artifact.Ecosystem)
    if ecosystem == "" {
        return scanner.ScanResult{Verdict: scanner.VerdictClean, ScannerID: s.Name()}, nil
    }

    reqBody := osvRequest{
        Package: osvPackage{
            Name:      artifact.Name,
            Ecosystem: ecosystem,
        },
        Version: artifact.Version,
    }

    body, err := json.Marshal(reqBody)
    if err != nil {
        return scanner.ScanResult{Verdict: scanner.VerdictClean, ScannerID: s.Name(), Error: err}, nil
    }

    req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.apiURL+"/v1/query", bytes.NewReader(body))
    if err != nil {
        return scanner.ScanResult{Verdict: scanner.VerdictClean, ScannerID: s.Name(), Error: err}, nil
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := s.httpClient.Do(req)
    if err != nil {
        return scanner.ScanResult{
            Verdict:   scanner.VerdictClean,
            ScannerID: s.Name(),
            Error:     fmt.Errorf("osv: querying %s:%s: %w", artifact.Name, artifact.Version, err),
        }, nil
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return scanner.ScanResult{
            Verdict:   scanner.VerdictClean,
            ScannerID: s.Name(),
            Error:     fmt.Errorf("osv: API returned status %d", resp.StatusCode),
        }, nil
    }

    respBody, err := io.ReadAll(resp.Body)
    if err != nil {
        return scanner.ScanResult{Verdict: scanner.VerdictClean, ScannerID: s.Name(), Error: err}, nil
    }

    var osvResp osvResponse
    if err := json.Unmarshal(respBody, &osvResp); err != nil {
        return scanner.ScanResult{Verdict: scanner.VerdictClean, ScannerID: s.Name(), Error: err}, nil
    }

    if len(osvResp.Vulns) == 0 {
        return scanner.ScanResult{
            Verdict:    scanner.VerdictClean,
            Confidence: 1.0,
            ScannerID:  s.Name(),
        }, nil
    }

    var findings []scanner.Finding
    for _, v := range osvResp.Vulns {
        findings = append(findings, scanner.Finding{
            Severity:    mapOSVSeverity(v.Severity),
            Category:    v.ID,
            Description: v.Summary,
        })
    }

    return scanner.ScanResult{
        Verdict:    scanner.VerdictSuspicious,
        Confidence: 0.85,
        Findings:   findings,
        ScannerID:  s.Name(),
    }, nil
}

type osvRequest struct {
    Package osvPackage `json:"package"`
    Version string     `json:"version"`
}

type osvPackage struct {
    Name      string `json:"name"`
    Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
    Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
    ID       string        `json:"id"`
    Summary  string        `json:"summary"`
    Severity []osvSeverity `json:"severity"`
}

type osvSeverity struct {
    Type  string `json:"type"`
    Score string `json:"score"`
}

func mapEcosystem(eco scanner.Ecosystem) string {
    switch eco {
    case scanner.EcosystemPyPI:
        return "PyPI"
    case scanner.EcosystemNPM:
        return "npm"
    case scanner.EcosystemNuGet:
        return "NuGet"
    default:
        return ""
    }
}

func mapOSVSeverity(severities []osvSeverity) scanner.Severity {
    if len(severities) == 0 {
        return scanner.SeverityMedium
    }
    // Simple heuristic based on CVSS score string
    return scanner.SeverityHigh
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scanner/osv/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/osv/
git commit -m "feat(scanner): add OSV API client for known vulnerability lookup"
```

---

### Task 6: Verify All Phase 3 Tests Pass

- [ ] **Step 1: Run all scanner tests**

Run: `go test ./internal/scanner/... -v -race`
Expected: All tests PASS.

- [ ] **Step 2: Run vet**

Run: `go vet ./internal/scanner/...`
Expected: No issues.
