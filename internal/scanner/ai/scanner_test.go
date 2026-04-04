package ai

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	pb "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

type mockAIBridgeServer struct {
	pb.UnimplementedScannerBridgeServer
	aiScanFn func(*pb.AIScanRequest) *pb.AIScanResponse
	healthFn func() *pb.HealthResponse
}

func (s *mockAIBridgeServer) ScanArtifactAI(_ context.Context, req *pb.AIScanRequest) (*pb.AIScanResponse, error) {
	return s.aiScanFn(req), nil
}

func (s *mockAIBridgeServer) HealthCheck(_ context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	return s.healthFn(), nil
}

func startMockAIBridge(t *testing.T, server *mockAIBridgeServer) string {
	t.Helper()
	sockPath := fmt.Sprintf("/tmp/aitest-%d.sock", os.Getpid())
	_ = os.Remove(sockPath)
	lis, err := net.Listen("unix", sockPath)
	require.NoError(t, err)

	grpcServer := grpc.NewServer()
	pb.RegisterScannerBridgeServer(grpcServer, server)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = os.Remove(sockPath)
	})

	return sockPath
}

func TestAIScanner_InterfaceCompliance(t *testing.T) {
	var _ scanner.Scanner = (*AIScanner)(nil)
}

func TestAIScanner_Name(t *testing.T) {
	s := &AIScanner{}
	assert.Equal(t, "ai-scanner", s.Name())
}

func TestAIScanner_Version(t *testing.T) {
	s := &AIScanner{}
	assert.Equal(t, "1.0.0", s.Version())
}

func TestAIScanner_SupportedEcosystems(t *testing.T) {
	s := &AIScanner{}
	eco := s.SupportedEcosystems()
	assert.Contains(t, eco, scanner.EcosystemPyPI)
	assert.Contains(t, eco, scanner.EcosystemNPM)
	assert.Contains(t, eco, scanner.EcosystemNuGet)
	assert.Contains(t, eco, scanner.EcosystemMaven)
	assert.Contains(t, eco, scanner.EcosystemRubyGems)
	assert.NotContains(t, eco, scanner.EcosystemDocker)
	assert.NotContains(t, eco, scanner.EcosystemGo)
}

func TestAIScanner_CleanArtifact_ReturnsClean(t *testing.T) {
	sock := startMockAIBridge(t, &mockAIBridgeServer{
		aiScanFn: func(req *pb.AIScanRequest) *pb.AIScanResponse {
			assert.Equal(t, "pypi", req.Ecosystem)
			assert.Equal(t, "safe-pkg", req.Name)
			return &pb.AIScanResponse{
				Verdict:     "CLEAN",
				Confidence:  0.5,
				Explanation: "No install-time scripts found.",
				ModelUsed:   "gpt-5.4-mini",
				TokensUsed:  0,
			}
		},
		healthFn: func() *pb.HealthResponse {
			return &pb.HealthResponse{Healthy: true, Version: "1.0.0"}
		},
	})

	s, err := NewAIScanner(AIConfig{Enabled: true, Socket: sock})
	require.NoError(t, err)
	defer s.Close()

	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "pypi:safe-pkg:1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "safe-pkg",
		Version:   "1.0.0",
		LocalPath: "/tmp/safe.whl",
		Filename:  "safe-pkg-1.0.0.whl",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
	assert.Equal(t, "ai-scanner", result.ScannerID)
}

func TestAIScanner_OriginalFilename_PassedInRequest(t *testing.T) {
	sock := startMockAIBridge(t, &mockAIBridgeServer{
		aiScanFn: func(req *pb.AIScanRequest) *pb.AIScanResponse {
			assert.Equal(t, "requests-2.32.3-py3-none-any.whl", req.OriginalFilename)
			return &pb.AIScanResponse{
				Verdict:    "CLEAN",
				Confidence: 0.9,
				ModelUsed:  "gpt-5.4-mini",
				TokensUsed: 100,
			}
		},
		healthFn: func() *pb.HealthResponse {
			return &pb.HealthResponse{Healthy: true, Version: "1.0.0"}
		},
	})

	s, err := NewAIScanner(AIConfig{Enabled: true, Socket: sock})
	require.NoError(t, err)
	defer s.Close()

	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "pypi:requests:2.32.3:requests-2.32.3-py3-none-any.whl",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "requests",
		Version:   "2.32.3",
		LocalPath: "/tmp/shieldoo-gate-pypi-12345.tmp",
		Filename:  "requests-2.32.3-py3-none-any.whl",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestAIScanner_MaliciousArtifact_ReturnsMalicious(t *testing.T) {
	sock := startMockAIBridge(t, &mockAIBridgeServer{
		aiScanFn: func(req *pb.AIScanRequest) *pb.AIScanResponse {
			return &pb.AIScanResponse{
				Verdict:     "MALICIOUS",
				Confidence:  0.99,
				Findings:    []string{".pth file with executable code", "double base64 decode + exec"},
				Explanation: "Malicious .pth file auto-executes credential stealing payload.",
				ModelUsed:   "gpt-5.4-mini",
				TokensUsed:  450,
			}
		},
		healthFn: func() *pb.HealthResponse {
			return &pb.HealthResponse{Healthy: true, Version: "1.0.0"}
		},
	})

	s, err := NewAIScanner(AIConfig{Enabled: true, Socket: sock})
	require.NoError(t, err)
	defer s.Close()

	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "pypi:evil-pkg:1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		Name:      "evil-pkg",
		Version:   "1.0.0",
		LocalPath: "/tmp/evil.whl",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictMalicious, result.Verdict)
	assert.InDelta(t, 0.99, result.Confidence, 0.01)
	assert.Len(t, result.Findings, 2)
	assert.Equal(t, ".pth file with executable code", result.Findings[0].Description)
	assert.Equal(t, scanner.SeverityCritical, result.Findings[0].Severity)
}

func TestAIScanner_SuspiciousArtifact_ReturnsSuspicious(t *testing.T) {
	sock := startMockAIBridge(t, &mockAIBridgeServer{
		aiScanFn: func(req *pb.AIScanRequest) *pb.AIScanResponse {
			return &pb.AIScanResponse{
				Verdict:     "SUSPICIOUS",
				Confidence:  0.7,
				Findings:    []string{"preinstall script runs external file"},
				Explanation: "Preinstall hook invokes external JS — unusual but possibly legitimate.",
				ModelUsed:   "gpt-5.4-mini",
				TokensUsed:  320,
			}
		},
		healthFn: func() *pb.HealthResponse {
			return &pb.HealthResponse{Healthy: true, Version: "1.0.0"}
		},
	})

	s, err := NewAIScanner(AIConfig{Enabled: true, Socket: sock})
	require.NoError(t, err)
	defer s.Close()

	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "npm:weird-pkg:2.0.0",
		Ecosystem: scanner.EcosystemNPM,
		Name:      "weird-pkg",
		Version:   "2.0.0",
		LocalPath: "/tmp/weird.tgz",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
	assert.Equal(t, scanner.SeverityMedium, result.Findings[0].Severity)
}

func TestAIScanner_UnknownVerdict_FailsOpen(t *testing.T) {
	sock := startMockAIBridge(t, &mockAIBridgeServer{
		aiScanFn: func(req *pb.AIScanRequest) *pb.AIScanResponse {
			return &pb.AIScanResponse{
				Verdict:     "UNKNOWN",
				Confidence:  0.0,
				Explanation: "ecosystem not supported",
				ModelUsed:   "none",
			}
		},
		healthFn: func() *pb.HealthResponse {
			return &pb.HealthResponse{Healthy: true, Version: "1.0.0"}
		},
	})

	s, err := NewAIScanner(AIConfig{Enabled: true, Socket: sock})
	require.NoError(t, err)
	defer s.Close()

	result, err := s.Scan(context.Background(), scanner.Artifact{
		ID:        "docker:nginx:latest",
		Ecosystem: scanner.EcosystemDocker,
		Name:      "nginx",
		Version:   "latest",
		LocalPath: "/tmp/nginx.tar",
	})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestAIScanner_HealthCheck_Healthy(t *testing.T) {
	sock := startMockAIBridge(t, &mockAIBridgeServer{
		aiScanFn: func(_ *pb.AIScanRequest) *pb.AIScanResponse {
			return &pb.AIScanResponse{Verdict: "CLEAN"}
		},
		healthFn: func() *pb.HealthResponse {
			return &pb.HealthResponse{Healthy: true, Version: "1.0.0"}
		},
	})

	s, err := NewAIScanner(AIConfig{Enabled: true, Socket: sock})
	require.NoError(t, err)
	defer s.Close()

	err = s.HealthCheck(context.Background())
	assert.NoError(t, err)
}

func TestMapVerdict(t *testing.T) {
	tests := []struct {
		input    string
		expected scanner.Verdict
	}{
		{"MALICIOUS", scanner.VerdictMalicious},
		{"SUSPICIOUS", scanner.VerdictSuspicious},
		{"CLEAN", scanner.VerdictClean},
		{"UNKNOWN", scanner.VerdictClean},
		{"", scanner.VerdictClean},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, mapVerdict(tt.input))
		})
	}
}

func TestSeverityFromVerdict(t *testing.T) {
	assert.Equal(t, scanner.SeverityCritical, severityFromVerdict("MALICIOUS", 0.99))
	assert.Equal(t, scanner.SeverityHigh, severityFromVerdict("MALICIOUS", 0.85))
	assert.Equal(t, scanner.SeverityMedium, severityFromVerdict("SUSPICIOUS", 0.7))
	assert.Equal(t, scanner.SeverityInfo, severityFromVerdict("CLEAN", 0.5))
}
