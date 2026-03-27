package guarddog

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"

	pb "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

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
	// macOS limits Unix socket paths to ~104 chars; use /tmp with a short unique name.
	sockPath := fmt.Sprintf("/tmp/gdtest-%d.sock", os.Getpid())
	_ = os.Remove(sockPath) // clean up any leftover from a previous run
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
