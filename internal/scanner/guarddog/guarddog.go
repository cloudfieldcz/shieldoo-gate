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

// compile-time interface check
var _ scanner.Scanner = (*GuardDogScanner)(nil)

// GuardDogScanner calls the Python GuardDog scanner bridge over gRPC.
type GuardDogScanner struct {
	conn   *grpc.ClientConn
	client pb.ScannerBridgeClient
}

// NewGuardDogScanner dials the scanner bridge Unix socket and returns a ready scanner.
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

// Close releases the underlying gRPC connection.
func (s *GuardDogScanner) Close() error {
	return s.conn.Close()
}

func (s *GuardDogScanner) Name() string    { return "guarddog" }
func (s *GuardDogScanner) Version() string { return "0.1.17" }

// SupportedEcosystems returns ecosystems understood by GuardDog (PyPI and npm only).
func (s *GuardDogScanner) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{scanner.EcosystemPyPI, scanner.EcosystemNPM}
}

// Scan forwards the artifact to the Python bridge and maps the response to a ScanResult.
// On transport/bridge error the scanner fails open (VerdictClean) and logs the error
// in the result — it never escalates to MALICIOUS on its own error.
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

// HealthCheck pings the bridge and returns an error if it reports unhealthy.
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
