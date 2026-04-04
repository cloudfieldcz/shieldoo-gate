// Package ai implements an AI-based supply chain security scanner that uses
// LLM analysis (gpt-5.4-mini via Azure OpenAI) to detect malicious patterns
// in package install-time scripts.
//
// The scanner communicates with the Python scanner-bridge sidecar via gRPC,
// which handles file extraction and LLM API calls. It operates exclusively
// in synchronous mode and follows fail-open semantics on errors.
package ai

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	pb "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto"
)

// compile-time interface check
var _ scanner.Scanner = (*AIScanner)(nil)

// AIConfig holds configuration for the AI scanner.
type AIConfig struct {
	Enabled  bool
	Timeout  time.Duration
	Socket   string // path to scanner-bridge Unix socket
	Provider string // "openai" or "azure_openai"
	Model    string // e.g. "gpt-5.4-mini"
}

// AIScanner calls the Python scanner-bridge AI analysis over gRPC.
type AIScanner struct {
	client pb.ScannerBridgeClient
	config AIConfig
	closer func() error
}

// NewAIScanner dials the scanner bridge Unix socket and returns a ready scanner.
func NewAIScanner(cfg AIConfig) (*AIScanner, error) {
	client, closer, err := dialBridge(cfg.Socket)
	if err != nil {
		return nil, fmt.Errorf("ai scanner: connecting to bridge at %s: %w", cfg.Socket, err)
	}
	return &AIScanner{
		client: client,
		config: cfg,
		closer: closer,
	}, nil
}

// Close releases the underlying gRPC connection.
func (s *AIScanner) Close() error {
	if s.closer != nil {
		return s.closer()
	}
	return nil
}

func (s *AIScanner) Name() string    { return "ai-scanner" }
func (s *AIScanner) Version() string { return "1.0.0" }

// SupportedEcosystems returns all ecosystems the AI scanner can analyze.
// Docker and Go are excluded — Docker uses layer scanning, Go has no install hooks.
func (s *AIScanner) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{
		scanner.EcosystemPyPI,
		scanner.EcosystemNPM,
		scanner.EcosystemNuGet,
		scanner.EcosystemMaven,
		scanner.EcosystemRubyGems,
	}
}

// Scan sends the artifact to the Python bridge for AI analysis.
// On error (network, timeout, API failure), it retries up to 3 times with
// exponential backoff. After all retries it fails open: returns VerdictClean
// with confidence 0 and logs the error. It never escalates to MALICIOUS on its own error.
func (s *AIScanner) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	timeout := s.config.Timeout
	if timeout == 0 {
		timeout = 45 * time.Second
	}

	req := &pb.AIScanRequest{
		ArtifactId:       artifact.ID,
		Ecosystem:        string(artifact.Ecosystem),
		Name:             artifact.Name,
		Version:          artifact.Version,
		LocalPath:        artifact.LocalPath,
		OriginalFilename: artifact.Filename,
	}

	var resp *pb.AIScanResponse
	var err error
	backoff := 2 * time.Second

	for attempt := 0; attempt < 3; attempt++ {
		timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
		resp, err = s.client.ScanArtifactAI(timeoutCtx, req)
		cancel()

		if err == nil {
			break
		}

		log.Warn().Err(err).
			Str("artifact", artifact.ID).
			Int("attempt", attempt+1).
			Msg("ai scanner: bridge call failed, retrying")

		// Don't retry if parent context is done.
		select {
		case <-ctx.Done():
			break
		case <-time.After(backoff):
			backoff *= 2
		}
	}

	if err != nil {
		log.Warn().Err(err).
			Str("artifact", artifact.ID).
			Msg("ai scanner: all retries exhausted, failing open")
		return scanner.ScanResult{
			Verdict:    scanner.VerdictClean,
			Confidence: 0,
			ScannerID:  s.Name(),
			ScannedAt:  time.Now(),
			Error:      fmt.Errorf("ai scanner: %s: %w", artifact.ID, err),
		}, nil
	}

	result := scanner.ScanResult{
		Verdict:    mapVerdict(resp.Verdict),
		Confidence: resp.Confidence,
		ScannerID:  s.Name(),
		ScannedAt:  time.Now(),
	}

	for _, f := range resp.Findings {
		result.Findings = append(result.Findings, scanner.Finding{
			Severity:    severityFromVerdict(resp.Verdict, resp.Confidence),
			Category:    "ai-analysis",
			Description: f,
		})
	}

	log.Info().
		Str("artifact", artifact.ID).
		Str("verdict", resp.Verdict).
		Float32("confidence", resp.Confidence).
		Str("model", resp.ModelUsed).
		Int32("tokens", resp.TokensUsed).
		Msg("ai scanner: scan complete")

	return result, nil
}

// HealthCheck pings the bridge to verify the AI scanner is operational.
func (s *AIScanner) HealthCheck(ctx context.Context) error {
	resp, err := s.client.HealthCheck(ctx, &pb.HealthRequest{})
	if err != nil {
		return fmt.Errorf("ai scanner: health check: %w", err)
	}
	if !resp.Healthy {
		return fmt.Errorf("ai scanner: bridge reports unhealthy")
	}
	return nil
}

// mapVerdict converts the string verdict from the AI response to a scanner.Verdict.
func mapVerdict(v string) scanner.Verdict {
	switch v {
	case "MALICIOUS":
		return scanner.VerdictMalicious
	case "SUSPICIOUS":
		return scanner.VerdictSuspicious
	case "CLEAN":
		return scanner.VerdictClean
	default:
		// UNKNOWN or unexpected values → treat as clean (fail-open).
		return scanner.VerdictClean
	}
}

// severityFromVerdict maps the AI verdict and confidence to a Finding severity.
func severityFromVerdict(verdict string, confidence float32) scanner.Severity {
	switch verdict {
	case "MALICIOUS":
		if confidence >= 0.95 {
			return scanner.SeverityCritical
		}
		return scanner.SeverityHigh
	case "SUSPICIOUS":
		return scanner.SeverityMedium
	default:
		return scanner.SeverityInfo
	}
}
