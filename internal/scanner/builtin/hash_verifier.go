package builtin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface compliance check.
var _ scanner.Scanner = (*HashVerifier)(nil)

// HashVerifier computes the SHA256 digest of an artifact file and compares it
// against the expected hash stored in Artifact.SHA256.
type HashVerifier struct{}

// NewHashVerifier creates a new HashVerifier.
func NewHashVerifier() *HashVerifier {
	return &HashVerifier{}
}

func (h *HashVerifier) Name() string    { return "hash-verifier" }
func (h *HashVerifier) Version() string { return "1.0.0" }

func (h *HashVerifier) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{
		scanner.EcosystemPyPI,
		scanner.EcosystemNPM,
		scanner.EcosystemDocker,
		scanner.EcosystemNuGet,
	}
}

func (h *HashVerifier) HealthCheck(_ context.Context) error { return nil }

// Scan computes the SHA256 of the artifact file and compares it to
// artifact.SHA256. If the expected hash is empty the scan is inconclusive but
// returns VerdictClean with reduced confidence (0.5). A mismatch returns
// VerdictMalicious.
func (h *HashVerifier) Scan(_ context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	start := time.Now()

	// No expected hash — nothing to verify.
	if strings.TrimSpace(artifact.SHA256) == "" {
		return scanner.ScanResult{
			Verdict:    scanner.VerdictClean,
			Confidence: 0.5,
			ScannerID:  h.Name(),
			Duration:   time.Since(start),
			ScannedAt:  start,
		}, nil
	}

	actual, err := computeSHA256(artifact.LocalPath)
	if err != nil {
		return scanner.ScanResult{
			Verdict:   scanner.VerdictClean,
			ScannerID: h.Name(),
			Duration:  time.Since(start),
			ScannedAt: start,
			Error:     fmt.Errorf("hash-verifier: compute sha256 for %s: %w", artifact.LocalPath, err),
		}, nil
	}

	expected := strings.ToLower(strings.TrimSpace(artifact.SHA256))
	if actual != expected {
		finding := scanner.Finding{
			Severity:    scanner.SeverityCritical,
			Category:    "hash-mismatch",
			Description: "SHA256 digest does not match expected value",
			Location:    artifact.LocalPath,
			IoCs: []string{
				fmt.Sprintf("expected=%s", expected),
				fmt.Sprintf("actual=%s", actual),
			},
		}
		return buildResult(h.Name(), start, scanner.VerdictMalicious, 1.0, []scanner.Finding{finding}), nil
	}

	return buildResult(h.Name(), start, scanner.VerdictClean, 1.0, nil), nil
}

// computeSHA256 streams the file at path and returns its lower-cased hex SHA256 digest.
func computeSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
