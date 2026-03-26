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

// compile-time interface check
var _ scanner.Scanner = (*OSVScanner)(nil)

// OSVScanner queries the OSV.dev HTTP API for known vulnerabilities.
type OSVScanner struct {
	apiURL  string
	client  *http.Client
}

// NewOSVScanner returns an OSVScanner that talks to apiURL (e.g. "https://api.osv.dev").
func NewOSVScanner(apiURL string, timeout time.Duration) *OSVScanner {
	return &OSVScanner{
		apiURL: apiURL,
		client: &http.Client{Timeout: timeout},
	}
}

func (s *OSVScanner) Name() string    { return "osv" }
func (s *OSVScanner) Version() string { return "1.0" }

// SupportedEcosystems returns the package ecosystems supported by the OSV API.
// Docker is excluded because OSV works on package identifiers, not container images.
func (s *OSVScanner) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{
		scanner.EcosystemPyPI,
		scanner.EcosystemNPM,
		scanner.EcosystemNuGet,
	}
}

// Scan queries the OSV API for vulnerabilities affecting the given artifact.
// On API errors the scanner fails open (VerdictClean) with the error in ScanResult.Error.
func (s *OSVScanner) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
	start := time.Now()

	req := osvRequest{
		Package: osvPackage{
			Name:      artifact.Name,
			Ecosystem: ecosystemName(artifact.Ecosystem),
		},
		Version: artifact.Version,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return scanner.ScanResult{
			Verdict:   scanner.VerdictClean,
			ScannerID: s.Name(),
			ScannedAt: time.Now(),
			Duration:  time.Since(start),
			Error:     fmt.Errorf("osv scanner: marshalling request for %s: %w", artifact.ID, err),
		}, nil
	}

	url := s.apiURL + "/v1/query"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return scanner.ScanResult{
			Verdict:   scanner.VerdictClean,
			ScannerID: s.Name(),
			ScannedAt: time.Now(),
			Duration:  time.Since(start),
			Error:     fmt.Errorf("osv scanner: building request for %s: %w", artifact.ID, err),
		}, nil
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return scanner.ScanResult{
			Verdict:   scanner.VerdictClean,
			ScannerID: s.Name(),
			ScannedAt: time.Now(),
			Duration:  time.Since(start),
			Error:     fmt.Errorf("osv scanner: querying API for %s: %w", artifact.ID, err),
		}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return scanner.ScanResult{
			Verdict:   scanner.VerdictClean,
			ScannerID: s.Name(),
			ScannedAt: time.Now(),
			Duration:  time.Since(start),
			Error:     fmt.Errorf("osv scanner: API returned status %d for %s", resp.StatusCode, artifact.ID),
		}, nil
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return scanner.ScanResult{
			Verdict:   scanner.VerdictClean,
			ScannerID: s.Name(),
			ScannedAt: time.Now(),
			Duration:  time.Since(start),
			Error:     fmt.Errorf("osv scanner: reading response for %s: %w", artifact.ID, err),
		}, nil
	}

	var osvResp osvResponse
	if err := json.Unmarshal(respBody, &osvResp); err != nil {
		return scanner.ScanResult{
			Verdict:   scanner.VerdictClean,
			ScannerID: s.Name(),
			ScannedAt: time.Now(),
			Duration:  time.Since(start),
			Error:     fmt.Errorf("osv scanner: parsing response for %s: %w", artifact.ID, err),
		}, nil
	}

	if len(osvResp.Vulns) == 0 {
		return scanner.ScanResult{
			Verdict:    scanner.VerdictClean,
			Confidence: 1.0,
			ScannerID:  s.Name(),
			ScannedAt:  time.Now(),
			Duration:   time.Since(start),
		}, nil
	}

	findings := make([]scanner.Finding, 0, len(osvResp.Vulns))
	for _, v := range osvResp.Vulns {
		findings = append(findings, scanner.Finding{
			Severity:    scanner.SeverityMedium,
			Category:    v.ID,
			Description: v.Summary,
		})
	}

	return scanner.ScanResult{
		Verdict:    scanner.VerdictSuspicious,
		Confidence: 0.85,
		Findings:   findings,
		ScannerID:  s.Name(),
		ScannedAt:  time.Now(),
		Duration:   time.Since(start),
	}, nil
}

// HealthCheck verifies the OSV API is reachable by making a minimal query.
func (s *OSVScanner) HealthCheck(ctx context.Context) error {
	req := osvRequest{
		Package: osvPackage{Name: "requests", Ecosystem: "PyPI"},
		Version: "99.99.99",
	}
	body, _ := json.Marshal(req)
	url := s.apiURL + "/v1/query"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("osv scanner: health check request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("osv scanner: health check: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("osv scanner: health check returned status %d", resp.StatusCode)
	}
	return nil
}

// --- API types ---

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

// ecosystemName maps internal Ecosystem constants to the names expected by the OSV API.
func ecosystemName(eco scanner.Ecosystem) string {
	switch eco {
	case scanner.EcosystemPyPI:
		return "PyPI"
	case scanner.EcosystemNPM:
		return "npm"
	case scanner.EcosystemNuGet:
		return "NuGet"
	default:
		return string(eco)
	}
}
