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
		resp := osvResponse{Vulns: []osvVuln{{ID: "GHSA-1234-5678", Summary: "Test vulnerability", Severity: []osvSeverity{{Type: "CVSS_V3", Score: "7.5"}}}}}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	s := NewOSVScanner(server.URL, 30*time.Second)
	result, err := s.Scan(context.Background(), scanner.Artifact{Ecosystem: scanner.EcosystemPyPI, Name: "vulnerable-pkg", Version: "1.0.0"})
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
	result, err := s.Scan(context.Background(), scanner.Artifact{Ecosystem: scanner.EcosystemNPM, Name: "clean-pkg", Version: "2.0.0"})
	require.NoError(t, err)
	assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestOSVScanner_APIError_FailsOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	s := NewOSVScanner(server.URL, 30*time.Second)
	result, err := s.Scan(context.Background(), scanner.Artifact{Ecosystem: scanner.EcosystemPyPI, Name: "any-pkg", Version: "1.0.0"})
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

var _ scanner.Scanner = (*OSVScanner)(nil)
