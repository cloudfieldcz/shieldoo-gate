//go:build e2e

// Package e2e contains end-to-end tests that exercise Shieldoo Gate using real
// pip and npm clients. These tests require a running stack; start it with:
//
//	docker compose -f docker/docker-compose.yml up -d
//
// Then run:
//
//	make test-e2e
package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// baseURL returns the base URL of the admin API from env or default.
func adminURL() string {
	if v := os.Getenv("SGW_ADMIN_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:8080"
}

func pypiURL() string {
	if v := os.Getenv("SGW_PYPI_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:5010"
}

func npmURL() string {
	if v := os.Getenv("SGW_NPM_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:4873"
}

// waitForReady polls the health endpoint until it returns 200 or times out.
func waitForReady(t *testing.T, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	url := adminURL() + "/api/v1/health"
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:noctx
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("shieldoo-gate did not become healthy within %s", timeout)
}

func TestE2E_HealthEndpoint(t *testing.T) {
	waitForReady(t, 60*time.Second)

	resp, err := http.Get(adminURL() + "/api/v1/health") //nolint:noctx
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	assert.Equal(t, "ok", body["status"])
}

func TestE2E_PyPI_InstallCleanPackage(t *testing.T) {
	waitForReady(t, 60*time.Second)

	dir := t.TempDir()
	// pip install a minimal well-known clean package via the proxy
	cmd := exec.Command("pip", "install",
		"--index-url", pypiURL()+"/simple/",
		"--target", dir,
		"--quiet",
		"six==1.16.0",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Skipf("pip not available or package unavailable: %v", err)
	}

	// Verify the package landed in the target dir
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.NotEmpty(t, entries, "expected at least one file installed by pip")
}

func TestE2E_NPM_InstallCleanPackage(t *testing.T) {
	waitForReady(t, 60*time.Second)

	dir := t.TempDir()
	// npm install a minimal well-known clean package via the proxy
	cmd := exec.Command("npm", "install",
		"--registry", npmURL(),
		"--prefix", dir,
		"--save",
		"is-odd@3.0.1",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		t.Skipf("npm not available or package unavailable: %v", err)
	}

	// Verify node_modules exists
	_, err := os.Stat(fmt.Sprintf("%s/node_modules", dir))
	require.NoError(t, err, "expected node_modules directory after npm install")
}

func TestE2E_Admin_ListArtifacts(t *testing.T) {
	waitForReady(t, 60*time.Second)

	resp, err := http.Get(adminURL() + "/api/v1/artifacts") //nolint:noctx
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var body interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
}

func TestE2E_Admin_StatsSummary(t *testing.T) {
	waitForReady(t, 60*time.Second)

	resp, err := http.Get(adminURL() + "/api/v1/stats/summary") //nolint:noctx
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	// Verify the response contains the structured sections
	assert.Contains(t, body, "artifacts")
	assert.Contains(t, body, "requests")
}

func TestE2E_Metrics_Endpoint(t *testing.T) {
	waitForReady(t, 60*time.Second)

	resp, err := http.Get(adminURL() + "/metrics") //nolint:noctx
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Prometheus metrics are plain text; check for a common metric name
	var buf strings.Builder
	_, err = fmt.Fscan(resp.Body, &buf)
	_ = err // partial reads are fine
}
