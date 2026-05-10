package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunScan_WithSbomFlag_PostsToGate(t *testing.T) {
	tmp := t.TempDir()
	sbomPath := filepath.Join(tmp, "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	got := struct {
		called bool
		auth   string
		eco    string
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.called = true
		got.auth = r.Header.Get("Authorization")
		got.eco = r.URL.Query().Get("ecosystem")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"scan_run_id": 1, "component_id": 1})
	}))
	defer srv.Close()

	t.Setenv("SHIELDOO_URL", srv.URL)
	t.Setenv("SHIELDOO_TOKEN", "tok")

	rc := runScan([]string{
		"--project", "myproj",
		"--component", "web",
		"--sbom", sbomPath,
		"--ecosystem", "pypi",
	})
	if rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	if !got.called {
		t.Errorf("gate never called")
	}
	if got.auth != "Bearer tok" {
		t.Errorf("auth=%q", got.auth)
	}
	if got.eco != "pypi" {
		t.Errorf("ecosystem=%q", got.eco)
	}
}

func TestRunScan_NoToken_Returns2(t *testing.T) {
	t.Setenv("SHIELDOO_URL", "http://x")
	t.Setenv("SHIELDOO_TOKEN", "")
	rc := runScan([]string{"--project", "p", "--component", "c", "--sbom", "/dev/null"})
	if rc != 2 {
		t.Errorf("rc=%d, want 2", rc)
	}
}

func TestRunScan_MissingFlags_Returns2(t *testing.T) {
	rc := runScan([]string{"--project", "p"}) // missing --component
	if rc != 2 {
		t.Errorf("rc=%d, want 2", rc)
	}
}

func TestRunScan_AutoEcosystem_DetectsAndPasses(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sbomPath := filepath.Join(tmp, "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	gotEco := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEco = r.URL.Query().Get("ecosystem")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"scan_run_id":1,"component_id":1}`))
	}))
	defer srv.Close()
	t.Setenv("SHIELDOO_URL", srv.URL)
	t.Setenv("SHIELDOO_TOKEN", "x")
	rc := runScan([]string{
		"--project", "p", "--component", "c",
		"--sbom", sbomPath, "--dir", tmp, "--ecosystem", "auto",
	})
	if rc != 0 {
		t.Fatalf("rc=%d, output via go test -v", rc)
	}
	if gotEco != "go" {
		t.Errorf("ecosystem=%q, want go (from go.mod)", gotEco)
	}
}

func TestRunScan_Wait_TerminalFailing_ReturnsNonZero(t *testing.T) {
	tmp := t.TempDir()
	sbomPath := filepath.Join(tmp, "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/scans"):
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"scan_run_id":99,"component_id":1}`))
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/scan-runs/99"):
			_, _ = w.Write([]byte(`{"id":99,"status":"done","new_critical_count":3}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	t.Setenv("SHIELDOO_URL", srv.URL)
	t.Setenv("SHIELDOO_TOKEN", "tok")

	rc := runScan([]string{
		"--project", "p", "--component", "c",
		"--sbom", sbomPath, "--ecosystem", "multi",
		"--wait", "--fail-on", "critical",
		"--poll-interval", "10ms", "--timeout", "5s",
	})
	if rc != 1 {
		t.Errorf("rc=%d, want 1 (new_critical_count > 0)", rc)
	}
}

// CI safety guard: --fail-on without --wait would silently ignore vulns.
func TestRunScan_FailOnWithoutWait_Returns2(t *testing.T) {
	rc := runScan([]string{"--project", "p", "--component", "c", "--sbom", "/dev/null", "--fail-on", "critical"})
	if rc != 2 {
		t.Errorf("rc=%d, want 2", rc)
	}
}

func TestRunScan_FailOnInvalidValue_Returns2(t *testing.T) {
	rc := runScan([]string{"--project", "p", "--component", "c", "--sbom", "/dev/null", "--wait", "--fail-on", "blocker"})
	if rc != 2 {
		t.Errorf("rc=%d, want 2", rc)
	}
}

func TestRunScan_Wait_BadPollInterval_Returns2(t *testing.T) {
	tmp := t.TempDir()
	sbomPath := filepath.Join(tmp, "sbom.json")
	_ = os.WriteFile(sbomPath, []byte(`{}`), 0o644)
	t.Setenv("SHIELDOO_URL", "http://x")
	t.Setenv("SHIELDOO_TOKEN", "x")
	rc := runScan([]string{
		"--project", "p", "--component", "c",
		"--sbom", sbomPath, "--wait",
		"--poll-interval", "bogus",
	})
	if rc != 2 {
		t.Errorf("rc=%d, want 2", rc)
	}
}

// Polling timeout must surface as rc=4 (not rc=1) so CI distinguishes
// "scan never finished" from "scan finished with findings".
func TestRunScan_Wait_PollingTimeout_Returns4(t *testing.T) {
	tmp := t.TempDir()
	sbomPath := filepath.Join(tmp, "sbom.json")
	_ = os.WriteFile(sbomPath, []byte(`{}`), 0o644)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"scan_run_id":7,"component_id":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":7,"status":"running"}`))
	}))
	defer srv.Close()
	t.Setenv("SHIELDOO_URL", srv.URL)
	t.Setenv("SHIELDOO_TOKEN", "tok")
	rc := runScan([]string{
		"--project", "p", "--component", "c",
		"--sbom", sbomPath, "--wait",
		"--poll-interval", "10ms", "--timeout", "50ms",
	})
	if rc != 4 {
		t.Errorf("rc=%d, want 4", rc)
	}
}

// generateSBOM must surface trivy's silent-empty-output regression as a
// real error, not let it fall through to the gate as "422: empty body".
// Uses a fake "trivy" shell script that exits 0 without writing the output
// file, which mimics Trivy 0.70.0's `--output -` quirk.
func TestGenerateSBOM_EmptyOutput_ReturnsError(t *testing.T) {
	tmp := t.TempDir()
	fakeTrivy := filepath.Join(tmp, "trivy")
	if err := os.WriteFile(fakeTrivy, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := generateSBOM(fakeTrivy, tmp)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "empty SBOM") {
		t.Errorf("error = %q, want substring 'empty SBOM'", err.Error())
	}
}

func TestRunScan_Wait_Done_ReturnsZero_WhenFailOnNone(t *testing.T) {
	tmp := t.TempDir()
	sbomPath := filepath.Join(tmp, "sbom.json")
	_ = os.WriteFile(sbomPath, []byte(`{}`), 0o644)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"scan_run_id":1,"component_id":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":1,"status":"done","new_critical_count":99}`))
	}))
	defer srv.Close()
	t.Setenv("SHIELDOO_URL", srv.URL)
	t.Setenv("SHIELDOO_TOKEN", "tok")

	rc := runScan([]string{
		"--project", "p", "--component", "c",
		"--sbom", sbomPath, "--wait", "--fail-on", "none",
		"--poll-interval", "10ms", "--timeout", "5s",
	})
	if rc != 0 {
		t.Errorf("rc=%d, want 0 with fail-on=none", rc)
	}
}
