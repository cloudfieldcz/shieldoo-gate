package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUploadSBOM_HappyPath_Returns202(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method %q want POST", r.Method)
		}
		if r.URL.Path != "/api/v1/projects/myproj/components/web/scans" {
			t.Errorf("path %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer t0k3n" {
			t.Errorf("missing Bearer header")
		}
		if r.Header.Get("Content-Type") != "application/vnd.cyclonedx+json" {
			t.Errorf("wrong content-type")
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "CycloneDX") {
			t.Errorf("body missing SBOM marker")
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"scan_run_id": 42, "component_id": 7})
	}))
	defer srv.Close()
	resp, err := uploadSBOM(srv.URL, "t0k3n", "myproj", "web", "multi",
		strings.NewReader(`{"bomFormat":"CycloneDX","components":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.ScanRunID != 42 {
		t.Errorf("got scan_run_id %d, want 42", resp.ScanRunID)
	}
}

func TestUploadSBOM_5xx_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := uploadSBOM(srv.URL, "t", "p", "c", "multi", strings.NewReader("{}")); err == nil {
		t.Errorf("expected error on 5xx")
	}
}

func TestUploadSBOM_BadRequest_PropagatesStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid"}`))
	}))
	defer srv.Close()
	_, err := uploadSBOM(srv.URL, "t", "p", "c", "multi", strings.NewReader("{}"))
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Errorf("expected 400 error, got %v", err)
	}
}

func TestUploadSBOM_RateLimited_RetriesUntilAccepted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"scan_run_id": 1, "component_id": 1})
	}))
	defer srv.Close()
	start := time.Now()
	resp, err := uploadSBOM(srv.URL, "t", "p", "c", "multi",
		strings.NewReader(`{"bomFormat":"CycloneDX"}`))
	if err != nil {
		t.Fatalf("expected eventual success, got %v", err)
	}
	if resp.ScanRunID != 1 {
		t.Errorf("scan_run_id=%d", resp.ScanRunID)
	}
	if calls.Load() != 3 {
		t.Errorf("expected 3 attempts (2 retries), got %d", calls.Load())
	}
	if elapsed := time.Since(start); elapsed < 2*time.Second {
		t.Errorf("expected at least 2s of backoff, elapsed=%v", elapsed)
	}
}

func TestUploadSBOM_RateLimited_GivesUpAfterMaxRetries(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
	}))
	defer srv.Close()
	_, err := uploadSBOM(srv.URL, "t", "p", "c", "multi", strings.NewReader("{}"))
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Errorf("expected 429 error after retry exhaustion, got %v", err)
	}
	// 1 initial attempt + uploadMaxRetries429 retries = 4 total calls.
	if got := calls.Load(); got != int32(uploadMaxRetries429+1) {
		t.Errorf("expected %d attempts, got %d", uploadMaxRetries429+1, got)
	}
}

func TestParseRetryAfter_HonoursIntegerHeader(t *testing.T) {
	if got := parseRetryAfter("3", 5*time.Second); got != 3*time.Second {
		t.Errorf("got %v, want 3s", got)
	}
}

func TestParseRetryAfter_FallsBackOnInvalid(t *testing.T) {
	if got := parseRetryAfter("Sun, 06 Nov 2026 08:49:37 GMT", 7*time.Second); got != 7*time.Second {
		t.Errorf("got %v, want fallback 7s", got)
	}
	if got := parseRetryAfter("", 7*time.Second); got != 7*time.Second {
		t.Errorf("got %v, want fallback 7s for empty header", got)
	}
}

func TestParseRetryAfter_ClampsRange(t *testing.T) {
	if got := parseRetryAfter("0", 5*time.Second); got != 1*time.Second {
		t.Errorf("got %v, want 1s (lower clamp)", got)
	}
	if got := parseRetryAfter("999", 5*time.Second); got != 60*time.Second {
		t.Errorf("got %v, want 60s (upper clamp)", got)
	}
}
