package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UploadResponse mirrors the gate's 202 body.
type UploadResponse struct {
	ScanRunID   int64  `json:"scan_run_id"`
	ComponentID int64  `json:"component_id"`
	DetailURL   string `json:"detail_url"`
}

// uploadMaxRetries429 caps how many times uploadSBOM retries on HTTP 429.
// CI runs that share a token across many parallel jobs can briefly exhaust the
// gate's per-token bucket; retry-with-backoff lets shdg recover instead of
// failing the build.
const uploadMaxRetries429 = 3

// uploadSBOM POSTs sbom to /api/v1/projects/{label}/components/{name}/scans?ecosystem=...
// and returns the parsed 202 body. The body is buffered so the request can be
// retried on HTTP 429 (rate-limited); the gate's Retry-After header is honoured
// when present, otherwise a 5s default backoff is used. Any other non-2xx
// response is returned as an error containing the status code and (best-effort)
// body excerpt.
func uploadSBOM(baseURL, token, project, component, ecosystem string, sbom io.Reader) (*UploadResponse, error) {
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("baseURL must start with http(s)://: %q", baseURL)
	}
	u := strings.TrimRight(baseURL, "/") +
		fmt.Sprintf("/api/v1/projects/%s/components/%s/scans",
			url.PathEscape(project), url.PathEscape(component))
	if ecosystem != "" {
		u += "?ecosystem=" + url.QueryEscape(ecosystem)
	}
	// Buffer the body once so we can replay it across retries.
	bodyBytes, err := io.ReadAll(sbom)
	if err != nil {
		return nil, fmt.Errorf("read sbom: %w", err)
	}

	c := &http.Client{Timeout: 60 * time.Second}
	var lastStatus int
	var lastBody string
	for attempt := 0; attempt <= uploadMaxRetries429; attempt++ {
		req, err := http.NewRequest("POST", u, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/vnd.cyclonedx+json")
		resp, err := c.Do(req)
		if err != nil {
			return nil, err
		}
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			var out UploadResponse
			if err := json.Unmarshal(respBody, &out); err != nil {
				return nil, fmt.Errorf("decode response: %w (body=%s)", err, string(respBody))
			}
			return &out, nil
		}
		lastStatus = resp.StatusCode
		lastBody = strings.TrimSpace(string(respBody))
		if resp.StatusCode == http.StatusTooManyRequests && attempt < uploadMaxRetries429 {
			delay := parseRetryAfter(resp.Header.Get("Retry-After"), 5*time.Second)
			time.Sleep(delay)
			continue
		}
		break
	}
	return nil, fmt.Errorf("upload failed: HTTP %d: %s", lastStatus, lastBody)
}

// parseRetryAfter returns the duration encoded in the Retry-After header. The
// header may be either an integer second count (RFC 7231 §7.1.3) or an HTTP
// date; we only honour the integer form (the gate emits seconds). A negative,
// missing, or unparseable header falls back to fallback. The result is clamped
// to [1s, 60s] so a misbehaving server cannot block a CI run indefinitely or
// hot-loop the client.
func parseRetryAfter(header string, fallback time.Duration) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return clampRetryAfter(fallback)
	}
	if n, err := strconv.Atoi(header); err == nil {
		return clampRetryAfter(time.Duration(n) * time.Second)
	}
	return clampRetryAfter(fallback)
}

func clampRetryAfter(d time.Duration) time.Duration {
	const minDelay = 1 * time.Second
	const maxDelay = 60 * time.Second
	if d < minDelay {
		return minDelay
	}
	if d > maxDelay {
		return maxDelay
	}
	return d
}
