package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ScanRunStatus is the subset of /vulnerabilities/scan-runs/{id} we care about.
// Statuses come from internal/component/component.go:108-111 — only "done" and
// "failed" are terminal.
type ScanRunStatus struct {
	ID          int64  `json:"id"`
	Status      string `json:"status"` // pending|running|done|failed
	NewCritical int    `json:"new_critical_count"`
	NewHigh     int    `json:"new_high_count"`
}

func (s ScanRunStatus) terminal() bool {
	return s.Status == "done" || s.Status == "failed"
}

// pollUntilTerminal GETs /scan-runs/{id} every interval until the run reaches a
// terminal status or timeout fires. Returns the final status on success.
//
// Transient fetch errors (network blip, 5xx) do not abort polling — they are
// recorded as lastErr and the loop retries on the next tick. Only context
// timeout breaks the loop, surfacing the most recent error in the message so
// CI logs can distinguish "stuck running" from "API was unreachable".
func pollUntilTerminal(baseURL, token string, id int64, interval, timeout time.Duration) (ScanRunStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	url := strings.TrimRight(baseURL, "/") +
		fmt.Sprintf("/api/v1/vulnerabilities/scan-runs/%d", id)
	t := time.NewTicker(interval)
	defer t.Stop()
	c := &http.Client{Timeout: 30 * time.Second}
	var lastSt ScanRunStatus
	var lastErr error
	for {
		st, err := fetchStatus(ctx, c, url, token)
		if err == nil {
			lastSt = st
			lastErr = nil
			if st.terminal() {
				return st, nil
			}
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return lastSt, fmt.Errorf("timed out waiting for scan-run %d (last error: %v)", id, lastErr)
			}
			return lastSt, fmt.Errorf("timed out waiting for scan-run %d (last status=%s)", id, lastSt.Status)
		case <-t.C:
		}
	}
}

func fetchStatus(ctx context.Context, c *http.Client, url, token string) (ScanRunStatus, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	if err != nil {
		return ScanRunStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return ScanRunStatus{}, fmt.Errorf("GET %s: HTTP %d: %s", url, resp.StatusCode, string(body))
	}
	var st ScanRunStatus
	if err := json.NewDecoder(resp.Body).Decode(&st); err != nil {
		return ScanRunStatus{}, fmt.Errorf("decode status: %w", err)
	}
	return st, nil
}

// exitCodeFor maps (status, fail-on policy) to a CLI exit code.
//
//	0 — clean per policy
//	1 — done but new findings hit the fail-on threshold
//	3 — terminal but failed
//	4 — caller maps timeouts to 4 (see runScan)
func exitCodeFor(s ScanRunStatus, failOn string) int {
	if s.Status == "failed" {
		return 3
	}
	if s.Status != "done" {
		return 0 // shouldn't happen; non-terminal not passed in
	}
	switch failOn {
	case "none":
		return 0
	case "high":
		if s.NewCritical > 0 || s.NewHigh > 0 {
			return 1
		}
	case "critical":
		if s.NewCritical > 0 {
			return 1
		}
	}
	return 0
}
