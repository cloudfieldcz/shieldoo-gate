# Vulnerability Scan — Final Polish — Phase 2: `shdg` `--wait` + `--fail-on`

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--wait`, `--fail-on critical|high|none`, and `--timeout <duration>` to `shdg scan` so CI gates can fail the build when a scan adds new criticals/highs. Without `--wait`, exit-code semantics stay identical to Phase 1 (returns 0 on 202).

**Architecture:** Polling loop against `GET /api/v1/vulnerabilities/scan-runs/{id}` with constant-interval back-off (default 2 s, configurable via `--poll-interval`). Terminal statuses per [`internal/component/component.go:108-111`](../../internal/component/component.go) are exactly `done` and `failed` — no `succeeded`/`cancelled` states exist. Exit-code policy:

| Status / count | Exit code |
|---|---|
| Run terminal `done`, fail-on=none | 0 |
| Run terminal `done`, fail-on=high, `new_high_count`>0 OR `new_critical_count`>0 | 1 |
| Run terminal `done`, fail-on=critical, `new_critical_count`>0 | 1 |
| Run terminal `failed` | 3 |
| Polling timed out | 4 |

**Tech Stack:** Same as Phase 1 — Go stdlib `net/http`, `time.Ticker`.

**Index:** [`plan-index.md`](./2026-05-08-vuln-scan-finish-plan-index.md)

**Depends on:** Phase 1.

---

## File map

| Path | Action | Responsibility |
|------|--------|----------------|
| `cmd/shdg/poll.go` | Create | Polling client + exit-code policy. |
| `cmd/shdg/poll_test.go` | Create | Unit tests against `httptest.Server`. |
| `cmd/shdg/scan.go` | Modify | When `--wait`, invoke poller after upload; map terminal+counts → rc. |
| `cmd/shdg/scan_test.go` | Modify | Add `--wait` integration tests. |

---

## Task 1: Polling client + exit-code policy

**Files:**
- Create: `cmd/shdg/poll.go`
- Create: `cmd/shdg/poll_test.go`

The poller's `Wait(scanRunID)` returns a `(ScanRunStatus, error)` where `ScanRunStatus` carries the terminal status string and `new_critical_count` / `new_high_count`. The exit-code mapping is computed by a separate `exitCodeFor(status, failOn)` so the test surface is small.

- [ ] **Step 1: Write the failing tests**

```go
package main

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestExitCodeFor_Done_NoCriticals_FailOnCritical_Returns0(t *testing.T) {
	st := ScanRunStatus{Status: "done", NewCritical: 0, NewHigh: 5}
	if got := exitCodeFor(st, "critical"); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestExitCodeFor_Done_HighOnly_FailOnHigh_Returns1(t *testing.T) {
	st := ScanRunStatus{Status: "done", NewHigh: 1}
	if got := exitCodeFor(st, "high"); got != 1 {
		t.Errorf("got %d, want 1", got)
	}
}

func TestExitCodeFor_Done_HighOnly_FailOnCritical_Returns0(t *testing.T) {
	st := ScanRunStatus{Status: "done", NewHigh: 5}
	if got := exitCodeFor(st, "critical"); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestExitCodeFor_Done_FailOnNone_Returns0(t *testing.T) {
	st := ScanRunStatus{Status: "done", NewCritical: 99}
	if got := exitCodeFor(st, "none"); got != 0 {
		t.Errorf("got %d, want 0", got)
	}
}

func TestExitCodeFor_TerminalFailed_Returns3(t *testing.T) {
	if got := exitCodeFor(ScanRunStatus{Status: "failed"}, "critical"); got != 3 {
		t.Errorf("got %d, want 3", got)
	}
}

func TestPollUntilTerminal_RunningThenDone(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			_, _ = w.Write([]byte(`{"id":1,"status":"running","new_critical_count":0,"new_high_count":0}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":1,"status":"done","new_critical_count":2,"new_high_count":1}`))
	}))
	defer srv.Close()

	st, err := pollUntilTerminal(srv.URL, "tok", 1, 50*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "done" {
		t.Errorf("status=%q", st.Status)
	}
	if st.NewCritical != 2 || st.NewHigh != 1 {
		t.Errorf("counts %d/%d", st.NewCritical, st.NewHigh)
	}
}

func TestPollUntilTerminal_TimesOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":1,"status":"running"}`))
	}))
	defer srv.Close()
	_, err := pollUntilTerminal(srv.URL, "tok", 1, 30*time.Millisecond, 100*time.Millisecond)
	if err == nil {
		t.Errorf("expected timeout error")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/shdg/ -run "ExitCodeFor|PollUntilTerminal" -v`
Expected: FAIL — symbols undefined.

- [ ] **Step 3: Implement `poll.go`**

```go
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
func pollUntilTerminal(baseURL, token string, id int64, interval, timeout time.Duration) (ScanRunStatus, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	url := strings.TrimRight(baseURL, "/") +
		fmt.Sprintf("/api/v1/vulnerabilities/scan-runs/%d", id)
	t := time.NewTicker(interval)
	defer t.Stop()
	c := &http.Client{Timeout: 30 * time.Second}
	for {
		st, err := fetchStatus(ctx, c, url, token)
		if err != nil {
			return ScanRunStatus{}, err
		}
		if st.terminal() {
			return st, nil
		}
		select {
		case <-ctx.Done():
			return st, fmt.Errorf("timed out waiting for scan-run %d (last status=%s)", id, st.Status)
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
//   0 — clean per policy
//   1 — done but new findings hit the fail-on threshold
//   3 — terminal but failed
//   4 — caller maps timeouts to 4 (see runScan)
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/shdg/ -run "ExitCodeFor|PollUntilTerminal" -v`
Expected: PASS for all 7 test cases.

- [ ] **Step 5: Commit**

```bash
git add cmd/shdg/poll.go cmd/shdg/poll_test.go
git commit -m "feat(shdg): polling client + fail-on critical|high|none exit policy"
```

---

## Task 2: Wire `--wait` into `runScan`

**Files:**
- Modify: `cmd/shdg/scan.go`

`scanOpts` already has `wait`, `failOn`, `timeout` from Phase 1 task 3. Add a `pollInterval` field and parse it. Then in `executeScan`, after `uploadSBOM` succeeds and we have `resp.ScanRunID`, branch:

- If `!opts.wait`: print response JSON and return nil (current behavior).
- If `opts.wait`: parse `--timeout` (`time.ParseDuration`), call `pollUntilTerminal`, then encode the final status to stdout, then `os.Exit(exitCodeFor(...))` so the rc reaches the shell.

Because `executeScan` returns `error` and `runScan` maps that to rc=1, we need a small refactor: `runScan` should consume both the error path and the wait-final-rc path. Easiest: `executeScan` returns `(int, error)` where the int is a final-status-driven rc (0 for non-wait happy path, possibly 1/3/4 for wait paths).

- [ ] **Step 1: Refactor `executeScan` signature**

Update `cmd/shdg/scan.go`:

```go
func runScan(args []string) int {
	opts, err := parseScanFlags(args, os.Stderr)
	if err != nil {
		return 2
	}
	rc, err := executeScan(opts, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shdg: %v\n", err)
		if rc != 0 {
			return rc
		}
		return 1
	}
	return rc
}

func executeScan(opts scanOpts, out, errW io.Writer) (int, error) {
	token := os.Getenv("SHIELDOO_TOKEN")
	if token == "" {
		return 2, fmt.Errorf("SHIELDOO_TOKEN env required")
	}
	baseURL := os.Getenv("SHIELDOO_URL")
	if baseURL == "" {
		return 2, fmt.Errorf("SHIELDOO_URL env required (e.g. https://gate.example.com)")
	}

	eco, err := resolveEcosystem(opts.ecosystem, opts.dir)
	if err != nil {
		return 2, err
	}

	var sbom io.Reader
	if opts.sbomPath != "" {
		f, err := os.Open(opts.sbomPath)
		if err != nil {
			return 1, fmt.Errorf("open --sbom: %w", err)
		}
		defer f.Close()
		sbom = f
	} else {
		bin, err := ensureTrivy(trivyVersion, defaultTrivyBaseURL)
		if err != nil {
			return 1, fmt.Errorf("ensure trivy: %w", err)
		}
		if opts.verbose {
			fmt.Fprintf(errW, "shdg: using trivy %s at %s\n", trivyVersion, bin)
		}
		raw, err := generateSBOM(bin, opts.dir)
		if err != nil {
			return 1, fmt.Errorf("generate sbom: %w", err)
		}
		sbom = bytes.NewReader(raw)
	}

	resp, err := uploadSBOM(baseURL, token, opts.project, opts.component, eco, sbom)
	if err != nil {
		return 1, err
	}

	if !opts.wait {
		return 0, json.NewEncoder(out).Encode(resp)
	}

	timeout, err := time.ParseDuration(opts.timeout)
	if err != nil {
		return 2, fmt.Errorf("invalid --timeout: %w", err)
	}
	interval := 2 * time.Second
	if opts.pollInterval != "" {
		if d, err := time.ParseDuration(opts.pollInterval); err == nil {
			interval = d
		}
	}
	st, err := pollUntilTerminal(baseURL, token, resp.ScanRunID, interval, timeout)
	if err != nil {
		_ = json.NewEncoder(out).Encode(map[string]any{"scan_run_id": resp.ScanRunID, "status": st.Status, "error": err.Error()})
		return 4, err
	}
	_ = json.NewEncoder(out).Encode(st)
	return exitCodeFor(st, opts.failOn), nil
}
```

Add `time` to the imports. Add the `pollInterval` field to `scanOpts` and the flag to `parseScanFlags`:

```go
fs.StringVar(&o.pollInterval, "poll-interval", "2s", "Poll interval when --wait is set")
```

(and add the field declaration to the struct.)

- [ ] **Step 2: Add a `--wait` integration test in `scan_test.go`**

```go
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
```

- [ ] **Step 3: Run tests**

Run: `go test ./cmd/shdg/ -run "RunScan_Wait" -v`
Expected: PASS.

- [ ] **Step 4: Run full suite**

```bash
go build ./... && go test ./cmd/shdg/... -v -race
```

Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/shdg/scan.go cmd/shdg/scan_test.go
git commit -m "feat(shdg): --wait + --fail-on critical|high|none for CI gating"
```

---

## Phase 2 verification

- [ ] **Step 1: Local smoke against running gate** (manual)

If a dev gate is running with vuln-scan enabled at `localhost:8080`:

```bash
SHIELDOO_TOKEN=$SUPERTOKEN \
SHIELDOO_URL=http://localhost:8080 \
bin/shdg scan \
  --project default --component shdg-smoke \
  --sbom tests/e2e-shell/fixtures/pypi/sbom-vulnerable.json \
  --wait --fail-on critical --poll-interval 1s --timeout 60s
```

Expected: prints final status JSON; exit code = number of new criticals > 0 ? 1 : 0.
