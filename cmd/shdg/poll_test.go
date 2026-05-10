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
	if calls.Load() < 3 {
		t.Errorf("expected >=3 polls (2 running + 1 done), got %d", calls.Load())
	}
}

// Transient 5xx must NOT abort polling — the loop retries on the next tick.
func TestPollUntilTerminal_TransientErrorThenDone(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_, _ = w.Write([]byte(`{"id":1,"status":"done","new_critical_count":0,"new_high_count":0}`))
	}))
	defer srv.Close()
	st, err := pollUntilTerminal(srv.URL, "tok", 1, 20*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("expected retry to recover: %v", err)
	}
	if st.Status != "done" {
		t.Errorf("status=%q want done", st.Status)
	}
	if calls.Load() < 3 {
		t.Errorf("expected >=3 calls (2 transient + 1 success), got %d", calls.Load())
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
