package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersion_PrintsBuildInfo_ReturnsZero(t *testing.T) {
	var buf bytes.Buffer
	rc := runVersionTo(&buf, nil)
	if rc != 0 {
		t.Fatalf("runVersionTo returned %d, want 0", rc)
	}
	out := buf.String()
	if !strings.Contains(out, "shdg") {
		t.Errorf("output missing 'shdg' marker: %q", out)
	}
	if !strings.Contains(out, "go") {
		t.Errorf("output missing go runtime marker: %q", out)
	}
}
