package component

import "testing"

func TestValidateComponentName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"api", true},
		{"my-service", true},
		{"my.service", true},
		{"sub/dir/component", true},
		{"a", true},
		{"", false},
		{"-leading", false},
		{"trailing-", true},
		{"WithUpper", false},
		{"has space", false},
		{"has\x00nul", false},
		{"path/../traversal", false},
		{"control\x07char", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateComponentName(tt.name)
			if got != tt.want {
				t.Errorf("ValidateComponentName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestComputeDelta_NewCritical(t *testing.T) {
	prev := []*ScanFinding{
		{CVEID: "CVE-A", PackageName: "p1", Severity: SeverityHigh},
	}
	curr := []*ScanFinding{
		{CVEID: "CVE-A", PackageName: "p1", Severity: SeverityHigh},
		{CVEID: "CVE-B", PackageName: "p2", Severity: SeverityCritical},
		{CVEID: "CVE-C", PackageName: "p3", Severity: SeverityHigh},
	}
	d := ComputeDelta(curr, prev)
	if len(d.NewCritical) != 1 {
		t.Errorf("expected 1 new critical, got %d", len(d.NewCritical))
	}
	if len(d.NewHigh) != 1 {
		t.Errorf("expected 1 new high, got %d", len(d.NewHigh))
	}
}

func TestComputeDelta_Suppressed(t *testing.T) {
	curr := []*ScanFinding{
		{CVEID: "CVE-X", PackageName: "p", Severity: SeverityCritical, IsSuppressed: true},
	}
	d := ComputeDelta(curr, nil)
	if len(d.NewCritical) != 0 {
		t.Errorf("suppressed findings must not appear in delta, got %d", len(d.NewCritical))
	}
}
