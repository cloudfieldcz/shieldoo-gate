package model

import (
	"testing"
	"time"
)

func TestPolicyOverride_Matches_ExactVersion(t *testing.T) {
	o := PolicyOverride{
		Ecosystem: "pypi", Name: "requests", Version: "2.32.3",
		Scope: ScopeVersion,
	}
	if !o.Matches("pypi", "requests", "2.32.3") {
		t.Error("expected match for exact version")
	}
	if o.Matches("pypi", "requests", "2.32.4") {
		t.Error("expected no match for different version")
	}
}

func TestPolicyOverride_Matches_PackageScope(t *testing.T) {
	o := PolicyOverride{
		Ecosystem: "pypi", Name: "requests", Version: "",
		Scope: ScopePackage,
	}
	if !o.Matches("pypi", "requests", "2.32.3") {
		t.Error("expected match for any version with package scope")
	}
	if !o.Matches("pypi", "requests", "3.0.0") {
		t.Error("expected match for any version with package scope")
	}
	if o.Matches("npm", "requests", "2.32.3") {
		t.Error("expected no match for different ecosystem")
	}
}

func TestPolicyOverride_Matches_Revoked(t *testing.T) {
	o := PolicyOverride{
		Ecosystem: "pypi", Name: "requests", Version: "2.32.3",
		Scope: ScopeVersion, Revoked: true,
	}
	if o.Matches("pypi", "requests", "2.32.3") {
		t.Error("expected no match for revoked override")
	}
}

func TestPolicyOverride_Matches_Expired(t *testing.T) {
	past := time.Now().UTC().Add(-1 * time.Hour)
	o := PolicyOverride{
		Ecosystem: "pypi", Name: "requests", Version: "2.32.3",
		Scope: ScopeVersion, ExpiresAt: &past,
	}
	if o.Matches("pypi", "requests", "2.32.3") {
		t.Error("expected no match for expired override")
	}
}

func TestPolicyOverride_Matches_NotExpired(t *testing.T) {
	future := time.Now().UTC().Add(24 * time.Hour)
	o := PolicyOverride{
		Ecosystem: "pypi", Name: "requests", Version: "2.32.3",
		Scope: ScopeVersion, ExpiresAt: &future,
	}
	if !o.Matches("pypi", "requests", "2.32.3") {
		t.Error("expected match for non-expired override")
	}
}
