package api

import "testing"

func TestIsLicenseQuarantineReason_LicensePolicyPrefix_True(t *testing.T) {
	if !isLicenseQuarantineReason("license policy: GPL-3.0-only blocked") {
		t.Errorf("expected true for canonical 'license policy:' prefix")
	}
}

func TestIsLicenseQuarantineReason_TyposquatPrefix_False(t *testing.T) {
	if isLicenseQuarantineReason("typosquat: lodsah ~ lodash") {
		t.Errorf("expected false for typosquat reason")
	}
}

func TestIsLicenseQuarantineReason_MaliciousPrefix_False(t *testing.T) {
	if isLicenseQuarantineReason("scanner=guarddog verdict=MALICIOUS") {
		t.Errorf("expected false for scanner verdict")
	}
}

func TestIsLicenseQuarantineReason_CaseInsensitive_True(t *testing.T) {
	if !isLicenseQuarantineReason("LICENSE POLICY: AGPL-3.0") {
		t.Errorf("expected true for upper-case prefix")
	}
}

func TestIsLicenseQuarantineReason_Empty_False(t *testing.T) {
	if isLicenseQuarantineReason("") {
		t.Errorf("expected false for empty reason")
	}
}
