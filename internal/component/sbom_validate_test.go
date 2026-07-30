package component

import (
	"errors"
	"strings"
	"testing"
)

// Phase 2: default SBOM limits must be generous enough for realistic
// `trivy image` SBOMs (1.5–5 MiB typical; >10 MiB on multi-language fat
// images). Pre-feature defaults rejected those with 413.
func TestDefaultSBOMLimits_HasImageScanHeadroom(t *testing.T) {
	l := DefaultSBOMLimits()
	const minBytes = int64(500 * 1024 * 1024)
	const minComponents = 500000
	if l.MaxBytes < minBytes {
		t.Errorf("MaxBytes = %d, want at least %d (image SBOMs need 500+ MiB headroom)", l.MaxBytes, minBytes)
	}
	if l.MaxComponents < minComponents {
		t.Errorf("MaxComponents = %d, want at least %d (image SBOMs need 500k+ headroom)", l.MaxComponents, minComponents)
	}
}

// Regression guard: an 11 MiB body must NOT be rejected by the default
// limits. The pre-feature 10 MiB cap rejected typical image SBOMs.
// We synthesise the body to be just over 11 MiB to keep the test fast.
func TestValidateSBOMStructure_11MiB_AcceptedByDefaults(t *testing.T) {
	// Build a valid CycloneDX with a single component and padding in a
	// string field so total size exceeds 11 MiB without inflating component
	// count.
	pad := strings.Repeat("x", 11*1024*1024)
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"description":"` + pad + `"},"components":[{"name":"foo","version":"1.0"}]}`)
	if int64(len(body)) < 11*1024*1024 {
		t.Fatalf("test body only %d bytes, expected > 11 MiB", len(body))
	}
	// MaxStringLength of 1024 in the default limits would otherwise reject
	// the padded description. Bypass it for this test by extending only
	// MaxStringLength; the focus here is MaxBytes.
	limits := DefaultSBOMLimits()
	limits.MaxStringLength = len(pad) + 1024
	_, err := ValidateSBOMStructure(body, limits)
	if err != nil {
		t.Fatalf("expected 11 MiB body to pass default size cap, got: %v", err)
	}
}

// licenseNameSBOM wraps a free-text license name in a minimal but
// spec-shaped CycloneDX document: components[] -> licenses[] -> license.name.
func licenseNameSBOM(name string) []byte {
	return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[` +
		`{"type":"library","name":"tiktoken","version":"0.12.0",` +
		`"licenses":[{"license":{"name":"` + name + `"}}]}]}`)
}

// Regression: `trivy image` writes the entire license body into
// `licenses[].license.name` for any package without a machine-readable SPDX
// identifier (tiktoken 0.12.0 yields 1077 chars of MIT text). That field is
// free-form per the CycloneDX spec, so the identifier cap must not apply to
// it — the pre-fix validator rejected every such image SBOM with 422.
func TestValidateSBOMStructure_FullLicenseTextInName_Accepted(t *testing.T) {
	name := "MIT License\\n\\nCopyright (c) 2022 OpenAI, Shantanu Jain\\n\\n" +
		strings.Repeat("Permission is hereby granted, free of charge, to any person obtaining a copy. ", 20)
	if len(name) <= DefaultSBOMLimits().MaxStringLength {
		t.Fatalf("test license text only %d chars, must exceed the %d-char identifier cap",
			len(name), DefaultSBOMLimits().MaxStringLength)
	}
	if _, err := ValidateSBOMStructure(licenseNameSBOM(name), DefaultSBOMLimits()); err != nil {
		t.Fatalf("expected free-text license name to pass, got: %v", err)
	}
}

// The prose allowance is scoped by parent key: `components[].name` is an
// identifier that lands in DB columns and OSV requests, so it stays capped at
// MaxStringLength even though `license.name` no longer is.
func TestValidateSBOMStructure_LongComponentName_StillRejected(t *testing.T) {
	huge := strings.Repeat("x", DefaultSBOMLimits().MaxStringLength+1)
	body := []byte(`{"bomFormat":"CycloneDX","components":[{"name":"` + huge + `","version":"1"}]}`)
	_, err := ValidateSBOMStructure(body, DefaultSBOMLimits())
	if !errors.Is(err, ErrInvalidSBOM) {
		t.Errorf("expected ErrInvalidSBOM for oversized component name, got %v", err)
	}
}

// Free text is bounded, not unbounded: MaxTextLength still fails closed.
func TestValidateSBOMStructure_LicenseNameOverTextLimit_Rejected(t *testing.T) {
	limits := DefaultSBOMLimits()
	limits.MaxTextLength = 2048
	name := strings.Repeat("y", limits.MaxTextLength+1)
	_, err := ValidateSBOMStructure(licenseNameSBOM(name), limits)
	if !errors.Is(err, ErrInvalidSBOM) {
		t.Errorf("expected ErrInvalidSBOM for license name over MaxTextLength, got %v", err)
	}
}

// A hand-built SBOMLimits (as several callers and tests do) leaves
// MaxTextLength at zero. That must fall back to the default prose cap rather
// than rejecting every non-empty free-text field.
func TestValidateSBOMStructure_ZeroMaxTextLength_FallsBackToDefault(t *testing.T) {
	limits := SBOMLimits{MaxBytes: 1 << 20, MaxComponents: 10, MaxDepth: 16, MaxStringLength: 1024}
	name := strings.Repeat("z", 4096)
	if _, err := ValidateSBOMStructure(licenseNameSBOM(name), limits); err != nil {
		t.Fatalf("expected zero MaxTextLength to fall back to the default cap, got: %v", err)
	}
}

// Free-text keys are only exempt where the CycloneDX spec says they are:
// `properties[].value` is prose, `properties[].name` is not.
func TestValidateSBOMStructure_PropertyValueProseVsName(t *testing.T) {
	long := strings.Repeat("p", DefaultSBOMLimits().MaxStringLength+1)
	okBody := []byte(`{"bomFormat":"CycloneDX","components":[{"name":"foo","version":"1",` +
		`"properties":[{"name":"aquasecurity:trivy:LayerDigest","value":"` + long + `"}]}]}`)
	if _, err := ValidateSBOMStructure(okBody, DefaultSBOMLimits()); err != nil {
		t.Fatalf("expected long properties[].value to pass, got: %v", err)
	}
	badBody := []byte(`{"bomFormat":"CycloneDX","components":[{"name":"foo","version":"1",` +
		`"properties":[{"name":"` + long + `","value":"x"}]}]}`)
	if _, err := ValidateSBOMStructure(badBody, DefaultSBOMLimits()); !errors.Is(err, ErrInvalidSBOM) {
		t.Errorf("expected ErrInvalidSBOM for oversized properties[].name, got %v", err)
	}
}

// String arrays must not shift the validator's key/value phase: an attacker
// who could get an element read as a key would inherit that key's prose cap
// for the following element and slip past MaxStringLength.
func TestValidateSBOMStructure_StringArrayCannotForgeFreeTextKey(t *testing.T) {
	long := strings.Repeat("q", DefaultSBOMLimits().MaxStringLength+1)
	body := []byte(`{"bomFormat":"CycloneDX","components":[{"name":"foo","version":"1",` +
		`"tags":["a","description","` + long + `"]}]}`)
	_, err := ValidateSBOMStructure(body, DefaultSBOMLimits())
	if !errors.Is(err, ErrInvalidSBOM) {
		t.Errorf("expected ErrInvalidSBOM — array element must not inherit a prose cap, got %v", err)
	}
}

func TestValidateContentType(t *testing.T) {
	cases := []struct {
		ct      string
		wantErr bool
	}{
		{"application/json", false},
		{"application/vnd.cyclonedx+json", false},
		{"application/vnd.cyclonedx+json; charset=utf-8", false},
		{"text/html", true},
		{"application/xml", true},
	}
	for _, c := range cases {
		err := ValidateContentType(c.ct)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidateContentType(%q) err=%v, wantErr=%v", c.ct, err, c.wantErr)
		}
	}
}

func TestValidateSBOMStructure_Valid(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"name":"foo","version":"1.0"},{"name":"bar","version":"2.0"}]}`)
	count, err := ValidateSBOMStructure(body, DefaultSBOMLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 components, got %d", count)
	}
}

func TestValidateSBOMStructure_DepthBomb(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX",` + strings.Repeat(`"a":{`, 20) + strings.Repeat(`}`, 20) + `}`)
	limits := DefaultSBOMLimits()
	limits.MaxDepth = 5
	_, err := ValidateSBOMStructure(body, limits)
	if !errors.Is(err, ErrInvalidSBOM) {
		t.Errorf("expected ErrInvalidSBOM for depth-bomb, got %v", err)
	}
}

func TestValidateSBOMStructure_TooLarge(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX"}`)
	limits := DefaultSBOMLimits()
	limits.MaxBytes = 5
	_, err := ValidateSBOMStructure(body, limits)
	if !errors.Is(err, ErrSBOMTooLarge) {
		t.Errorf("expected ErrSBOMTooLarge, got %v", err)
	}
}

func TestValidateSBOMStructure_MissingBomFormat(t *testing.T) {
	body := []byte(`{"specVersion":"1.5","components":[]}`)
	_, err := ValidateSBOMStructure(body, DefaultSBOMLimits())
	if !errors.Is(err, ErrInvalidSBOM) {
		t.Errorf("expected ErrInvalidSBOM, got %v", err)
	}
}

func TestValidateSBOMStructure_TooManyComponents(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","components":[`)
	for i := 0; i < 6; i++ {
		if i > 0 {
			body = append(body, ',')
		}
		body = append(body, []byte(`{"name":"a","version":"1"}`)...)
	}
	body = append(body, []byte(`]}`)...)
	limits := DefaultSBOMLimits()
	limits.MaxComponents = 3
	_, err := ValidateSBOMStructure(body, limits)
	if !errors.Is(err, ErrInvalidSBOM) {
		t.Errorf("expected ErrInvalidSBOM, got %v", err)
	}
}
