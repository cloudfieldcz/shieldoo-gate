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
