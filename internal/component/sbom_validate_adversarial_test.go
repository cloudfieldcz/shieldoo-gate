package component

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestValidateSBOMStructure_BillionComponents enforces the components-cap on a
// reasonably-large flood. We don't actually allocate a billion entries (that
// would dominate the test wallclock); the limit gate must trip well before
// that. The byte cap is a separate, earlier guard.
//
// We deliberately override limits.MaxComponents below the synthetic count
// so the test pins the *cap behaviour*, not the default value. The default
// (500k post-image-scan) is exercised by TestDefaultSBOMLimits_HasImageScanHeadroom.
func TestValidateSBOMStructure_BillionComponents(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(`{"bomFormat":"CycloneDX","components":[`)
	const N = 50_000
	for i := 0; i < N; i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(`{"name":"a","version":"1"}`)
	}
	buf.WriteString(`]}`)

	limits := DefaultSBOMLimits()
	limits.MaxBytes = int64(buf.Len() * 2) // not byte-bound; the components cap should catch us
	limits.MaxComponents = N - 1           // force the cap below our synthetic count
	_, err := ValidateSBOMStructure(buf.Bytes(), limits)
	if !errors.Is(err, ErrInvalidSBOM) {
		t.Fatalf("expected ErrInvalidSBOM (component cap), got %v", err)
	}
}

// TestValidateSBOMStructure_NestedArrayDepthBomb verifies that adversaries
// can't bypass the {-based depth check by stacking [].
func TestValidateSBOMStructure_NestedArrayDepthBomb(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","x":` + strings.Repeat(`[`, 30) + strings.Repeat(`]`, 30) + `}`)
	limits := DefaultSBOMLimits()
	limits.MaxDepth = 5
	_, err := ValidateSBOMStructure(body, limits)
	if !errors.Is(err, ErrInvalidSBOM) {
		t.Errorf("expected ErrInvalidSBOM for nested-array depth bomb, got %v", err)
	}
}

// TestValidateSBOMStructure_LongStringValue exercises the per-string-length cap.
// A pathological component whose `name` is megabytes long must be rejected
// before downstream consumers (OSV API requests, DB inserts) see it.
func TestValidateSBOMStructure_LongStringValue(t *testing.T) {
	huge := strings.Repeat("x", 5000)
	body := []byte(`{"bomFormat":"CycloneDX","components":[{"name":"` + huge + `","version":"1"}]}`)
	limits := DefaultSBOMLimits()
	limits.MaxStringLength = 100
	_, err := ValidateSBOMStructure(body, limits)
	if !errors.Is(err, ErrInvalidSBOM) {
		t.Errorf("expected ErrInvalidSBOM for long-string DoS, got %v", err)
	}
}

// TestValidateSBOMStructure_TruncatedJSON ensures the streaming validator
// rejects unbalanced documents instead of silently accepting partial parses.
func TestValidateSBOMStructure_TruncatedJSON(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","components":[{"name":"foo","version":"1"`)
	_, err := ValidateSBOMStructure(body, DefaultSBOMLimits())
	if !errors.Is(err, ErrInvalidSBOM) {
		t.Errorf("expected ErrInvalidSBOM for truncated body, got %v", err)
	}
}

// TestValidateSBOMStructure_GarbageInput catches the case where someone uploads
// a non-JSON payload (e.g. binary, plain text). The decoder must surface the
// error rather than panic.
func TestValidateSBOMStructure_GarbageInput(t *testing.T) {
	body := []byte("\x00\x01\x02not really json\xff\xff")
	_, err := ValidateSBOMStructure(body, DefaultSBOMLimits())
	if !errors.Is(err, ErrInvalidSBOM) {
		t.Errorf("expected ErrInvalidSBOM for garbage payload, got %v", err)
	}
}

// TestValidateSBOMStructure_TopLevelArray rejects payloads where the top-level
// value isn't an object (some tools ship `[]` for empty SBOMs — wrong).
func TestValidateSBOMStructure_TopLevelArray(t *testing.T) {
	_, err := ValidateSBOMStructure([]byte(`[]`), DefaultSBOMLimits())
	if !errors.Is(err, ErrInvalidSBOM) {
		t.Errorf("expected ErrInvalidSBOM for non-object root, got %v", err)
	}
}

// TestValidateSBOMStructure_EmptyComponents is the inverse: a valid SBOM with
// zero components must NOT error — the guard is just structural.
func TestValidateSBOMStructure_EmptyComponents(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","components":[]}`)
	count, err := ValidateSBOMStructure(body, DefaultSBOMLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 components, got %d", count)
	}
}
