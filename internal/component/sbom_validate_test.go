package component

import (
	"errors"
	"strings"
	"testing"
)

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
