package manifest

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseCycloneDXComponents_HappyPath(t *testing.T) {
	body := []byte(`{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.5",
	  "components": [
	    {"name":"requests","version":"2.31.0","purl":"pkg:pypi/requests@2.31.0","type":"library"},
	    {"name":"lodash","version":"4.17.21","purl":"pkg:npm/lodash@4.17.21","type":"library"}
	  ]
	}`)
	got, err := ParseCycloneDXComponents(body)
	assert.NoError(t, err)
	assert.Len(t, got, 2)
	assert.Equal(t, "PyPI", got[0].Ecosystem)
	assert.Equal(t, "npm", got[1].Ecosystem)
}

// Adversarial: the parser must not panic on malformed JSON; it returns an error
// the caller can wrap.
func TestParseCycloneDXComponents_MalformedJSON(t *testing.T) {
	_, err := ParseCycloneDXComponents([]byte(`{"bomFormat":"CycloneDX","components":[{"name":"foo"`))
	assert.Error(t, err)
}

// A non-CycloneDX bomFormat must be rejected — the scanner pipeline assumes
// CycloneDX semantics for ecosystem extraction.
func TestParseCycloneDXComponents_WrongBomFormat(t *testing.T) {
	_, err := ParseCycloneDXComponents([]byte(`{"bomFormat":"SPDX","components":[]}`))
	assert.Error(t, err)
}

// Empty SBOM is a valid edge case (CycloneDX permits zero components).
func TestParseCycloneDXComponents_EmptyArray(t *testing.T) {
	got, err := ParseCycloneDXComponents([]byte(`{"bomFormat":"CycloneDX","components":[]}`))
	assert.NoError(t, err)
	assert.Empty(t, got)
}

// Components missing name OR version are silently filtered: they wouldn't
// produce a usable OSV /querybatch query anyway. Make sure the filter is
// applied (and doesn't panic on missing fields).
func TestParseCycloneDXComponents_FiltersIncomplete(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","components":[
	  {"name":"good","version":"1.0","purl":"pkg:pypi/good@1.0"},
	  {"name":"only-name"},
	  {"version":"only-version"},
	  {}
	]}`)
	got, err := ParseCycloneDXComponents(body)
	assert.NoError(t, err)
	assert.Len(t, got, 1)
	assert.Equal(t, "good", got[0].Name)
}

// Pathologically long string fields don't crash the parser. They flow through
// to the ScanOutcome but length enforcement happens upstream in
// component.ValidateSBOMStructure (covered by sbom_validate_adversarial_test.go).
func TestParseCycloneDXComponents_LongStrings(t *testing.T) {
	huge := strings.Repeat("x", 50_000)
	body := []byte(`{"bomFormat":"CycloneDX","components":[{"name":"` + huge + `","version":"1.0"}]}`)
	got, err := ParseCycloneDXComponents(body)
	assert.NoError(t, err)
	assert.Len(t, got, 1)
	assert.Equal(t, len(huge), len(got[0].Name))
}

// purl-less components default to empty Ecosystem; OSV.Scan filters those out
// of the batch query — their presence here proves the parser doesn't drop them
// (preserving fidelity for downstream Trivy lookups, which handle
// ecosystem-less components via path/sbom inference).
func TestParseCycloneDXComponents_NoPurlEmptyEcosystem(t *testing.T) {
	body := []byte(`{"bomFormat":"CycloneDX","components":[
	  {"name":"foo","version":"1.0"}
	]}`)
	got, err := ParseCycloneDXComponents(body)
	assert.NoError(t, err)
	assert.Len(t, got, 1)
	assert.Equal(t, "", got[0].Ecosystem)
}

func TestEcosystemFromPurl_AllSupportedEcosystems(t *testing.T) {
	cases := map[string]string{
		"pkg:pypi/foo@1.0":           "PyPI",
		"pkg:npm/lodash@4.17.21":     "npm",
		"pkg:maven/org.apache/x@1":   "Maven",
		"pkg:gem/rails@7":            "RubyGems",
		"pkg:golang/k8s.io/api@v0.1": "Go",
		"pkg:nuget/Newtonsoft.Json@13": "NuGet",
		"pkg:apk/alpine/musl@1.2":    "Alpine",
		"pkg:deb/debian/curl@7":      "Debian",
		"pkg:rpm/redhat/openssl@1":   "RPM",
		// Adversarial: empty / malformed inputs.
		"":               "",
		"not-a-purl":     "",
		"pkg:":           "",
		"pkg:unknown/x":  "",
	}
	for purl, want := range cases {
		assert.Equal(t, want, EcosystemFromPurl(purl), "purl=%q", purl)
	}
}
