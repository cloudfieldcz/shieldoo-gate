package sbom

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sampleCycloneDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {
    "tools": [{"vendor":"aquasecurity","name":"trivy","version":"0.50.0"}]
  },
  "components": [
    {"type":"library","name":"requests","version":"2.31.0","licenses":[{"license":{"id":"Apache-2.0"}}]},
    {"type":"library","name":"idna","version":"3.4","licenses":[{"license":{"id":"BSD-3-Clause"}}]},
    {"type":"library","name":"certifi","version":"2023.7.22","licenses":[{"license":{"name":"Mozilla Public License 2.0"}}]},
    {"type":"library","name":"charset-normalizer","version":"3.2.0","licenses":[{"expression":"MIT OR Apache-2.0"}]}
  ]
}`

func TestParse_ExtractsIDsNamesExpressions(t *testing.T) {
	ext, err := Parse([]byte(sampleCycloneDX))
	require.NoError(t, err)
	assert.Equal(t, 4, ext.ComponentCount)
	// Deduplicated and sorted.
	assert.Contains(t, ext.Licenses, "Apache-2.0")
	assert.Contains(t, ext.Licenses, "BSD-3-Clause")
	assert.Contains(t, ext.Licenses, "MPL-2.0") // aliased from "Mozilla Public License 2.0"
	assert.Contains(t, ext.Licenses, "MIT OR Apache-2.0")
	assert.Equal(t, "trivy-0.50.0", ext.Generator)
}

func TestParse_EmptyBytesOK(t *testing.T) {
	ext, err := Parse(nil)
	require.NoError(t, err)
	assert.Equal(t, 0, ext.ComponentCount)
}

func TestParse_InvalidJSON(t *testing.T) {
	_, err := Parse([]byte("not json"))
	require.Error(t, err)
}

func TestParse_CycloneDX15ToolsObjectShape(t *testing.T) {
	// Trivy 0.50 in CycloneDX 1.5 mode emits metadata.tools as an OBJECT,
	// not an array. Regression for e2e failure: "cannot unmarshal object
	// into Go struct field .metadata.tools of type []sbom.cdxTool".
	raw := `{
	  "bomFormat":"CycloneDX","specVersion":"1.5",
	  "metadata":{
	    "tools":{
	      "components":[
	        {"type":"application","vendor":"aquasecurity","name":"trivy","version":"0.50.0"}
	      ]
	    }
	  },
	  "components":[{"name":"requests","licenses":[{"license":{"id":"Apache-2.0"}}]}]
	}`
	ext, err := Parse([]byte(raw))
	require.NoError(t, err)
	assert.Equal(t, 1, ext.ComponentCount)
	assert.Equal(t, "trivy-0.50.0", ext.Generator)
}

func TestParse_DedupesLicenses(t *testing.T) {
	raw := `{
	  "bomFormat":"CycloneDX","specVersion":"1.4",
	  "components":[
	    {"name":"a","licenses":[{"license":{"id":"MIT"}}]},
	    {"name":"b","licenses":[{"license":{"id":"MIT"}}]},
	    {"name":"c","licenses":[{"license":{"name":"MIT License"}}]}
	  ]
	}`
	ext, err := Parse([]byte(raw))
	require.NoError(t, err)
	assert.Len(t, ext.Licenses, 1)
	assert.Equal(t, "MIT", ext.Licenses[0])
}

// `trivy image` puts the whole LICENSE file body into
// `licenses[].license.name` when a package ships no machine-readable SPDX
// identifier (tiktoken 0.12.0 is the canonical example). Storing that blob as
// a license identifier would poison policy matching and the UI; the license
// text's own title line recovers the real SPDX ID.
func TestParse_FullMITTextInLicenseName_NormalizesToMIT(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"bomFormat": "CycloneDX",
		"components": []any{map[string]any{
			"type": "library", "name": "tiktoken", "version": "0.12.0",
			"licenses": []any{map[string]any{"license": map[string]any{
				"name": "MIT License\n\nCopyright (c) 2022 OpenAI, Shantanu Jain\n\n" +
					strings.Repeat("Permission is hereby granted, free of charge, to any person. ", 20),
			}}},
		}},
	})
	require.NoError(t, err)
	ext, err := Parse(body)
	require.NoError(t, err)
	assert.Equal(t, []string{"MIT"}, ext.Licenses)
}

// An unrecognised prose license name must be truncated to identifier length
// rather than stored verbatim — policy `unknown_action` then sees a stable,
// human-readable marker instead of kilobytes of legal text.
func TestParse_UnknownProseLicenseName_TruncatedToIdentifierLength(t *testing.T) {
	long := strings.Repeat("Custom Proprietary Terms ", 200)
	body, err := json.Marshal(map[string]any{
		"bomFormat": "CycloneDX",
		"components": []any{map[string]any{
			"type": "library", "name": "vendorlib", "version": "1.0",
			"licenses": []any{map[string]any{"license": map[string]any{"name": long}}},
		}},
	})
	require.NoError(t, err)
	ext, err := Parse(body)
	require.NoError(t, err)
	require.Len(t, ext.Licenses, 1)
	assert.LessOrEqual(t, len([]rune(ext.Licenses[0])), maxLicenseNameLen)
	assert.True(t, strings.HasPrefix(ext.Licenses[0], "Custom Proprietary Terms"))
}

// Short names keep passing through untouched (alias hit or verbatim).
func TestNormalizeLicenseName_ShortNames_Unchanged(t *testing.T) {
	assert.Equal(t, "MIT", normalizeLicenseName("  MIT License  "))
	assert.Equal(t, "Vendor EULA", normalizeLicenseName("Vendor EULA"))
	assert.Equal(t, "", normalizeLicenseName("\n\n"))
}

func TestNameAliasToID_EUPLFreeText_ReturnsEUPL12(t *testing.T) {
	for _, in := range []string{"EUPL v1.2 Licensed", "EUPL 1.2", "EUPL-1.2"} {
		id, ok := NameAliasToID(in)
		assert.True(t, ok, "expected %q to resolve", in)
		assert.Equal(t, "EUPL-1.2", id, "input %q", in)
	}
}

func TestNameAliasToID_ExpatLicense_ReturnsMIT(t *testing.T) {
	for _, in := range []string{"Expat", "Expat License"} {
		id, ok := NameAliasToID(in)
		assert.True(t, ok, "expected %q to resolve", in)
		assert.Equal(t, "MIT", id, "input %q", in)
	}
}

func TestNameAliasToID_ModifiedBSD_ReturnsBSD3Clause(t *testing.T) {
	for _, in := range []string{"3-Clause BSD License", "Modified BSD License", "New BSD License"} {
		id, ok := NameAliasToID(in)
		assert.True(t, ok, "expected %q to resolve", in)
		assert.Equal(t, "BSD-3-Clause", id, "input %q", in)
	}
}

func TestSanitize_StripsCachePrefix(t *testing.T) {
	raw := []byte(`{"path":"/var/cache/shieldoo-gate/pypi/requests-2.31.0.whl","other":"value"}`)
	out := Sanitize(raw, "/var/cache/shieldoo-gate")
	assert.NotContains(t, string(out), "/var/cache/shieldoo-gate")
	assert.Contains(t, string(out), "pypi/requests-2.31.0.whl")
}

func TestSanitize_NoPrefix_ReturnsInput(t *testing.T) {
	raw := []byte(`{"x":1}`)
	out := Sanitize(raw, "")
	assert.Equal(t, raw, out)
}

func TestSanitize_Idempotent(t *testing.T) {
	raw := []byte(`/var/cache/shieldoo-gate/file`)
	once := Sanitize(raw, "/var/cache/shieldoo-gate")
	twice := Sanitize(once, "/var/cache/shieldoo-gate")
	assert.Equal(t, once, twice)
}
