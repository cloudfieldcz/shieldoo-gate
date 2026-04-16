package sbom

import (
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
