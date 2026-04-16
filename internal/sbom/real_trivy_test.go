package sbom

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Real Trivy 0.50.0 CycloneDX 1.5 output captured from `trivy fs requests-2.31.0
// --format cyclonedx --scanners vuln,license`.
func TestParse_RealTrivy050CycloneDX15_NoDeps(t *testing.T) {
	raw := []byte(`{
	  "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.5",
	  "metadata": {
	    "timestamp": "2026-04-15T12:20:11+00:00",
	    "tools": {
	      "components": [
	        {"type":"application","group":"aquasecurity","name":"trivy","version":"0.50.0"}
	      ]
	    }
	  },
	  "components": [],
	  "dependencies": [],
	  "vulnerabilities": []
	}`)
	ext, err := Parse(raw)
	assert.NoError(t, err)
	assert.Equal(t, 0, ext.ComponentCount, "requests-2.31.0 source dir has 0 deps")
	assert.Equal(t, "trivy-0.50.0", ext.Generator)
}
