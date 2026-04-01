package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestArtifactID_Format(t *testing.T) {
	a := Artifact{
		Ecosystem: "pypi",
		Name:      "litellm",
		Version:   "1.82.6",
	}
	assert.Equal(t, "pypi:litellm:1.82.6", a.ID())
}

func TestArtifactID_WithFilename(t *testing.T) {
	a := Artifact{
		Ecosystem: "pypi",
		Name:      "cffi",
		Version:   "2.0.0",
		Filename:  "cffi-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl",
	}
	assert.Equal(t, "pypi:cffi:2.0.0:cffi-2.0.0-cp312-cp312-manylinux_2_17_x86_64.whl", a.ID())
}

func TestArtifactID_WithoutFilename_Unchanged(t *testing.T) {
	a := Artifact{
		Ecosystem: "npm",
		Name:      "lodash",
		Version:   "4.17.21",
	}
	assert.Equal(t, "npm:lodash:4.17.21", a.ID())
}

func TestArtifactStatus_IsServable_Clean(t *testing.T) {
	s := ArtifactStatus{Status: StatusClean}
	assert.True(t, s.IsServable())
}

func TestArtifactStatus_IsServable_Quarantined(t *testing.T) {
	s := ArtifactStatus{Status: StatusQuarantined}
	assert.False(t, s.IsServable())
}
