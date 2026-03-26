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

func TestArtifactStatus_IsServable_Clean(t *testing.T) {
	s := ArtifactStatus{Status: StatusClean}
	assert.True(t, s.IsServable())
}

func TestArtifactStatus_IsServable_Quarantined(t *testing.T) {
	s := ArtifactStatus{Status: StatusQuarantined}
	assert.False(t, s.IsServable())
}
