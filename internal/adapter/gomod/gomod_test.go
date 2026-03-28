package gomod

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

func TestGoModAdapter_Ecosystem(t *testing.T) {
	a := &GoModAdapter{}
	assert.Equal(t, scanner.EcosystemGo, a.Ecosystem())
}

func TestGoModAdapter_ParseRequest_VersionList(t *testing.T) {
	parsed, err := parseGoModRequest("github.com/user/repo/@v/list")
	require.NoError(t, err)
	assert.Equal(t, "github.com/user/repo", parsed.modulePath)
	assert.Equal(t, "", parsed.version)
	assert.Equal(t, reqVersionList, parsed.reqType)
}

func TestGoModAdapter_ParseRequest_ZipDownload(t *testing.T) {
	parsed, err := parseGoModRequest("github.com/user/repo/@v/v1.2.3.zip")
	require.NoError(t, err)
	assert.Equal(t, "github.com/user/repo", parsed.modulePath)
	assert.Equal(t, "v1.2.3", parsed.version)
	assert.Equal(t, reqZipDownload, parsed.reqType)
}

func TestGoModAdapter_ParseRequest_ModFile(t *testing.T) {
	parsed, err := parseGoModRequest("github.com/user/repo/@v/v1.0.0.mod")
	require.NoError(t, err)
	assert.Equal(t, "github.com/user/repo", parsed.modulePath)
	assert.Equal(t, "v1.0.0", parsed.version)
	assert.Equal(t, reqGoMod, parsed.reqType)
}

func TestGoModAdapter_ParseRequest_VersionInfo(t *testing.T) {
	parsed, err := parseGoModRequest("github.com/user/repo/@v/v1.0.0.info")
	require.NoError(t, err)
	assert.Equal(t, "github.com/user/repo", parsed.modulePath)
	assert.Equal(t, "v1.0.0", parsed.version)
	assert.Equal(t, reqVersionInfo, parsed.reqType)
}

func TestGoModAdapter_ParseRequest_Latest(t *testing.T) {
	parsed, err := parseGoModRequest("github.com/user/repo/@latest")
	require.NoError(t, err)
	assert.Equal(t, "github.com/user/repo", parsed.modulePath)
	assert.Equal(t, reqLatest, parsed.reqType)
}

func TestGoModAdapter_ModulePathEncoding(t *testing.T) {
	// Module path with uppercase: github.com/!foo/!bar decodes to github.com/Foo/Bar
	parsed, err := parseGoModRequest("github.com/!foo/!bar/@v/list")
	require.NoError(t, err)
	assert.Equal(t, "github.com/Foo/Bar", parsed.modulePath)
}

func TestGoModAdapter_MajorVersionSuffix(t *testing.T) {
	// github.com/user/repo/v2 is a valid module path with major version suffix
	parsed, err := parseGoModRequest("github.com/user/repo/v2/@v/v2.1.0.zip")
	require.NoError(t, err)
	assert.Equal(t, "github.com/user/repo/v2", parsed.modulePath)
	assert.Equal(t, "v2.1.0", parsed.version)
	assert.Equal(t, reqZipDownload, parsed.reqType)
}

func TestGoModAdapter_ArtifactID_Format(t *testing.T) {
	id := gomodArtifactID("github.com/user/repo", "v1.2.3")
	assert.Equal(t, "go:github.com/user/repo:v1.2.3", id)
}

func TestGoModAdapter_PathTraversal_Rejected(t *testing.T) {
	cases := []string{
		"../etc/passwd/@v/list",
		"github.com/../../etc/passwd/@v/list",
		"github.com/user/repo/..%00/@v/list",
	}
	for _, tc := range cases {
		t.Run(tc, func(t *testing.T) {
			_, err := parseGoModRequest(tc)
			assert.Error(t, err)
		})
	}
}

func TestGoModAdapter_ControlChars_Rejected(t *testing.T) {
	cases := []string{
		"github.com/user/repo\x00/@v/list",
		"github.com/user/repo\n/@v/list",
		"github.com/user/repo?foo=bar/@v/list",
		"github.com/user/repo#fragment/@v/list",
	}
	for _, tc := range cases {
		t.Run("control_char", func(t *testing.T) {
			_, err := parseGoModRequest(tc)
			assert.Error(t, err)
		})
	}
}

func TestGoModAdapter_PassThrough_Info(t *testing.T) {
	parsed, err := parseGoModRequest("golang.org/x/text/@v/v0.14.0.info")
	require.NoError(t, err)
	assert.Equal(t, reqVersionInfo, parsed.reqType)
	assert.Equal(t, "golang.org/x/text", parsed.modulePath)
	assert.Equal(t, "v0.14.0", parsed.version)
}

func TestGoModAdapter_PassThrough_Mod(t *testing.T) {
	parsed, err := parseGoModRequest("golang.org/x/text/@v/v0.14.0.mod")
	require.NoError(t, err)
	assert.Equal(t, reqGoMod, parsed.reqType)
	assert.Equal(t, "golang.org/x/text", parsed.modulePath)
	assert.Equal(t, "v0.14.0", parsed.version)
}

func TestGoModAdapter_MissingAtV_Rejected(t *testing.T) {
	_, err := parseGoModRequest("github.com/user/repo/v1.0.0.zip")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "/@v/")
}

func TestGoModAdapter_UnrecognisedAction_Rejected(t *testing.T) {
	_, err := parseGoModRequest("github.com/user/repo/@v/v1.0.0.unknown")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unrecognised action")
}

func TestGoModAdapter_DeepModulePath(t *testing.T) {
	// Deeply nested module path
	parsed, err := parseGoModRequest("github.com/org/repo/sub/pkg/@v/v0.1.0.zip")
	require.NoError(t, err)
	assert.Equal(t, "github.com/org/repo/sub/pkg", parsed.modulePath)
	assert.Equal(t, "v0.1.0", parsed.version)
	assert.Equal(t, reqZipDownload, parsed.reqType)
}

func TestGoModAdapter_ValidateModuleURLPath(t *testing.T) {
	assert.NoError(t, validateModuleURLPath("github.com/user/repo/@v/list"))
	assert.Error(t, validateModuleURLPath("github.com/user/repo?x=1"))
	assert.Error(t, validateModuleURLPath("github.com/user/repo#frag"))
	assert.Error(t, validateModuleURLPath("github.com/user/\x00repo"))
	assert.Error(t, validateModuleURLPath("github.com/user/\x01repo"))
}
