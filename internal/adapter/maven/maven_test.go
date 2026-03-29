package maven

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

func TestMavenAdapter_ParsePath_ValidJAR(t *testing.T) {
	p, err := parseMavenPath("org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar")
	require.NoError(t, err)

	assert.Equal(t, "org.apache.commons", p.groupID)
	assert.Equal(t, "commons-lang3", p.artifactID)
	assert.Equal(t, "3.14.0", p.version)
	assert.Equal(t, "commons-lang3-3.14.0.jar", p.filename)
	assert.Equal(t, ".jar", p.extension)
	assert.Equal(t, "", p.classifier)
	assert.True(t, p.scannable)
	assert.False(t, p.passThru)
}

func TestMavenAdapter_ParsePath_WithClassifier(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		classifier string
	}{
		{"sources", "org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0-sources.jar", "sources"},
		{"javadoc", "org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0-javadoc.jar", "javadoc"},
		{"tests", "junit/junit/4.13.2/junit-4.13.2-tests.jar", "tests"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parseMavenPath(tt.path)
			require.NoError(t, err)
			assert.Equal(t, tt.classifier, p.classifier)
			assert.True(t, p.scannable)
		})
	}
}

func TestMavenAdapter_ParsePath_MetadataPassThrough(t *testing.T) {
	// maven-metadata.xml at group/artifact level should be handled by the
	// handleRequest method before parseMavenPath is called. But we can test
	// that the path is recognized as metadata in the handler.
	// Here we test that .pom is pass-through via parseMavenPath.
	p, err := parseMavenPath("org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom")
	require.NoError(t, err)
	assert.True(t, p.passThru)
	assert.False(t, p.scannable)
	assert.Equal(t, ".pom", p.extension)
}

func TestMavenAdapter_ParsePath_ChecksumPassThrough(t *testing.T) {
	tests := []struct {
		name string
		path string
		ext  string
	}{
		{"sha1", "org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar.sha1", ".sha1"},
		{"md5", "org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar.md5", ".md5"},
		{"sha256", "org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar.sha256", ".sha256"},
		{"asc", "org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar.asc", ".asc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parseMavenPath(tt.path)
			require.NoError(t, err)
			assert.True(t, p.passThru)
			assert.False(t, p.scannable)
			assert.Equal(t, tt.ext, p.extension)
		})
	}
}

func TestMavenAdapter_PathTraversal_Rejected(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"dot-dot in group", "../etc/passwd/commons-lang3/3.14.0/commons-lang3-3.14.0.jar"},
		{"dot-dot mid path", "org/apache/../../../etc/passwd"},
		{"dot-dot in version", "org/apache/commons/commons-lang3/../../secret/commons-lang3-3.14.0.jar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal adapter to test the handler.
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fatal("upstream should not be reached for path traversal")
			}))
			defer upstream.Close()

			a := NewMavenAdapter(nil, nil, nil, nil, upstream.URL)
			req := httptest.NewRequest(http.MethodGet, "/"+tt.path, nil)
			w := httptest.NewRecorder()
			a.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestMavenAdapter_ParsePath_InvalidCharacters(t *testing.T) {
	_, err := parseMavenPath("org/apache/<script>/commons-lang3/3.14.0/commons-lang3-3.14.0.jar")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid characters")
}

func TestMavenAdapter_ArtifactID_Format(t *testing.T) {
	id := mavenArtifactID("org.apache.commons", "commons-lang3", "3.14.0")
	assert.Equal(t, "maven:org.apache.commons:commons-lang3:3.14.0", id)
}

func TestMavenAdapter_Ecosystem_ReturnsMaven(t *testing.T) {
	a := NewMavenAdapter(nil, nil, nil, nil, "https://repo1.maven.org/maven2")
	assert.Equal(t, scanner.EcosystemMaven, a.Ecosystem())
}

func TestMavenAdapter_HealthCheck(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	a := NewMavenAdapter(nil, nil, nil, nil, upstream.URL)
	err := a.HealthCheck(context.Background())
	assert.NoError(t, err)
}

func TestMavenAdapter_HealthCheck_UpstreamDown(t *testing.T) {
	a := NewMavenAdapter(nil, nil, nil, nil, "http://127.0.0.1:1")
	err := a.HealthCheck(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "health check")
}

func TestMavenAdapter_ParsePath_WARFile(t *testing.T) {
	p, err := parseMavenPath("com/example/webapp/1.0.0/webapp-1.0.0.war")
	require.NoError(t, err)
	assert.Equal(t, "com.example", p.groupID)
	assert.Equal(t, "webapp", p.artifactID)
	assert.Equal(t, "1.0.0", p.version)
	assert.Equal(t, ".war", p.extension)
	assert.True(t, p.scannable)
}

func TestMavenAdapter_ParsePath_SingleGroupSegment(t *testing.T) {
	p, err := parseMavenPath("junit/junit/4.13.2/junit-4.13.2.jar")
	require.NoError(t, err)
	assert.Equal(t, "junit", p.groupID)
	assert.Equal(t, "junit", p.artifactID)
	assert.Equal(t, "4.13.2", p.version)
	assert.True(t, p.scannable)
}

func TestMavenAdapter_ParsePath_TooShort(t *testing.T) {
	_, err := parseMavenPath("org/artifact/file.jar")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestMavenAdapter_PassThrough_MetadataXML(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/org/apache/commons/commons-lang3/maven-metadata.xml", r.URL.Path)
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<metadata/>"))
	}))
	defer upstream.Close()

	a := NewMavenAdapter(nil, nil, nil, nil, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/org/apache/commons/commons-lang3/maven-metadata.xml", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "<metadata/>", w.Body.String())
}

func TestMavenAdapter_PassThrough_POM(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom", r.URL.Path)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<project/>"))
	}))
	defer upstream.Close()

	a := NewMavenAdapter(nil, nil, nil, nil, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "<project/>", w.Body.String())
}

func TestMavenAdapter_GroupID_DotsToSlashes_Bidirectional(t *testing.T) {
	// Test that dots in groupId become slashes in path and back.
	p, err := parseMavenPath("io/netty/netty-all/4.1.100.Final/netty-all-4.1.100.Final.jar")
	require.NoError(t, err)
	assert.Equal(t, "io.netty", p.groupID)
	assert.Equal(t, "netty-all", p.artifactID)
	assert.Equal(t, "4.1.100.Final", p.version)
}

func TestParseClassifier(t *testing.T) {
	tests := []struct {
		filename   string
		artifactID string
		version    string
		ext        string
		want       string
	}{
		{"commons-lang3-3.14.0.jar", "commons-lang3", "3.14.0", ".jar", ""},
		{"commons-lang3-3.14.0-sources.jar", "commons-lang3", "3.14.0", ".jar", "sources"},
		{"commons-lang3-3.14.0-javadoc.jar", "commons-lang3", "3.14.0", ".jar", "javadoc"},
		{"netty-all-4.1.100.Final-linux-x86_64.jar", "netty-all", "4.1.100.Final", ".jar", "linux-x86_64"},
	}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := parseClassifier(tt.filename, tt.artifactID, tt.version, tt.ext)
			assert.Equal(t, tt.want, got)
		})
	}
}
