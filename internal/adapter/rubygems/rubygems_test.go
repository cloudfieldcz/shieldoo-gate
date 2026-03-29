package rubygems

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

func TestRubyGemsAdapter_ParseGemFilename_Simple(t *testing.T) {
	name, version, err := parseGemFilename("rails-7.1.3.gem")
	require.NoError(t, err)
	assert.Equal(t, "rails", name)
	assert.Equal(t, "7.1.3", version)
}

func TestRubyGemsAdapter_ParseGemFilename_Hyphenated(t *testing.T) {
	tests := []struct {
		filename    string
		wantName    string
		wantVersion string
	}{
		{"aws-sdk-core-3.0.0.gem", "aws-sdk-core", "3.0.0"},
		{"activerecord-7.1.3.gem", "activerecord", "7.1.3"},
		{"net-http-0.4.1.gem", "net-http", "0.4.1"},
		{"ruby-openid-2.9.2.gem", "ruby-openid", "2.9.2"},
		{"multi-json-1.15.0.gem", "multi-json", "1.15.0"},
	}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			name, version, err := parseGemFilename(tt.filename)
			require.NoError(t, err)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantVersion, version)
		})
	}
}

func TestRubyGemsAdapter_ParseGemFilename_PlatformSpecific(t *testing.T) {
	tests := []struct {
		filename    string
		wantName    string
		wantVersion string
	}{
		{"nokogiri-1.16.0-x86_64-linux.gem", "nokogiri", "1.16.0"},
		{"ffi-1.16.3-x86_64-linux-gnu.gem", "ffi", "1.16.3"},
		{"grpc-1.60.0-x86_64-linux.gem", "grpc", "1.60.0"},
		{"google-protobuf-3.25.1-x86_64-linux.gem", "google-protobuf", "3.25.1"},
	}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			name, version, err := parseGemFilename(tt.filename)
			require.NoError(t, err)
			assert.Equal(t, tt.wantName, name)
			assert.Equal(t, tt.wantVersion, version)
		})
	}
}

func TestRubyGemsAdapter_ParseGemFilename_Invalid(t *testing.T) {
	tests := []struct {
		name     string
		filename string
	}{
		{"no .gem suffix", "rails-7.1.3.tar.gz"},
		{"empty", ".gem"},
		{"no version", "rails.gem"},
		{"only hyphen", "-.gem"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseGemFilename(tt.filename)
			assert.Error(t, err)
		})
	}
}

func TestRubyGemsAdapter_ArtifactID_Format(t *testing.T) {
	id := rubygemsArtifactID("rails", "7.1.3")
	assert.Equal(t, "rubygems:rails:7.1.3", id)
}

func TestRubyGemsAdapter_ArtifactID_Hyphenated(t *testing.T) {
	id := rubygemsArtifactID("aws-sdk-core", "3.0.0")
	assert.Equal(t, "rubygems:aws-sdk-core:3.0.0", id)
}

func TestRubyGemsAdapter_Ecosystem(t *testing.T) {
	a := NewRubyGemsAdapter(nil, nil, nil, nil, "https://rubygems.org")
	assert.Equal(t, scanner.EcosystemRubyGems, a.Ecosystem())
}

func TestRubyGemsAdapter_PassThrough_Specs(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"specs", "/specs.4.8.gz"},
		{"latest_specs", "/latest_specs.4.8.gz"},
		{"prerelease_specs", "/prerelease_specs.4.8.gz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tt.path, r.URL.Path)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("index-data"))
			}))
			defer upstream.Close()

			a := NewRubyGemsAdapter(nil, nil, nil, nil, upstream.URL)
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()
			a.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, "index-data", w.Body.String())
		})
	}
}

func TestRubyGemsAdapter_PassThrough_Metadata(t *testing.T) {
	tests := []struct {
		name string
		path string
	}{
		{"gem info", "/api/v1/gems/rails.json"},
		{"versions", "/api/v1/versions/rails.json"},
		{"quick spec", "/quick/Marshal.4.8/rails-7.1.3.gemspec.rz"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, tt.path, r.URL.Path)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("metadata"))
			}))
			defer upstream.Close()

			a := NewRubyGemsAdapter(nil, nil, nil, nil, upstream.URL)
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()
			a.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, "metadata", w.Body.String())
		})
	}
}

func TestRubyGemsAdapter_PathTraversal_Rejected(t *testing.T) {
	// Chi normalizes paths with ".." before matching routes, so path traversal
	// attempts like "/gems/../../etc/passwd.gem" result in 404 (no route match).
	// We test that a filename containing ".." as a substring is still rejected
	// by the handler's own validation.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be reached for path traversal")
	}))
	defer upstream.Close()

	a := NewRubyGemsAdapter(nil, nil, nil, nil, upstream.URL)

	// A filename that contains ".." but is a single path segment will be
	// caught by the validComponentRe check (dots are allowed but the full
	// filename must pass parseGemFilename validation).
	req := httptest.NewRequest(http.MethodGet, "/gems/..passwd-1.0.0.gem", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	// ".." prefix triggers path traversal check in handler.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRubyGemsAdapter_HealthCheck(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/gems/rails.json" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer upstream.Close()

	a := NewRubyGemsAdapter(nil, nil, nil, nil, upstream.URL)
	err := a.HealthCheck(context.Background())
	assert.NoError(t, err)
}

func TestRubyGemsAdapter_HealthCheck_UpstreamDown(t *testing.T) {
	a := NewRubyGemsAdapter(nil, nil, nil, nil, "http://127.0.0.1:1")
	err := a.HealthCheck(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "health check")
}

func TestStripPlatform(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"3.0.0", "3.0.0"},
		{"7.1.3", "7.1.3"},
		{"1.16.0-x86_64-linux", "1.16.0"},
		{"1.16.3-x86_64-linux-gnu", "1.16.3"},
		{"3.25.1-x86_64-linux", "3.25.1"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripPlatform(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRubyGemsAdapter_InvalidFilenameCharacters_Rejected(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream should not be reached for invalid characters")
	}))
	defer upstream.Close()

	a := NewRubyGemsAdapter(nil, nil, nil, nil, upstream.URL)
	req := httptest.NewRequest(http.MethodGet, "/gems/<script>-1.0.0.gem", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
