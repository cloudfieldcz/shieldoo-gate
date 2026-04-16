package effectivepom

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Parser tests
// ---------------------------------------------------------------------------

func TestParser_NoLicenses(t *testing.T) {
	data, err := os.ReadFile("testdata/no_licenses_no_parent.pom")
	require.NoError(t, err)
	result, err := parsePOM(strings.NewReader(string(data)))
	require.NoError(t, err)
	assert.Empty(t, result.Licenses)
	assert.Nil(t, result.Parent)
}

func TestParser_InlineLicenses(t *testing.T) {
	data, err := os.ReadFile("testdata/with_licenses.pom")
	require.NoError(t, err)
	result, err := parsePOM(strings.NewReader(string(data)))
	require.NoError(t, err)
	assert.Equal(t, []string{"Apache-2.0"}, result.Licenses)
	assert.Nil(t, result.Parent)
}

func TestParser_ParentReference(t *testing.T) {
	data, err := os.ReadFile("testdata/with_parent.pom")
	require.NoError(t, err)
	result, err := parsePOM(strings.NewReader(string(data)))
	require.NoError(t, err)
	assert.Empty(t, result.Licenses)
	require.NotNil(t, result.Parent)
	assert.Equal(t, "com.mysql", result.Parent.GroupID)
	assert.Equal(t, "mysql-parent", result.Parent.ArtifactID)
	assert.Equal(t, "8.4.0", result.Parent.Version)
}

func TestParser_MultipleLicenses(t *testing.T) {
	pom := `<?xml version="1.0"?>
<project>
  <licenses>
    <license><name>MIT</name></license>
    <license><name>Apache-2.0</name></license>
  </licenses>
</project>`
	result, err := parsePOM(strings.NewReader(pom))
	require.NoError(t, err)
	assert.Equal(t, []string{"MIT", "Apache-2.0"}, result.Licenses)
}

func TestParser_LicenseFromURL(t *testing.T) {
	pom := `<?xml version="1.0"?>
<project>
  <licenses>
    <license><url>https://www.apache.org/licenses/LICENSE-2.0</url></license>
  </licenses>
</project>`
	result, err := parsePOM(strings.NewReader(pom))
	require.NoError(t, err)
	assert.Equal(t, []string{"https://www.apache.org/licenses/LICENSE-2.0"}, result.Licenses)
}

func TestParser_XMLBomb_DoesNotOOM(t *testing.T) {
	// Create a POM that exceeds 1MB to test the size cap.
	filler := strings.Repeat("<dependency/>", 100000)
	pom := fmt.Sprintf(`<?xml version="1.0"?><project>%s</project>`, filler)
	_, err := parsePOM(strings.NewReader(pom))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestParser_DOCTYPEStripped(t *testing.T) {
	pom := `<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd">
<project>
  <licenses>
    <license><name>MIT</name></license>
  </licenses>
</project>`
	result, err := parsePOM(strings.NewReader(pom))
	require.NoError(t, err)
	assert.Equal(t, []string{"MIT"}, result.Licenses)
}

func TestParser_MalformedXML(t *testing.T) {
	_, err := parsePOM(strings.NewReader("this is not xml"))
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Cache tests
// ---------------------------------------------------------------------------

func TestCache_HitAndMiss(t *testing.T) {
	c := newPOMCache(10, 1*time.Hour)
	coords := Coords{GroupID: "org.apache", ArtifactID: "apache", Version: "23"}
	result := &pomResult{Licenses: []string{"Apache-2.0"}}

	// Miss
	assert.Nil(t, c.get(coords))

	// Put + hit
	c.put(coords, result)
	got := c.get(coords)
	require.NotNil(t, got)
	assert.Equal(t, []string{"Apache-2.0"}, got.Licenses)
}

func TestCache_TTLExpiration(t *testing.T) {
	c := newPOMCache(10, 1*time.Millisecond)
	coords := Coords{GroupID: "org.apache", ArtifactID: "apache", Version: "23"}
	c.put(coords, &pomResult{Licenses: []string{"Apache-2.0"}})

	time.Sleep(5 * time.Millisecond)
	assert.Nil(t, c.get(coords), "expired entry should return nil")
}

func TestCache_EvictsOldest(t *testing.T) {
	c := newPOMCache(2, 1*time.Hour)

	c1 := Coords{GroupID: "a", ArtifactID: "1", Version: "1"}
	c2 := Coords{GroupID: "b", ArtifactID: "2", Version: "2"}
	c3 := Coords{GroupID: "c", ArtifactID: "3", Version: "3"}

	c.put(c1, &pomResult{Licenses: []string{"L1"}})
	time.Sleep(time.Millisecond) // ensure different insertion times
	c.put(c2, &pomResult{Licenses: []string{"L2"}})
	time.Sleep(time.Millisecond)
	c.put(c3, &pomResult{Licenses: []string{"L3"}}) // should evict c1

	assert.Nil(t, c.get(c1), "oldest entry should be evicted")
	assert.NotNil(t, c.get(c2))
	assert.NotNil(t, c.get(c3))
}

// ---------------------------------------------------------------------------
// Resolver tests
// ---------------------------------------------------------------------------

func TestResolver_DirectLicenses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<?xml version="1.0"?>
<project>
  <licenses><license><name>MIT</name></license></licenses>
</project>`)
	}))
	defer srv.Close()

	resolver := NewResolver(srv.URL, srv.Client(), Config{MaxDepth: 5})
	licenses := resolver.Resolve(context.Background(), Coords{
		GroupID: "com.example", ArtifactID: "lib", Version: "1.0",
	})
	assert.Equal(t, []string{"MIT"}, licenses)
}

func TestResolver_ParentChain(t *testing.T) {
	// Simulate: child → parent → grandparent (with licenses)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "child"):
			fmt.Fprint(w, `<?xml version="1.0"?>
<project>
  <parent><groupId>com.example</groupId><artifactId>parent</artifactId><version>1.0</version></parent>
</project>`)
		case strings.Contains(r.URL.Path, "parent") && !strings.Contains(r.URL.Path, "grandparent"):
			fmt.Fprint(w, `<?xml version="1.0"?>
<project>
  <parent><groupId>com.example</groupId><artifactId>grandparent</artifactId><version>1.0</version></parent>
</project>`)
		case strings.Contains(r.URL.Path, "grandparent"):
			fmt.Fprint(w, `<?xml version="1.0"?>
<project>
  <licenses><license><name>Apache-2.0</name></license></licenses>
</project>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resolver := NewResolver(srv.URL, srv.Client(), Config{MaxDepth: 5})
	licenses := resolver.Resolve(context.Background(), Coords{
		GroupID: "com.example", ArtifactID: "child", Version: "1.0",
	})
	assert.Equal(t, []string{"Apache-2.0"}, licenses)
}

func TestResolver_DepthLimit(t *testing.T) {
	// Every POM points to the next level — resolver should stop at maxDepth.
	var depth int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d := atomic.AddInt32(&depth, 1)
		fmt.Fprintf(w, `<?xml version="1.0"?>
<project>
  <parent><groupId>com.example</groupId><artifactId>level%d</artifactId><version>1.0</version></parent>
</project>`, d+1)
	}))
	defer srv.Close()

	resolver := NewResolver(srv.URL, srv.Client(), Config{MaxDepth: 2})
	licenses := resolver.Resolve(context.Background(), Coords{
		GroupID: "com.example", ArtifactID: "level0", Version: "1.0",
	})
	assert.Nil(t, licenses, "should return nil when depth limit exceeded")
	assert.LessOrEqual(t, int(atomic.LoadInt32(&depth)), 3, "should not exceed max_depth+1 fetches")
}

func TestResolver_CycleDetection(t *testing.T) {
	// A → B → A (cycle)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "artifact-a") {
			fmt.Fprint(w, `<?xml version="1.0"?>
<project>
  <parent><groupId>com.example</groupId><artifactId>artifact-b</artifactId><version>1.0</version></parent>
</project>`)
		} else {
			fmt.Fprint(w, `<?xml version="1.0"?>
<project>
  <parent><groupId>com.example</groupId><artifactId>artifact-a</artifactId><version>1.0</version></parent>
</project>`)
		}
	}))
	defer srv.Close()

	resolver := NewResolver(srv.URL, srv.Client(), Config{MaxDepth: 10})
	licenses := resolver.Resolve(context.Background(), Coords{
		GroupID: "com.example", ArtifactID: "artifact-a", Version: "1.0",
	})
	assert.Nil(t, licenses, "should return nil on cycle")
}

func TestResolver_CacheHit(t *testing.T) {
	var fetchCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&fetchCount, 1)
		fmt.Fprint(w, `<?xml version="1.0"?>
<project>
  <licenses><license><name>MIT</name></license></licenses>
</project>`)
	}))
	defer srv.Close()

	resolver := NewResolver(srv.URL, srv.Client(), Config{MaxDepth: 5})
	coords := Coords{GroupID: "com.example", ArtifactID: "lib", Version: "1.0"}

	// First call — cache miss.
	licenses1 := resolver.Resolve(context.Background(), coords)
	assert.Equal(t, []string{"MIT"}, licenses1)
	assert.Equal(t, int32(1), atomic.LoadInt32(&fetchCount))

	// Second call — cache hit, no additional fetch.
	licenses2 := resolver.Resolve(context.Background(), coords)
	assert.Equal(t, []string{"MIT"}, licenses2)
	assert.Equal(t, int32(1), atomic.LoadInt32(&fetchCount), "second call should hit cache")
}

func TestResolver_NetworkFailure_FailsOpen(t *testing.T) {
	// Unreachable server — resolver should return nil (fail-open), not error.
	resolver := NewResolver("http://127.0.0.1:1", &http.Client{Timeout: 100 * time.Millisecond}, Config{
		MaxDepth:        5,
		ResolverTimeout: 500 * time.Millisecond,
		FetchTimeout:    200 * time.Millisecond,
	})
	licenses := resolver.Resolve(context.Background(), Coords{
		GroupID: "com.example", ArtifactID: "lib", Version: "1.0",
	})
	assert.Nil(t, licenses, "network failure should fail-open with nil licenses")
}

func TestResolver_HTTP404_FailsOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resolver := NewResolver(srv.URL, srv.Client(), Config{MaxDepth: 5})
	licenses := resolver.Resolve(context.Background(), Coords{
		GroupID: "com.example", ArtifactID: "nonexistent", Version: "1.0",
	})
	assert.Nil(t, licenses)
}

func TestResolver_NoLicensesNoParent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<?xml version="1.0"?>
<project>
  <groupId>com.example</groupId>
  <artifactId>orphan</artifactId>
  <version>1.0.0</version>
</project>`)
	}))
	defer srv.Close()

	resolver := NewResolver(srv.URL, srv.Client(), Config{MaxDepth: 5})
	licenses := resolver.Resolve(context.Background(), Coords{
		GroupID: "com.example", ArtifactID: "orphan", Version: "1.0.0",
	})
	assert.Nil(t, licenses)
}

func TestResolver_PomURL(t *testing.T) {
	resolver := NewResolver("https://repo1.maven.org/maven2", nil, Config{})
	url := resolver.pomURL(Coords{
		GroupID:    "com.mysql",
		ArtifactID: "mysql-connector-j",
		Version:    "8.4.0",
	})
	assert.Equal(t, "https://repo1.maven.org/maven2/com/mysql/mysql-connector-j/8.4.0/mysql-connector-j-8.4.0.pom", url)
}

func TestCoords_String(t *testing.T) {
	c := Coords{GroupID: "org.apache.commons", ArtifactID: "commons-lang3", Version: "3.14.0"}
	assert.Equal(t, "org.apache.commons:commons-lang3:3.14.0", c.String())
}

// ---------------------------------------------------------------------------
// Integration test (requires real Maven Central — skipped in CI)
// ---------------------------------------------------------------------------

func TestResolver_RealMavenCentral_MysqlConnectorJ(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	resolver := NewResolver(
		"https://repo1.maven.org/maven2",
		&http.Client{Timeout: 10 * time.Second},
		Config{MaxDepth: 5, FetchTimeout: 5 * time.Second, ResolverTimeout: 15 * time.Second},
	)

	// mysql-connector-j inherits GPL-2.0 from oss-parent/mysql-parent.
	licenses := resolver.Resolve(context.Background(), Coords{
		GroupID:    "com.mysql",
		ArtifactID: "mysql-connector-j",
		Version:    "8.4.0",
	})
	require.NotEmpty(t, licenses, "mysql-connector-j should have licenses via parent chain")
	// The exact license string is "The GNU General Public License, v2 with Universal FOSS Exception, v1.0"
	// (or similar). Just check it's non-empty — normalization happens downstream.
	t.Logf("mysql-connector-j licenses: %v", licenses)
}

func TestResolver_RealMavenCentral_CommonsLang3(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	resolver := NewResolver(
		"https://repo1.maven.org/maven2",
		&http.Client{Timeout: 10 * time.Second},
		Config{MaxDepth: 5, FetchTimeout: 5 * time.Second, ResolverTimeout: 15 * time.Second},
	)

	licenses := resolver.Resolve(context.Background(), Coords{
		GroupID:    "org.apache.commons",
		ArtifactID: "commons-lang3",
		Version:    "3.14.0",
	})
	require.NotEmpty(t, licenses)
	t.Logf("commons-lang3 licenses: %v", licenses)
}

func TestResolver_RealMavenCentral_Slf4jApi(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	resolver := NewResolver(
		"https://repo1.maven.org/maven2",
		&http.Client{Timeout: 10 * time.Second},
		Config{MaxDepth: 5, FetchTimeout: 5 * time.Second, ResolverTimeout: 15 * time.Second},
	)

	licenses := resolver.Resolve(context.Background(), Coords{
		GroupID:    "org.slf4j",
		ArtifactID: "slf4j-api",
		Version:    "1.7.36",
	})
	require.NotEmpty(t, licenses)
	t.Logf("slf4j-api licenses: %v", licenses)
}
