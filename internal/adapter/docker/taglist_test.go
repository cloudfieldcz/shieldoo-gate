package docker_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// tagListRequest records what the mock upstream registry was asked for.
type tagListRequest struct {
	path          string
	query         string
	accept        string
	authorization string
}

// setupTagListAdapter wires an adapter whose default registry and single
// allowed registry ("ghcr.io") both point at the same mock upstream, so a test
// can assert which upstream path a client request resolved to. pushEnabled
// turns on the internal (pushed) namespace path.
func setupTagListAdapter(t *testing.T, pushEnabled bool, upstream http.HandlerFunc) (*docker.DockerAdapter, *config.GateDB, *[]tagListRequest) {
	t.Helper()

	seen := &[]tagListRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, tagListRequest{
			path:          r.URL.Path,
			query:         r.URL.RawQuery,
			accept:        r.Header.Get("Accept"),
			authorization: r.Header.Get("Authorization"),
		})
		upstream(w, r)
	}))
	t.Cleanup(srv.Close)

	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cacheStore, err := local.NewLocalCacheStore(t.TempDir(), 10)
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second, 0)
	policyEngine := policy.NewEngine(policy.EngineConfig{}, nil)
	cfg := config.DockerUpstreamConfig{
		DefaultRegistry: srv.URL,
		AllowedRegistries: []config.DockerRegistryEntry{
			{Host: "ghcr.io", URL: srv.URL},
		},
		Push: config.DockerPushConfig{Enabled: pushEnabled},
	}

	if pushEnabled {
		blobBackend, err := local.NewLocalCacheStore(t.TempDir(), 0)
		require.NoError(t, err)
		blobStore := docker.NewBlobStore(blobBackend, "docker-push")
		return docker.NewDockerAdapterWithPush(db, cacheStore, scanEngine, policyEngine, cfg, blobStore), db, seen
	}
	return docker.NewDockerAdapter(db, cacheStore, cacheStore, scanEngine, policyEngine, cfg), db, seen
}

// writeTagList is a mock upstream that answers a fixed OCI tag list.
func writeTagList(name string, tags ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"name": name, "tags": tags})
	}
}

func decodeTagList(t *testing.T, body []byte) (string, []string) {
	t.Helper()
	var got struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	require.NoError(t, json.Unmarshal(body, &got))
	return got.Name, got.Tags
}

func TestDockerAdapter_TagsList_BareName_ProxiesDockerHubLibraryPath(t *testing.T) {
	a, _, seen := setupTagListAdapter(t, false, writeTagList("library/python", "3.13", "3.14"))

	req := httptest.NewRequest(http.MethodGet, "/v2/python/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, *seen, 1)
	assert.Equal(t, "/v2/library/python/tags/list", (*seen)[0].path)
	name, tags := decodeTagList(t, w.Body.Bytes())
	assert.Equal(t, []string{"3.13", "3.14"}, tags)
	// The name is reported as the client asked for it (upstream says
	// "library/python"), matching the rewritten Link and the internal path.
	assert.Equal(t, "python", name)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "registry/2.0", w.Header().Get("Docker-Distribution-API-Version"))
}

func TestDockerAdapter_TagsList_HostileUpstreamContentType_ForcedToJSON(t *testing.T) {
	// A 200 body is decoded and re-encoded, so an upstream cannot deliver HTML
	// (or any other renderable media type) through the gate's own origin.
	a, _, _ := setupTagListAdapter(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"library/python","tags":["3.13"],"extra":"<script>alert(1)</script>"}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/python/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
	assert.NotContains(t, w.Body.String(), "script", "only name and tags are re-emitted")
	_, tags := decodeTagList(t, w.Body.Bytes())
	assert.Equal(t, []string{"3.13"}, tags)
}

func TestDockerAdapter_TagsList_UpstreamBodyNotATagList_Returns502(t *testing.T) {
	a, _, _ := setupTagListAdapter(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>not a registry</body></html>"))
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/python/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadGateway, w.Code, "a 200 that is not an OCI tag list must fail closed")
	assert.NotContains(t, w.Body.String(), "not a registry")
}

func TestDockerAdapter_TagsList_UpstreamBodyOverCap_Returns502(t *testing.T) {
	a, _, _ := setupTagListAdapter(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"x","tags":["`))
		padding := bytes.Repeat([]byte("a"), 1<<20)
		for i := 0; i < 9; i++ {
			_, _ = w.Write(padding)
		}
		_, _ = w.Write([]byte(`"]}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/python/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadGateway, w.Code)
}

func TestDockerAdapter_TagsList_UpstreamNullTags_ServesEmptyArray(t *testing.T) {
	a, _, _ := setupTagListAdapter(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"name":"library/python","tags":null}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/python/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"tags":[]`)
}

func TestDockerAdapter_TagsList_UnknownQueryParams_NotForwardedUpstream(t *testing.T) {
	// `ns=` would make a mirror upstream resolve a namespace the resolver never
	// authorised; a token in the query would reach a third-party registry.
	a, _, seen := setupTagListAdapter(t, false, writeTagList("library/python", "3.13"))

	req := httptest.NewRequest(http.MethodGet, "/v2/python/tags/list?n=2&ns=evil.example.com&access_token=secret", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, *seen, 1)
	assert.Equal(t, "n=2", (*seen)[0].query)
}

func TestDockerAdapter_TagsList_AllowedRegistry_ProxiesRegistryPath(t *testing.T) {
	a, _, seen := setupTagListAdapter(t, false, writeTagList("org/img", "v1"))

	req := httptest.NewRequest(http.MethodGet, "/v2/ghcr.io/org/img/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, *seen, 1)
	assert.Equal(t, "/v2/org/img/tags/list", (*seen)[0].path)
}

func TestDockerAdapter_TagsList_NamespacedHubImage_ProxiesVerbatimPath(t *testing.T) {
	a, _, seen := setupTagListAdapter(t, false, writeTagList("bitnami/nginx", "latest"))

	req := httptest.NewRequest(http.MethodGet, "/v2/bitnami/nginx/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, *seen, 1)
	assert.Equal(t, "/v2/bitnami/nginx/tags/list", (*seen)[0].path)
}

func TestDockerAdapter_TagsList_DisallowedRegistry_Returns403AndAudits(t *testing.T) {
	a, db, seen := setupTagListAdapter(t, false, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be contacted for a disallowed registry")
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/evil.io/malware/pkg/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, *seen)

	var count int
	require.NoError(t, db.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE event_type = 'BLOCKED' AND artifact_id = ?`,
		"docker:evil.io/malware/pkg:tags-list").Scan(&count))
	assert.Equal(t, 1, count)
}

func TestDockerAdapter_TagsList_InvalidName_Returns400(t *testing.T) {
	a, _, seen := setupTagListAdapter(t, false, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be contacted for an invalid name")
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/a..b/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Empty(t, *seen)
}

func TestDockerAdapter_TagsList_EmptyName_Returns400(t *testing.T) {
	a, _, _ := setupTagListAdapter(t, false, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be contacted for an empty name")
	})

	req := httptest.NewRequest(http.MethodGet, "/v2//tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDockerAdapter_TagsList_PaginationQuery_ForwardedUpstream(t *testing.T) {
	a, _, seen := setupTagListAdapter(t, false, writeTagList("library/python", "3.13"))

	req := httptest.NewRequest(http.MethodGet, "/v2/python/tags/list?n=2&last=3.12", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, *seen, 1)
	assert.Equal(t, "last=3.12&n=2", (*seen)[0].query)
}

func TestDockerAdapter_TagsList_InvalidPageSize_Returns400(t *testing.T) {
	a, _, seen := setupTagListAdapter(t, false, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be contacted for an invalid n")
	})

	for _, query := range []string{"?n=abc", "?n=-1"} {
		req := httptest.NewRequest(http.MethodGet, "/v2/python/tags/list"+query, nil)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code, "query=%s", query)
	}
	assert.Empty(t, *seen)
}

func TestDockerAdapter_TagsList_UpstreamLinkHeader_RewrittenToClientName(t *testing.T) {
	a, _, _ := setupTagListAdapter(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `</v2/library/python/tags/list?n=2&last=3.13>; rel="next"`)
		writeTagList("library/python", "3.12", "3.13")(w, r)
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/python/tags/list?n=2", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, `</v2/python/tags/list?last=3.13&n=2>; rel="next"`, w.Header().Get("Link"))
}

func TestDockerAdapter_TagsList_ForeignLinkHeader_NotRelayed(t *testing.T) {
	a, _, _ := setupTagListAdapter(t, false, func(w http.ResponseWriter, r *http.Request) {
		// A link pointing at a different repository must never reach the client.
		w.Header().Set("Link", `</v2/library/other/tags/list?n=2>; rel="next"`)
		writeTagList("library/python", "3.13")(w, r)
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/python/tags/list?n=2", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Link"))
}

func TestDockerAdapter_TagsList_UpstreamUnauthorized_Returns403WithoutChallenge(t *testing.T) {
	a, _, _ := setupTagListAdapter(t, false, func(w http.ResponseWriter, r *http.Request) {
		// Unparseable challenge → no token exchange; the 401 reaches the handler.
		w.Header().Set("Www-Authenticate", "Basic realm=\"upstream\"")
		w.WriteHeader(http.StatusUnauthorized)
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/python/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Empty(t, w.Header().Get("Www-Authenticate"))
}

func TestDockerAdapter_TagsList_UpstreamForbidden_Returns403(t *testing.T) {
	a, _, _ := setupTagListAdapter(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/python/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "tag listing denied by upstream")
}

func TestDockerAdapter_TagsList_UpstreamNotFound_PassesThrough404(t *testing.T) {
	a, _, _ := setupTagListAdapter(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[{"code":"NAME_UNKNOWN"}]}`))
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/nope/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "NAME_UNKNOWN")
}

func TestDockerAdapter_TagsList_NeverForwardsClientAuthorization(t *testing.T) {
	a, _, seen := setupTagListAdapter(t, false, writeTagList("library/python", "3.13"))

	req := httptest.NewRequest(http.MethodGet, "/v2/python/tags/list", nil)
	req.Header.Set("Authorization", "Basic c2VjcmV0OnRva2Vu")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, *seen, 1)
	assert.Empty(t, (*seen)[0].authorization, "client Authorization must never reach the upstream")
}

func TestDockerAdapter_TagsList_HeadRequest_Returns404(t *testing.T) {
	// HEAD on tags/list is not part of the Distribution Spec; it stays a 404.
	a, _, _ := setupTagListAdapter(t, false, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be contacted for HEAD tags/list")
	})

	req := httptest.NewRequest(http.MethodHead, "/v2/python/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ---- internal (pushed) namespaces ----

func TestDockerAdapter_TagsList_InternalRepo_ServesTagsFromDB(t *testing.T) {
	a, db, seen := setupTagListAdapter(t, true, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be contacted for an internal repository")
	})

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)
	require.NoError(t, docker.UpsertTag(db, repo.ID, "v1.0", "sha256:aa", ""))
	require.NoError(t, docker.UpsertTag(db, repo.ID, "v2.0", "sha256:bb", ""))

	req := httptest.NewRequest(http.MethodGet, "/v2/myteam/myapp/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, *seen)
	name, tags := decodeTagList(t, w.Body.Bytes())
	assert.Equal(t, "myteam/myapp", name)
	assert.Equal(t, []string{"v1.0", "v2.0"}, tags)
	assert.Equal(t, "registry/2.0", w.Header().Get("Docker-Distribution-API-Version"))
	assert.Empty(t, w.Header().Get("Link"))
}

func TestDockerAdapter_TagsList_InternalRepoPaginated_ReturnsLinkHeader(t *testing.T) {
	a, db, _ := setupTagListAdapter(t, true, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be contacted for an internal repository")
	})

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)
	for _, tag := range []string{"v1.0", "v2.0", "v3.0"} {
		require.NoError(t, docker.UpsertTag(db, repo.ID, tag, "sha256:aa", ""))
	}

	req := httptest.NewRequest(http.MethodGet, "/v2/myteam/myapp/tags/list?n=2", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	_, tags := decodeTagList(t, w.Body.Bytes())
	assert.Equal(t, []string{"v1.0", "v2.0"}, tags)
	assert.Equal(t, `</v2/myteam/myapp/tags/list?n=2&last=v2.0>; rel="next"`, w.Header().Get("Link"))

	// Follow the cursor: the last page has no Link.
	req2 := httptest.NewRequest(http.MethodGet, "/v2/myteam/myapp/tags/list?n=2&last=v2.0", nil)
	w2 := httptest.NewRecorder()
	a.ServeHTTP(w2, req2)

	require.Equal(t, http.StatusOK, w2.Code)
	_, tags2 := decodeTagList(t, w2.Body.Bytes())
	assert.Equal(t, []string{"v3.0"}, tags2)
	assert.Empty(t, w2.Header().Get("Link"))
}

func TestDockerAdapter_TagsList_InternalRepoZeroPageSize_ReturnsEmptyList(t *testing.T) {
	a, db, _ := setupTagListAdapter(t, true, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be contacted for an internal repository")
	})

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)
	require.NoError(t, docker.UpsertTag(db, repo.ID, "v1.0", "sha256:aa", ""))

	req := httptest.NewRequest(http.MethodGet, "/v2/myteam/myapp/tags/list?n=0", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	_, tags := decodeTagList(t, w.Body.Bytes())
	assert.Empty(t, tags)
	assert.Empty(t, w.Header().Get("Link"))
}

func TestDockerAdapter_TagsList_InternalRepoInvalidPageSize_Returns400(t *testing.T) {
	a, db, _ := setupTagListAdapter(t, true, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be contacted for an internal repository")
	})

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)
	require.NoError(t, docker.UpsertTag(db, repo.ID, "v1.0", "sha256:aa", ""))

	req := httptest.NewRequest(http.MethodGet, "/v2/myteam/myapp/tags/list?n=nope", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDockerAdapter_TagsList_PushAllowedNameUpstreamUnauthorized_Returns404(t *testing.T) {
	// A push-allowed name that misses the internal store and cannot be
	// authenticated upstream is "no tags here" (404), not a denial — mirrors the
	// manifest HEAD path so push clients are not aborted by a leaked 401.
	a, _, _ := setupTagListAdapter(t, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Www-Authenticate", "Basic realm=\"upstream\"")
		w.WriteHeader(http.StatusUnauthorized)
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/myteam/never-pushed/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Empty(t, w.Header().Get("Www-Authenticate"))
}

func TestDockerAdapter_TagsList_UnknownInternalName_FallsThroughUpstream(t *testing.T) {
	// A push-allowed name with no internal repository is a pull-through
	// (e.g. bitnami/nginx on Docker Hub) — the upstream must answer.
	a, _, seen := setupTagListAdapter(t, true, writeTagList("bitnami/nginx", "latest"))

	req := httptest.NewRequest(http.MethodGet, "/v2/bitnami/nginx/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, *seen, 1)
	assert.Equal(t, "/v2/bitnami/nginx/tags/list", (*seen)[0].path)
}

func TestDockerAdapter_TagsList_InternalRepoWithoutTags_FallsThroughUpstream(t *testing.T) {
	a, db, seen := setupTagListAdapter(t, true, writeTagList("myteam/myapp", "upstream-tag"))

	_, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/v2/myteam/myapp/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, *seen, 1)
	_, tags := decodeTagList(t, w.Body.Bytes())
	assert.Equal(t, []string{"upstream-tag"}, tags)
}

func TestDockerAdapter_TagsList_PushDisabled_InternalNameGoesUpstream(t *testing.T) {
	a, db, seen := setupTagListAdapter(t, false, writeTagList("myteam/myapp", "upstream-tag"))

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)
	require.NoError(t, docker.UpsertTag(db, repo.ID, "v1.0", "sha256:aa", ""))

	req := httptest.NewRequest(http.MethodGet, "/v2/myteam/myapp/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, *seen, 1, "with push disabled the internal store is not consulted")
	_, tags := decodeTagList(t, w.Body.Bytes())
	assert.Equal(t, []string{"upstream-tag"}, tags)
}

func TestDockerAdapter_TagsList_UpstreamErrorBody_NotRenderable(t *testing.T) {
	a, _, _ := setupTagListAdapter(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<html>gone</html>"))
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/python/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
}

func TestDockerAdapter_TagsList_TyposquatName_Returns403BeforeUpstream(t *testing.T) {
	// A name the policy refuses to serve must not be enumerable either — and the
	// block must leave the same audit trail as a manifest pull.
	upstreamHit := false
	a, _, db := setupTestDockerWithTyposquat(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/v2/library/nginxx/tags/list", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.False(t, upstreamHit, "upstream must not be reached for a blocked typosquat")
	assert.Contains(t, w.Body.String(), "typosquatting detected")

	var count int
	require.NoError(t, db.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE event_type = 'BLOCKED' AND artifact_id = ?`,
		"docker:docker_io_library_nginxx:*").Scan(&count))
	assert.Equal(t, 1, count, "a blocked tag listing is audited like a blocked pull")
}

func TestDockerAdapter_TagsList_InternalRepoCursorPastEnd_ReturnsEmptyNotUpstream(t *testing.T) {
	// A cursor beyond the last tag is the end of pagination, not a reason to ask
	// the upstream (which would report a foreign repo under an internal name).
	a, db, seen := setupTagListAdapter(t, true, func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("upstream must not be contacted for a known internal repository")
	})

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)
	require.NoError(t, docker.UpsertTag(db, repo.ID, "v1.0", "sha256:aa", ""))

	req := httptest.NewRequest(http.MethodGet, "/v2/myteam/myapp/tags/list?last=zzz", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, *seen)
	_, tags := decodeTagList(t, w.Body.Bytes())
	assert.Empty(t, tags)
	assert.Empty(t, w.Header().Get("Link"))
}
