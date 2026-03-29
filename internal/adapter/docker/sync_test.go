package docker_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

func TestSyncService_StartsAndStops(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)

	cfg := config.DockerSyncConfig{
		Enabled:        true,
		Interval:       "100ms",
		RescanInterval: "10s",
		MaxConcurrent:  2,
	}

	resolver := docker.NewRegistryResolver(config.DockerUpstreamConfig{})
	svc := docker.NewSyncService(db, nil, nil, nil, resolver, cfg)
	ctx, cancel := context.WithCancel(context.Background())

	go svc.Start(ctx)
	time.Sleep(200 * time.Millisecond)
	cancel()
	// Should not panic or deadlock.
}

func TestSyncService_StartsAndStops_DefaultInterval(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)

	cfg := config.DockerSyncConfig{
		Enabled:        true,
		Interval:       "invalid",
		RescanInterval: "10s",
		MaxConcurrent:  0, // should default to 3
	}

	resolver := docker.NewRegistryResolver(config.DockerUpstreamConfig{})
	svc := docker.NewSyncService(db, nil, nil, nil, resolver, cfg)
	ctx, cancel := context.WithCancel(context.Background())

	go svc.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	cancel()
}

func TestListSyncableRepos_FiltersCorrectly(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	// Create upstream repo (sync_enabled=true by default for non-internal)
	_, err = docker.EnsureRepository(db, "docker.io", "library/nginx", false)
	require.NoError(t, err)

	// Create internal repo (sync_enabled=false for internal)
	_, err = docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)

	repos, err := docker.ListSyncableRepos(db)
	require.NoError(t, err)
	assert.Len(t, repos, 1)
	assert.Equal(t, "library/nginx", repos[0].Name)
}

func TestSyncService_SyncRepository_DetectsChange(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)

	// Create mock upstream that returns a known manifest.
	newManifest := []byte(`{"schemaVersion":2,"config":{"digest":"sha256:newdigest"}}`)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.WriteHeader(http.StatusOK)
		w.Write(newManifest)
	}))
	defer ts.Close()

	dockerCfg := config.DockerUpstreamConfig{
		DefaultRegistry: ts.URL,
	}
	resolver := docker.NewRegistryResolver(dockerCfg)

	repo, err := docker.EnsureRepository(db, "docker.io", "library/nginx", false)
	require.NoError(t, err)
	err = docker.UpsertTag(db, repo.ID, "latest", "sha256:olddigest", "")
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
	}, db)

	cfg := config.DockerSyncConfig{
		Enabled:        true,
		Interval:       "200ms",
		RescanInterval: "1s",
		MaxConcurrent:  1,
	}

	svc := docker.NewSyncService(db, nil, scanEngine, policyEngine, resolver, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	go svc.Start(ctx)
	time.Sleep(500 * time.Millisecond)
	cancel()

	// Allow goroutines to finish.
	time.Sleep(100 * time.Millisecond)

	// The tag should now have the new digest.
	tags, err := docker.ListTags(db, repo.ID)
	require.NoError(t, err)
	require.Len(t, tags, 1)

	h := sha256.Sum256(newManifest)
	expectedDigest := "sha256:" + hex.EncodeToString(h[:])
	assert.Equal(t, expectedDigest, tags[0].ManifestDigest)
}

func TestSyncService_SyncRepository_NoChange_SkipsRescan(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)

	// The manifest that upstream returns.
	manifest := []byte(`{"schemaVersion":2,"config":{"digest":"sha256:samedigest"}}`)
	h := sha256.Sum256(manifest)
	currentDigest := "sha256:" + hex.EncodeToString(h[:])

	var requestCount int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.WriteHeader(http.StatusOK)
		w.Write(manifest)
	}))
	defer ts.Close()

	dockerCfg := config.DockerUpstreamConfig{
		DefaultRegistry: ts.URL,
	}
	resolver := docker.NewRegistryResolver(dockerCfg)

	repo, err := docker.EnsureRepository(db, "docker.io", "library/nginx", false)
	require.NoError(t, err)
	err = docker.UpsertTag(db, repo.ID, "latest", currentDigest, "")
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
	}, db)

	cfg := config.DockerSyncConfig{
		Enabled:        true,
		Interval:       "200ms",
		RescanInterval: "1h", // Long rescan interval — should skip.
		MaxConcurrent:  1,
	}

	svc := docker.NewSyncService(db, nil, scanEngine, policyEngine, resolver, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go svc.Start(ctx)
	time.Sleep(400 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	// The upstream was contacted to fetch the manifest.
	assert.GreaterOrEqual(t, atomic.LoadInt64(&requestCount), int64(1))

	// Tag digest should remain unchanged.
	tags, err := docker.ListTags(db, repo.ID)
	require.NoError(t, err)
	require.Len(t, tags, 1)
	assert.Equal(t, currentDigest, tags[0].ManifestDigest)
}

func TestSyncService_SyncRepository_Upstream404_DisablesSync(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	dockerCfg := config.DockerUpstreamConfig{
		DefaultRegistry: ts.URL,
	}
	resolver := docker.NewRegistryResolver(dockerCfg)

	repo, err := docker.EnsureRepository(db, "docker.io", "library/nginx", false)
	require.NoError(t, err)
	err = docker.UpsertTag(db, repo.ID, "latest", "sha256:abc123", "")
	require.NoError(t, err)

	// Verify sync is enabled before.
	repos, err := docker.ListSyncableRepos(db)
	require.NoError(t, err)
	assert.Len(t, repos, 1)

	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
	}, db)

	cfg := config.DockerSyncConfig{
		Enabled:        true,
		Interval:       "200ms",
		RescanInterval: "10s",
		MaxConcurrent:  1,
	}

	svc := docker.NewSyncService(db, nil, scanEngine, policyEngine, resolver, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go svc.Start(ctx)
	time.Sleep(400 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	// After 404, sync should be disabled.
	repos, err = docker.ListSyncableRepos(db)
	require.NoError(t, err)
	assert.Len(t, repos, 0, "sync should be disabled after 404")
}

func TestSyncService_SyncRepository_Upstream429_SkipsTag(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	dockerCfg := config.DockerUpstreamConfig{
		DefaultRegistry: ts.URL,
	}
	resolver := docker.NewRegistryResolver(dockerCfg)

	repo, err := docker.EnsureRepository(db, "docker.io", "library/nginx", false)
	require.NoError(t, err)
	err = docker.UpsertTag(db, repo.ID, "latest", "sha256:abc123", "")
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
	}, db)

	cfg := config.DockerSyncConfig{
		Enabled:        true,
		Interval:       "200ms",
		RescanInterval: "10s",
		MaxConcurrent:  1,
	}

	svc := docker.NewSyncService(db, nil, scanEngine, policyEngine, resolver, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go svc.Start(ctx)
	time.Sleep(400 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	// Sync should still be enabled (429 does not disable).
	repos, err := docker.ListSyncableRepos(db)
	require.NoError(t, err)
	assert.Len(t, repos, 1, "sync should still be enabled after 429")
}

func TestSyncService_SyncRepository_UpstreamUnreachable_SkipsRepo(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)

	// Use an unreachable URL.
	dockerCfg := config.DockerUpstreamConfig{
		DefaultRegistry: "http://127.0.0.1:1", // Unreachable port.
	}
	resolver := docker.NewRegistryResolver(dockerCfg)

	repo, err := docker.EnsureRepository(db, "docker.io", "library/nginx", false)
	require.NoError(t, err)
	err = docker.UpsertTag(db, repo.ID, "latest", "sha256:abc123", "")
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
	}, db)

	cfg := config.DockerSyncConfig{
		Enabled:        true,
		Interval:       "200ms",
		RescanInterval: "10s",
		MaxConcurrent:  1,
	}

	svc := docker.NewSyncService(db, nil, scanEngine, policyEngine, resolver, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go svc.Start(ctx)
	time.Sleep(400 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	// Sync should still be enabled (unreachable does not disable).
	repos, err := docker.ListSyncableRepos(db)
	require.NoError(t, err)
	assert.Len(t, repos, 1, "sync should still be enabled after unreachable upstream")
}

func TestDisableSync_SetsSyncEnabledFalse(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "docker.io", "library/nginx", false)
	require.NoError(t, err)
	assert.True(t, repo.SyncEnabled)

	docker.DisableSync(db, repo.ID)

	repos, err := docker.ListSyncableRepos(db)
	require.NoError(t, err)
	assert.Len(t, repos, 0)
}

func TestParseRetryAfter_Seconds(t *testing.T) {
	d := docker.ParseRetryAfter("120")
	assert.Equal(t, 120*time.Second, d)
}

func TestParseRetryAfter_Empty(t *testing.T) {
	d := docker.ParseRetryAfter("")
	assert.Equal(t, 30*time.Second, d)
}

func TestParseRetryAfter_Invalid(t *testing.T) {
	d := docker.ParseRetryAfter("not-a-number")
	assert.Equal(t, 30*time.Second, d)
}

func TestSyncService_RescanInterval_Elapsed_TriggersRescan(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)

	// Manifest that upstream returns (same as what's stored).
	manifest := []byte(`{"schemaVersion":2,"same":true}`)
	h := sha256.Sum256(manifest)
	currentDigest := "sha256:" + hex.EncodeToString(h[:])

	var scanCalled int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&scanCalled, 1)
		w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
		w.WriteHeader(http.StatusOK)
		w.Write(manifest)
	}))
	defer ts.Close()

	dockerCfg := config.DockerUpstreamConfig{
		DefaultRegistry: ts.URL,
	}
	resolver := docker.NewRegistryResolver(dockerCfg)

	repo, err := docker.EnsureRepository(db, "docker.io", "library/nginx", false)
	require.NoError(t, err)

	err = docker.UpsertTag(db, repo.ID, "latest", currentDigest, "")
	require.NoError(t, err)

	// Backdate the updated_at to make it past rescan interval.
	_, err = db.Exec("UPDATE docker_tags SET updated_at = ? WHERE repo_id = ? AND tag = ?",
		time.Now().UTC().Add(-2*time.Hour), repo.ID, "latest")
	require.NoError(t, err)

	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
	}, db)

	cfg := config.DockerSyncConfig{
		Enabled:        true,
		Interval:       "200ms",
		RescanInterval: "1s", // 1s rescan, but updated_at is 2h ago.
		MaxConcurrent:  1,
	}

	svc := docker.NewSyncService(db, nil, scanEngine, policyEngine, resolver, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go svc.Start(ctx)
	time.Sleep(400 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	assert.Greater(t, atomic.LoadInt64(&scanCalled), int64(0), "upstream should have been contacted for rescan")

	// Since the digest didn't change, the tag should keep same digest.
	tags, err := docker.ListTags(db, repo.ID)
	require.NoError(t, err)
	require.Len(t, tags, 1)
	assert.Equal(t, currentDigest, tags[0].ManifestDigest)
}

func TestSyncService_MultipleRepos_ConcurrentSync(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()
	db.SetMaxOpenConns(1)

	manifest := []byte(`{"schemaVersion":2}`)
	var requestCount int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requestCount, 1)
		w.WriteHeader(http.StatusOK)
		w.Write(manifest)
	}))
	defer ts.Close()

	dockerCfg := config.DockerUpstreamConfig{
		DefaultRegistry: ts.URL,
	}
	resolver := docker.NewRegistryResolver(dockerCfg)

	// Create two repos.
	for _, name := range []string{"library/nginx", "library/alpine"} {
		repo, err := docker.EnsureRepository(db, "docker.io", name, false)
		require.NoError(t, err)
		err = docker.UpsertTag(db, repo.ID, "latest", "sha256:old", "")
		require.NoError(t, err)
	}

	scanEngine := scanner.NewEngine(nil, 30*time.Second)
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.VerdictMalicious,
		QuarantineIfVerdict: scanner.VerdictSuspicious,
	}, db)

	cfg := config.DockerSyncConfig{
		Enabled:        true,
		Interval:       "200ms",
		RescanInterval: "10s",
		MaxConcurrent:  2,
	}

	svc := docker.NewSyncService(db, nil, scanEngine, policyEngine, resolver, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go svc.Start(ctx)
	time.Sleep(400 * time.Millisecond)
	cancel()
	time.Sleep(100 * time.Millisecond)

	// Both repos should have been synced (manifests fetched for each tag).
	assert.GreaterOrEqual(t, atomic.LoadInt64(&requestCount), int64(2),
		fmt.Sprintf("expected at least 2 requests, got %d", atomic.LoadInt64(&requestCount)))
}
