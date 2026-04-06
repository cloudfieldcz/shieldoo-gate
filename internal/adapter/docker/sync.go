package docker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// SyncService periodically re-pulls and re-scans upstream Docker images.
type SyncService struct {
	db             *config.GateDB
	cache          cache.CacheStore
	scanEngine     *scanner.Engine
	policyEng      *policy.Engine
	resolver       *RegistryResolver
	cfg            config.DockerSyncConfig
	sem            *semaphore.Weighted
	httpClient     *http.Client
	tokenExch      *tokenExchanger
	rescanInterval time.Duration
}

// NewSyncService creates a new sync service.
func NewSyncService(
	db *config.GateDB,
	cacheStore cache.CacheStore,
	scanEngine *scanner.Engine,
	policyEngine *policy.Engine,
	resolver *RegistryResolver,
	cfg config.DockerSyncConfig,
) *SyncService {
	maxConc := int64(cfg.MaxConcurrent)
	if maxConc <= 0 {
		maxConc = 3
	}
	rescanInterval, err := time.ParseDuration(cfg.RescanInterval)
	if err != nil {
		rescanInterval = 24 * time.Hour
	}
	httpClient := &http.Client{Timeout: 10 * time.Minute}
	return &SyncService{
		db:             db,
		cache:          cacheStore,
		scanEngine:     scanEngine,
		policyEng:      policyEngine,
		resolver:       resolver,
		cfg:            cfg,
		sem:            semaphore.NewWeighted(maxConc),
		httpClient:     httpClient,
		tokenExch:      newTokenExchanger(httpClient),
		rescanInterval: rescanInterval,
	}
}

// Start runs the sync loop until ctx is cancelled.
func (s *SyncService) Start(ctx context.Context) {
	interval, err := time.ParseDuration(s.cfg.Interval)
	if err != nil {
		interval = 6 * time.Hour
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Info().Dur("interval", interval).Msg("docker sync: service started")

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("docker sync: service stopped")
			return
		case <-ticker.C:
			s.syncAll(ctx)
		}
	}
}

// syncAll iterates all sync-enabled upstream repos and syncs them.
func (s *SyncService) syncAll(ctx context.Context) {
	repos, err := ListSyncableRepos(s.db)
	if err != nil {
		log.Error().Err(err).Msg("docker sync: failed to list repos")
		return
	}

	log.Info().Int("repos", len(repos)).Msg("docker sync: starting sync cycle")

	for _, repo := range repos {
		if ctx.Err() != nil {
			return
		}
		if err := s.sem.Acquire(ctx, 1); err != nil {
			return
		}
		go func(r DockerRepository) {
			defer s.sem.Release(1)
			s.syncRepository(ctx, r)
		}(repo)
	}
}

// SyncRepositoryByID loads a repository by ID and syncs it.
// Intended for manual sync triggers from the API.
func (s *SyncService) SyncRepositoryByID(ctx context.Context, repoID int64) {
	repo, err := GetRepositoryByID(s.db, repoID)
	if err != nil {
		log.Error().Err(err).Int64("repo_id", repoID).Msg("docker sync: failed to get repository for manual sync")
		return
	}
	s.syncRepository(ctx, *repo)
}

// syncRepository syncs a single repository by checking each tag against upstream.
func (s *SyncService) syncRepository(ctx context.Context, repo DockerRepository) {
	tags, err := ListTags(s.db, repo.ID)
	if err != nil {
		log.Error().Err(err).Int64("repo_id", repo.ID).Msg("docker sync: failed to list tags")
		return
	}

	if len(tags) == 0 {
		log.Debug().Str("repo", repo.Name).Msg("docker sync: no tags to sync")
		updateLastSyncedAt(s.db, repo.ID)
		return
	}

	// Resolve upstream URL for this repo.
	_, _, upstreamURL, err := s.resolver.Resolve(repo.Registry + "/" + repo.Name)
	if err != nil {
		// If the repo is on docker.io (default registry), the name doesn't have a registry prefix.
		_, _, upstreamURL, err = s.resolver.Resolve(repo.Name)
		if err != nil {
			log.Warn().Err(err).Str("repo", repo.Name).Msg("docker sync: cannot resolve upstream")
			return
		}
	}

	for _, tag := range tags {
		if ctx.Err() != nil {
			return
		}
		s.syncTag(ctx, repo, tag, upstreamURL)
	}

	updateLastSyncedAt(s.db, repo.ID)
}

// syncTag syncs a single tag: fetches upstream manifest, compares digest, re-scans if needed.
func (s *SyncService) syncTag(ctx context.Context, repo DockerRepository, tag DockerTag, upstreamURL string) {
	// Fetch manifest from upstream.
	manifestBytes, statusCode, err := s.fetchManifestForSync(ctx, upstreamURL, repo.Registry, repo.Name, tag.Tag)
	if err != nil {
		s.handleSyncError(repo, tag, statusCode, err)
		return
	}

	// Compute digest.
	h := sha256.Sum256(manifestBytes)
	upstreamDigest := "sha256:" + hex.EncodeToString(h[:])

	digestChanged := upstreamDigest != tag.ManifestDigest
	rescanDue := !digestChanged && tag.UpdatedAt.Add(s.rescanInterval).Before(time.Now().UTC())

	if !digestChanged && !rescanDue {
		log.Debug().
			Str("repo", repo.Name).
			Str("tag", tag.Tag).
			Msg("docker sync: tag unchanged and within rescan interval, skipping")
		return
	}

	reason := "digest changed"
	if !digestChanged && rescanDue {
		reason = "rescan interval elapsed"
	}
	log.Info().
		Str("repo", repo.Name).
		Str("tag", tag.Tag).
		Str("reason", reason).
		Msg("docker sync: re-scanning tag")

	// Audit log: tag digest mutation detected.
	if digestChanged {
		safeName := MakeSafeName(repo.Registry, repo.Name)
		tagArtifactID := fmt.Sprintf("docker:%s:%s", safeName, tag.Tag)
		metaJSON := fmt.Sprintf(`{"old_digest":%q,"new_digest":%q}`, tag.ManifestDigest, upstreamDigest)
		_ = adapter.WriteAuditLog(s.db, model.AuditEntry{
			EventType:    model.EventTagMutated,
			ArtifactID:   tagArtifactID,
			Reason:       "upstream digest changed",
			MetadataJSON: metaJSON,
		})
		// Record both old and new digests in tag_digest_history.
		if tag.ManifestDigest != "" {
			_ = adapter.RecordDigestHistory(s.db, "docker", safeName, tag.Tag, tag.ManifestDigest)
		}
		_ = adapter.RecordDigestHistory(s.db, "docker", safeName, tag.Tag, upstreamDigest)
	}

	// Build artifact for scanning.
	safeName := MakeSafeName(repo.Registry, repo.Name)
	artifactID := fmt.Sprintf("docker:%s:%s", safeName, tag.Tag)
	manifestSHA := hex.EncodeToString(h[:])

	// Write manifest to temp file for scanning.
	manifestTmp, err := writeManifestToTemp(manifestBytes)
	if err != nil {
		log.Error().Err(err).Str("repo", repo.Name).Str("tag", tag.Tag).Msg("docker sync: failed to write manifest temp file")
		return
	}
	defer os.Remove(manifestTmp)

	scanArtifact := scanner.Artifact{
		ID:          artifactID,
		Ecosystem:   scanner.EcosystemDocker,
		Name:        safeName,
		Version:     tag.Tag,
		LocalPath:   manifestTmp,
		SHA256:      manifestSHA,
		SizeBytes:   int64(len(manifestBytes)),
		UpstreamURL: upstreamURL + "/v2/" + repo.Name + "/manifests/" + tag.Tag,
	}

	// Scan. Failure fails open (log error, don't quarantine).
	scanResults, scanErr := s.scanEngine.ScanAll(ctx, scanArtifact)
	if scanErr != nil {
		log.Error().Err(scanErr).
			Str("artifact", artifactID).
			Msg("docker sync: scan engine error, failing open")
		scanResults = nil
	}

	// Policy evaluation.
	policyResult := s.policyEng.Evaluate(ctx, scanArtifact, scanResults)
	log.Info().
		Str("artifact", artifactID).
		Str("action", string(policyResult.Action)).
		Str("reason", policyResult.Reason).
		Msg("docker sync: policy decision")

	// Persist artifact and update tag.
	switch policyResult.Action {
	case policy.ActionQuarantine:
		now := time.Now().UTC()
		_ = s.persistArtifact(artifactID, scanArtifact, manifestSHA, int64(len(manifestBytes)),
			model.StatusQuarantined, policyResult.Reason, &now, scanResults)
		_ = adapter.WriteAuditLog(s.db, model.AuditEntry{
			EventType:  model.EventQuarantined,
			ArtifactID: artifactID,
			Reason:     policyResult.Reason,
		})
	case policy.ActionAllowWithWarning:
		_ = s.persistArtifact(artifactID, scanArtifact, manifestSHA, int64(len(manifestBytes)),
			model.StatusClean, "", nil, scanResults)
		_ = adapter.WriteAuditLog(s.db, model.AuditEntry{
			EventType:  model.EventAllowedWithWarning,
			ArtifactID: artifactID,
			Reason:     policyResult.Reason,
		})
	default:
		// ActionAllow or ActionBlock (block from sync just logs, doesn't quarantine)
		_ = s.persistArtifact(artifactID, scanArtifact, manifestSHA, int64(len(manifestBytes)),
			model.StatusClean, "", nil, scanResults)
	}

	// Update the tag digest (even if quarantined, we track the latest digest).
	if digestChanged {
		artIDPtr := artifactID
		_ = UpsertTag(s.db, repo.ID, tag.Tag, upstreamDigest, artIDPtr)
	}

	// Cache the manifest if allowed and cache is available.
	if (policyResult.Action == policy.ActionAllow || policyResult.Action == policy.ActionAllowWithWarning) && s.cache != nil {
		cacheTmp, err := writeManifestToTemp(manifestBytes)
		if err == nil {
			defer os.Remove(cacheTmp)
			cacheArtifact := scanner.Artifact{
				ID:        artifactID,
				Ecosystem: scanner.EcosystemDocker,
				Name:      safeName,
				Version:   tag.Tag,
				LocalPath: cacheTmp,
				SHA256:    manifestSHA,
				SizeBytes: int64(len(manifestBytes)),
			}
			_ = s.cache.Put(ctx, cacheArtifact, cacheTmp)
		}
	}
}

// fetchManifestForSync downloads a manifest from upstream for sync purposes.
// Returns (body, httpStatusCode, error). statusCode is 0 if the error is not HTTP-related.
// SECURITY: Uses per-registry credentials from config, NOT client Authorization header.
func (s *SyncService) fetchManifestForSync(ctx context.Context, upstreamURL, registryHost, name, ref string) ([]byte, int, error) {
	target := upstreamURL + "/v2/" + name + "/manifests/" + ref
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("docker sync: building request: %w", err)
	}

	// Request all common manifest types.
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.oci.image.index.v1+json",
	}, ", "))

	// SECURITY: Use per-registry credentials from config, NEVER forward client headers.
	if s.resolver != nil {
		if auth := s.resolver.AuthForRegistry(registryHost); auth != "" {
			req.Header.Set("Authorization", auth)
		}
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("docker sync: fetching manifest %s/%s:%s: %w", registryHost, name, ref, err)
	}

	// Handle 401 — Bearer token exchange (Docker Registry v2 auth flow).
	if resp.StatusCode == http.StatusUnauthorized && s.tokenExch != nil {
		wwwAuth := resp.Header.Get("Www-Authenticate")
		resp.Body.Close()
		realm, service, scope, ok := parseWwwAuthenticate(wwwAuth)
		if ok {
			token, tokenErr := s.tokenExch.exchangeToken(ctx, realm, service, scope)
			if tokenErr != nil {
				return nil, http.StatusUnauthorized, fmt.Errorf("docker sync: token exchange for %s/%s:%s: %w", registryHost, name, ref, tokenErr)
			}
			req2, err2 := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err2 != nil {
				return nil, 0, fmt.Errorf("docker sync: building retry request: %w", err2)
			}
			req2.Header.Set("Accept", req.Header.Get("Accept"))
			req2.Header.Set("Authorization", "Bearer "+token)
			resp, err = s.httpClient.Do(req2)
			if err != nil {
				return nil, 0, fmt.Errorf("docker sync: retry after token exchange %s/%s:%s: %w", registryHost, name, ref, err)
			}
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("docker sync: upstream returned %d for %s/%s:%s", resp.StatusCode, registryHost, name, ref)
	}

	const maxManifestSize = 10 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestSize))
	if err != nil {
		return nil, 0, fmt.Errorf("docker sync: reading manifest body: %w", err)
	}

	return body, http.StatusOK, nil
}

// handleSyncError handles errors from fetching a manifest during sync.
// Implements the error table: 404 disables sync, 429 logs with Retry-After, others log warning.
func (s *SyncService) handleSyncError(repo DockerRepository, tag DockerTag, statusCode int, err error) {
	switch statusCode {
	case http.StatusNotFound:
		log.Warn().
			Str("repo", repo.Name).
			Str("tag", tag.Tag).
			Msg("docker sync: upstream 404, disabling sync for repository")
		DisableSync(s.db, repo.ID)

	case http.StatusTooManyRequests:
		log.Warn().
			Str("repo", repo.Name).
			Str("tag", tag.Tag).
			Msg("docker sync: upstream 429 (rate limited), skipping")
		// Retry-After handling is done at the caller level if needed.

	default:
		log.Warn().Err(err).
			Str("repo", repo.Name).
			Str("tag", tag.Tag).
			Int("status_code", statusCode).
			Msg("docker sync: upstream error, skipping tag")
	}
}

// persistArtifact writes the artifact, status, and scan results to the DB.
func (s *SyncService) persistArtifact(
	artifactID string,
	sa scanner.Artifact,
	manifestSHA string,
	manifestSize int64,
	status model.Status,
	quarantineReason string,
	quarantinedAt *time.Time,
	scanResults []scanner.ScanResult,
) error {
	now := time.Now().UTC()
	art := model.Artifact{
		Ecosystem:      string(sa.Ecosystem),
		Name:           sa.Name,
		Version:        sa.Version,
		UpstreamURL:    sa.UpstreamURL,
		SHA256:         manifestSHA,
		SizeBytes:      manifestSize,
		CachedAt:       now,
		LastAccessedAt: now,
		StoragePath:    sa.LocalPath,
	}
	artStatus := model.ArtifactStatus{
		ArtifactID:       artifactID,
		Status:           status,
		QuarantineReason: quarantineReason,
		QuarantinedAt:    quarantinedAt,
	}
	if err := adapter.InsertArtifact(s.db, artifactID, art, artStatus); err != nil {
		return err
	}
	return adapter.InsertScanResults(s.db, artifactID, scanResults)
}

// ListSyncableRepos returns repos that are sync-enabled and not internal.
func ListSyncableRepos(db *config.GateDB) ([]DockerRepository, error) {
	var repos []DockerRepository
	return repos, db.Select(&repos,
		"SELECT "+repoColumns+" FROM docker_repositories WHERE sync_enabled = TRUE AND is_internal = FALSE ORDER BY last_synced_at ASC")
}

// DisableSync sets sync_enabled=false for a repository.
func DisableSync(db *config.GateDB, repoID int64) {
	_, err := db.Exec("UPDATE docker_repositories SET sync_enabled = FALSE WHERE id = ?", repoID)
	if err != nil {
		log.Error().Err(err).Int64("repo_id", repoID).Msg("docker sync: failed to disable sync")
	}
}

// updateLastSyncedAt updates the last_synced_at timestamp for a repository.
func updateLastSyncedAt(db *config.GateDB, repoID int64) {
	now := time.Now().UTC()
	_, err := db.Exec("UPDATE docker_repositories SET last_synced_at = ? WHERE id = ?", now, repoID)
	if err != nil {
		log.Error().Err(err).Int64("repo_id", repoID).Msg("docker sync: failed to update last_synced_at")
	}
}

// ParseRetryAfter parses the Retry-After header value and returns a duration to wait.
func ParseRetryAfter(value string) time.Duration {
	if value == "" {
		return 30 * time.Second
	}
	// Try as seconds first.
	if seconds, err := strconv.Atoi(value); err == nil {
		return time.Duration(seconds) * time.Second
	}
	// Try as HTTP-date.
	if t, err := http.ParseTime(value); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
	}
	return 30 * time.Second
}
