// Package gcs implements the cache.CacheStore interface using Google Cloud Storage.
package gcs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	gcsstorage "cloud.google.com/go/storage"
	"github.com/rs/zerolog/log"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface check.
var _ cache.CacheStore = (*GCSCacheStore)(nil)

// GCSCacheStore stores cached artifacts in a Google Cloud Storage bucket.
type GCSCacheStore struct {
	client *gcsstorage.Client
	bucket string
	prefix string

	// Cached stats with periodic refresh to avoid expensive list operations.
	statsMu        sync.RWMutex
	cachedStats    cache.CacheStats
	statsRefreshAt time.Time
}

const statsRefreshInterval = 5 * time.Minute

// NewGCSCacheStore creates a new GCSCacheStore from the given config.
// Authentication uses:
//  1. Explicit credentials file if CredentialsFile is set
//  2. GOOGLE_APPLICATION_CREDENTIALS env var or default credentials (workload identity)
func NewGCSCacheStore(cfg config.GCSCacheConfig) (*GCSCacheStore, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("gcs cache: bucket is required")
	}

	ctx := context.Background()

	var opts []option.ClientOption
	if cfg.CredentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(cfg.CredentialsFile))
	}

	client, err := gcsstorage.NewClient(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcs cache: creating client: %w", err)
	}

	store := &GCSCacheStore{
		client: client,
		bucket: cfg.Bucket,
		prefix: strings.TrimSuffix(cfg.Prefix, "/"),
	}

	log.Info().
		Str("bucket", cfg.Bucket).
		Str("prefix", cfg.Prefix).
		Str("credentials_file", cfg.CredentialsFile).
		Msg("gcs cache store initialized")

	return store, nil
}

// objectKey builds the GCS object key for an artifact.
// Format: {prefix}/{ecosystem}/{name}/{version}/{sha256}
func (s *GCSCacheStore) objectKey(eco, name, version, sha string) string {
	parts := []string{eco, name, version, sha}
	key := strings.Join(parts, "/")
	if s.prefix != "" {
		key = s.prefix + "/" + key
	}
	return key
}

// objectKeyPrefixFromID builds a key prefix from an artifact ID (eco:name:version).
func (s *GCSCacheStore) objectKeyPrefixFromID(artifactID string) (string, error) {
	eco, name, version, err := parseArtifactID(artifactID)
	if err != nil {
		return "", err
	}
	prefix := strings.Join([]string{eco, name, version}, "/")
	if s.prefix != "" {
		prefix = s.prefix + "/" + prefix
	}
	return prefix + "/", nil
}

// parseArtifactID splits "eco:name:version" into its three components.
func parseArtifactID(artifactID string) (eco, name, version string, err error) {
	parts := strings.SplitN(artifactID, ":", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("gcs cache: invalid artifact ID %q: expected eco:name:version", artifactID)
	}
	return parts[0], parts[1], parts[2], nil
}

// Put uploads a local file to GCS.
func (s *GCSCacheStore) Put(ctx context.Context, artifact scanner.Artifact, localPath string) error {
	eco := string(artifact.Ecosystem)
	name := artifact.Name
	version := artifact.Version
	sha := artifact.SHA256

	if sha == "" {
		computed, err := computeFileSHA256(localPath)
		if err != nil {
			return fmt.Errorf("gcs cache: computing SHA256 for %s: %w", localPath, err)
		}
		sha = computed
	}

	key := s.objectKey(eco, name, version, sha)

	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("gcs cache: opening local file %s: %w", localPath, err)
	}
	defer f.Close()

	writer := s.client.Bucket(s.bucket).Object(key).NewWriter(ctx)
	if _, err := io.Copy(writer, f); err != nil {
		writer.Close()
		return fmt.Errorf("gcs cache: uploading %s to gs://%s/%s: %w", localPath, s.bucket, key, err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("gcs cache: finalizing upload to gs://%s/%s: %w", s.bucket, key, err)
	}

	log.Debug().
		Str("key", key).
		Str("bucket", s.bucket).
		Str("sha256", sha).
		Msg("gcs cache: artifact uploaded")

	return nil
}

// Get downloads the artifact from GCS to a temp file and returns the temp path.
// MANDATORY: SHA256 integrity is verified after download. If the hash in the
// object key does not match the downloaded content, the temp file is removed
// and an error is returned.
func (s *GCSCacheStore) Get(ctx context.Context, artifactID string) (string, error) {
	prefix, err := s.objectKeyPrefixFromID(artifactID)
	if err != nil {
		return "", err
	}

	// List objects under the artifact prefix to find the actual key (which includes sha256).
	it := s.client.Bucket(s.bucket).Objects(ctx, &gcsstorage.Query{
		Prefix: prefix,
	})

	attrs, err := it.Next()
	if errors.Is(err, iterator.Done) {
		return "", cache.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("gcs cache: listing objects for %s: %w", artifactID, err)
	}

	key := attrs.Name

	// Extract expected SHA256 from the key (last path segment).
	keyParts := strings.Split(key, "/")
	expectedSHA := keyParts[len(keyParts)-1]

	// Download to temp file.
	reader, err := s.client.Bucket(s.bucket).Object(key).NewReader(ctx)
	if err != nil {
		return "", fmt.Errorf("gcs cache: downloading gs://%s/%s: %w", s.bucket, key, err)
	}
	defer reader.Close()

	tmpFile, err := os.CreateTemp("", "shieldoo-gcs-cache-*")
	if err != nil {
		return "", fmt.Errorf("gcs cache: creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Write and compute SHA256 simultaneously.
	hasher := sha256.New()
	writer := io.MultiWriter(tmpFile, hasher)

	if _, err := io.Copy(writer, reader); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("gcs cache: writing temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("gcs cache: closing temp file: %w", err)
	}

	// SECURITY: Verify SHA256 integrity.
	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if expectedSHA != "" && actualSHA != expectedSHA {
		os.Remove(tmpPath)
		log.Error().
			Str("artifact_id", artifactID).
			Str("expected_sha256", expectedSHA).
			Str("actual_sha256", actualSHA).
			Msg("CRITICAL: gcs cache integrity check failed — downloaded content does not match expected SHA256")
		return "", fmt.Errorf("gcs cache: integrity check failed for %s: expected SHA256 %s, got %s", artifactID, expectedSHA, actualSHA)
	}

	log.Debug().
		Str("artifact_id", artifactID).
		Str("tmp_path", tmpPath).
		Msg("gcs cache: artifact downloaded and verified")

	// Schedule background cleanup of temp file after 5 minutes.
	go func() {
		time.Sleep(5 * time.Minute)
		if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
			log.Warn().Err(err).Str("path", tmpPath).Msg("gcs cache: failed to clean up temp file")
		}
	}()

	return tmpPath, nil
}

// Delete removes the artifact object(s) from GCS.
func (s *GCSCacheStore) Delete(ctx context.Context, artifactID string) error {
	prefix, err := s.objectKeyPrefixFromID(artifactID)
	if err != nil {
		return err
	}

	it := s.client.Bucket(s.bucket).Objects(ctx, &gcsstorage.Query{
		Prefix: prefix,
	})

	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return fmt.Errorf("gcs cache: listing objects for delete %s: %w", artifactID, err)
		}

		if err := s.client.Bucket(s.bucket).Object(attrs.Name).Delete(ctx); err != nil {
			return fmt.Errorf("gcs cache: deleting gs://%s/%s: %w", s.bucket, attrs.Name, err)
		}
	}

	return nil
}

// List returns artifactIDs matching the optional filter.
func (s *GCSCacheStore) List(ctx context.Context, filter cache.CacheFilter) ([]string, error) {
	listPrefix := ""
	if s.prefix != "" {
		listPrefix = s.prefix + "/"
	}
	if filter.Ecosystem != "" {
		listPrefix += filter.Ecosystem + "/"
		if filter.Name != "" {
			listPrefix += filter.Name + "/"
		}
	}

	var ids []string
	seen := make(map[string]bool)

	it := s.client.Bucket(s.bucket).Objects(ctx, &gcsstorage.Query{
		Prefix: listPrefix,
	})

	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("gcs cache: listing objects: %w", err)
		}

		key := attrs.Name
		rel := key
		if s.prefix != "" {
			rel = strings.TrimPrefix(key, s.prefix+"/")
		}

		parts := strings.Split(rel, "/")
		if len(parts) < 4 {
			continue
		}
		eco, name, version := parts[0], parts[1], parts[2]

		id := eco + ":" + name + ":" + version
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}

	return ids, nil
}

// Stats returns aggregate cache statistics. Results are cached in memory
// and refreshed at most every 5 minutes to avoid expensive list operations.
func (s *GCSCacheStore) Stats(ctx context.Context) (cache.CacheStats, error) {
	s.statsMu.RLock()
	if time.Now().Before(s.statsRefreshAt) {
		stats := s.cachedStats
		s.statsMu.RUnlock()
		return stats, nil
	}
	s.statsMu.RUnlock()

	stats := cache.CacheStats{
		ByEcosystem: make(map[string]int64),
	}

	listPrefix := ""
	if s.prefix != "" {
		listPrefix = s.prefix + "/"
	}

	it := s.client.Bucket(s.bucket).Objects(ctx, &gcsstorage.Query{
		Prefix: listPrefix,
	})

	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return cache.CacheStats{}, fmt.Errorf("gcs cache: stats listing: %w", err)
		}

		stats.TotalItems++
		stats.TotalBytes += attrs.Size

		key := attrs.Name
		rel := key
		if s.prefix != "" {
			rel = strings.TrimPrefix(key, s.prefix+"/")
		}
		parts := strings.Split(rel, "/")
		if len(parts) >= 1 {
			stats.ByEcosystem[parts[0]] += attrs.Size
		}
	}

	s.statsMu.Lock()
	s.cachedStats = stats
	s.statsRefreshAt = time.Now().Add(statsRefreshInterval)
	s.statsMu.Unlock()

	return stats, nil
}

// computeFileSHA256 computes the SHA256 hex digest of a file.
func computeFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
