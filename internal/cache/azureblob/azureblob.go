// Package azureblob implements the cache.CacheStore interface using Azure Blob Storage.
package azureblob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface check.
var _ cache.CacheStore = (*AzureBlobStore)(nil)

// AzureBlobStore stores cached artifacts in an Azure Blob Storage container.
type AzureBlobStore struct {
	client        *azblob.Client
	containerName string
	prefix        string

	// Cached stats with periodic refresh to avoid expensive list operations.
	statsMu        sync.RWMutex
	cachedStats    cache.CacheStats
	statsRefreshAt time.Time
}

const statsRefreshInterval = 5 * time.Minute

// NewAzureBlobStore creates a new AzureBlobStore from the given config.
// Authentication is resolved in this order:
//  1. Connection string from the env var named in ConnectionStrEnv
//  2. DefaultAzureCredential (managed identity, CLI, env vars)
func NewAzureBlobStore(cfg config.AzureBlobConfig) (*AzureBlobStore, error) {
	if cfg.ContainerName == "" {
		return nil, fmt.Errorf("azure blob cache: container_name is required")
	}
	if cfg.AccountName == "" && cfg.ConnectionStrEnv == "" {
		return nil, fmt.Errorf("azure blob cache: account_name or connection_string_env is required")
	}

	var client *azblob.Client
	var err error

	// Try connection string first if configured.
	if cfg.ConnectionStrEnv != "" {
		connStr := os.Getenv(cfg.ConnectionStrEnv)
		if connStr == "" {
			log.Warn().Str("env_var", cfg.ConnectionStrEnv).Msg("azure blob cache: connection_string_env references an unset environment variable")
		}
		if connStr != "" {
			client, err = azblob.NewClientFromConnectionString(connStr, nil)
			if err != nil {
				return nil, fmt.Errorf("azure blob cache: creating client from connection string: %w", err)
			}
		}
	}

	// Fall back to DefaultAzureCredential with account name.
	if client == nil {
		if cfg.AccountName == "" {
			return nil, fmt.Errorf("azure blob cache: account_name is required when connection string is not available")
		}
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("azure blob cache: creating default credential: %w", err)
		}
		serviceURL := fmt.Sprintf("https://%s.blob.core.windows.net", cfg.AccountName)
		client, err = azblob.NewClient(serviceURL, cred, nil)
		if err != nil {
			return nil, fmt.Errorf("azure blob cache: creating client with default credential: %w", err)
		}
	}

	store := &AzureBlobStore{
		client:        client,
		containerName: cfg.ContainerName,
		prefix:        strings.TrimSuffix(cfg.Prefix, "/"),
	}

	log.Info().
		Str("account_name", cfg.AccountName).
		Str("container", cfg.ContainerName).
		Str("prefix", cfg.Prefix).
		Msg("azure blob cache store initialized")

	return store, nil
}

// objectKey builds the blob key for an artifact.
// Format: {prefix}/{ecosystem}/{name}/{version}/{sha256}
func (s *AzureBlobStore) objectKey(eco, name, version, sha string) string {
	parts := []string{eco, name, version, sha}
	key := strings.Join(parts, "/")
	if s.prefix != "" {
		key = s.prefix + "/" + key
	}
	return key
}

// objectKeyPrefixFromID builds a key prefix from an artifact ID (eco:name:version).
func (s *AzureBlobStore) objectKeyPrefixFromID(artifactID string) (string, error) {
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
		return "", "", "", fmt.Errorf("azure blob cache: invalid artifact ID %q: expected eco:name:version", artifactID)
	}
	return parts[0], parts[1], parts[2], nil
}

// Put uploads a local file to Azure Blob Storage.
func (s *AzureBlobStore) Put(ctx context.Context, artifact scanner.Artifact, localPath string) error {
	eco := string(artifact.Ecosystem)
	name := artifact.Name
	version := artifact.Version
	sha := artifact.SHA256

	if sha == "" {
		computed, err := computeFileSHA256(localPath)
		if err != nil {
			return fmt.Errorf("azure blob cache: computing SHA256 for %s: %w", localPath, err)
		}
		sha = computed
	}

	key := s.objectKey(eco, name, version, sha)

	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("azure blob cache: opening local file %s: %w", localPath, err)
	}
	defer f.Close()

	_, err = s.client.UploadFile(ctx, s.containerName, key, f, nil)
	if err != nil {
		return fmt.Errorf("azure blob cache: uploading %s to %s/%s: %w", localPath, s.containerName, key, err)
	}

	log.Debug().
		Str("key", key).
		Str("container", s.containerName).
		Str("sha256", sha).
		Msg("azure blob cache: artifact uploaded")

	return nil
}

// Get downloads the artifact from Azure Blob Storage to a temp file and returns the temp path.
// MANDATORY: SHA256 integrity is verified after download. If the hash in the
// object key does not match the downloaded content, the temp file is removed
// and an error is returned.
func (s *AzureBlobStore) Get(ctx context.Context, artifactID string) (string, error) {
	prefix, err := s.objectKeyPrefixFromID(artifactID)
	if err != nil {
		return "", err
	}

	// List blobs under the artifact prefix to find the actual key (which includes sha256).
	pager := s.client.NewListBlobsFlatPager(s.containerName, &azblob.ListBlobsFlatOptions{
		Prefix:     &prefix,
		MaxResults: int32Ptr(1),
	})

	var blobName string
	if pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return "", fmt.Errorf("azure blob cache: listing blobs for %s: %w", artifactID, err)
		}
		if len(page.Segment.BlobItems) == 0 {
			return "", cache.ErrNotFound
		}
		blobName = *page.Segment.BlobItems[0].Name
	} else {
		return "", cache.ErrNotFound
	}

	// Extract expected SHA256 from the key (last path segment).
	keyParts := strings.Split(blobName, "/")
	expectedSHA := keyParts[len(keyParts)-1]

	// Download to temp file.
	resp, err := s.client.DownloadStream(ctx, s.containerName, blobName, nil)
	if err != nil {
		return "", fmt.Errorf("azure blob cache: downloading %s/%s: %w", s.containerName, blobName, err)
	}
	defer resp.Body.Close()

	tmpFile, err := os.CreateTemp("", "shieldoo-azblob-cache-*")
	if err != nil {
		return "", fmt.Errorf("azure blob cache: creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Write and compute SHA256 simultaneously.
	hasher := sha256.New()
	writer := io.MultiWriter(tmpFile, hasher)

	if _, err := io.Copy(writer, resp.Body); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("azure blob cache: writing temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("azure blob cache: closing temp file: %w", err)
	}

	// SECURITY: Verify SHA256 integrity.
	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if expectedSHA != "" && actualSHA != expectedSHA {
		os.Remove(tmpPath)
		log.Error().
			Str("artifact_id", artifactID).
			Str("expected_sha256", expectedSHA).
			Str("actual_sha256", actualSHA).
			Msg("CRITICAL: azure blob cache integrity check failed — downloaded content does not match expected SHA256")
		return "", fmt.Errorf("azure blob cache: integrity check failed for %s: expected SHA256 %s, got %s", artifactID, expectedSHA, actualSHA)
	}

	log.Debug().
		Str("artifact_id", artifactID).
		Str("tmp_path", tmpPath).
		Msg("azure blob cache: artifact downloaded and verified")

	// Schedule background cleanup of temp file after 5 minutes.
	go func() {
		time.Sleep(5 * time.Minute)
		if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
			log.Warn().Err(err).Str("path", tmpPath).Msg("azure blob cache: failed to clean up temp file")
		}
	}()

	return tmpPath, nil
}

// Delete removes the artifact blob(s) from Azure Blob Storage.
func (s *AzureBlobStore) Delete(ctx context.Context, artifactID string) error {
	prefix, err := s.objectKeyPrefixFromID(artifactID)
	if err != nil {
		return err
	}

	pager := s.client.NewListBlobsFlatPager(s.containerName, &azblob.ListBlobsFlatOptions{
		Prefix: &prefix,
	})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("azure blob cache: listing blobs for delete %s: %w", artifactID, err)
		}
		for _, blob := range page.Segment.BlobItems {
			_, err := s.client.DeleteBlob(ctx, s.containerName, *blob.Name, nil)
			if err != nil {
				return fmt.Errorf("azure blob cache: deleting %s/%s: %w", s.containerName, *blob.Name, err)
			}
		}
	}

	return nil
}

// List returns artifactIDs matching the optional filter.
func (s *AzureBlobStore) List(ctx context.Context, filter cache.CacheFilter) ([]string, error) {
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

	pager := s.client.NewListBlobsFlatPager(s.containerName, &azblob.ListBlobsFlatOptions{
		Prefix: &listPrefix,
	})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("azure blob cache: listing blobs: %w", err)
		}
		for _, blob := range page.Segment.BlobItems {
			key := *blob.Name

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
	}

	return ids, nil
}

// Stats returns aggregate cache statistics. Results are cached in memory
// and refreshed at most every 5 minutes to avoid expensive list operations.
func (s *AzureBlobStore) Stats(ctx context.Context) (cache.CacheStats, error) {
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

	pager := s.client.NewListBlobsFlatPager(s.containerName, &azblob.ListBlobsFlatOptions{
		Prefix: &listPrefix,
	})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return cache.CacheStats{}, fmt.Errorf("azure blob cache: stats listing: %w", err)
		}
		for _, blob := range page.Segment.BlobItems {
			stats.TotalItems++
			if blob.Properties != nil && blob.Properties.ContentLength != nil {
				stats.TotalBytes += *blob.Properties.ContentLength
			}

			key := *blob.Name
			rel := key
			if s.prefix != "" {
				rel = strings.TrimPrefix(key, s.prefix+"/")
			}
			parts := strings.Split(rel, "/")
			if len(parts) >= 1 && blob.Properties != nil && blob.Properties.ContentLength != nil {
				stats.ByEcosystem[parts[0]] += *blob.Properties.ContentLength
			}
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

// int32Ptr is a helper to create an *int32.
func int32Ptr(v int32) *int32 {
	return &v
}
