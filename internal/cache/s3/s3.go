// Package s3 implements the cache.CacheStore interface using Amazon S3
// (or any S3-compatible service such as MinIO).
package s3

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

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Compile-time interface check.
var _ cache.CacheStore = (*S3CacheStore)(nil)

// S3CacheStore stores cached artifacts in an S3 bucket.
type S3CacheStore struct {
	client *s3.Client
	bucket string
	prefix string

	// Cached stats with periodic refresh to avoid expensive ListObjects on every call.
	statsMu        sync.RWMutex
	cachedStats    cache.CacheStats
	statsRefreshAt time.Time
}

const statsRefreshInterval = 5 * time.Minute

// NewS3CacheStore creates a new S3CacheStore from the given config.
// Credentials are loaded from environment variables referenced in the config,
// or fall back to the standard AWS credential chain (env vars, shared config, IAM role).
func NewS3CacheStore(cfg config.S3CacheConfig) (*S3CacheStore, error) {
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("s3 cache: bucket is required")
	}
	if cfg.Region == "" && cfg.Endpoint == "" {
		return nil, fmt.Errorf("s3 cache: region is required when no custom endpoint is set")
	}

	ctx := context.Background()

	var opts []func(*awsconfig.LoadOptions) error

	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	}

	// If explicit credential env var names are provided, load from those env vars.
	if cfg.AccessKeyEnv != "" && cfg.SecretKeyEnv != "" {
		accessKey := os.Getenv(cfg.AccessKeyEnv)
		secretKey := os.Getenv(cfg.SecretKeyEnv)
		if accessKey == "" {
			log.Warn().Str("env_var", cfg.AccessKeyEnv).Msg("s3 cache: access_key_env references an unset environment variable")
		}
		if secretKey == "" {
			log.Warn().Str("env_var", cfg.SecretKeyEnv).Msg("s3 cache: secret_key_env references an unset environment variable")
		}
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(accessKey, secretKey, ""),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("s3 cache: loading AWS config: %w", err)
	}

	var s3Opts []func(*s3.Options)

	if cfg.Endpoint != "" {
		// Warn about non-HTTPS endpoints (except localhost for dev/MinIO).
		if !strings.HasPrefix(cfg.Endpoint, "https://") &&
			!strings.HasPrefix(cfg.Endpoint, "http://localhost") &&
			!strings.HasPrefix(cfg.Endpoint, "http://127.0.0.1") {
			log.Warn().Str("endpoint", cfg.Endpoint).Msg("s3 cache: non-HTTPS endpoint configured (potential SSRF risk)")
		}
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		})
	}

	if cfg.ForcePathStyle {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}

	client := s3.NewFromConfig(awsCfg, s3Opts...)

	store := &S3CacheStore{
		client: client,
		bucket: cfg.Bucket,
		prefix: strings.TrimSuffix(cfg.Prefix, "/"),
	}

	log.Info().
		Str("bucket", cfg.Bucket).
		Str("region", cfg.Region).
		Str("prefix", cfg.Prefix).
		Str("endpoint", cfg.Endpoint).
		Msg("s3 cache store initialized")

	return store, nil
}

// objectKey builds the S3 object key for an artifact.
// Format: {prefix}/{ecosystem}/{name}/{version}/{sha256}
func (s *S3CacheStore) objectKey(eco, name, version, sha string) string {
	parts := []string{eco, name, version, sha}
	key := strings.Join(parts, "/")
	if s.prefix != "" {
		key = s.prefix + "/" + key
	}
	return key
}

// objectKeyFromID builds a key prefix from an artifact ID (eco:name:version).
// Used for Get/Delete/List where we don't know the sha256 yet.
func (s *S3CacheStore) objectKeyPrefixFromID(artifactID string) (string, error) {
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
		return "", "", "", fmt.Errorf("s3 cache: invalid artifact ID %q: expected eco:name:version", artifactID)
	}
	return parts[0], parts[1], parts[2], nil
}

// Put uploads a local file to S3 and verifies SHA256 integrity after upload.
func (s *S3CacheStore) Put(ctx context.Context, artifact scanner.Artifact, localPath string) error {
	eco := string(artifact.Ecosystem)
	name := artifact.Name
	version := artifact.Version
	sha := artifact.SHA256

	if sha == "" {
		// Compute SHA256 of the file if not provided.
		computed, err := computeFileSHA256(localPath)
		if err != nil {
			return fmt.Errorf("s3 cache: computing SHA256 for %s: %w", localPath, err)
		}
		sha = computed
	}

	key := s.objectKey(eco, name, version, sha)

	f, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("s3 cache: opening local file %s: %w", localPath, err)
	}
	defer f.Close()

	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   f,
	})
	if err != nil {
		return fmt.Errorf("s3 cache: uploading %s to s3://%s/%s: %w", localPath, s.bucket, key, err)
	}

	log.Debug().
		Str("key", key).
		Str("bucket", s.bucket).
		Str("sha256", sha).
		Msg("s3 cache: artifact uploaded")

	return nil
}

// Get downloads the artifact from S3 to a temp file and returns the temp path.
// MANDATORY: SHA256 integrity is verified after download. If the hash in the
// object key does not match the downloaded content, the temp file is removed
// and an error is returned. This protects against compromised buckets or
// storage corruption.
func (s *S3CacheStore) Get(ctx context.Context, artifactID string) (string, error) {
	prefix, err := s.objectKeyPrefixFromID(artifactID)
	if err != nil {
		return "", err
	}

	// List objects under the artifact prefix to find the actual key (which includes sha256).
	listOut, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(s.bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: aws.Int32(1),
	})
	if err != nil {
		return "", fmt.Errorf("s3 cache: listing objects for %s: %w", artifactID, err)
	}
	if len(listOut.Contents) == 0 {
		return "", cache.ErrNotFound
	}

	key := aws.ToString(listOut.Contents[0].Key)

	// Extract expected SHA256 from the key (last path segment).
	keyParts := strings.Split(key, "/")
	expectedSHA := keyParts[len(keyParts)-1]

	// Download to temp file.
	getOut, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", fmt.Errorf("s3 cache: downloading s3://%s/%s: %w", s.bucket, key, err)
	}
	defer getOut.Body.Close()

	tmpFile, err := os.CreateTemp("", "shieldoo-s3-cache-*")
	if err != nil {
		return "", fmt.Errorf("s3 cache: creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Write and compute SHA256 simultaneously.
	hasher := sha256.New()
	writer := io.MultiWriter(tmpFile, hasher)

	if _, err := io.Copy(writer, getOut.Body); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return "", fmt.Errorf("s3 cache: writing temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return "", fmt.Errorf("s3 cache: closing temp file: %w", err)
	}

	// SECURITY: Verify SHA256 integrity.
	actualSHA := hex.EncodeToString(hasher.Sum(nil))
	if expectedSHA != "" && actualSHA != expectedSHA {
		os.Remove(tmpPath)
		log.Error().
			Str("artifact_id", artifactID).
			Str("expected_sha256", expectedSHA).
			Str("actual_sha256", actualSHA).
			Msg("CRITICAL: s3 cache integrity check failed — downloaded content does not match expected SHA256")
		return "", fmt.Errorf("s3 cache: integrity check failed for %s: expected SHA256 %s, got %s", artifactID, expectedSHA, actualSHA)
	}

	log.Debug().
		Str("artifact_id", artifactID).
		Str("tmp_path", tmpPath).
		Msg("s3 cache: artifact downloaded and verified")

	// Schedule background cleanup of temp file after 5 minutes.
	go func() {
		time.Sleep(5 * time.Minute)
		if err := os.Remove(tmpPath); err != nil && !os.IsNotExist(err) {
			log.Warn().Err(err).Str("path", tmpPath).Msg("s3 cache: failed to clean up temp file")
		}
	}()

	return tmpPath, nil
}

// Delete removes the artifact object(s) from S3.
func (s *S3CacheStore) Delete(ctx context.Context, artifactID string) error {
	prefix, err := s.objectKeyPrefixFromID(artifactID)
	if err != nil {
		return err
	}

	// List all objects under the prefix and delete them.
	listOut, err := s.client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})
	if err != nil {
		return fmt.Errorf("s3 cache: listing objects for delete %s: %w", artifactID, err)
	}

	for _, obj := range listOut.Contents {
		_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket: aws.String(s.bucket),
			Key:    obj.Key,
		})
		if err != nil {
			return fmt.Errorf("s3 cache: deleting s3://%s/%s: %w", s.bucket, aws.ToString(obj.Key), err)
		}
	}

	return nil
}

// List returns artifactIDs matching the optional filter.
func (s *S3CacheStore) List(ctx context.Context, filter cache.CacheFilter) ([]string, error) {
	// Build list prefix based on filter.
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

	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(listPrefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("s3 cache: listing objects: %w", err)
		}

		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)

			// Strip prefix to get eco/name/version/sha256.
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
func (s *S3CacheStore) Stats(ctx context.Context) (cache.CacheStats, error) {
	s.statsMu.RLock()
	if time.Now().Before(s.statsRefreshAt) {
		stats := s.cachedStats
		s.statsMu.RUnlock()
		return stats, nil
	}
	s.statsMu.RUnlock()

	// Compute fresh stats.
	stats := cache.CacheStats{
		ByEcosystem: make(map[string]int64),
	}

	listPrefix := ""
	if s.prefix != "" {
		listPrefix = s.prefix + "/"
	}

	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(listPrefix),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return cache.CacheStats{}, fmt.Errorf("s3 cache: stats listing: %w", err)
		}

		for _, obj := range page.Contents {
			stats.TotalItems++
			stats.TotalBytes += aws.ToInt64(obj.Size)

			key := aws.ToString(obj.Key)
			rel := key
			if s.prefix != "" {
				rel = strings.TrimPrefix(key, s.prefix+"/")
			}
			parts := strings.Split(rel, "/")
			if len(parts) >= 1 {
				stats.ByEcosystem[parts[0]] += aws.ToInt64(obj.Size)
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
