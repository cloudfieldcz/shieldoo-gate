package s3

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time interface check.
var _ cache.CacheStore = (*S3CacheStore)(nil)

func TestParseArtifactID_Valid(t *testing.T) {
	eco, name, version, err := parseArtifactID("pypi:requests:2.31.0")
	require.NoError(t, err)
	assert.Equal(t, "pypi", eco)
	assert.Equal(t, "requests", name)
	assert.Equal(t, "2.31.0", version)
}

func TestParseArtifactID_Invalid(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{"empty", ""},
		{"one_part", "pypi"},
		{"two_parts", "pypi:requests"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := parseArtifactID(tc.id)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid artifact ID")
		})
	}
}

func TestObjectKey_WithPrefix(t *testing.T) {
	store := &S3CacheStore{prefix: "cache"}
	key := store.objectKey("pypi", "requests", "2.31.0", "abc123")
	assert.Equal(t, "cache/pypi/requests/2.31.0/abc123", key)
}

func TestObjectKey_WithoutPrefix(t *testing.T) {
	store := &S3CacheStore{prefix: ""}
	key := store.objectKey("npm", "lodash", "4.17.21", "def456")
	assert.Equal(t, "npm/lodash/4.17.21/def456", key)
}

func TestObjectKey_PrefixTrailingSlashStripped(t *testing.T) {
	// NewS3CacheStore strips trailing slash; simulate that.
	store := &S3CacheStore{prefix: "artifacts"}
	key := store.objectKey("docker", "library__nginx", "latest", "sha123")
	assert.Equal(t, "artifacts/docker/library__nginx/latest/sha123", key)
}

func TestObjectKeyPrefixFromID_Valid(t *testing.T) {
	store := &S3CacheStore{prefix: "cache"}
	prefix, err := store.objectKeyPrefixFromID("pypi:requests:2.31.0")
	require.NoError(t, err)
	assert.Equal(t, "cache/pypi/requests/2.31.0/", prefix)
}

func TestObjectKeyPrefixFromID_NoPrefix(t *testing.T) {
	store := &S3CacheStore{prefix: ""}
	prefix, err := store.objectKeyPrefixFromID("npm:lodash:4.17.21")
	require.NoError(t, err)
	assert.Equal(t, "npm/lodash/4.17.21/", prefix)
}

func TestObjectKeyPrefixFromID_InvalidID(t *testing.T) {
	store := &S3CacheStore{prefix: ""}
	_, err := store.objectKeyPrefixFromID("invalid")
	assert.Error(t, err)
}

func TestComputeFileSHA256(t *testing.T) {
	content := []byte("hello artifact content")
	tmpFile, err := os.CreateTemp(t.TempDir(), "sha-test-*")
	require.NoError(t, err)
	_, err = tmpFile.Write(content)
	require.NoError(t, err)
	require.NoError(t, tmpFile.Close())

	got, err := computeFileSHA256(tmpFile.Name())
	require.NoError(t, err)

	expected := sha256.Sum256(content)
	assert.Equal(t, hex.EncodeToString(expected[:]), got)
}

func TestComputeFileSHA256_NonExistent(t *testing.T) {
	_, err := computeFileSHA256("/nonexistent/file")
	assert.Error(t, err)
}

func TestNewS3CacheStore_EmptyBucket_Error(t *testing.T) {
	_, err := NewS3CacheStore(config.S3CacheConfig{
		Bucket: "",
		Region: "us-east-1",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bucket is required")
}

func TestNewS3CacheStore_NoRegionNoEndpoint_Error(t *testing.T) {
	_, err := NewS3CacheStore(config.S3CacheConfig{
		Bucket: "my-bucket",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "region is required")
}

func TestNewS3CacheStore_EndpointWithoutRegion_OK(t *testing.T) {
	// MinIO scenario: endpoint set, no region required.
	store, err := NewS3CacheStore(config.S3CacheConfig{
		Bucket:         "test-bucket",
		Endpoint:       "http://localhost:9000",
		ForcePathStyle: true,
	})
	require.NoError(t, err)
	assert.NotNil(t, store)
	assert.Equal(t, "test-bucket", store.bucket)
}

func TestNewS3CacheStore_PrefixTrailingSlashStripped(t *testing.T) {
	store, err := NewS3CacheStore(config.S3CacheConfig{
		Bucket:   "test-bucket",
		Region:   "us-east-1",
		Prefix:   "cache/",
	})
	require.NoError(t, err)
	assert.Equal(t, "cache", store.prefix)
}
