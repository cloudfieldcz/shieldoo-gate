package gcs

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
var _ cache.CacheStore = (*GCSCacheStore)(nil)

func TestParseArtifactID_Valid(t *testing.T) {
	eco, name, version, filename, err := parseArtifactID("pypi:requests:2.31.0")
	require.NoError(t, err)
	assert.Equal(t, "pypi", eco)
	assert.Equal(t, "requests", name)
	assert.Equal(t, "2.31.0", version)
	assert.Equal(t, "", filename)
}

func TestParseArtifactID_FourSegments(t *testing.T) {
	eco, name, version, filename, err := parseArtifactID("pypi:cffi:2.0.0:cffi-2.0.0-cp312-manylinux.whl")
	require.NoError(t, err)
	assert.Equal(t, "pypi", eco)
	assert.Equal(t, "cffi", name)
	assert.Equal(t, "2.0.0", version)
	assert.Equal(t, "cffi-2.0.0-cp312-manylinux.whl", filename)
}

func TestParseArtifactID_ThreeSegments_BackwardCompat(t *testing.T) {
	eco, name, version, filename, err := parseArtifactID("npm:lodash:4.17.21")
	require.NoError(t, err)
	assert.Equal(t, "npm", eco)
	assert.Equal(t, "lodash", name)
	assert.Equal(t, "4.17.21", version)
	assert.Equal(t, "", filename)
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
			_, _, _, _, err := parseArtifactID(tc.id)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid artifact ID")
		})
	}
}

func TestObjectKey_WithPrefix(t *testing.T) {
	store := &GCSCacheStore{prefix: "cache"}
	key := store.objectKey("pypi", "requests", "2.31.0", "", "abc123")
	assert.Equal(t, "cache/pypi/requests/2.31.0/abc123", key)
}

func TestObjectKey_WithoutPrefix(t *testing.T) {
	store := &GCSCacheStore{prefix: ""}
	key := store.objectKey("npm", "lodash", "4.17.21", "", "def456")
	assert.Equal(t, "npm/lodash/4.17.21/def456", key)
}

func TestObjectKey_PrefixTrailingSlashStripped(t *testing.T) {
	store := &GCSCacheStore{prefix: "artifacts"}
	key := store.objectKey("docker", "library__nginx", "latest", "", "sha123")
	assert.Equal(t, "artifacts/docker/library__nginx/latest/sha123", key)
}

func TestObjectKey_WithFilename(t *testing.T) {
	store := &GCSCacheStore{prefix: "cache"}
	key := store.objectKey("pypi", "cffi", "2.0.0", "cffi-2.0.0-cp312-manylinux.whl", "abc123")
	assert.Equal(t, "cache/pypi/cffi/2.0.0/cffi-2.0.0-cp312-manylinux.whl/abc123", key)
}

func TestObjectKey_WithFilenameNoPrefix(t *testing.T) {
	store := &GCSCacheStore{prefix: ""}
	key := store.objectKey("pypi", "cffi", "2.0.0", "cffi-2.0.0-cp312-manylinux.whl", "def456")
	assert.Equal(t, "pypi/cffi/2.0.0/cffi-2.0.0-cp312-manylinux.whl/def456", key)
}

func TestObjectKeyPrefixFromID_Valid(t *testing.T) {
	store := &GCSCacheStore{prefix: "cache"}
	prefix, err := store.objectKeyPrefixFromID("pypi:requests:2.31.0")
	require.NoError(t, err)
	assert.Equal(t, "cache/pypi/requests/2.31.0/", prefix)
}

func TestObjectKeyPrefixFromID_NoPrefix(t *testing.T) {
	store := &GCSCacheStore{prefix: ""}
	prefix, err := store.objectKeyPrefixFromID("npm:lodash:4.17.21")
	require.NoError(t, err)
	assert.Equal(t, "npm/lodash/4.17.21/", prefix)
}

func TestObjectKeyPrefixFromID_InvalidID(t *testing.T) {
	store := &GCSCacheStore{prefix: ""}
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

func TestNewGCSCacheStore_EmptyBucket_Error(t *testing.T) {
	_, err := NewGCSCacheStore(config.GCSCacheConfig{
		Bucket: "",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bucket is required")
}

func TestNewGCSCacheStore_ValidConfig_OK(t *testing.T) {
	// Set STORAGE_EMULATOR_HOST to bypass real credential requirements.
	// The GCS SDK skips authentication when this env var is set.
	t.Setenv("STORAGE_EMULATOR_HOST", "localhost:4443")

	store, err := NewGCSCacheStore(config.GCSCacheConfig{
		Bucket: "test-bucket",
		Prefix: "cache/",
	})
	require.NoError(t, err)
	assert.NotNil(t, store)
	assert.Equal(t, "test-bucket", store.bucket)
	assert.Equal(t, "cache", store.prefix) // trailing slash stripped
}

func TestNewGCSCacheStore_WithCredentialsFile_NonExistent(t *testing.T) {
	// Passing a non-existent credentials file should error because the GCS SDK
	// validates the file during client creation.
	_, err := NewGCSCacheStore(config.GCSCacheConfig{
		Bucket:          "test-bucket",
		CredentialsFile: "/nonexistent/creds.json",
	})
	// The SDK should fail to read the credentials file.
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "creating client")
}
