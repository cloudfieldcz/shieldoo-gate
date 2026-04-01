package azureblob

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
var _ cache.CacheStore = (*AzureBlobStore)(nil)

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
	store := &AzureBlobStore{prefix: "cache"}
	key := store.objectKey("pypi", "requests", "2.31.0", "", "abc123")
	assert.Equal(t, "cache/pypi/requests/2.31.0/abc123", key)
}

func TestObjectKey_WithoutPrefix(t *testing.T) {
	store := &AzureBlobStore{prefix: ""}
	key := store.objectKey("npm", "lodash", "4.17.21", "", "def456")
	assert.Equal(t, "npm/lodash/4.17.21/def456", key)
}

func TestObjectKey_PrefixTrailingSlashStripped(t *testing.T) {
	store := &AzureBlobStore{prefix: "artifacts"}
	key := store.objectKey("docker", "library__nginx", "latest", "", "sha123")
	assert.Equal(t, "artifacts/docker/library__nginx/latest/sha123", key)
}

func TestObjectKey_WithFilename(t *testing.T) {
	store := &AzureBlobStore{prefix: "cache"}
	key := store.objectKey("pypi", "cffi", "2.0.0", "cffi-2.0.0-cp312-manylinux.whl", "abc123")
	assert.Equal(t, "cache/pypi/cffi/2.0.0/cffi-2.0.0-cp312-manylinux.whl/abc123", key)
}

func TestObjectKeyPrefixFromID_Valid(t *testing.T) {
	store := &AzureBlobStore{prefix: "cache"}
	prefix, err := store.objectKeyPrefixFromID("pypi:requests:2.31.0")
	require.NoError(t, err)
	assert.Equal(t, "cache/pypi/requests/2.31.0/", prefix)
}

func TestObjectKeyPrefixFromID_NoPrefix(t *testing.T) {
	store := &AzureBlobStore{prefix: ""}
	prefix, err := store.objectKeyPrefixFromID("npm:lodash:4.17.21")
	require.NoError(t, err)
	assert.Equal(t, "npm/lodash/4.17.21/", prefix)
}

func TestObjectKeyPrefixFromID_InvalidID(t *testing.T) {
	store := &AzureBlobStore{prefix: ""}
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

func TestNewAzureBlobStore_EmptyContainer_Error(t *testing.T) {
	_, err := NewAzureBlobStore(config.AzureBlobConfig{
		AccountName:   "testaccount",
		ContainerName: "",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "container_name is required")
}

func TestNewAzureBlobStore_NoAccountNoConnStr_Error(t *testing.T) {
	_, err := NewAzureBlobStore(config.AzureBlobConfig{
		ContainerName: "test-container",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "account_name or connection_string_env is required")
}

func TestNewAzureBlobStore_ConnectionStringFromEnv(t *testing.T) {
	// Set a valid Azure Storage connection string in the env var.
	envVar := "TEST_AZURE_CONN_STR"
	connStr := "DefaultEndpointsProtocol=https;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=https://devstoreaccount1.blob.core.windows.net"
	t.Setenv(envVar, connStr)

	store, err := NewAzureBlobStore(config.AzureBlobConfig{
		ContainerName:    "test-container",
		ConnectionStrEnv: envVar,
		Prefix:           "cache/",
	})
	require.NoError(t, err)
	assert.NotNil(t, store)
	assert.Equal(t, "test-container", store.containerName)
	assert.Equal(t, "cache", store.prefix) // trailing slash stripped
}

func TestNewAzureBlobStore_ConnectionStringEnvUnset_FallbackToAccount(t *testing.T) {
	// connection_string_env is set but the env var is empty — falls through to account_name.
	// DefaultAzureCredential may or may not succeed depending on the environment
	// (it uses lazy auth, so client creation can succeed even without real credentials).
	store, err := NewAzureBlobStore(config.AzureBlobConfig{
		ContainerName:    "test-container",
		ConnectionStrEnv: "NONEXISTENT_AZURE_CONN_STR_VAR",
		AccountName:      "testaccount",
	})
	if err != nil {
		// Expected in environments without Azure credentials configured.
		assert.Contains(t, err.Error(), "credential")
	} else {
		// DefaultAzureCredential succeeded (lazy auth) — verify store is properly set up.
		assert.NotNil(t, store)
		assert.Equal(t, "test-container", store.containerName)
	}
}

func TestInt32Ptr(t *testing.T) {
	v := int32Ptr(42)
	assert.Equal(t, int32(42), *v)
}
