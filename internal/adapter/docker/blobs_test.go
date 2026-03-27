package docker_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
)

func TestBlobStore_PutAndGet(t *testing.T) {
	bs := docker.NewBlobStore(t.TempDir())

	content := []byte("fake layer content")
	digest := "sha256:abc123def456"

	err := bs.Put(digest, content)
	require.NoError(t, err)

	data, err := bs.Get(digest)
	require.NoError(t, err)
	assert.Equal(t, content, data)
}

func TestBlobStore_Exists(t *testing.T) {
	bs := docker.NewBlobStore(t.TempDir())

	assert.False(t, bs.Exists("sha256:doesnotexist"))

	err := bs.Put("sha256:abc123", []byte("data"))
	require.NoError(t, err)

	assert.True(t, bs.Exists("sha256:abc123"))
}

func TestBlobStore_PathTraversal_Rejected(t *testing.T) {
	bs := docker.NewBlobStore(t.TempDir())

	err := bs.Put("sha256:../../etc/passwd", []byte("evil"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid digest")
}

func TestBlobStore_InvalidDigestFormat_Rejected(t *testing.T) {
	bs := docker.NewBlobStore(t.TempDir())

	err := bs.Put("nocolon", []byte("bad"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid digest")
}

func TestBlobStore_GetSize(t *testing.T) {
	bs := docker.NewBlobStore(t.TempDir())
	content := []byte("some blob data here")
	digest := "sha256:deadbeef"

	err := bs.Put(digest, content)
	require.NoError(t, err)

	size, err := bs.GetSize(digest)
	require.NoError(t, err)
	assert.Equal(t, int64(len(content)), size)
}
