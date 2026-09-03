package docker_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

func TestUpsertTag_CreatesNewTag(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)

	err = docker.UpsertTag(db, repo.ID, "v1.0", "sha256:abc123", "")
	require.NoError(t, err)

	tags, err := docker.ListTags(db, repo.ID)
	require.NoError(t, err)
	require.Len(t, tags, 1)
	assert.Equal(t, "v1.0", tags[0].Tag)
	assert.Equal(t, "sha256:abc123", tags[0].ManifestDigest)
	assert.Nil(t, tags[0].ArtifactID) // empty string maps to NULL
}

func TestUpsertTag_UpdatesExistingTag(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)

	// Create initial tag
	err = docker.UpsertTag(db, repo.ID, "latest", "sha256:old", "")
	require.NoError(t, err)

	// Update to new digest
	err = docker.UpsertTag(db, repo.ID, "latest", "sha256:new", "")
	require.NoError(t, err)

	tags, err := docker.ListTags(db, repo.ID)
	require.NoError(t, err)
	require.Len(t, tags, 1)
	assert.Equal(t, "sha256:new", tags[0].ManifestDigest)
}

func TestListTags_ReturnsAllForRepo(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)

	require.NoError(t, docker.UpsertTag(db, repo.ID, "v1.0", "sha256:aaa", ""))
	require.NoError(t, docker.UpsertTag(db, repo.ID, "v2.0", "sha256:bbb", ""))
	require.NoError(t, docker.UpsertTag(db, repo.ID, "latest", "sha256:bbb", ""))

	tags, err := docker.ListTags(db, repo.ID)
	require.NoError(t, err)
	assert.Len(t, tags, 3)
	// Should be sorted by tag name
	assert.Equal(t, "latest", tags[0].Tag)
	assert.Equal(t, "v1.0", tags[1].Tag)
	assert.Equal(t, "v2.0", tags[2].Tag)
}

func TestListTags_EmptyForNewRepo(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "", "myteam/empty", true)
	require.NoError(t, err)

	tags, err := docker.ListTags(db, repo.ID)
	require.NoError(t, err)
	assert.Len(t, tags, 0)
}

func TestDeleteTag_RemovesTag(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)

	require.NoError(t, docker.UpsertTag(db, repo.ID, "v1.0", "sha256:aaa", ""))
	require.NoError(t, docker.UpsertTag(db, repo.ID, "v2.0", "sha256:bbb", ""))

	err = docker.DeleteTag(db, repo.ID, "v1.0")
	require.NoError(t, err)

	tags, err := docker.ListTags(db, repo.ID)
	require.NoError(t, err)
	assert.Len(t, tags, 1)
	assert.Equal(t, "v2.0", tags[0].Tag)
}

func TestDeleteTag_NotFound_ReturnsError(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)

	err = docker.DeleteTag(db, repo.ID, "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestGetTagByDigest_ReturnsMatchingTags(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)

	digest := "sha256:samedigest"
	require.NoError(t, docker.UpsertTag(db, repo.ID, "v1.0", digest, ""))
	require.NoError(t, docker.UpsertTag(db, repo.ID, "latest", digest, ""))
	require.NoError(t, docker.UpsertTag(db, repo.ID, "v2.0", "sha256:other", ""))

	tags, err := docker.GetTagByDigest(db, repo.ID, digest)
	require.NoError(t, err)
	assert.Len(t, tags, 2)
	assert.Equal(t, "latest", tags[0].Tag)
	assert.Equal(t, "v1.0", tags[1].Tag)
}

func TestGetTagByDigest_NoMatch_ReturnsEmpty(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)

	tags, err := docker.GetTagByDigest(db, repo.ID, "sha256:doesnotexist")
	require.NoError(t, err)
	assert.Len(t, tags, 0)
}

func TestCountTags_EmptyRepo_ReturnsZero(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)

	count, err := docker.CountTags(db, repo.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestCountTags_WithTags_ReturnsCount(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)
	for _, tag := range []string{"v1.0", "v2.0", "v3.0"} {
		require.NoError(t, docker.UpsertTag(db, repo.ID, tag, "sha256:aa", ""))
	}

	count, err := docker.CountTags(db, repo.ID)
	require.NoError(t, err)
	assert.Equal(t, 3, count)
}

func TestListTagsPage_NoCursor_ReturnsFirstPageInOrder(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)
	for _, tag := range []string{"v3.0", "v1.0", "v2.0"} {
		require.NoError(t, docker.UpsertTag(db, repo.ID, tag, "sha256:aa", ""))
	}

	page, err := docker.ListTagsPage(db, repo.ID, "", 2)
	require.NoError(t, err)
	require.Len(t, page, 2)
	assert.Equal(t, "v1.0", page[0].Tag)
	assert.Equal(t, "v2.0", page[1].Tag)
}

func TestListTagsPage_WithCursor_SkipsUpToCursor(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)
	for _, tag := range []string{"v1.0", "v2.0", "v3.0"} {
		require.NoError(t, docker.UpsertTag(db, repo.ID, tag, "sha256:aa", ""))
	}

	page, err := docker.ListTagsPage(db, repo.ID, "v2.0", 10)
	require.NoError(t, err)
	require.Len(t, page, 1)
	assert.Equal(t, "v3.0", page[0].Tag)
}

func TestListTagsPage_CursorPastEnd_ReturnsEmpty(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)
	require.NoError(t, docker.UpsertTag(db, repo.ID, "v1.0", "sha256:aa", ""))

	page, err := docker.ListTagsPage(db, repo.ID, "zzz", 10)
	require.NoError(t, err)
	assert.Empty(t, page)
}

func TestListTagsPage_OtherRepoTags_NotIncluded(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	mine, err := docker.EnsureRepository(db, "", "myteam/myapp", true)
	require.NoError(t, err)
	other, err := docker.EnsureRepository(db, "", "myteam/other", true)
	require.NoError(t, err)
	require.NoError(t, docker.UpsertTag(db, mine.ID, "v1.0", "sha256:aa", ""))
	require.NoError(t, docker.UpsertTag(db, other.ID, "v9.9", "sha256:bb", ""))

	page, err := docker.ListTagsPage(db, mine.ID, "", 10)
	require.NoError(t, err)
	require.Len(t, page, 1)
	assert.Equal(t, "v1.0", page[0].Tag)
}
