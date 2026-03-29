package docker_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
)

func TestEnsureRepository_CreatesOnFirstCall(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo, err := docker.EnsureRepository(db, "ghcr.io", "cloudfieldcz/cf-powers", false)
	require.NoError(t, err)
	assert.Equal(t, "ghcr.io", repo.Registry)
	assert.Equal(t, "cloudfieldcz/cf-powers", repo.Name)
	assert.False(t, repo.IsInternal)
	assert.True(t, repo.ID > 0)
}

func TestEnsureRepository_ReturnsExistingOnSecondCall(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	repo1, err := docker.EnsureRepository(db, "ghcr.io", "user/app", false)
	require.NoError(t, err)

	repo2, err := docker.EnsureRepository(db, "ghcr.io", "user/app", false)
	require.NoError(t, err)

	assert.Equal(t, repo1.ID, repo2.ID)
}

func TestListRepositories_ReturnsAll(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	_, err = docker.EnsureRepository(db, "docker.io", "library/nginx", false)
	require.NoError(t, err)
	_, err = docker.EnsureRepository(db, "ghcr.io", "user/app", false)
	require.NoError(t, err)

	repos, err := docker.ListRepositories(db, "")
	require.NoError(t, err)
	assert.Len(t, repos, 2)
}

func TestListRepositories_FilterByRegistry(t *testing.T) {
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	_, err = docker.EnsureRepository(db, "docker.io", "library/nginx", false)
	require.NoError(t, err)
	_, err = docker.EnsureRepository(db, "ghcr.io", "user/app", false)
	require.NoError(t, err)

	repos, err := docker.ListRepositories(db, "ghcr.io")
	require.NoError(t, err)
	assert.Len(t, repos, 1)
	assert.Equal(t, "ghcr.io", repos[0].Registry)
}
