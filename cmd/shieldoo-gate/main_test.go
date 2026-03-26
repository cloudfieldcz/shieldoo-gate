//go:build !e2e

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/stretchr/testify/require"
)

func TestMain_ConfigAndDBInit(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	dbPath := filepath.Join(dir, "test.db")
	cachePath := filepath.Join(dir, "cache")

	err := os.WriteFile(cfgPath, []byte(`
server:
  host: "127.0.0.1"
ports:
  pypi: 15000
  npm: 14873
  nuget: 15001
  docker: 15002
  admin: 18080
cache:
  backend: "local"
  local:
    path: "`+cachePath+`"
    max_size_gb: 1
database:
  backend: "sqlite"
  sqlite:
    path: "`+dbPath+`"
scanners:
  parallel: true
  timeout: "10s"
log:
  level: "debug"
  format: "text"
`), 0644)
	require.NoError(t, err)

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())

	db, err := config.InitDB(cfg.Database.SQLite.Path)
	require.NoError(t, err)
	defer db.Close()
}
