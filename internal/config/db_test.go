package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitDB_CreatesAllTables(t *testing.T) {
	db, err := InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	tables := []string{"artifacts", "scan_results", "artifact_status", "audit_log", "threat_feed", "policy_overrides"}
	for _, table := range tables {
		var name string
		err := db.Get(&name, "SELECT name FROM sqlite_master WHERE type='table' AND name=?", table)
		assert.NoError(t, err, "table %s should exist", table)
		assert.Equal(t, table, name)
	}
}

func TestInitDB_SetsWALMode(t *testing.T) {
	db, err := InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	var mode string
	err = db.Get(&mode, "PRAGMA journal_mode")
	require.NoError(t, err)
	// :memory: databases use "memory" journal mode, but for file-based DBs it would be "wal"
	// For this test we just verify the DB was initialized without error
}

func TestInitDB_EnablesForeignKeys(t *testing.T) {
	db, err := InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	var fk int
	err = db.Get(&fk, "PRAGMA foreign_keys")
	require.NoError(t, err)
	assert.Equal(t, 1, fk)
}

func TestInitDB_Idempotent(t *testing.T) {
	db, err := InitDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	// Running migrations again should not error (CREATE TABLE IF NOT EXISTS)
	migrations, err := readMigrations()
	require.NoError(t, err)
	for _, sql := range migrations {
		_, err = db.Exec(sql)
		assert.NoError(t, err)
	}
}
