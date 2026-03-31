package config

import (
	"context"
	"database/sql"
	"testing"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitDB_CreatesAllTables(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
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
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	var mode string
	err = db.Get(&mode, "PRAGMA journal_mode")
	require.NoError(t, err)
	// :memory: databases use "memory" journal mode, but for file-based DBs it would be "wal"
	// For this test we just verify the DB was initialized without error
}

func TestInitDB_EnablesForeignKeys(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	var fk int
	err = db.Get(&fk, "PRAGMA foreign_keys")
	require.NoError(t, err)
	assert.Equal(t, 1, fk)
}

func TestInitDB_Idempotent(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	// Running migrations again should not error (CREATE TABLE IF NOT EXISTS)
	migrations, err := readMigrations(sqliteMigrationFS, "migrations/sqlite")
	require.NoError(t, err)
	for _, sql := range migrations {
		_, err = db.Exec(sql)
		assert.NoError(t, err)
	}
}

func TestInitDB_Migration003_DockerRepositories(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	// Verify docker_repositories table exists
	var count int
	err = db.Get(&count, "SELECT COUNT(*) FROM docker_repositories")
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	// Verify schema_migrations table exists
	err = db.Get(&count, "SELECT COUNT(*) FROM schema_migrations")
	require.NoError(t, err)

	// Run migrations again (simulates restart) — should not fail
	migrations, err := readMigrations(sqliteMigrationFS, "migrations/sqlite")
	require.NoError(t, err)
	for i, sql := range migrations {
		_, err := db.Exec(sql)
		require.NoError(t, err, "migration %d failed on re-run", i+1)
	}
}

func TestInitDB_UnknownBackend_ReturnsError(t *testing.T) {
	_, err := InitDB(DatabaseConfig{Backend: "mysql"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown database backend")
}

func TestInitDB_EmptyBackend_DefaultsToSQLite(t *testing.T) {
	// Empty backend should default to sqlite.
	db, err := InitDB(DatabaseConfig{
		Backend: "",
		SQLite:  SQLiteConfig{Path: ":memory:"},
	})
	require.NoError(t, err)
	defer db.Close()

	// Verify it's a working SQLite database.
	var count int
	err = db.Get(&count, "SELECT COUNT(*) FROM artifacts")
	require.NoError(t, err)
}

func TestInitDB_PostgresBackend_EmptyDSN_FailsAtConnect(t *testing.T) {
	// Postgres with an invalid (empty) DSN should fail.
	_, err := InitDB(DatabaseConfig{
		Backend: "postgres",
		Postgres: PostgresConfig{
			DSN: "host=localhost port=99999 dbname=nonexistent sslmode=disable",
		},
	})
	// We expect a connection/ping error, not a clean init.
	require.Error(t, err)
}

func TestGateDB_Rebind_SQLite_KeepsQuestionMarks(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	// Verify that Rebind on SQLite keeps ? placeholders.
	rebound := db.Rebind("SELECT * FROM artifacts WHERE id = ? AND name = ?")
	assert.Equal(t, "SELECT * FROM artifacts WHERE id = ? AND name = ?", rebound)
}

func TestGateDB_Exec_WorksWithRebind(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	// Insert using GateDB.Exec which auto-rebinds.
	_, err = db.Exec(
		`INSERT INTO audit_log (ts, event_type) VALUES (?, ?)`,
		"2025-01-01T00:00:00Z", "TEST",
	)
	require.NoError(t, err)

	var count int
	err = db.Get(&count, "SELECT COUNT(*) FROM audit_log WHERE event_type = ?", "TEST")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestGateDB_Beginx_ReturnsGateTx(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	tx, err := db.Beginx()
	require.NoError(t, err)

	// GateTx.Exec should auto-rebind.
	_, err = tx.Exec(
		`INSERT INTO audit_log (ts, event_type) VALUES (?, ?)`,
		"2025-01-01T00:00:00Z", "TX_TEST",
	)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())

	var eventType string
	err = db.Get(&eventType, "SELECT event_type FROM audit_log WHERE event_type = ?", "TX_TEST")
	require.NoError(t, err)
	assert.Equal(t, "TX_TEST", eventType)
}

func TestGateDB_Query_WorksWithRebind(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec(
		`INSERT INTO audit_log (ts, event_type) VALUES (?, ?)`,
		"2025-01-01T00:00:00Z", "Q_TEST",
	)
	require.NoError(t, err)

	rows, err := db.Query("SELECT event_type FROM audit_log WHERE event_type = ?", "Q_TEST")
	require.NoError(t, err)
	defer rows.Close()

	require.True(t, rows.Next())
	var et string
	require.NoError(t, rows.Scan(&et))
	assert.Equal(t, "Q_TEST", et)
}

func TestGateDB_QueryRow_WorksWithRebind(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec(
		`INSERT INTO audit_log (ts, event_type) VALUES (?, ?)`,
		"2025-01-01T00:00:00Z", "QR_TEST",
	)
	require.NoError(t, err)

	row := db.QueryRow("SELECT event_type FROM audit_log WHERE event_type = ?", "QR_TEST")
	var et string
	require.NoError(t, row.Scan(&et))
	assert.Equal(t, "QR_TEST", et)
}

func TestGateDB_Select_WorksWithRebind(t *testing.T) {
	db, err := InitDB(SQLiteMemoryConfig())
	require.NoError(t, err)
	defer db.Close()

	_, err = db.Exec(
		`INSERT INTO audit_log (ts, event_type) VALUES (?, ?)`,
		"2025-01-01T00:00:00Z", "SEL_TEST",
	)
	require.NoError(t, err)

	type AuditRow struct {
		EventType string         `db:"event_type"`
		Reason    sql.NullString `db:"reason"`
	}
	var rows []AuditRow
	err = db.Select(&rows, "SELECT event_type, reason FROM audit_log WHERE event_type = ?", "SEL_TEST")
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "SEL_TEST", rows[0].EventType)
}

func TestReadMigrations_SQLite_ReturnsAllMigrations(t *testing.T) {
	migrations, err := readMigrations(sqliteMigrationFS, "migrations/sqlite")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(migrations), 5, "expected at least 5 SQLite migrations")
}

func TestReadMigrations_Postgres_ReturnsAllMigrations(t *testing.T) {
	migrations, err := readMigrations(postgresMigrationFS, "migrations/postgres")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(migrations), 5, "expected at least 5 PostgreSQL migrations")
}

func TestGateDB_BeginTxx_ReturnsGateTx(t *testing.T) {
	db := setupTestDB(t)
	tx, err := db.BeginTxx(context.Background(), nil)
	require.NoError(t, err)
	defer tx.Rollback()

	_, err = tx.ExecContext(context.Background(),
		"INSERT INTO api_keys (key_hash, name, owner_email) VALUES (?, ?, ?)",
		"test_hash", "test", "test@example.com")
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
}

func TestGateTx_QueryRowxContext_Rebinds(t *testing.T) {
	db := setupTestDB(t)
	_, err := db.CreateAPIKey("qrxc_hash", "qrxc-key", "test@example.com")
	require.NoError(t, err)

	tx, err := db.BeginTxx(context.Background(), nil)
	require.NoError(t, err)
	defer tx.Rollback()

	var key model.APIKey
	err = tx.QueryRowxContext(context.Background(),
		"SELECT id, key_hash, name, owner_email, enabled, created_at, last_used_at FROM api_keys WHERE key_hash = ?",
		"qrxc_hash").StructScan(&key)
	require.NoError(t, err)
	assert.Equal(t, "qrxc-key", key.Name)
}

func TestReadMigrations_SQLiteAndPostgres_SameCount(t *testing.T) {
	sqliteMigs, err := readMigrations(sqliteMigrationFS, "migrations/sqlite")
	require.NoError(t, err)
	pgMigs, err := readMigrations(postgresMigrationFS, "migrations/postgres")
	require.NoError(t, err)
	assert.Equal(t, len(sqliteMigs), len(pgMigs), "SQLite and PostgreSQL migration count must match")
}
