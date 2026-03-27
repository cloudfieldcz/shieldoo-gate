package config

import (
	"embed"
	"fmt"
	"sort"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

func readMigrations() ([]string, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("config: reading migrations dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var sqls []string
	for _, name := range names {
		data, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, fmt.Errorf("config: reading migration %s: %w", name, err)
		}
		sqls = append(sqls, string(data))
	}
	return sqls, nil
}

func InitDB(dbPath string) (*sqlx.DB, error) {
	db, err := sqlx.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("config: opening database %s: %w", dbPath, err)
	}

	// Set SQLite PRAGMAs
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("config: setting pragma %q: %w", pragma, err)
		}
	}

	// Ensure schema_migrations table exists (bootstrap).
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at DATETIME NOT NULL
	)`); err != nil {
		db.Close()
		return nil, fmt.Errorf("config: creating schema_migrations: %w", err)
	}

	// Run only unapplied migrations.
	migrations, err := readMigrations()
	if err != nil {
		db.Close()
		return nil, err
	}
	for i, sql := range migrations {
		version := i + 1
		var count int
		_ = db.Get(&count, "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", version)
		if count > 0 {
			continue // already applied
		}
		if _, err := db.Exec(sql); err != nil {
			db.Close()
			return nil, fmt.Errorf("config: running migration %d: %w", version, err)
		}
		db.Exec("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)", version, time.Now().UTC())
	}

	return db, nil
}
