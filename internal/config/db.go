package config

import (
	"embed"
	"fmt"

	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed migrations/001_init.sql
var migrationFS embed.FS

func mustReadMigration() string {
	data, err := migrationFS.ReadFile("migrations/001_init.sql")
	if err != nil {
		panic(fmt.Sprintf("config: reading migration: %v", err))
	}
	return string(data)
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

	// Run migration
	migration := mustReadMigration()
	if _, err := db.Exec(migration); err != nil {
		db.Close()
		return nil, fmt.Errorf("config: running migration: %w", err)
	}

	return db, nil
}
