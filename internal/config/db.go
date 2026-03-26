package config

import (
	"embed"
	"fmt"
	"sort"

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

	// Run all migrations in order
	migrations, err := readMigrations()
	if err != nil {
		db.Close()
		return nil, err
	}
	for i, sql := range migrations {
		if _, err := db.Exec(sql); err != nil {
			db.Close()
			return nil, fmt.Errorf("config: running migration %d: %w", i+1, err)
		}
	}

	return db, nil
}
