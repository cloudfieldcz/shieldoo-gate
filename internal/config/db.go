package config

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"sort"
	"time"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

//go:embed migrations/sqlite/*.sql
var sqliteMigrationFS embed.FS

//go:embed migrations/postgres/*.sql
var postgresMigrationFS embed.FS

// GateDB wraps *sqlx.DB with auto-rebind for dialect portability.
// All application code should use *GateDB instead of *sqlx.DB so that
// placeholder syntax (? vs $1) is handled transparently.
type GateDB struct {
	*sqlx.DB
}

func (db *GateDB) Exec(query string, args ...any) (sql.Result, error) {
	return db.DB.Exec(db.Rebind(query), args...)
}

func (db *GateDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return db.DB.ExecContext(ctx, db.Rebind(query), args...)
}

func (db *GateDB) Get(dest any, query string, args ...any) error {
	return db.DB.Get(dest, db.Rebind(query), args...)
}

func (db *GateDB) GetContext(ctx context.Context, dest any, query string, args ...any) error {
	return db.DB.GetContext(ctx, dest, db.Rebind(query), args...)
}

func (db *GateDB) Select(dest any, query string, args ...any) error {
	return db.DB.Select(dest, db.Rebind(query), args...)
}

func (db *GateDB) SelectContext(ctx context.Context, dest any, query string, args ...any) error {
	return db.DB.SelectContext(ctx, dest, db.Rebind(query), args...)
}

func (db *GateDB) Query(query string, args ...any) (*sql.Rows, error) {
	return db.DB.Query(db.Rebind(query), args...)
}

func (db *GateDB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return db.DB.QueryContext(ctx, db.Rebind(query), args...)
}

func (db *GateDB) QueryRow(query string, args ...any) *sql.Row {
	return db.DB.QueryRow(db.Rebind(query), args...)
}

func (db *GateDB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return db.DB.QueryRowContext(ctx, db.Rebind(query), args...)
}

// Beginx starts a transaction and returns a GateTx with auto-rebind.
func (db *GateDB) Beginx() (*GateTx, error) {
	tx, err := db.DB.Beginx()
	if err != nil {
		return nil, err
	}
	return &GateTx{Tx: tx}, nil
}

// GateTx wraps *sqlx.Tx with auto-rebind for dialect portability.
type GateTx struct {
	*sqlx.Tx
}

func (tx *GateTx) Exec(query string, args ...any) (sql.Result, error) {
	return tx.Tx.Exec(tx.Rebind(query), args...)
}

func (tx *GateTx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return tx.Tx.ExecContext(ctx, tx.Rebind(query), args...)
}

func (tx *GateTx) Get(dest any, query string, args ...any) error {
	return tx.Tx.Get(dest, tx.Rebind(query), args...)
}

func (tx *GateTx) Select(dest any, query string, args ...any) error {
	return tx.Tx.Select(dest, tx.Rebind(query), args...)
}

func (tx *GateTx) Query(query string, args ...any) (*sql.Rows, error) {
	return tx.Tx.Query(tx.Rebind(query), args...)
}

func (tx *GateTx) QueryRow(query string, args ...any) *sql.Row {
	return tx.Tx.QueryRow(tx.Rebind(query), args...)
}

// readMigrations reads SQL migration files from the given embed.FS and subdirectory.
func readMigrations(fs embed.FS, dir string) ([]string, error) {
	entries, err := fs.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("config: reading migrations dir %s: %w", dir, err)
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
		data, err := fs.ReadFile(dir + "/" + name)
		if err != nil {
			return nil, fmt.Errorf("config: reading migration %s: %w", name, err)
		}
		sqls = append(sqls, string(data))
	}
	return sqls, nil
}

// runMigrations applies unapplied migrations to the database.
func runMigrations(db *sqlx.DB, fs embed.FS, dir string) error {
	// Ensure schema_migrations table exists (bootstrap).
	// Use ANSI SQL compatible syntax for both backends.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at TIMESTAMP NOT NULL
	)`); err != nil {
		return fmt.Errorf("config: creating schema_migrations: %w", err)
	}

	migrations, err := readMigrations(fs, dir)
	if err != nil {
		return err
	}
	for i, sql := range migrations {
		version := i + 1
		var count int
		_ = db.Get(&count, db.Rebind("SELECT COUNT(*) FROM schema_migrations WHERE version = ?"), version)
		if count > 0 {
			continue
		}
		if _, err := db.Exec(sql); err != nil {
			return fmt.Errorf("config: running migration %d: %w", version, err)
		}
		db.Exec(db.Rebind("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)"), version, time.Now().UTC()) //nolint:errcheck
	}
	return nil
}

// InitDB creates a database connection based on the configured backend.
// It returns a *GateDB that auto-rebinds placeholder syntax.
func InitDB(cfg DatabaseConfig) (*GateDB, error) {
	switch cfg.Backend {
	case "postgres":
		return initPostgres(cfg.Postgres)
	case "sqlite", "":
		return initSQLite(cfg.SQLite)
	default:
		return nil, fmt.Errorf("config: unknown database backend: %s", cfg.Backend)
	}
}

func initSQLite(cfg SQLiteConfig) (*GateDB, error) {
	db, err := sqlx.Open("sqlite3", cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("config: opening database %s: %w", cfg.Path, err)
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

	if err := runMigrations(db, sqliteMigrationFS, "migrations/sqlite"); err != nil {
		db.Close()
		return nil, err
	}

	return &GateDB{db}, nil
}

func initPostgres(cfg PostgresConfig) (*GateDB, error) {
	db, err := sqlx.Open("postgres", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("config: opening postgres database: %w", err)
	}

	// Connection pool settings with defaults.
	maxOpen := cfg.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = 25
	}
	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 5
	}
	connMaxLifetime := 5 * time.Minute
	if cfg.ConnMaxLifetime != "" {
		d, err := time.ParseDuration(cfg.ConnMaxLifetime)
		if err != nil {
			db.Close()
			return nil, fmt.Errorf("config: parsing conn_max_lifetime %q: %w", cfg.ConnMaxLifetime, err)
		}
		connMaxLifetime = d
	}

	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(connMaxLifetime)

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("config: pinging postgres: %w", err)
	}
	log.Info().Int("max_open_conns", maxOpen).Int("max_idle_conns", maxIdle).Dur("conn_max_lifetime", connMaxLifetime).Msg("postgres connection pool configured")

	if err := runMigrations(db, postgresMigrationFS, "migrations/postgres"); err != nil {
		db.Close()
		return nil, err
	}

	return &GateDB{db}, nil
}

// SQLiteMemoryConfig returns a DatabaseConfig for an in-memory SQLite database.
// Intended for use in tests.
func SQLiteMemoryConfig() DatabaseConfig {
	return DatabaseConfig{
		Backend: "sqlite",
		SQLite:  SQLiteConfig{Path: ":memory:"},
	}
}
