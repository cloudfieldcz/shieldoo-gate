package config

import (
	"fmt"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// CreateAPIKey inserts a new API key record and returns the generated ID.
func (db *GateDB) CreateAPIKey(keyHash, name, ownerEmail string) (int64, error) {
	res, err := db.Exec(
		"INSERT INTO api_keys (key_hash, name, owner_email) VALUES (?, ?, ?)",
		keyHash, name, ownerEmail,
	)
	if err != nil {
		return 0, fmt.Errorf("db: create api key: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("db: create api key: last insert id: %w", err)
	}
	return id, nil
}

// GetAPIKeyByHash looks up an enabled API key by its SHA-256 hash.
// Returns nil if not found or disabled.
func (db *GateDB) GetAPIKeyByHash(keyHash string) (*model.APIKey, error) {
	var key model.APIKey
	err := db.Get(&key, "SELECT id, key_hash, name, owner_email, enabled, created_at, last_used_at FROM api_keys WHERE key_hash = ? AND enabled = 1", keyHash)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

// ListAPIKeys returns all API keys (enabled and disabled), ordered by creation time descending.
func (db *GateDB) ListAPIKeys() ([]model.APIKey, error) {
	var keys []model.APIKey
	err := db.Select(&keys, "SELECT id, key_hash, name, owner_email, enabled, created_at, last_used_at FROM api_keys ORDER BY created_at DESC")
	if err != nil {
		return nil, fmt.Errorf("db: list api keys: %w", err)
	}
	return keys, nil
}

// RevokeAPIKey permanently disables an API key by setting enabled=false.
func (db *GateDB) RevokeAPIKey(id int64) error {
	res, err := db.Exec("UPDATE api_keys SET enabled = 0 WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("db: revoke api key: %w", err)
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("db: revoke api key: key %d not found", id)
	}
	return nil
}

// TouchAPIKeyLastUsed updates the last_used_at timestamp for the given key.
func (db *GateDB) TouchAPIKeyLastUsed(id int64) error {
	_, err := db.Exec("UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("db: touch api key last used: %w", err)
	}
	return nil
}
