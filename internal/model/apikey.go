package model

import "time"

// APIKey represents a proxy API key stored in the database.
// The plaintext key is never stored — only the SHA-256 hash (key_hash).
type APIKey struct {
	ID         int64      `db:"id" json:"id"`
	KeyHash    string     `db:"key_hash" json:"-"`
	Name       string     `db:"name" json:"name"`
	OwnerEmail string     `db:"owner_email" json:"owner_email"`
	Enabled    bool       `db:"enabled" json:"enabled"`
	CreatedAt  time.Time  `db:"created_at" json:"created_at"`
	LastUsedAt *time.Time `db:"last_used_at" json:"last_used_at,omitempty"`
}
