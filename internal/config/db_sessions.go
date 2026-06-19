package config

import (
	"fmt"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// CreateSession inserts a new server-side session row.
func (db *GateDB) CreateSession(s model.Session) error {
	_, err := db.Exec(
		"INSERT INTO sessions (id, subject, email, name, id_token, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		s.ID, s.Subject, s.Email, s.Name, s.IDToken, s.CreatedAt, s.LastSeenAt, s.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("db: create session: %w", err)
	}
	return nil
}

// GetSession returns the session row for id (regardless of expiry — the caller
// decides what to do with an expired row). Returns sql.ErrNoRows when absent.
func (db *GateDB) GetSession(id string) (*model.Session, error) {
	var s model.Session
	err := db.Get(&s,
		"SELECT id, subject, email, name, id_token, created_at, last_seen_at, expires_at FROM sessions WHERE id = ?",
		id,
	)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// TouchSession updates last_seen_at and expires_at for a session (used to record
// activity and to extend a session on refresh).
func (db *GateDB) TouchSession(id string, lastSeen, expiresAt time.Time) error {
	_, err := db.Exec(
		"UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?",
		lastSeen, expiresAt, id,
	)
	if err != nil {
		return fmt.Errorf("db: touch session: %w", err)
	}
	return nil
}

// DeleteSession removes a session row (logout / revocation).
func (db *GateDB) DeleteSession(id string) error {
	_, err := db.Exec("DELETE FROM sessions WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("db: delete session: %w", err)
	}
	return nil
}

// DeleteExpiredSessions purges sessions whose expiry is at or before now and
// returns the number removed.
func (db *GateDB) DeleteExpiredSessions(now time.Time) (int64, error) {
	res, err := db.Exec("DELETE FROM sessions WHERE expires_at <= ?", now)
	if err != nil {
		return 0, fmt.Errorf("db: delete expired sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
