package model

import "time"

// Session is a server-side admin UI session. The opaque ID is what travels in the
// session cookie; the verified OIDC identity claims are stored server-side so that
// logout and expiry are enforceable (a captured cookie can be revoked) and the raw
// ID token never leaves the IdP/callback boundary.
type Session struct {
	ID         string    `db:"id"`
	Subject    string    `db:"subject"`
	Email      string    `db:"email"`
	Name       string    `db:"name"`
	IDToken    string    `db:"id_token"`
	CreatedAt  time.Time `db:"created_at"`
	LastSeenAt time.Time `db:"last_seen_at"`
	ExpiresAt  time.Time `db:"expires_at"`
}
