package auth

import (
	"database/sql"
	"errors"
	"sync"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/rs/zerolog/log"
)

const (
	// sessionIDBytes is the entropy of an opaque session ID (256 bits).
	sessionIDBytes = 32
	// sessionJanitorInterval is how often expired sessions are swept from the DB.
	sessionJanitorInterval = 10 * time.Minute
	// defaultSessionTTL is the session lifetime when none is configured.
	defaultSessionTTL = 15 * time.Minute
)

// SessionStore manages server-side admin UI sessions. The opaque session ID lives in
// the cookie; the verified identity is stored in the DB so logout/expiry are enforced
// server-side and a captured cookie can be revoked (unlike a self-contained JWT cookie).
type SessionStore struct {
	db       *config.GateDB
	ttl      time.Duration
	now      func() time.Time // injectable clock for tests
	stop     chan struct{}
	stopOnce sync.Once
}

// NewSessionStore constructs a store with the given session TTL and starts a janitor
// that periodically purges expired rows. Call Stop to end the janitor.
func NewSessionStore(db *config.GateDB, ttl time.Duration) *SessionStore {
	if ttl <= 0 {
		ttl = defaultSessionTTL
	}
	s := &SessionStore{
		db:   db,
		ttl:  ttl,
		now:  time.Now,
		stop: make(chan struct{}),
	}
	go s.janitorLoop()
	return s
}

// TTL returns the configured session lifetime.
func (s *SessionStore) TTL() time.Duration { return s.ttl }

// Create persists a new session for the given verified identity (and its raw OIDC id_token,
// used later as id_token_hint for RP-initiated logout) and returns its opaque ID.
func (s *SessionStore) Create(u *UserInfo, idToken string) (string, error) {
	id, err := randomString(sessionIDBytes)
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	sess := model.Session{
		ID:         id,
		Subject:    u.Subject,
		Email:      u.Email,
		Name:       u.Name,
		IDToken:    idToken,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(s.ttl),
	}
	if err := s.db.CreateSession(sess); err != nil {
		return "", err
	}
	return id, nil
}

// IDTokenFor returns the raw OIDC id_token stored for the given session ID, or "" when the
// session is missing or stored no token. Used ONLY by the logout path to build id_token_hint;
// the token is deliberately NOT returned by Validate, so it never reaches request context.
func (s *SessionStore) IDTokenFor(id string) string {
	if id == "" {
		return ""
	}
	sess, err := s.db.GetSession(id)
	if err != nil {
		return ""
	}
	return sess.IDToken
}

// Validate returns the identity for a live session and records activity. It returns
// (nil, false) when the session is missing or expired; an expired row is deleted.
// Expiry is NOT extended here — only Refresh slides the window.
func (s *SessionStore) Validate(id string) (*UserInfo, bool) {
	if id == "" {
		return nil, false
	}
	sess, err := s.db.GetSession(id)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			log.Error().Err(err).Msg("auth: session lookup failed")
		}
		return nil, false
	}
	now := s.now().UTC()
	if !sess.ExpiresAt.After(now) {
		_ = s.db.DeleteSession(id)
		return nil, false
	}
	// Record activity (best-effort; keep the existing expiry).
	_ = s.db.TouchSession(id, now, sess.ExpiresAt)
	return &UserInfo{Subject: sess.Subject, Email: sess.Email, Name: sess.Name}, true
}

// Refresh slides a live session's expiry by the configured TTL. Returns false when
// the session is missing or already expired (expired rows are deleted).
func (s *SessionStore) Refresh(id string) (bool, error) {
	if id == "" {
		return false, nil
	}
	sess, err := s.db.GetSession(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	now := s.now().UTC()
	if !sess.ExpiresAt.After(now) {
		_ = s.db.DeleteSession(id)
		return false, nil
	}
	if err := s.db.TouchSession(id, now, now.Add(s.ttl)); err != nil {
		return false, err
	}
	return true, nil
}

// Delete removes a session (logout / revocation). Best-effort; errors are logged.
func (s *SessionStore) Delete(id string) {
	if id == "" {
		return
	}
	if err := s.db.DeleteSession(id); err != nil {
		log.Warn().Err(err).Msg("auth: session delete failed")
	}
}

// Stop ends the janitor goroutine. Safe on a nil receiver and to call repeatedly.
func (s *SessionStore) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() { close(s.stop) })
}

func (s *SessionStore) janitorLoop() {
	ticker := time.NewTicker(sessionJanitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if n, err := s.db.DeleteExpiredSessions(s.now().UTC()); err != nil {
				log.Warn().Err(err).Msg("auth: expired-session sweep failed")
			} else if n > 0 {
				log.Debug().Int64("removed", n).Msg("auth: swept expired sessions")
			}
		case <-s.stop:
			return
		}
	}
}
