package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/rs/zerolog/log"
)

// APIKeyMiddleware authenticates proxy requests using HTTP Basic Auth.
// The password field carries the API key (PAT or global token).
// The username field is ignored for authentication but logged for audit.
type APIKeyMiddleware struct {
	db          *config.GateDB
	globalToken string // plaintext global token from env; empty = disabled

	// lastUsed debounces last_used_at DB updates.
	// Key: api_keys.id, Value: time.Time of last flush.
	lastUsed      sync.Map
	flushInterval time.Duration
	stopFlush     chan struct{}
}

// NewAPIKeyMiddleware creates middleware that validates API keys via Basic Auth.
// globalToken is the plaintext global shared token (empty string disables it).
func NewAPIKeyMiddleware(db *config.GateDB, globalToken string) *APIKeyMiddleware {
	m := &APIKeyMiddleware{
		db:            db,
		globalToken:   globalToken,
		flushInterval: 30 * time.Second,
		stopFlush:     make(chan struct{}),
	}
	go m.flushLoop()
	return m
}

// Authenticate returns HTTP middleware that validates Basic Auth credentials.
func (m *APIKeyMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, password, ok := r.BasicAuth()
		if !ok || password == "" {
			writeProxyAuthError(w)
			return
		}

		username, _, _ := r.BasicAuth()

		// 1. Check global token (constant-time comparison).
		if m.globalToken != "" && subtle.ConstantTimeCompare([]byte(password), []byte(m.globalToken)) == 1 {
			user := &UserInfo{
				Email: username,
				Name:  "global-token",
			}
			ctx := ContextWithUser(r.Context(), user)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// 2. Check PAT via SHA-256 hash lookup.
		hash := sha256Hex(password)
		key, err := m.db.GetAPIKeyByHash(hash)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Error().Err(err).Msg("auth: api key lookup failed")
			}
			writeProxyAuthError(w)
			return
		}

		// Debounce last_used_at update.
		m.touchLastUsed(key.ID)

		user := &UserInfo{
			Email: key.OwnerEmail,
			Name:  key.Name,
		}
		ctx := ContextWithUser(r.Context(), user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Stop performs a final flush of last_used_at timestamps and stops the background goroutine.
func (m *APIKeyMiddleware) Stop() {
	close(m.stopFlush)
	m.flush()
}

// touchLastUsed records that a key was used. Actual DB write is debounced.
func (m *APIKeyMiddleware) touchLastUsed(keyID int64) {
	m.lastUsed.Store(keyID, time.Now())
}

// flushLoop periodically writes accumulated last_used_at timestamps to the DB.
func (m *APIKeyMiddleware) flushLoop() {
	ticker := time.NewTicker(m.flushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.flush()
		case <-m.stopFlush:
			return
		}
	}
}

// flush writes all pending last_used_at updates to the database.
func (m *APIKeyMiddleware) flush() {
	m.lastUsed.Range(func(key, value any) bool {
		keyID := key.(int64)
		m.lastUsed.Delete(keyID)
		if err := m.db.TouchAPIKeyLastUsed(keyID); err != nil {
			log.Warn().Err(err).Int64("key_id", keyID).Msg("auth: failed to update api key last_used_at")
		}
		return true
	})
}

// sha256Hex returns the lowercase hex-encoded SHA-256 hash of s.
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// writeProxyAuthError writes a 401 response with WWW-Authenticate header for proxy endpoints.
func writeProxyAuthError(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="shieldoo-gate"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}
