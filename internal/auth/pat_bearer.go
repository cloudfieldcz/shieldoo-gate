package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/rs/zerolog/log"
)

// PATBearerMiddleware authenticates admin-API requests using `Authorization: Bearer <PAT>`.
// Sister of APIKeyMiddleware (which is Basic-auth, proxy-only). On success the PAT's
// scope list is placed into the request context and downstream RequireScope decides.
//
// The middleware is *non-fatal*: when no Authorization header is present, the next
// handler is called without a user/scope set so a sibling OIDC fallback can authenticate
// the same request via session cookie.
type PATBearerMiddleware struct {
	db          *config.GateDB
	globalToken string
	auditWriter *AuditWriter
}

// NewPATBearerMiddleware constructs a PATBearerMiddleware.
func NewPATBearerMiddleware(db *config.GateDB, globalToken string, audit *AuditWriter) *PATBearerMiddleware {
	return &PATBearerMiddleware{db: db, globalToken: globalToken, auditWriter: audit}
}

// Authenticate is the chi middleware function.
func (m *PATBearerMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractBearer(r.Header.Get("Authorization"))
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Global super-token check first (constant-time).
		if m.globalToken != "" && subtle.ConstantTimeCompare([]byte(token), []byte(m.globalToken)) == 1 {
			ctx := r.Context()
			ctx = ContextWithUser(ctx, &UserInfo{Email: "", Name: "global-token"})
			ctx = WithScopes(ctx, []string{"*"})
			ctx = WithScopeKey(ctx, "global-token")
			// Security Invariant 6: fail CLOSED if the super-token use cannot be audited.
			if m.auditWriter != nil {
				if err := m.auditWriter.WriteVulnEvent(ctx, model.AuditEntry{
					EventType:    model.EventSuperTokenUsed,
					Reason:       "admin endpoint accessed via global token",
					ClientIP:     r.RemoteAddr,
					UserAgent:    r.UserAgent(),
					MetadataJSON: `{"name":"global-token"}`,
				}); err != nil {
					log.Error().Err(err).Msg("auth: failed to audit super_token_used (failing closed)")
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"error":"audit_error"}`))
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// PAT lookup by SHA-256.
		hash := sha256.Sum256([]byte(token))
		hashHex := hex.EncodeToString(hash[:])
		key, err := m.db.GetAPIKeyByHash(hashHex)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				log.Error().Err(err).Msg("auth: pat lookup failed")
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="shieldoo-gate"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
			return
		}

		ctx := r.Context()
		ctx = ContextWithUser(ctx, &UserInfo{Email: key.OwnerEmail, Name: key.Name})
		ctx = WithScopes(ctx, ScopesFromAPIKey(key))
		ctx = WithScopeKey(ctx, "pat:"+hashHex)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractBearer(h string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, prefix))
}
