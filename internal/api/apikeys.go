package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

const (
	apiKeyPrefix    = "sgw_"
	apiKeyRandBytes = 32 // 256 bits of entropy
)

// apiKeyCreateRequest is the JSON body for POST /api/v1/api-keys.
type apiKeyCreateRequest struct {
	Name   string   `json:"name"`
	Scopes []string `json:"scopes,omitempty"`
}

// apiKeyCreateResponse is the JSON response for POST /api/v1/api-keys.
// The Token field contains the plaintext key — shown only once.
type apiKeyCreateResponse struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	OwnerEmail string    `json:"owner_email"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	Scopes     []string  `json:"scopes"`
	Token      string    `json:"token"`
}

// handleCreateAPIKey creates a new API key and returns the plaintext token once.
func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req apiKeyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name is required"})
		return
	}
	if len(req.Name) > 255 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name too long (max 255 characters)"})
		return
	}

	// Generate plaintext token.
	plaintext, err := generateAPIKey()
	if err != nil {
		log.Error().Err(err).Msg("api: failed to generate api key")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate key"})
		return
	}

	// Hash for storage.
	hash := sha256Hex(plaintext)

	// Get owner from OIDC context.
	ownerEmail := ""
	if user := auth.UserFromContext(r.Context()); user != nil {
		ownerEmail = user.Email
	}

	// Validate + canonicalize scopes. Empty list defaults to legacy proxy:fetch.
	scopes, err := canonicalizeScopes(req.Scopes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	id, err := s.db.CreateAPIKeyWithScopes(hash, req.Name, ownerEmail, strings.Join(scopes, ","))
	if err != nil {
		log.Error().Err(err).Msg("api: failed to create api key")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create key"})
		return
	}

	resp := apiKeyCreateResponse{
		ID:         id,
		Name:       req.Name,
		OwnerEmail: ownerEmail,
		Enabled:    true,
		CreatedAt:  time.Now().UTC(),
		Scopes:     scopes,
		Token:      plaintext,
	}
	writeJSON(w, http.StatusCreated, resp)
}

// canonicalizeScopes deduplicates, validates, and orders the requested scopes.
// Empty input expands to [proxy:fetch] for backwards compatibility.
func canonicalizeScopes(in []string) ([]string, error) {
	if len(in) == 0 {
		return []string{model.ScopeProxyFetch}, nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		valid := false
		for _, allowed := range model.AllScopes {
			if s == allowed {
				valid = true
				break
			}
		}
		if !valid {
			return nil, errInvalidScope(s)
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		return []string{model.ScopeProxyFetch}, nil
	}
	// Stable canonical ordering matching model.AllScopes.
	canonical := make([]string, 0, len(out))
	for _, allowed := range model.AllScopes {
		if seen[allowed] {
			canonical = append(canonical, allowed)
		}
	}
	return canonical, nil
}

func errInvalidScope(s string) error {
	return scopeError("invalid scope: " + s)
}

type scopeError string

func (e scopeError) Error() string { return string(e) }

// handleListAPIKeys returns API keys owned by the authenticated user.
func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil || user.Email == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	keys, err := s.db.ListAPIKeysByOwner(user.Email)
	if err != nil {
		log.Error().Err(err).Msg("api: failed to list api keys")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list keys"})
		return
	}
	// KeyHash is excluded via json:"-" tag in model.APIKey.
	writeJSON(w, http.StatusOK, keys)
}

// handleRevokeAPIKey permanently disables an API key.
// Only the key owner can revoke their own keys.
func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil || user.Email == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid key id"})
		return
	}

	// Verify ownership before revoking.
	key, err := s.db.GetAPIKey(id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "key not found"})
		return
	}
	if key.OwnerEmail != user.Email {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "you can only revoke your own keys"})
		return
	}

	if err := s.db.RevokeAPIKey(id); err != nil {
		log.Error().Err(err).Int64("key_id", id).Msg("api: failed to revoke api key")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to revoke key"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// generateAPIKey creates a new API key with the sgw_ prefix.
func generateAPIKey() (string, error) {
	b := make([]byte, apiKeyRandBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return apiKeyPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

