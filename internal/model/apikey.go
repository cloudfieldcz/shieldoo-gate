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
	// Scopes is a comma-separated list of capability tokens (proxy:fetch,
	// scan:upload, admin:read, admin:write). Migration 032 adds this column;
	// rows with empty scopes are treated as legacy proxy:fetch only.
	Scopes string `db:"scopes" json:"scopes"`
}

// Scope constants for least-privilege PAT enforcement.
const (
	ScopeProxyFetch = "proxy:fetch"
	ScopeScanUpload = "scan:upload"
	ScopeAdminRead  = "admin:read"
	ScopeAdminWrite = "admin:write"
	// ScopeKeysManage authorizes API-key management (create/list/revoke). It is
	// separate from admin:write so a general admin token cannot mint or revoke API
	// keys (token self-replication / privilege persistence) unless explicitly granted.
	ScopeKeysManage = "keys:manage"
)

// AllScopes lists every recognized scope (used by the token-creation handler).
var AllScopes = []string{ScopeProxyFetch, ScopeScanUpload, ScopeAdminRead, ScopeAdminWrite, ScopeKeysManage}

// HasScope returns true when scopes (comma-separated) contains needle. Empty list
// is treated as legacy proxy:fetch only.
func HasScope(scopes, needle string) bool {
	if scopes == "" {
		return needle == ScopeProxyFetch
	}
	for _, s := range splitCSV(scopes) {
		if s == needle {
			return true
		}
	}
	return false
}

// ScopeList returns the parsed list of scopes from the comma-separated form.
// Empty input expands to [ScopeProxyFetch] for legacy compatibility.
func ScopeList(scopes string) []string {
	if scopes == "" {
		return []string{ScopeProxyFetch}
	}
	return splitCSV(scopes)
}

func splitCSV(s string) []string {
	out := []string{}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			t := s[start:i]
			// trim spaces
			for len(t) > 0 && (t[0] == ' ' || t[0] == '\t') {
				t = t[1:]
			}
			for len(t) > 0 && (t[len(t)-1] == ' ' || t[len(t)-1] == '\t') {
				t = t[:len(t)-1]
			}
			if t != "" {
				out = append(out, t)
			}
			start = i + 1
		}
	}
	return out
}
