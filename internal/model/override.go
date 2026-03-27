package model

import "time"

// OverrideScope defines whether an override applies to a specific version or all versions.
type OverrideScope string

const (
	ScopeVersion OverrideScope = "version"
	ScopePackage OverrideScope = "package"
)

// PolicyOverride represents a user-created exception that allows an artifact
// through the policy engine despite scanner findings.
type PolicyOverride struct {
	ID        int64          `db:"id" json:"id"`
	Ecosystem string         `db:"ecosystem" json:"ecosystem"`
	Name      string         `db:"name" json:"name"`
	Version   string         `db:"version" json:"version"`
	Scope     OverrideScope  `db:"scope" json:"scope"`
	Reason    string         `db:"reason" json:"reason"`
	CreatedBy string         `db:"created_by" json:"created_by"`
	CreatedAt time.Time      `db:"created_at" json:"created_at"`
	ExpiresAt *time.Time     `db:"expires_at" json:"expires_at,omitempty"`
	Revoked   bool           `db:"revoked" json:"revoked"`
	RevokedAt *time.Time     `db:"revoked_at" json:"revoked_at,omitempty"`
}

// Matches returns true if this override applies to the given artifact coordinates.
func (o PolicyOverride) Matches(ecosystem, name, version string) bool {
	if o.Revoked {
		return false
	}
	if o.ExpiresAt != nil && time.Now().UTC().After(*o.ExpiresAt) {
		return false
	}
	if o.Ecosystem != ecosystem || o.Name != name {
		return false
	}
	if o.Scope == ScopeVersion && o.Version != version {
		return false
	}
	return true
}
