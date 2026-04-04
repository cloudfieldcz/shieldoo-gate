package policy

import (
	"fmt"
	"strings"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// Action describes what the policy engine should do with a request.
type Action string

const (
	ActionAllow      Action = "allow"
	ActionBlock      Action = "block"
	ActionQuarantine Action = "quarantine"
)

// PolicyResult is the outcome of evaluating a policy against an artifact.
type PolicyResult struct {
	Action Action
	Reason string
}

// AllowlistEntry represents a parsed allowlist specification.
// Currently supports exact version matching via "eco:name:==version".
type AllowlistEntry struct {
	Ecosystem string
	Name      string
	Version   string // exact version, empty means all versions
}

// ParseAllowlistEntry parses an entry of the form "eco:name:==version".
// The version specifier "==" prefix is stripped; if omitted, all versions match.
func ParseAllowlistEntry(entry string) (AllowlistEntry, error) {
	parts := strings.SplitN(entry, ":", 3)
	if len(parts) < 2 {
		return AllowlistEntry{}, fmt.Errorf("policy: invalid allowlist entry %q: expected eco:name or eco:name:==version", entry)
	}

	e := AllowlistEntry{
		Ecosystem: parts[0],
		Name:      parts[1],
	}

	if len(parts) == 3 {
		versionSpec := parts[2]
		if strings.HasPrefix(versionSpec, "==") {
			e.Version = strings.TrimPrefix(versionSpec, "==")
		} else {
			// Accept bare version as exact match for convenience.
			e.Version = versionSpec
		}
	}

	return e, nil
}

// isAllowlisted returns true if the artifact matches any entry in the allowlist.
func isAllowlisted(artifact scanner.Artifact, allowlist []AllowlistEntry) bool {
	for _, entry := range allowlist {
		if entry.Ecosystem != string(artifact.Ecosystem) {
			continue
		}
		if entry.Name != artifact.Name {
			continue
		}
		// Empty version means all versions are allowed.
		if entry.Version == "" || entry.Version == artifact.Version {
			return true
		}
	}
	return false
}
