package sbom

import "strings"

// Sanitize replaces occurrences of the cache prefix inside the raw SBOM JSON
// with the empty string. This prevents the admin API from leaking the
// internal artifact cache path (e.g. "/var/cache/shieldoo-gate/pypi/...") to
// users who have permission to read the SBOM but not filesystem access.
//
// The function is deliberately a simple string replacement — it keeps the
// JSON valid because the prefix is always embedded inside string values, and
// the replacement is shorter than the original. Idempotent.
func Sanitize(raw []byte, cachePrefix string) []byte {
	if len(raw) == 0 || cachePrefix == "" {
		return raw
	}
	// Common path prefix can appear with or without trailing slash; handle both.
	trimmed := strings.TrimRight(cachePrefix, "/")
	s := string(raw)
	s = strings.ReplaceAll(s, trimmed+"/", "")
	s = strings.ReplaceAll(s, trimmed, "")
	return []byte(s)
}
