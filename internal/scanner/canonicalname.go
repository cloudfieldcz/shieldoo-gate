package scanner

import (
	"regexp"
	"strings"
)

// pypiNameSeparatorRe matches runs of PEP 503 separators (`-`, `_`, `.`).
var pypiNameSeparatorRe = regexp.MustCompile(`[-_.]+`)

// CanonicalPackageName returns the canonical form of a package name for the
// given ecosystem. Used by adapters, policy matching, override insertion, and
// admin search to ensure all references key on a single, predictable name
// regardless of the source spelling.
//
// PyPI: lowercase ASCII with `[-_.]+` collapsed to `-` (PEP 503).
// Other ecosystems: returned unchanged. If their wire formats start to require
// normalization (npm scopes already have their own rules, NuGet is
// case-insensitive, etc.) extend the dispatch here — keeping a single
// authoritative function for all callers.
func CanonicalPackageName(eco Ecosystem, name string) string {
	if eco == EcosystemPyPI {
		return strings.ToLower(pypiNameSeparatorRe.ReplaceAllString(name, "-"))
	}
	return name
}
