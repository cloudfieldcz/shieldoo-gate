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
// NuGet: lowercase ASCII. NuGet package ids are officially case-insensitive and
// NuGet clients lowercase them in V3 registration / flat-container URLs, so the
// gate must match (and scope-glob) on the lowercased form — otherwise a private
// index scoped with `MyCompany.*` would never claim the `mycompany.*` requests
// the client actually sends, silently re-opening dependency-confusion (the very
// thing `packages` scoping exists to prevent). See issue #32 security review.
// Other ecosystems: returned unchanged.
func CanonicalPackageName(eco Ecosystem, name string) string {
	switch eco {
	case EcosystemPyPI:
		return strings.ToLower(pypiNameSeparatorRe.ReplaceAllString(name, "-"))
	case EcosystemNuGet:
		return strings.ToLower(name)
	default:
		return name
	}
}
