package pypi

import "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"

// CanonicalName returns the PEP 503 canonical form of a PyPI distribution name:
// lowercase ASCII with runs of `-`, `_`, or `.` collapsed to a single `-`.
//
// Thin wrapper over scanner.CanonicalPackageName so callers inside the PyPI
// adapter don't need to import scanner just to get this. The single source of
// truth lives in scanner so policy matching, override insertion, and admin
// search can all share it without importing the pypi adapter (which would
// otherwise pull a heavy dependency tree).
//
// Reference: https://peps.python.org/pep-0503/#normalized-names
func CanonicalName(name string) string {
	return scanner.CanonicalPackageName(scanner.EcosystemPyPI, name)
}
