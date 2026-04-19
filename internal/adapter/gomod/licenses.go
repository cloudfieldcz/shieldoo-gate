package gomod

import (
	"archive/zip"
	"io"
	"sort"
	"strings"

	"github.com/google/licensecheck"
)

// Go module zips never embed any scanner like Trivy for license detection,
// so this package detects licenses by scanning LICENSE-family files inside
// the module zip with google/licensecheck (the same classifier used by
// pkg.go.dev). Results are written via adapter.TriggerAsyncLicenseWrite so
// the licenses appear in sbom_metadata and the admin UI.

// licenseConfidenceThreshold is the minimum licensecheck coverage percent
// required to accept a match. Below this we treat the file as ambiguous
// and return no license rather than guess.
const licenseConfidenceThreshold = 75.0

// maxLicenseFileBytes caps how much of a single license file we scan; any
// legitimate LICENSE text fits comfortably below this.
const maxLicenseFileBytes = 1 << 20 // 1 MiB

// extractLicensesFromGoModuleZip opens the Go module zip at path and returns
// canonical SPDX license IDs for LICENSE-family files at the module root.
// Best-effort: any error (missing file, bad zip, read failure) yields nil.
// The caller must not fail the scan pipeline on an empty return.
func extractLicensesFromGoModuleZip(path string) []string {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil
	}
	defer r.Close()

	seen := make(map[string]struct{})
	for _, f := range r.File {
		if !isRootLicenseFile(f.Name) {
			continue
		}
		if f.UncompressedSize64 > maxLicenseFileBytes {
			continue
		}
		ids := scanLicenseFile(f)
		for _, id := range ids {
			seen[id] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// scanLicenseFile reads a single zip entry and runs licensecheck over its
// contents. Returns distinct SPDX IDs whose combined coverage meets the
// confidence threshold.
func scanLicenseFile(f *zip.File) []string {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()

	data, err := io.ReadAll(io.LimitReader(rc, maxLicenseFileBytes))
	if err != nil {
		return nil
	}
	cov := licensecheck.Scan(data)
	if cov.Percent < licenseConfidenceThreshold {
		return nil
	}
	seen := make(map[string]struct{}, len(cov.Match))
	for _, m := range cov.Match {
		if m.ID == "" {
			continue
		}
		seen[m.ID] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	return out
}

// isRootLicenseFile reports whether name is a LICENSE-style file sitting
// directly under the module-root directory inside a Go module zip.
//
// Go module zips prefix every entry with "<module-path>@<version>/" where
// the module path itself may contain slashes
// ("github.com/rs/zerolog@v1.33.0/LICENSE"). We locate the root by
// finding the segment that carries the "@<version>" marker and then
// require the file to sit exactly one segment below it — otherwise a
// vendored dependency's LICENSE ("vendor/x/LICENSE") would be mis-
// attributed to the module itself.
func isRootLicenseFile(name string) bool {
	parts := strings.Split(name, "/")
	rootIdx := -1
	for i, p := range parts {
		if strings.Contains(p, "@") {
			rootIdx = i
			break
		}
	}
	if rootIdx < 0 || rootIdx+1 != len(parts)-1 {
		return false
	}
	base := strings.ToLower(parts[len(parts)-1])
	if dot := strings.IndexByte(base, '.'); dot > 0 {
		base = base[:dot]
	}
	switch base {
	case "license", "licence", "copying", "unlicense":
		return true
	}
	return false
}
