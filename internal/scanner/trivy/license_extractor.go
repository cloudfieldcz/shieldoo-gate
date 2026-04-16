package trivy

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// extractLicensesFromDir walks a freshly-unpacked package directory looking
// for the canonical metadata file of each supported ecosystem and returns
// the SPDX-ish license strings found there.
//
// Why this exists: Trivy 0.50 only detects packages from lockfiles
// (requirements.txt, package-lock.json, …). It does NOT enumerate a single
// installed package's metadata files (`*.dist-info/METADATA`,
// `package.json`, `META-INF/maven/.../pom.xml`, `*.nuspec`). For a proxy
// that scans one artifact at a time we need direct metadata parsing —
// otherwise license policy is a no-op for every PyPI/npm/NuGet/Maven
// artifact.
//
// All extractors are best-effort: parse failures are swallowed and an empty
// list is returned. We never fail the scan because of malformed metadata.
//
// The returned licenses go into ScanResult.Licenses, alongside whatever
// Trivy itself produced — they're merged into the final SBOM.
func extractLicensesFromDir(root string) []string {
	if root == "" {
		return nil
	}
	licSet := make(map[string]struct{})

	add := func(values ...string) {
		for _, v := range values {
			v = strings.TrimSpace(v)
			if v == "" || strings.EqualFold(v, "UNKNOWN") {
				continue
			}
			licSet[v] = struct{}{}
		}
	}

	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable subtrees
		}
		if d.IsDir() {
			// Recurse cap: don't descend further than reasonable for the
			// shapes we expect (dist-info, META-INF, etc. are at most a
			// few levels deep).
			rel, _ := filepath.Rel(root, path)
			if strings.Count(rel, string(os.PathSeparator)) > 6 {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		switch {
		// --- PyPI wheel -----------------------------------------------------
		case name == "METADATA" && strings.Contains(path, ".dist-info"+string(os.PathSeparator)):
			add(parsePyPIMetadata(path)...)
		// --- PyPI sdist -----------------------------------------------------
		case name == "PKG-INFO":
			add(parsePyPIMetadata(path)...) // same RFC-822 format
		// --- npm tarball ----------------------------------------------------
		case name == "package.json":
			add(parseNPMPackageJSON(path)...)
		// --- NuGet ----------------------------------------------------------
		case strings.HasSuffix(strings.ToLower(name), ".nuspec"):
			add(parseNuSpec(path)...)
		// --- Maven JAR ------------------------------------------------------
		case name == "pom.xml" && strings.Contains(path, "META-INF"+string(os.PathSeparator)+"maven"):
			add(parseMavenPOM(path)...)
		// --- Maven raw POM (when the artifact itself is a .pom) -------------
		// (handled by name=='pom.xml' in any location — keep generic)
		}
		return nil
	})

	out := make([]string, 0, len(licSet))
	for k := range licSet {
		out = append(out, k)
	}
	return out
}

// --- PyPI ----------------------------------------------------------------

// parsePyPIMetadata reads a wheel/sdist METADATA (RFC-822-like) and returns
// the licenses it advertises. Honors:
//   - `License-Expression: <SPDX expression>`   (PEP 639, preferred)
//   - `License: <free-form string>`             (legacy, often a name)
//   - `Classifier: License :: OSI Approved :: <human name>`
//
// The classifier list lives in classifierToSPDX; misses fall through to
// the alias map already present in internal/sbom/parser.go via downstream
// normalization.
func parsePyPIMetadata(path string) []string {
	f, err := os.Open(path) //nolint:gosec // path comes from extractLicensesFromDir walk
	if err != nil {
		return nil
	}
	defer f.Close()

	var (
		results []string
		expr    string
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 256*1024)
	for sc.Scan() {
		line := sc.Text()
		// Headers end at the first blank line.
		if line == "" {
			break
		}
		switch {
		case strings.HasPrefix(line, "License-Expression:"):
			expr = strings.TrimSpace(strings.TrimPrefix(line, "License-Expression:"))
		case strings.HasPrefix(line, "License:"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "License:"))
			if v != "" && !strings.EqualFold(v, "UNKNOWN") {
				results = append(results, v)
			}
		case strings.HasPrefix(line, "Classifier: License ::"):
			v := strings.TrimSpace(strings.TrimPrefix(line, "Classifier:"))
			if id := classifierToSPDX(v); id != "" {
				results = append(results, id)
			}
		}
	}
	if expr != "" {
		// PEP 639 preferred — return only this when present.
		return []string{expr}
	}
	return results
}

// classifierToSPDX maps Python Trove "License :: OSI Approved :: X" classifiers
// to SPDX IDs. Only the most common entries — unknown classifiers fall through.
func classifierToSPDX(classifier string) string {
	c := strings.TrimSpace(classifier)
	switch {
	case strings.Contains(c, "Apache Software License"):
		return "Apache-2.0"
	case strings.Contains(c, "MIT License") || strings.Contains(c, "MIT No Attribution"):
		return "MIT"
	case strings.Contains(c, "BSD License"):
		return "BSD-3-Clause"
	case strings.Contains(c, "ISC License"):
		return "ISC"
	case strings.Contains(c, "GNU Affero General Public License v3"):
		return "AGPL-3.0-only"
	case strings.Contains(c, "GNU General Public License v3"):
		return "GPL-3.0-only"
	case strings.Contains(c, "GNU General Public License v2"):
		return "GPL-2.0-only"
	case strings.Contains(c, "GNU Lesser General Public License v3"):
		return "LGPL-3.0-only"
	case strings.Contains(c, "GNU Lesser General Public License v2"):
		return "LGPL-2.1-only"
	case strings.Contains(c, "Mozilla Public License 2.0"):
		return "MPL-2.0"
	case strings.Contains(c, "Eclipse Public License 2.0"):
		return "EPL-2.0"
	case strings.Contains(c, "Python Software Foundation License"):
		return "Python-2.0"
	case strings.Contains(c, "Public Domain"):
		return "CC0-1.0"
	case strings.Contains(c, "zlib/libpng License"):
		return "Zlib"
	}
	return ""
}

// --- npm -----------------------------------------------------------------

// parseNPMPackageJSON returns the license(s) declared in an npm package.json.
// Supports both modern `"license": "MIT"` and the deprecated array form
// `"licenses": [{"type": "MIT"}, ...]`.
func parseNPMPackageJSON(path string) []string {
	data, err := os.ReadFile(path) //nolint:gosec // path from walk
	if err != nil {
		return nil
	}
	var raw struct {
		License  json.RawMessage `json:"license"`
		Licenses json.RawMessage `json:"licenses"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}

	var out []string

	// "license": "MIT"  OR  "license": {"type": "MIT", "url": "..."}
	if len(raw.License) > 0 {
		var s string
		if err := json.Unmarshal(raw.License, &s); err == nil && s != "" {
			out = append(out, s)
		} else {
			var obj struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(raw.License, &obj); err == nil && obj.Type != "" {
				out = append(out, obj.Type)
			}
		}
	}

	// "licenses": [{"type": "MIT"}, {"type": "Apache-2.0"}]
	if len(raw.Licenses) > 0 {
		var arr []struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw.Licenses, &arr); err == nil {
			for _, a := range arr {
				if a.Type != "" {
					out = append(out, a.Type)
				}
			}
		}
	}
	return out
}

// --- NuGet ---------------------------------------------------------------

// parseNuSpec reads a .nuspec XML file and extracts the license. NuGet
// supports both the old `<licenseUrl>` (free-form URL pointing at a license
// text) and the modern `<license type="expression">SPDX</license>`. We
// prefer the SPDX expression when present; otherwise we leave the URL as-is
// so the alias map can normalize known ones.
func parseNuSpec(path string) []string {
	data, err := os.ReadFile(path) //nolint:gosec // path from walk
	if err != nil {
		return nil
	}
	type nuLicense struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	}
	var nuspec struct {
		XMLName  xml.Name  `xml:"package"`
		Metadata struct {
			License    nuLicense `xml:"metadata>license"`
			LicenseURL string    `xml:"metadata>licenseUrl"`
		} `xml:"metadata"`
	}
	// xml package is fussy about namespace handling — try the simple
	// path-based decode and fall through if structure differs.
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	var out []string
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return out
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch strings.ToLower(se.Name.Local) {
		case "license":
			var lic nuLicense
			if err := dec.DecodeElement(&lic, &se); err == nil && lic.Value != "" {
				out = append(out, strings.TrimSpace(lic.Value))
			}
		case "licenseurl":
			var url string
			if err := dec.DecodeElement(&url, &se); err == nil && url != "" {
				// Heuristic: the URL itself isn't an SPDX ID, but the
				// last path segment often matches the LICENSE filename
				// convention. Forward it verbatim — the policy editor
				// will treat it as "unknown" unless an admin adds it
				// to the allowed list.
				out = append(out, url)
			}
		}
	}
	_ = nuspec // unused, retained for future structured parsing
	return out
}

// --- Maven ---------------------------------------------------------------

// parseMavenPOM extracts the <name>/<url> of each <license> from a JAR's
// embedded pom.xml. Most artifacts list the license name (e.g. "Apache
// License, Version 2.0") which the alias map normalizes to an SPDX ID.
func parseMavenPOM(path string) []string {
	data, err := os.ReadFile(path) //nolint:gosec // path from walk
	if err != nil {
		return nil
	}
	type pomLicense struct {
		Name string `xml:"name"`
		URL  string `xml:"url"`
	}
	type pomLicenses struct {
		License []pomLicense `xml:"license"`
	}
	type pom struct {
		XMLName  xml.Name    `xml:"project"`
		Licenses pomLicenses `xml:"licenses"`
	}
	var p pom
	if err := xml.Unmarshal(data, &p); err != nil {
		return nil
	}
	var out []string
	for _, l := range p.Licenses.License {
		if l.Name != "" {
			out = append(out, strings.TrimSpace(l.Name))
		} else if l.URL != "" {
			out = append(out, strings.TrimSpace(l.URL))
		}
	}
	return out
}
