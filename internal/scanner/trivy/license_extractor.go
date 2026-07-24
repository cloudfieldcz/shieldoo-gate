package trivy

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"io/fs"
	"net/url"
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

// nuGetDeprecatedLicenseURL is the placeholder nuget.org stamps into
// <licenseUrl> whenever a package declares the modern <license> element.
// It never carries license information.
const nuGetDeprecatedLicenseURL = "https://aka.ms/deprecateLicenseUrl"

// maxLicenseFileSize caps how much of a <license type="file"> target we are
// willing to read. Real license texts are a few KB; anything bigger is not a
// license file.
const maxLicenseFileSize = 1 << 20 // 1 MiB

// nugetLicenseURLToExpression maps a licenses.nuget.org URL to the SPDX
// expression encoded in its path (e.g. .../Apache-2.0%20OR%20MIT). nuget.org
// generates these URLs mechanically from <license type="expression">, so the
// mapping is authoritative.
func nugetLicenseURLToExpression(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Hostname(), "licenses.nuget.org") {
		return "", false
	}
	expr := strings.Trim(u.Path, "/") // url.Parse already percent-decoded
	if expr == "" || strings.Contains(expr, "/") {
		return "", false
	}
	return expr, true
}

// classifyLicenseText heuristically maps a license file's text to SPDX IDs.
// Multi-license files (e.g. Hangfire's "LGPL v3 or commercial") yield every
// recognized branch; unrecognizable text yields nil so the artifact stays
// "unknown" for the policy engine instead of leaking a filename or URL as a
// pseudo-license. Best-effort by design — only unambiguous phrases match.
func classifyLicenseText(data []byte) []string {
	// Collapse all whitespace so phrases split across line breaks still match.
	text := strings.ToLower(strings.Join(strings.Fields(string(data)), " "))

	var out []string

	// GNU family. "GNU Lesser/Affero General Public License" contains the
	// plain-GPL phrase (and "lgpl"/"agpl" contain "gpl"), so detect the
	// specific variants first and strip them before looking for plain GPL.
	hasAny := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(text, s) {
				return true
			}
		}
		return false
	}
	hasLesser := hasAny("gnu lesser general public license", "gnu library general public license")
	switch {
	case (hasLesser && hasAny("version 2.1", "v2.1")) || hasAny("lgplv2.1", "lgpl-2.1", "lgpl v2.1"):
		out = append(out, "LGPL-2.1-only")
	case (hasLesser && hasAny("version 3", "v3")) || hasAny("lgplv3", "lgpl-3.0", "lgpl v3", "lgpl 3.0"):
		out = append(out, "LGPL-3.0-only")
	}
	if (strings.Contains(text, "gnu affero general public license") && hasAny("version 3", "v3")) || hasAny("agplv3", "agpl-3.0", "agpl v3") {
		out = append(out, "AGPL-3.0-only")
	}
	plain := strings.NewReplacer(
		"gnu lesser general public license", "",
		"gnu library general public license", "",
		"gnu affero general public license", "",
		"lgpl", "",
		"agpl", "",
	).Replace(text)
	switch {
	case strings.Contains(plain, "gnu general public license") && hasAny("version 3", "v3") || strings.Contains(plain, "gplv3") || strings.Contains(plain, "gpl-3.0"):
		out = append(out, "GPL-3.0-only")
	case strings.Contains(plain, "gnu general public license") && strings.Contains(plain, "version 2") || strings.Contains(plain, "gplv2") || strings.Contains(plain, "gpl-2.0"):
		out = append(out, "GPL-2.0-only")
	}

	if strings.Contains(text, "permission is hereby granted, free of charge") {
		out = append(out, "MIT")
	}
	if strings.Contains(text, "permission to use, copy, modify, and/or distribute this software") {
		out = append(out, "ISC")
	}
	if strings.Contains(text, "apache license") && strings.Contains(text, "version 2.0") {
		out = append(out, "Apache-2.0")
	}
	if strings.Contains(text, "mozilla public license") && strings.Contains(text, "2.0") {
		out = append(out, "MPL-2.0")
	}
	if strings.Contains(text, "redistribution and use in source and binary forms") {
		if strings.Contains(text, "neither the name") {
			out = append(out, "BSD-3-Clause")
		} else {
			out = append(out, "BSD-2-Clause")
		}
	}
	if strings.Contains(text, "free and unencumbered software released into the public domain") {
		out = append(out, "Unlicense")
	}
	return out
}

// parseNuSpec reads a .nuspec XML file and extracts the license. NuGet has
// three metadata shapes, handled in order of reliability:
//
//   - `<license type="expression">SPDX</license>` — used verbatim.
//   - `<license type="file">LICENSE.md</license>` — the referenced file is
//     read from the unpacked package and classified to SPDX IDs; the bare
//     filename is never emitted (it would poison the license list with a
//     meaningless "LICENSE.md" entry).
//   - `<licenseUrl>` — licenses.nuget.org URLs are decoded to the SPDX
//     expression in their path; the nuget.org deprecation placeholder is
//     dropped; any other URL is forwarded verbatim so the alias map or an
//     admin can deal with it.
func parseNuSpec(path string) []string {
	data, err := os.ReadFile(path) //nolint:gosec // path from walk
	if err != nil {
		return nil
	}
	type nuLicense struct {
		Type  string `xml:"type,attr"`
		Value string `xml:",chardata"`
	}
	// xml package is fussy about namespace handling — walk tokens instead of
	// unmarshalling a fixed structure.
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	var out []string
	seen := make(map[string]struct{})
	add := func(values ...string) {
		for _, v := range values {
			if _, dup := seen[v]; dup {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, v)
		}
	}
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
			if err := dec.DecodeElement(&lic, &se); err != nil {
				continue
			}
			value := strings.TrimSpace(lic.Value)
			if value == "" {
				continue
			}
			if strings.EqualFold(lic.Type, "file") {
				add(classifyNuSpecLicenseFile(path, value)...)
			} else {
				// type="expression" or absent — treat as SPDX expression.
				add(value)
			}
		case "licenseurl":
			var rawURL string
			if err := dec.DecodeElement(&rawURL, &se); err != nil || rawURL == "" {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(rawURL), nuGetDeprecatedLicenseURL) {
				continue // placeholder, never a license
			}
			if expr, ok := nugetLicenseURLToExpression(rawURL); ok {
				add(expr)
			} else {
				add(rawURL)
			}
		}
	}
	return out
}

// classifyNuSpecLicenseFile resolves a `<license type="file">` reference
// relative to the nuspec's directory (= package root in an unpacked nupkg)
// and classifies its text. Paths escaping the package directory are refused.
func classifyNuSpecLicenseFile(nuspecPath, ref string) []string {
	rel := filepath.Clean(filepath.FromSlash(strings.ReplaceAll(ref, `\`, "/")))
	if rel == "." || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return nil
	}
	full := filepath.Join(filepath.Dir(nuspecPath), rel)
	info, err := os.Stat(full)
	if err != nil || info.IsDir() || info.Size() > maxLicenseFileSize {
		return nil
	}
	data, err := os.ReadFile(full) //nolint:gosec // confined to package dir above
	if err != nil {
		return nil
	}
	return classifyLicenseText(data)
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
