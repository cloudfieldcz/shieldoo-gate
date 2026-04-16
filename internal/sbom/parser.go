package sbom

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// cycloneDXBOM is the minimal shape we care about from CycloneDX 1.4/1.5.
// We deliberately ignore fields irrelevant to license extraction to stay
// compatible across schema versions.
type cycloneDXBOM struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Metadata    cdxMetadata    `json:"metadata"`
	Components  []cdxComponent `json:"components"`
}

// cdxMetadata.Tools can be either:
//   - an array of tool objects (CycloneDX 1.4 style), or
//   - an object with "components" / "services" arrays (1.5+ style).
// We keep the raw JSON and parse both shapes in toolsList().
type cdxMetadata struct {
	Tools json.RawMessage `json:"tools"`
}

type cdxTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  string `json:"vendor"`
}

// toolsList normalizes the two CycloneDX shapes for metadata.tools into a
// single flat list of cdxTool entries. Unknown/unparseable values return an
// empty list — tools are only used for the generator string.
func toolsList(raw json.RawMessage) []cdxTool {
	if len(raw) == 0 {
		return nil
	}
	// First try: array of tools (1.4 style).
	var arr []cdxTool
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	// Second try: object with "components" array (1.5+ style).
	var obj struct {
		Components []cdxTool `json:"components"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj.Components
	}
	return nil
}

type cdxComponent struct {
	Type     string           `json:"type"`
	Name     string           `json:"name"`
	Version  string           `json:"version"`
	PURL     string           `json:"purl"`
	Licenses []cdxLicenseWrap `json:"licenses"`
}

type cdxLicenseWrap struct {
	License    *cdxLicense `json:"license,omitempty"`
	Expression string      `json:"expression,omitempty"`
}

type cdxLicense struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

// Parse reads a CycloneDX JSON SBOM and returns the component count + a
// deduplicated, sorted list of canonical SPDX identifiers found.
//
// License normalization is conservative: if a license block has `id` we use
// that as-is; if only `name` is present we try a limited alias map so that
// common variants ("Apache License 2.0") resolve to the SPDX ID
// ("Apache-2.0"). Unknown names are preserved as-is so downstream policy
// enforcement can apply its `unknown_action`.
func Parse(data []byte) (ExtractResult, error) {
	if len(data) == 0 {
		return ExtractResult{}, nil
	}
	var bom cycloneDXBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return ExtractResult{}, fmt.Errorf("sbom: parse cyclonedx: %w", err)
	}

	set := make(map[string]struct{})
	for _, c := range bom.Components {
		for _, lw := range c.Licenses {
			// Expression takes precedence (e.g. "MIT OR Apache-2.0").
			if lw.Expression != "" {
				set[strings.TrimSpace(lw.Expression)] = struct{}{}
				continue
			}
			if lw.License == nil {
				continue
			}
			switch {
			case lw.License.ID != "":
				set[strings.TrimSpace(lw.License.ID)] = struct{}{}
			case lw.License.Name != "":
				// Try alias normalization.
				if id, ok := nameAliasToID(lw.License.Name); ok {
					set[id] = struct{}{}
				} else {
					set[strings.TrimSpace(lw.License.Name)] = struct{}{}
				}
			}
		}
	}

	ids := make([]string, 0, len(set))
	for id := range set {
		if id != "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	generator := "unknown"
	tools := toolsList(bom.Metadata.Tools)
	if len(tools) > 0 {
		t := tools[0]
		if t.Name != "" {
			generator = t.Name
			if t.Version != "" {
				generator += "-" + t.Version
			}
		}
	}

	return ExtractResult{
		ComponentCount: len(bom.Components),
		Licenses:       ids,
		Generator:      generator,
	}, nil
}

// nameAliasToID returns the canonical SPDX ID for common non-standard
// license name strings. The table is intentionally small — its purpose is to
// catch the most common Trivy / upstream variants rather than to be a
// complete SPDX name database.
func nameAliasToID(name string) (string, bool) {
	key := strings.ToLower(strings.TrimSpace(name))
	id, ok := licenseAliases[key]
	return id, ok
}

// NameAliasToID is the exported variant of nameAliasToID for use by other
// packages (e.g. internal/scanner/trivy when normalizing licenses that came
// out of per-artifact metadata extraction). Returns the canonical SPDX ID
// when a known alias matches, or (input, false) when it doesn't.
//
// Always returning a usable string lets callers use a one-liner:
//
//	for i, l := range licenses { licenses[i], _ = sbom.NameAliasToID(l) }
func NameAliasToID(name string) (string, bool) {
	if id, ok := nameAliasToID(name); ok {
		return id, true
	}
	return name, false
}

// licenseAliases is populated from licenseAliasEntries at init time. Keys are
// lowercased; values are canonical SPDX IDs. New entries should prefer the
// shortest reasonable lowercase match over regex/loose matches.
var licenseAliases = buildLicenseAliases()

func buildLicenseAliases() map[string]string {
	out := make(map[string]string, len(licenseAliasEntries))
	for _, e := range licenseAliasEntries {
		out[strings.ToLower(e.alias)] = e.id
	}
	return out
}

type aliasEntry struct {
	alias string
	id    string
}

// licenseAliasEntries covers the most frequently observed non-SPDX license
// name strings in package metadata (PyPI classifiers, npm license strings,
// Maven pom licenses, etc.). Keep sorted alphabetically by alias for easy
// diffing and code review.
var licenseAliasEntries = []aliasEntry{
	{"apache 2", "Apache-2.0"},
	{"apache 2.0", "Apache-2.0"},
	{"apache license", "Apache-2.0"},
	{"apache license 2.0", "Apache-2.0"},
	{"apache license, version 2.0", "Apache-2.0"},
	{"apache license version 2.0", "Apache-2.0"},
	{"apache software license", "Apache-2.0"},
	{"apache-2", "Apache-2.0"},
	{"bsd 2-clause", "BSD-2-Clause"},
	{"bsd 2-clause license", "BSD-2-Clause"},
	{"bsd 3-clause", "BSD-3-Clause"},
	{"bsd 3-clause license", "BSD-3-Clause"},
	{"bsd license", "BSD-3-Clause"},
	{"bsd-3-clause license", "BSD-3-Clause"},
	{"eclipse public license 1.0", "EPL-1.0"},
	{"eclipse public license 2.0", "EPL-2.0"},
	{"gnu affero general public license v3", "AGPL-3.0-only"},
	{"gnu general public license v2", "GPL-2.0-only"},
	{"gnu general public license v3", "GPL-3.0-only"},
	{"gnu general public license, v2", "GPL-2.0-only"},
	{"gnu general public license, version 2", "GPL-2.0-only"},
	{"gnu general public license, version 2.0", "GPL-2.0-only"},
	{"gnu general public license, version 3", "GPL-3.0-only"},
	{"gnu lesser general public license v2.1", "LGPL-2.1-only"},
	{"gnu lesser general public license v3", "LGPL-3.0-only"},
	{"gnu lesser general public license, version 2.1", "LGPL-2.1-only"},
	{"gpl-2", "GPL-2.0-only"},
	{"gpl-2.0", "GPL-2.0-only"},
	{"gpl-3", "GPL-3.0-only"},
	{"gpl-3.0", "GPL-3.0-only"},
	{"gplv2", "GPL-2.0-only"},
	{"gplv3", "GPL-3.0-only"},
	{"isc", "ISC"},
	{"isc license", "ISC"},
	{"lgpl-2.1", "LGPL-2.1-only"},
	{"lgpl-3.0", "LGPL-3.0-only"},
	{"mit", "MIT"},
	{"mit license", "MIT"},
	{"mit license (mit)", "MIT"},
	{"mit-0", "MIT-0"},
	{"mozilla public license 2.0", "MPL-2.0"},
	{"mpl-2.0", "MPL-2.0"},
	{"public domain", "Unlicense"},
	// MySQL Connector/J ships GPLv2 with the FOSS exception. Trivy / our
	// extractor see the literal pom.xml `<name>` field — normalize so it
	// matches a `blocked: ["GPL-2.0-only"]` policy line. Two phrasings exist:
	// the older "with FOSS exception" and the post-Oracle-rename "with
	// Universal FOSS Exception, v1.0".
	{"the gnu general public license, v2 with foss exception", "GPL-2.0-only"},
	{"the gnu general public license, v2 with universal foss exception, v1.0", "GPL-2.0-only"},
	{"gnu general public license version 2.0", "GPL-2.0-only"},
	{"the apache software license, version 2.0", "Apache-2.0"},
	{"the mit license", "MIT"},
	{"the mit license (mit)", "MIT"},
	{"the unlicense", "Unlicense"},
	{"zlib license", "Zlib"},
}
