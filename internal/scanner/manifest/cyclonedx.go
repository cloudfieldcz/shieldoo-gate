package manifest

import (
	"encoding/json"
	"fmt"
	"strings"
)

// cycloneDXDoc is the minimal subset of CycloneDX 1.4/1.5 we need to enumerate
// (purl, name, version, ecosystem) tuples for OSV batch queries.
type cycloneDXDoc struct {
	BomFormat  string         `json:"bomFormat"`
	Components []cdxComponent `json:"components"`
}

type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Group   string `json:"group"`
	Version string `json:"version"`
	Purl    string `json:"purl"`
}

// CycloneDXComponent is a normalized component view for OSV/Trivy lookups.
type CycloneDXComponent struct {
	Name      string
	Version   string
	Ecosystem string
	Purl      string
}

// ParseCycloneDXComponents returns a list of normalized components from an in-memory SBOM.
// Operating systems, files, and other non-package types are filtered out.
func ParseCycloneDXComponents(body []byte) ([]CycloneDXComponent, error) {
	var doc cycloneDXDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("manifest: unmarshal cyclonedx: %w", err)
	}
	if !strings.EqualFold(doc.BomFormat, "CycloneDX") {
		return nil, fmt.Errorf("manifest: bomFormat %q is not CycloneDX", doc.BomFormat)
	}
	out := make([]CycloneDXComponent, 0, len(doc.Components))
	for _, c := range doc.Components {
		if c.Name == "" || c.Version == "" {
			continue
		}
		eco := EcosystemFromPurl(c.Purl)
		out = append(out, CycloneDXComponent{
			Name:      c.Name,
			Version:   c.Version,
			Ecosystem: eco,
			Purl:      c.Purl,
		})
	}
	return out, nil
}

// EcosystemFromPurl extracts the OSV-canonical ecosystem name from a Package URL.
// Returns "" when the purl is empty or unrecognized.
func EcosystemFromPurl(purl string) string {
	if purl == "" {
		return ""
	}
	// pkg:<type>/<namespace>/<name>@<version> — we want <type>.
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return ""
	}
	t := rest[:slash]
	switch strings.ToLower(t) {
	case "pypi":
		return "PyPI"
	case "npm":
		return "npm"
	case "maven":
		return "Maven"
	case "gem":
		return "RubyGems"
	case "golang":
		return "Go"
	case "nuget":
		return "NuGet"
	case "apk":
		return "Alpine"
	case "deb":
		return "Debian"
	case "rpm":
		return "RPM"
	}
	return ""
}
