// Package effectivepom resolves Maven license metadata by walking the
// parent POM chain. Most Maven artifacts inherit their <licenses> block
// from a parent POM (e.g. org.apache:apache, org.apache.commons:commons-parent)
// rather than declaring it inline — this resolver fetches standalone .pom
// files from the upstream repository and walks up until it finds an explicit
// <licenses> declaration.
package effectivepom

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"

	"golang.org/x/text/encoding/charmap"
)

// maxPOMSize is the maximum allowed POM body size (1 MB). Legitimate POMs are
// well under 100 KB; anything larger is rejected to prevent XML bomb / Billion
// Laughs attacks.
const maxPOMSize = 1 * 1024 * 1024

// Coords identifies a Maven artifact by its GAV (Group-Artifact-Version)
// coordinates.
type Coords struct {
	GroupID    string
	ArtifactID string
	Version    string
}

// String returns "groupId:artifactId:version".
func (c Coords) String() string {
	return c.GroupID + ":" + c.ArtifactID + ":" + c.Version
}

// pomResult holds the parsed result of a single POM file.
type pomResult struct {
	Licenses []string // SPDX-ish license strings (from <licenses><license><name>)
	Parent   *Coords  // non-nil when the POM declares a <parent> reference
}

// parsePOM parses a POM XML body and extracts licenses and parent coordinates.
// The reader is limited to maxPOMSize bytes to prevent resource exhaustion.
// Returns an error only on malformed XML — an empty licenses list is not an error.
func parsePOM(r io.Reader) (*pomResult, error) {
	// Limit read to prevent XML bomb / resource exhaustion.
	limited := io.LimitReader(r, maxPOMSize+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("effectivepom: reading POM body: %w", err)
	}
	if len(data) > maxPOMSize {
		return nil, fmt.Errorf("effectivepom: POM exceeds %d bytes, rejected", maxPOMSize)
	}

	// Strip DTD declarations to prevent entity expansion attacks.
	// Go's encoding/xml does not expand external entities, but we strip
	// DOCTYPE as a defense-in-depth measure.
	cleaned := stripDOCTYPE(data)

	type pomLicense struct {
		Name string `xml:"name"`
		URL  string `xml:"url"`
	}
	type pomParent struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	}
	type pom struct {
		XMLName  xml.Name     `xml:"project"`
		Licenses []pomLicense `xml:"licenses>license"`
		Parent   *pomParent   `xml:"parent"`
	}

	var p pom
	dec := xml.NewDecoder(strings.NewReader(string(cleaned)))
	dec.CharsetReader = charsetReader
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("effectivepom: parsing POM XML: %w", err)
	}

	result := &pomResult{}

	for _, l := range p.Licenses {
		name := strings.TrimSpace(l.Name)
		if name != "" {
			result.Licenses = append(result.Licenses, name)
		} else if url := strings.TrimSpace(l.URL); url != "" {
			result.Licenses = append(result.Licenses, url)
		}
	}

	if p.Parent != nil && p.Parent.GroupID != "" && p.Parent.ArtifactID != "" && p.Parent.Version != "" {
		result.Parent = &Coords{
			GroupID:    p.Parent.GroupID,
			ArtifactID: p.Parent.ArtifactID,
			Version:    p.Parent.Version,
		}
	}

	return result, nil
}

// charsetReader returns an io.Reader that decodes the given charset into UTF-8.
// Many Maven POMs declare encoding="ISO-8859-1" — Go's xml.Decoder requires
// a CharsetReader to handle non-UTF-8 encodings.
func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(charset) {
	case "iso-8859-1", "latin-1", "latin1":
		return charmap.ISO8859_1.NewDecoder().Reader(input), nil
	case "windows-1252", "cp1252":
		return charmap.Windows1252.NewDecoder().Reader(input), nil
	default:
		return nil, fmt.Errorf("effectivepom: unsupported XML charset %q", charset)
	}
}

// stripDOCTYPE removes any <!DOCTYPE ...> declaration from the XML to prevent
// entity expansion attacks. This is a simple byte-level strip — it finds the
// first occurrence of "<!DOCTYPE" and removes everything up to the matching ">".
func stripDOCTYPE(data []byte) []byte {
	s := string(data)
	lower := strings.ToLower(s)
	idx := strings.Index(lower, "<!doctype")
	if idx < 0 {
		return data
	}
	end := strings.Index(s[idx:], ">")
	if end < 0 {
		// Malformed — return original and let XML parser handle it.
		return data
	}
	return []byte(s[:idx] + s[idx+end+1:])
}
