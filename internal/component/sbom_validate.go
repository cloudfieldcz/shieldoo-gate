package component

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// SBOMLimits describes the structural validation thresholds for an uploaded SBOM.
type SBOMLimits struct {
	MaxBytes        int64 // hard byte cap; reject above this
	MaxComponents   int   // reject SBOMs with components[] longer than this
	MaxDepth        int   // JSON nesting depth limit
	MaxStringLength int   // cap for identifier-shaped strings (name, version, purl, hashes)
	MaxTextLength   int   // cap for CycloneDX free-form prose fields (see isFreeTextSBOMField)
}

// DefaultSBOMLimits returns the canonical defaults: 500 MiB, 500000
// components, depth 16, 1024-char identifiers, 256 KiB free-form text.
//
// The 500 MiB / 500k component headroom is sized for `trivy image`-shaped
// CycloneDX SBOMs: realistic enterprise app images land at 1.5–5 MiB
// (well under the cap), but multi-language fat images, monorepo-based
// containers, and SBOMs that include layer-aware component metadata can
// push past the 10 MiB previously enforced. Deployments can tune both
// caps downward via `vuln_scan.max_sbom_bytes` and `vuln_scan.max_components`
// Viper keys.
//
// MaxStringLength stays tight because identifier-shaped fields end up in DB
// columns and OSV API requests. MaxTextLength is deliberately generous: the
// CycloneDX spec defines several fields as free-form prose, and generators
// legitimately put entire licence bodies in them — `trivy image` writes the
// full licence text into `licenses[].license.name` for any package without a
// machine-readable SPDX identifier (e.g. tiktoken ships a 1077-char MIT
// body). Those values are never used as identifiers, so the only thing the
// cap needs to do is bound memory; 256 KiB clears the longest real licence
// text (GPL-3.0 is ~35 KiB, ~48 KiB base64-encoded) with room to spare.
func DefaultSBOMLimits() SBOMLimits {
	return SBOMLimits{
		MaxBytes:        500 * 1024 * 1024,
		MaxComponents:   500000,
		MaxDepth:        16,
		MaxStringLength: 1024,
		MaxTextLength:   256 * 1024,
	}
}

// isFreeTextSBOMField reports whether a (parent container key, key) pair
// addresses a CycloneDX field the spec defines as free-form prose rather than
// an identifier. Prose fields get MaxTextLength instead of MaxStringLength.
//
// parent is the object/array key the value's enclosing container hangs off,
// which is what distinguishes `components[].name` (an identifier — capped
// tightly) from `licenses[].license.name` (free text — a licence body).
func isFreeTextSBOMField(parent, key string) bool {
	switch key {
	case "description", "copyright", "comment":
		// component/metadata prose and externalReferences[].comment.
		return true
	case "name":
		return parent == "license"
	case "content":
		// licenses[].license.text.content — base64 licence attachment.
		return parent == "text"
	case "value":
		// properties[].value — generators stash arbitrary blobs here.
		return parent == "properties"
	case "text":
		// annotations[].text.
		return parent == "annotations"
	}
	return false
}

// ValidateContentType returns nil if ct is one of the accepted CycloneDX media types.
func ValidateContentType(ct string) error {
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch ct {
	case "application/vnd.cyclonedx+json", "application/json", "":
		return nil
	}
	return fmt.Errorf("%w: %s", ErrUnsupportedMedia, ct)
}

// ValidateSBOMStructure performs a streaming structural pass over an already-buffered
// SBOM body. It enforces depth, components count, and per-string-length caps without
// allocating the full parsed structure.
//
// The function expects the body to be CycloneDX JSON with a top-level object containing
// `bomFormat: "CycloneDX"` and an array `components`. For our purposes we accept any
// document that parses as JSON within limits and contains the bomFormat header, even if
// `components` is missing (a CycloneDX SBOM with zero components is valid).
func ValidateSBOMStructure(body []byte, limits SBOMLimits) (componentCount int, err error) {
	if int64(len(body)) > limits.MaxBytes {
		return 0, fmt.Errorf("%w: %d bytes > limit %d", ErrSBOMTooLarge, len(body), limits.MaxBytes)
	}
	if len(body) == 0 {
		return 0, fmt.Errorf("%w: empty body", ErrInvalidSBOM)
	}

	textLimit := limits.MaxTextLength
	if textLimit <= 0 {
		textLimit = DefaultSBOMLimits().MaxTextLength
	}
	if limits.MaxStringLength > textLimit {
		// A caller that widened the identifier cap must not end up with a
		// *tighter* cap on prose fields.
		textLimit = limits.MaxStringLength
	}

	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()

	depth := 0
	insideComponents := false
	componentDepth := -1
	bomFormatSeen := false
	expectKey := true
	currentKey := ""
	rootDepth := -1 // depth at the moment we entered the top-level object

	// stack mirrors the currently-open containers. Each frame records the key
	// the container hangs off — so a string value's enclosing container key is
	// the top frame's — plus whether it is an object, which is what decides
	// where keys can appear at all: object members alternate key/value, array
	// elements are always values. Containers opened directly inside an array
	// inherit the array's key (`licenses` -> `[` -> `{` all read as
	// "licenses"), which is what makes `licenses[].license.name` addressable.
	type frame struct {
		key      string
		isObject bool
	}
	var stack []frame
	parentKey := func() string {
		if len(stack) == 0 {
			return ""
		}
		return stack[len(stack)-1].key
	}
	inObject := func() bool {
		return len(stack) > 0 && stack[len(stack)-1].isObject
	}
	push := func(isObject bool) {
		p := currentKey
		if p == "" {
			p = parentKey()
		}
		stack = append(stack, frame{key: p, isObject: isObject})
	}
	pop := func() {
		if len(stack) > 0 {
			stack = stack[:len(stack)-1]
		}
	}

	for {
		tok, terr := dec.Token()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			return 0, fmt.Errorf("%w: %v", ErrInvalidSBOM, terr)
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				depth++
				if rootDepth == -1 {
					rootDepth = depth
				}
				if insideComponents && depth == componentDepth+1 {
					componentCount++
					if componentCount > limits.MaxComponents {
						return 0, fmt.Errorf("%w: components > %d", ErrInvalidSBOM, limits.MaxComponents)
					}
				}
				if depth > limits.MaxDepth {
					return 0, fmt.Errorf("%w: depth > %d", ErrInvalidSBOM, limits.MaxDepth)
				}
				push(true)
				currentKey = ""
				expectKey = true
			case '[':
				depth++
				if depth > limits.MaxDepth {
					return 0, fmt.Errorf("%w: depth > %d", ErrInvalidSBOM, limits.MaxDepth)
				}
				if currentKey == "components" && !insideComponents {
					insideComponents = true
					componentDepth = depth
				}
				push(false)
				currentKey = ""
				expectKey = false
			case '}':
				if insideComponents && depth == componentDepth {
					// closing the components array? actually [] closes
				}
				depth--
				pop()
				currentKey = ""
				// A container that just closed was itself a value; the next
				// token is a key only if the *enclosing* container is an object.
				expectKey = inObject()
			case ']':
				if insideComponents && depth == componentDepth {
					insideComponents = false
					componentDepth = -1
				}
				depth--
				pop()
				currentKey = ""
				expectKey = inObject()
			}
		case string:
			if expectKey {
				currentKey = t
				expectKey = false
			} else {
				maxLen := limits.MaxStringLength
				if isFreeTextSBOMField(parentKey(), currentKey) {
					maxLen = textLimit
				}
				if len(t) > maxLen {
					return 0, fmt.Errorf("%w: string >%d chars at key %q", ErrInvalidSBOM, maxLen, currentKey)
				}
				if currentKey == "bomFormat" && t == "CycloneDX" {
					bomFormatSeen = true
				}
				// Array elements are always values — only object members
				// alternate. Without this, the second element of a string array
				// would be mistaken for a key and could lend its name (e.g.
				// "description") to the next element's length cap.
				expectKey = inObject()
				currentKey = ""
			}
		default:
			expectKey = inObject()
			currentKey = ""
			_ = t
		}
	}

	if depth != 0 {
		return 0, fmt.Errorf("%w: unbalanced JSON", ErrInvalidSBOM)
	}
	if !bomFormatSeen {
		return 0, fmt.Errorf("%w: missing bomFormat=CycloneDX", ErrInvalidSBOM)
	}
	return componentCount, nil
}

// ReadAllLimited reads up to limit+1 bytes from r and returns ErrSBOMTooLarge if the
// stream exceeds limit. Otherwise returns the buffered body.
func ReadAllLimited(r io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		limit = DefaultSBOMLimits().MaxBytes
	}
	lr := io.LimitReader(r, limit+1)
	buf, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > limit {
		return nil, fmt.Errorf("%w: limit %d", ErrSBOMTooLarge, limit)
	}
	return buf, nil
}

// IsErrInvalidSBOM returns true when err wraps ErrInvalidSBOM.
func IsErrInvalidSBOM(err error) bool {
	return errors.Is(err, ErrInvalidSBOM)
}
