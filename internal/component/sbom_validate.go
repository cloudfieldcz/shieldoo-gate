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
	MaxBytes         int64 // hard byte cap; reject above this
	MaxComponents    int   // reject SBOMs with components[] longer than this
	MaxDepth         int   // JSON nesting depth limit
	MaxStringLength  int   // reject any string longer than this (name, version, etc.)
}

// DefaultSBOMLimits returns the canonical defaults: 500 MiB, 500000
// components, depth 16, 1024-char strings.
//
// The 500 MiB / 500k component headroom is sized for `trivy image`-shaped
// CycloneDX SBOMs: realistic enterprise app images land at 1.5–5 MiB
// (well under the cap), but multi-language fat images, monorepo-based
// containers, and SBOMs that include layer-aware component metadata can
// push past the 10 MiB previously enforced. Deployments can tune both
// caps downward via `vuln_scan.max_sbom_bytes` and `vuln_scan.max_components`
// Viper keys.
func DefaultSBOMLimits() SBOMLimits {
	return SBOMLimits{
		MaxBytes:        500 * 1024 * 1024,
		MaxComponents:   500000,
		MaxDepth:        16,
		MaxStringLength: 1024,
	}
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

	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()

	depth := 0
	insideComponents := false
	componentDepth := -1
	bomFormatSeen := false
	expectKey := true
	currentKey := ""
	rootDepth := -1 // depth at the moment we entered the top-level object

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
				expectKey = false
			case '}':
				if insideComponents && depth == componentDepth {
					// closing the components array? actually [] closes
				}
				depth--
				expectKey = true
			case ']':
				if insideComponents && depth == componentDepth {
					insideComponents = false
					componentDepth = -1
				}
				depth--
				expectKey = true
			}
		case string:
			if expectKey {
				currentKey = t
				expectKey = false
			} else {
				if len(t) > limits.MaxStringLength {
					return 0, fmt.Errorf("%w: string >%d chars at key %q", ErrInvalidSBOM, limits.MaxStringLength, currentKey)
				}
				if currentKey == "bomFormat" && t == "CycloneDX" {
					bomFormatSeen = true
				}
				expectKey = true
				currentKey = ""
			}
		default:
			expectKey = true
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
