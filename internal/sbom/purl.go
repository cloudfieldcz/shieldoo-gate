package sbom

import (
	"net/url"
	"strings"
)

// BuildPURL constructs a Package URL (purl) for an artifact based on its
// ecosystem and identifying fields. Returns an empty string when the
// ecosystem is unknown or the inputs are insufficient (e.g. docker without a
// sha256 digest) — callers should emit the component without a purl field
// rather than fabricating an invalid one.
//
// Spec: https://github.com/package-url/purl-spec
//
// Per-ecosystem mapping:
//
//	pypi      → pkg:pypi/<name>@<version>
//	npm       → pkg:npm/<name>@<version>           (or .../%40scope/name@... for scoped)
//	maven     → pkg:maven/<groupId>/<artifactId>@<version>      (split on ':')
//	nuget     → pkg:nuget/<name>@<version>
//	rubygems  → pkg:gem/<name>@<version>
//	go        → pkg:golang/<namespace>/<name>@<version>          (split on last '/')
//	docker    → pkg:oci/<lastpath>@sha256:<digest>?repository_url=<host/path>&tag=<tag>
func BuildPURL(ecosystem, name, version, sha256, upstreamURL string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	switch ecosystem {
	case "pypi":
		return "pkg:pypi/" + segEscape(pep503Normalize(name)) + atVersion(version)
	case "npm":
		return npmPURL(name, version)
	case "maven":
		return mavenPURL(name, version)
	case "nuget":
		return "pkg:nuget/" + segEscape(name) + atVersion(version)
	case "rubygems":
		return "pkg:gem/" + segEscape(name) + atVersion(version)
	case "go":
		return golangPURL(name, version)
	case "docker":
		return ociPURL(name, version, sha256, upstreamURL)
	}
	return ""
}

// atVersion returns "@<encoded-version>" or "" when version is empty.
func atVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	return "@" + segEscape(v)
}

// pep503Normalize canonicalises a PyPI project name per PEP 503: lowercase
// the entire string and collapse any run of '.', '-', or '_' into a single
// '-'. The purl-spec for pypi MANDATES this normalisation, otherwise tools
// like Dependency-Track or Grype see "Django_package" and
// "django-package" as two different components and cannot reconcile them.
//
// Defence-in-depth: data migration 024 already canonicalises artifacts.name
// rows in the database, but BuildPURL is a public helper that may be called
// from tests, future code paths, or with hand-constructed inputs — applying
// the normalisation here makes the function correct on its own merits
// rather than dependent on the caller.
func pep503Normalize(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	b.Grow(len(name))
	prevDash := false
	for _, r := range name {
		if r == '.' || r == '_' || r == '-' {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
			continue
		}
		b.WriteRune(r)
		prevDash = false
	}
	return b.String()
}

// segEscape percent-encodes a single PURL path segment.
//
// PURL spec requires RFC 3986 path-segment encoding plus a few additional
// characters that Go's url.PathEscape leaves alone but PURL parsers treat as
// reserved: '@' (otherwise ambiguous with the version separator), '+', and
// '#'. Without this, "@types/node" round-trips as "pkg:npm/@types/node@..."
// which a strict purl parser cannot disambiguate.
func segEscape(s string) string {
	out := url.PathEscape(s)
	out = strings.ReplaceAll(out, "@", "%40")
	out = strings.ReplaceAll(out, "+", "%2B")
	out = strings.ReplaceAll(out, "#", "%23")
	return out
}

// npmPURL handles plain and scoped names. Scoped npm packages are stored as
// "@scope/name" in the DB; PURL splits that into namespace "@scope" and name
// "name", with '@' percent-encoded to '%40'.
func npmPURL(name, version string) string {
	if strings.HasPrefix(name, "@") {
		slash := strings.IndexByte(name, '/')
		if slash > 1 && slash < len(name)-1 {
			scope := name[:slash]
			leaf := name[slash+1:]
			return "pkg:npm/" + segEscape(scope) + "/" + segEscape(leaf) + atVersion(version)
		}
	}
	return "pkg:npm/" + segEscape(name) + atVersion(version)
}

// mavenPURL splits "groupId:artifactId" stored in artifacts.name. The colon
// is mandatory — without it we can't form a valid maven purl.
func mavenPURL(name, version string) string {
	idx := strings.LastIndexByte(name, ':')
	if idx <= 0 || idx >= len(name)-1 {
		return ""
	}
	group := name[:idx]
	artifact := name[idx+1:]
	// Maven groupIds may contain dots — these are NOT encoded; the purl spec
	// treats each '/' as a namespace separator only. Dots survive as-is.
	return "pkg:maven/" + segEscape(group) + "/" + segEscape(artifact) + atVersion(version)
}

// golangPURL splits a Go module path on the last '/' to derive namespace+name.
// A single-segment module path (rare, e.g. a non-domain root) becomes a name
// with no namespace.
//
// Per purl-spec (https://github.com/package-url/purl-spec/blob/main/types-doc/golang-definition.md):
// "The namespace must be lowercased" and "The name must be lowercased."
// This is lossy for legacy mixed-case module paths (e.g. the historical
// Sirupsen/logrus → sirupsen/logrus rename), but spec compliance wins.
// It also matches Trivy's pkg/purl/purl.go:parseGolang which lowercases the
// same way — keeping the per-artifact SBOM (Trivy) and per-project SBOM
// (this generator) emitting identical PURLs for the same module so
// downstream tools (Dependency-Track, Grype) reconcile components
// correctly.
func golangPURL(modulePath, version string) string {
	modulePath = strings.ToLower(modulePath)
	idx := strings.LastIndexByte(modulePath, '/')
	if idx <= 0 {
		return "pkg:golang/" + segEscape(modulePath) + atVersion(version)
	}
	ns := modulePath[:idx]
	leaf := modulePath[idx+1:]
	// Encode each '/' segment of ns individually, then rejoin with literal '/'.
	parts := strings.Split(ns, "/")
	for i, p := range parts {
		parts[i] = segEscape(p)
	}
	return "pkg:golang/" + strings.Join(parts, "/") + "/" + segEscape(leaf) + atVersion(version)
}

// ociPURL constructs a pkg:oci PURL. The OCI purl type requires a sha256
// digest as the version (NOT the tag) and exposes the original tag + full
// repository URL via qualifiers. Returns "" when no digest is available.
func ociPURL(safeName, ref, sha256, upstreamURL string) string {
	if sha256 == "" {
		return ""
	}
	// Try to recover registry host + image path from upstream URL.
	// Format produced by the docker adapter:
	//     https://<host>/v2/<image-path>/manifests/<ref>
	repoURL, imageName := parseDockerUpstream(upstreamURL)
	if imageName == "" {
		// Fallback: derive name from the safeName ("host_path_seg") by taking
		// the last underscore-delimited segment.
		imageName = lastUnderscoreSeg(safeName)
	}
	if imageName == "" {
		return ""
	}
	out := "pkg:oci/" + segEscape(strings.ToLower(imageName)) + "@sha256:" + segEscape(strings.TrimPrefix(sha256, "sha256:"))
	qs := url.Values{}
	if repoURL != "" {
		qs.Set("repository_url", repoURL)
	}
	// Only include tag qualifier when ref is a tag, not a digest.
	if ref != "" && !strings.HasPrefix(ref, "sha256:") {
		qs.Set("tag", ref)
	}
	if enc := qs.Encode(); enc != "" {
		out += "?" + enc
	}
	return out
}

// parseDockerUpstream extracts (repository_url, image_name) from an upstream
// URL of the form "https://<host>/v2/<path>/manifests/<ref>". repository_url
// is the host + path joined with '/' (no scheme, no /v2/, no /manifests/...).
// image_name is the last path segment.
func parseDockerUpstream(upstream string) (string, string) {
	if upstream == "" {
		return "", ""
	}
	u, err := url.Parse(upstream)
	if err != nil || u.Host == "" {
		return "", ""
	}
	p := u.Path
	const v2 = "/v2/"
	i := strings.Index(p, v2)
	if i < 0 {
		return "", ""
	}
	p = p[i+len(v2):]
	if j := strings.Index(p, "/manifests/"); j >= 0 {
		p = p[:j]
	} else if j := strings.Index(p, "/blobs/"); j >= 0 {
		p = p[:j]
	}
	p = strings.Trim(p, "/")
	if p == "" {
		return "", ""
	}
	repo := u.Host + "/" + p
	leaf := p
	if k := strings.LastIndexByte(p, '/'); k >= 0 {
		leaf = p[k+1:]
	}
	return repo, leaf
}

// lastUnderscoreSeg returns the last '_'-delimited segment of s. Used as a
// best-effort fallback when the upstream URL doesn't parse cleanly.
func lastUnderscoreSeg(s string) string {
	if s == "" {
		return ""
	}
	if i := strings.LastIndexByte(s, '_'); i >= 0 && i < len(s)-1 {
		return s[i+1:]
	}
	return s
}
