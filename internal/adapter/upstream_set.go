package adapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"golang.org/x/net/html"
)

// NamespacedEcosystem folds an upstream-index identity into the ecosystem
// segment of an artifact ID. The default index (empty name) keeps the bare
// ecosystem, preserving existing cache layout, audit, and SBOM history. An
// extra index `corp` for `pypi` becomes `pypi__corp`.
//
// The "__" separator is valid under the cache layer's validNameRe
// (^[a-zA-Z0-9._\-]+$), so no cache backend (local/S3/Azure/GCS) needs changes —
// they isolate on the eco segment on disk/key already. Index names are validated
// to ^[a-z0-9-]+$ at config load, so the "__" boundary is never ambiguous.
func NamespacedEcosystem(eco, indexName string) string {
	if indexName == "" {
		return eco
	}
	return eco + "__" + indexName
}

// ResolvedIndex is one upstream to try for a package, in fallback order.
// The default index has Name "" and FilesHost "" (the adapter applies its own default).
type ResolvedIndex struct {
	Name      string
	URL       string
	FilesHost string
	authType  string // "bearer" | "basic" | ""
	tokenEnv  string
}

type resolvedIndexInternal struct {
	ResolvedIndex
	packages []string // glob scope; empty = unscoped
}

// UpstreamResolver routes bare-name package requests across a default upstream
// and ordered extra indexes, with optional per-index glob scoping. It is the
// non-Docker analogue of docker.RegistryResolver.
type UpstreamResolver struct {
	ecosystem string
	def       ResolvedIndex
	extras    []resolvedIndexInternal
	byName    map[string]resolvedIndexInternal

	client  *http.Client
	breaker *indexBreaker
}

// NewUpstreamResolver builds a resolver for one ecosystem from its UpstreamSet.
// The set is assumed already validated by config.validateUpstreamSet.
func NewUpstreamResolver(ecosystem string, set config.UpstreamSet) (*UpstreamResolver, error) {
	if ecosystem == "" {
		return nil, fmt.Errorf("upstream resolver: ecosystem must not be empty")
	}
	r := &UpstreamResolver{
		ecosystem: ecosystem,
		def:       ResolvedIndex{Name: "", URL: strings.TrimRight(set.Default, "/")},
		byName:    make(map[string]resolvedIndexInternal, len(set.ExtraIndexes)),
		breaker:   newIndexBreaker(defaultBreakerThreshold, defaultBreakerCooldown, time.Now),
	}
	for _, idx := range set.ExtraIndexes {
		// Canonicalise the scope globs the same way package names are canonicalised
		// before matching (ResolveForPackage matches against canonical(name)). This
		// keeps case-insensitive ecosystems (NuGet lowercases; PyPI PEP 503) honest:
		// a config glob `MyCompany.*` becomes `mycompany.*` so it actually claims the
		// lowercased ids the client sends. Without this the scope silently never
		// matches → dependency-confusion regression (issue #32 security review).
		pats := make([]string, len(idx.Packages))
		for i, p := range idx.Packages {
			pats[i] = scanner.CanonicalPackageName(scanner.Ecosystem(ecosystem), p)
		}
		ri := resolvedIndexInternal{
			ResolvedIndex: ResolvedIndex{
				Name:      idx.Name,
				URL:       strings.TrimRight(idx.URL, "/"),
				FilesHost: strings.TrimRight(idx.FilesHost, "/"),
			},
			packages: pats,
		}
		if idx.Auth != nil {
			ri.authType = idx.Auth.Type
			ri.tokenEnv = idx.Auth.TokenEnv
		}
		r.extras = append(r.extras, ri)
		r.byName[idx.Name] = ri
	}
	r.client = newMetadataClient()
	return r, nil
}

// canonical returns the ecosystem-canonical package name for glob matching.
func (r *UpstreamResolver) canonical(name string) string {
	return scanner.CanonicalPackageName(scanner.Ecosystem(r.ecosystem), name)
}

// ResolveForPackage returns the ordered indexes to try for a package name.
//
//   - If the name is CLAIMED (any scoped index's globs match the canonical name)
//     → return ONLY the claiming indexes that are not breaker-open, in config
//     order. NEVER fall back to the default/public index — a claimed namespace is
//     never silently shadowed.
//   - Otherwise → default first, then unscoped extra indexes in config order.
//
// Breaker-open indexes are skipped. CRITICAL: "claimed" is decided independently
// of the breaker. If every claiming index has an open breaker, the result is an
// EMPTY list (the handler then 404s — a scoped miss), NOT a public fallback.
// (security review finding #1 — dependency-confusion guard).
func (r *UpstreamResolver) ResolveForPackage(name string) []ResolvedIndex {
	canon := r.canonical(name)

	claimed := false
	var scoped []ResolvedIndex
	for _, e := range r.extras {
		if len(e.packages) == 0 {
			continue
		}
		if matchAny(e.packages, canon) {
			claimed = true
			if !r.breaker.open(e.Name) {
				scoped = append(scoped, e.ResolvedIndex)
			}
		}
	}
	if claimed {
		return scoped // may be empty → scoped miss (404); NEVER public fallback
	}

	var out []ResolvedIndex
	if r.def.URL != "" {
		out = append(out, r.def) // default breaker is never opened (it is the baseline)
	}
	for _, e := range r.extras {
		if len(e.packages) == 0 && !r.breaker.open(e.Name) {
			out = append(out, e.ResolvedIndex)
		}
	}
	return out
}

func matchAny(patterns []string, s string) bool {
	for _, p := range patterns {
		// Pattern validity is guaranteed by config.validateUpstreamSet (it rejects bad
		// globs at load time), so filepath.Match's error is unreachable here.
		if ok, _ := filepath.Match(p, s); ok {
			return true
		}
	}
	return false
}

const (
	defaultBreakerThreshold = 5
	defaultBreakerCooldown  = 30 * time.Second
)

// indexBreaker is a per-index consecutive-failure circuit breaker. After
// `threshold` consecutive failures an index is skipped until `cooldown` elapses.
type indexBreaker struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	now       func() time.Time
	fails     map[string]int
	openUntil map[string]time.Time
}

func newIndexBreaker(threshold int, cooldown time.Duration, now func() time.Time) *indexBreaker {
	return &indexBreaker{
		threshold: threshold,
		cooldown:  cooldown,
		now:       now,
		fails:     make(map[string]int),
		openUntil: make(map[string]time.Time),
	}
}

// open reports whether the breaker for name is currently open (i.e. the index
// should be skipped).
//
// Half-open policy: when the cooldown elapses, the consecutive-failure count is
// reset to zero and the index is allowed through immediately. A subsequent
// failure must again accumulate `threshold` consecutive failures before the
// breaker re-opens. This is an intentionally lenient policy — a single half-open
// probe failure does NOT immediately re-open the breaker, which is appropriate
// for a metadata-probe breaker where transient errors are common.
func (b *indexBreaker) open(name string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	until, ok := b.openUntil[name]
	if !ok {
		return false
	}
	if b.now().Before(until) {
		return true
	}
	delete(b.openUntil, name) // cooldown elapsed → half-open (allow a probe)
	b.fails[name] = 0
	return false
}

// Record reports the outcome of a probe against an index. A nil err resets the
// failure count; a non-nil err increments it and opens the breaker at threshold.
func (b *indexBreaker) Record(name string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		b.fails[name] = 0
		delete(b.openUntil, name)
		return
	}
	b.fails[name]++
	if b.fails[name] >= b.threshold {
		b.openUntil[name] = b.now().Add(b.cooldown)
	}
}

// AuthHeader returns the Authorization header value for an index, or "" if the
// index has no auth or its token env var is unset. Never derived from a client
// request — credentials come only from the configured env var.
func (r *UpstreamResolver) AuthHeader(idx ResolvedIndex) string {
	if idx.tokenEnv == "" {
		return ""
	}
	tok := os.Getenv(idx.tokenEnv)
	if tok == "" {
		return ""
	}
	switch idx.authType {
	case "basic":
		return "Basic " + tok
	case "bearer":
		return "Bearer " + tok
	default:
		return "" // unknown type → fail closed (config validation should have caught it)
	}
}

// FilesHostFor returns the configured files host for an index name (PyPI only).
// For the default index ("") it returns ("", true) — the adapter supplies its
// own default CDN. For an unknown / forged name it returns ("", false) so the
// download handler can 404 BEFORE constructing any upstream URL (SSRF control).
func (r *UpstreamResolver) FilesHostFor(name string) (string, bool) {
	if name == "" {
		return "", true
	}
	idx, ok := r.byName[name]
	if !ok {
		return "", false
	}
	return idx.FilesHost, true
}

// IndexByName returns a resolved index by name (for the download leg's auth lookup).
func (r *UpstreamResolver) IndexByName(name string) (ResolvedIndex, bool) {
	if name == "" {
		return r.def, true
	}
	idx, ok := r.byName[name]
	if !ok {
		return ResolvedIndex{}, false
	}
	return idx.ResolvedIndex, true
}

const (
	metadataProbeTimeout = 15 * time.Second
	maxRedirects         = 10
)

// NewRedirectSafeClient returns an *http.Client with the given timeout whose
// CheckRedirect: (1) caps redirect depth; (2) refuses a credentialed redirect to a
// non-https target BEFORE stripping; (3) strips Authorization on any host/scheme
// change (ports normalised via sameHostScheme/hostWithPort). Used for upstream
// metadata probes AND artifact downloads so per-index credentials never leak
// across a redirect to another host.
func NewRedirectSafeClient(timeout time.Duration) *http.Client {
	base := NewProxyHTTPClient(timeout)
	base.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// (1) Cap redirect depth.
		if len(via) >= maxRedirects {
			return fmt.Errorf("upstream: too many redirects (>%d)", maxRedirects)
		}
		prev := via[len(via)-1].URL
		cur := req.URL
		// (2) Refuse credentialed redirect to non-https — BEFORE stripping.
		if req.Header.Get("Authorization") != "" && cur.Scheme != "https" {
			return fmt.Errorf("upstream: refusing credentialed redirect to non-https %q", cur.Scheme)
		}
		// (3) Strip on host/scheme change (ports normalised).
		if !sameHostScheme(prev, cur) {
			req.Header.Del("Authorization")
		}
		return nil
	}
	return base
}

// newMetadataClient returns the HTTP client used for upstream METADATA probes
// (small, short timeout) — distinct from adapters' 5-minute artifact-download
// client. CheckRedirect enforces three rules IN THIS ORDER:
//  1. Cap redirect depth (fail closed at maxRedirects).
//  2. Refuse a credentialed redirect to a non-https target, regardless of host
//     (fail closed, evaluated against the TARGET scheme before any strip — this
//     must run before step 3 or it becomes dead code: stripping first would clear
//     the header and the refusal would never trigger).
//  3. Strip Authorization on any host or scheme change (Go's stdlib only strips
//     on host change, missing same-host https→http downgrades), comparing hosts
//     with default ports normalised so :443/:80 don't cause spurious strips.
func newMetadataClient() *http.Client {
	return NewRedirectSafeClient(metadataProbeTimeout)
}

// sameHostScheme reports whether two URLs share scheme and host, treating an
// implicit default port as equal to its explicit form (e.g. example.com ==
// example.com:443 for https).
func sameHostScheme(a, b *url.URL) bool {
	if a.Scheme != b.Scheme {
		return false
	}
	return hostWithPort(a) == hostWithPort(b)
}

// hostWithPort returns a bracket-free host:port string (via url.Hostname /
// url.Port) with the scheme's default port (443 for https, 80 for http) filled
// in when implicit — so IPv6 brackets are handled and default-port forms compare
// equal (e.g. "example.com:443" == "example.com" on https).
func hostWithPort(u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		case "http":
			port = "80"
		}
	}
	return host + ":" + port
}

// Client returns the resolver's metadata HTTP client (redirect-safe, short timeout).
func (r *UpstreamResolver) Client() *http.Client { return r.client }

// RecordProbe reports a metadata-probe outcome for an index so the circuit
// breaker can skip persistently-failing indexes. The default index ("") is never breakered.
func (r *UpstreamResolver) RecordProbe(indexName string, err error) {
	if indexName == "" {
		return
	}
	r.breaker.Record(indexName, err)
}

// ObserveProbe records a probe-outcome metric and updates the breaker.
// result must be one of "hit", "miss", "error".
func (r *UpstreamResolver) ObserveProbe(indexName, result string) {
	label := indexName
	if label == "" {
		label = "default"
	}
	upstreamIndexProbeTotal.WithLabelValues(r.ecosystem, label, result).Inc()
	switch result {
	case "error":
		r.RecordProbe(indexName, errProbe)
	case "hit", "miss":
		r.RecordProbe(indexName, nil)
	}
}

// ObserveScopedMiss records that a scoped lookup found no serving index.
func (r *UpstreamResolver) ObserveScopedMiss() {
	upstreamScopedMissTotal.WithLabelValues(r.ecosystem).Inc()
}

var errProbe = fmt.Errorf("upstream: index probe failed")

// ScopeMatches reports whether the package name is claimed by any scoped index.
func (r *UpstreamResolver) ScopeMatches(name string) bool {
	return len(r.ClaimingIndexNames(name)) > 0
}

// ClaimingIndexNames returns the names of every scoped index whose globs claim
// the package name (in config order). Used for the scoped-miss audit.
func (r *UpstreamResolver) ClaimingIndexNames(name string) []string {
	canon := r.canonical(name)
	var out []string
	for _, e := range r.extras {
		if len(e.packages) > 0 && matchAny(e.packages, canon) {
			out = append(out, e.Name)
		}
	}
	return out
}

// RewriteExtraIndexSimplePage rewrites the download anchors of an EXTRA index's
// PEP 503 simple page so artifacts route through /ext-packages/<name>/. It uses
// a proper HTML tokenizer (golang.org/x/net/html) so that attribute-value
// boundaries are always parsed correctly — eliminating the embedded-quote
// injection (NEW-1) and adjacent-href bypass (NEW-2) that plagued the old
// byte-regex approach. FAIL CLOSED: an absolute http(s) href whose host is
// neither the index host nor its configured files host returns an error (serving
// it would bypass scanning). The DEFAULT index is NOT handled here.
func RewriteExtraIndexSimplePage(body []byte, idx ResolvedIndex, pageURL string) ([]byte, error) {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil, fmt.Errorf("upstream: parsing page URL %q: %w", pageURL, err)
	}
	// Lower-case hosts when building the allowed set (FIX D).
	allowed := map[string]bool{strings.ToLower(base.Host): true}
	if idx.FilesHost != "" {
		if fh, e := url.Parse(idx.FilesHost); e == nil {
			allowed[strings.ToLower(fh.Host)] = true
		}
	}

	// rawTextContainers are HTML elements that Go's tokenizer treats as raw-text
	// (CDATA) containers: inner content is emitted as a single TextToken, not
	// parsed. pip's html.parser does NOT share this behaviour, so an <a href>
	// inside one of these would be live for pip but invisible to us — a
	// parser-differential scan-bypass. Fail closed on any such element.
	rawTextContainers := map[string]bool{
		"noscript": true,
		"noembed":  true,
		"noframes": true,
	}

	var out bytes.Buffer
	var consumed int // sum of len(z.Raw()) for every non-ErrorToken
	z := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if z.Err() == io.EOF {
				break
			}
			return nil, fmt.Errorf("upstream: HTML tokenizer error: %w", z.Err())
		}

		consumed += len(z.Raw())

		// Only <a ...> and <a .../> tokens with an href attribute need rewriting.
		// For everything else, emit raw bytes verbatim to preserve them exactly.
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			out.Write(z.Raw())
			continue
		}

		// Raw() is valid until the next Next() call — copy it before calling Token().
		// IMPORTANT: copy raw BEFORE calling Token(), which advances internal state.
		raw := make([]byte, len(z.Raw()))
		copy(raw, z.Raw())

		tok := z.Token()

		// FIX: Detect raw-text container elements (noscript/noembed/noframes) that
		// cause a parser-differential scan-bypass. Go's x/net/html tokenizer treats
		// these as raw-text (CDATA) containers: their inner content is emitted as a
		// single TextToken (never parsed as child elements). pip's html.parser does
		// NOT share this behaviour — it parses <a href> inside <noscript> as a live
		// download link. A legitimate PEP 503 simple index never uses these tags.
		// Fail closed: return an error so the caller serves 502.
		tagName := strings.ToLower(tok.Data)
		if rawTextContainers[tagName] {
			return nil, fmt.Errorf("upstream: index %q simple page contains a <%s> raw-text element (parser-differential scan-bypass risk); refusing to serve", idx.Name, tagName)
		}

		if tok.Data != "a" {
			// Not an anchor — emit verbatim.
			out.Write(raw)
			continue
		}

		// Find the href attribute index (-1 if absent).
		hrefIdx := -1
		for i, attr := range tok.Attr {
			if strings.EqualFold(attr.Key, "href") {
				hrefIdx = i
				break
			}
		}
		if hrefIdx == -1 {
			// Anchor without href — emit verbatim.
			out.Write(raw)
			continue
		}

		// Rewrite the href value.
		newVal, changed, rewriteErr := rewriteExtraHrefValue(
			tok.Attr[hrefIdx].Val, idx.Name, base, allowed,
		)
		if rewriteErr != nil {
			return nil, rewriteErr
		}
		if changed {
			tok.Attr[hrefIdx].Val = newVal
		}
		// Re-emit via tok.String(): the tokenizer has already parsed the real value
		// boundaries, so String() re-encodes with correct double-quoting and HTML
		// escaping — no injection possible regardless of the original quoting style.
		out.WriteString(tok.String())
	}
	// FIX: Detect truncated / incomplete HTML. For well-formed input the tokenizer
	// emits every input byte in exactly one non-ErrorToken's Raw(), so summing
	// len(Raw()) across all non-ErrorTokens must equal len(body). A page that ends
	// mid-tag (or is otherwise byte-incomplete) causes the tokenizer to emit the
	// partial tag only in the ErrorToken's Raw() — which we exclude — so consumed
	// will be less than len(body). Serving a truncated page would silently drop
	// download anchors, potentially bypassing scanning. Fail closed instead.
	if consumed != len(body) {
		return nil, fmt.Errorf("upstream: index %q simple page is truncated or incomplete (%d of %d bytes tokenized); refusing to serve", idx.Name, consumed, len(body))
	}
	return out.Bytes(), nil
}

// rewriteExtraHrefValue resolves href against base and rewrites it to route
// through /ext-packages/<idxName>/. Returns (newVal, true, nil) on success,
// ("", false, nil) to leave the value unchanged (non-http(s) scheme, parse
// error), or ("", false, err) to fail closed (unroutable host, path traversal).
func rewriteExtraHrefValue(href, idxName string, base *url.URL, allowed map[string]bool) (string, bool, error) {
	ref, err := url.Parse(href)
	if err != nil {
		return "", false, nil // leave unchanged
	}
	abs := base.ResolveReference(ref)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return "", false, nil // leave non-http(s) (mailto/data/fragment) unchanged
	}
	// Fail closed: link to an unroutable host would bypass scanning.
	if !allowed[strings.ToLower(abs.Host)] {
		return "", false, fmt.Errorf("upstream: index %q simple page links to unroutable host %q (would bypass scanning)", idxName, abs.Host)
	}
	// FIX C: reject path traversal — a ".." segment could let pip's client-side
	// path normalisation escape the /ext-packages/<index>/ scope.
	for _, seg := range strings.Split(abs.Path, "/") {
		if seg == ".." {
			return "", false, fmt.Errorf("upstream: index %q simple page href has a path-traversal segment %q", idxName, abs.Path)
		}
	}
	suffix := strings.TrimPrefix(abs.Path, "/")
	if abs.RawQuery != "" {
		suffix += "?" + abs.RawQuery
	}
	if abs.Fragment != "" {
		suffix += "#" + abs.Fragment
	}
	return "/ext-packages/" + idxName + "/" + suffix, true, nil
}

// RewriteNPMPackumentTarballs rewrites every versions.*.dist.tarball URL of an
// EXTRA-index npm packument so artifacts route through the proxy's scan pipeline.
// It is JSON-aware (parses the document) so it can FAIL CLOSED on any tarball
// whose host is neither the serving index host nor its configured files host —
// serving such a packument would let npm fetch the artifact directly, bypassing
// the scan. Non-download URLs (repository.url, homepage, …) are left untouched.
// The DEFAULT index is NOT handled here (it keeps the serving-origin string
// replace in the adapter, byte-identical to today).
//
// proxyOrigin is "<scheme>://<host>" (no trailing slash). The download leg
// recovers the serving index by re-resolving the package name, so the rewritten
// path is the tarball URL's path verbatim under the proxy origin.
func RewriteNPMPackumentTarballs(body []byte, idx ResolvedIndex, proxyOrigin string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		// FAIL CLOSED: a packument we cannot parse cannot be safely rewritten.
		return nil, fmt.Errorf("upstream: index %q packument is not valid JSON (cannot rewrite, refusing to serve): %w", idx.Name, err)
	}
	allowed := downloadHostSet(idx)
	versions, _ := doc["versions"].(map[string]any)
	for _, v := range versions {
		vm, ok := v.(map[string]any)
		if !ok {
			continue
		}
		dist, ok := vm["dist"].(map[string]any)
		if !ok {
			continue
		}
		tb, ok := dist["tarball"].(string)
		if !ok || tb == "" {
			continue
		}
		rewritten, err := proxyRewriteDownloadURL(tb, idx.Name, allowed, proxyOrigin)
		if err != nil {
			return nil, err
		}
		dist["tarball"] = rewritten
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("upstream: index %q packument re-marshal: %w", idx.Name, err)
	}
	return out, nil
}

// nugetFlatContainerPathRe matches the EXACT scanned download route shape
// /v3-flatcontainer/{id}/{version}/{filename}. A packageContent whose path does
// not match this would, after host-rewrite, route to the gate's unscanned
// catch-all passthrough (or 404) instead of the scan pipeline — a scan bypass.
var nugetFlatContainerPathRe = regexp.MustCompile(`^/v3-flatcontainer/[^/]+/[^/]+/[^/]+$`)

// AssertNoForeignNuGetDownloadURLs parses a NuGet V3 registration document that
// has ALREADY had its serving-index origin string-replaced to the proxy origin,
// and FAILS CLOSED if:
//   - any download URL (packageContent) or registration sub-page link (@id)
//     still points at a host other than proxyHost (after the string replace every
//     serving-host URL is a proxy-host URL, so a surviving foreign host means a
//     foreign CDN download — scan bypass — or a foreign pagination page the gate
//     would never see — transitive bypass); OR
//   - a packageContent URL's PATH does not match the gate's scanned
//     /v3-flatcontainer/{id}/{version}/{filename} download route. Host-equality
//     alone is insufficient: a malicious index can point packageContent at
//     `<serving>/v3/<anything>.nupkg`, which rewrites to the proxy host (host check
//     passes) but routes to the gate's unscanned catch-all passthrough. Pinning
//     the path shape forces every artifact download through the scan pipeline.
//
// Non-download metadata URLs (licenseUrl, projectUrl) are ignored — they are not
// artifact or pagination links.
func AssertNoForeignNuGetDownloadURLs(body []byte, proxyHost string) error {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("nuget registration is not valid JSON (cannot verify, refusing to serve): %w", err)
	}
	proxyHost = strings.ToLower(proxyHost)
	var walkErr error
	var walk func(node any)
	walk = func(node any) {
		if walkErr != nil {
			return
		}
		switch n := node.(type) {
		case map[string]any:
			for k, v := range n {
				if s, ok := v.(string); ok && (k == "packageContent" || k == "@id") {
					if u, err := url.Parse(s); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
						if strings.ToLower(u.Host) != proxyHost {
							walkErr = fmt.Errorf("nuget registration links to unroutable host %q in %q (would bypass scanning)", u.Host, k)
							return
						}
						if k == "packageContent" && !nugetFlatContainerPathRe.MatchString(u.Path) {
							walkErr = fmt.Errorf("nuget registration packageContent path %q is not the scanned /v3-flatcontainer/{id}/{version}/{file} route (would bypass scanning)", u.Path)
							return
						}
					}
				}
				walk(v)
			}
		case []any:
			for _, v := range n {
				walk(v)
			}
		}
	}
	walk(doc)
	return walkErr
}

// downloadHostSet returns the lower-cased set of hosts an extra index may serve
// download URLs from: its own host and (optionally) its configured files host.
func downloadHostSet(idx ResolvedIndex) map[string]bool {
	allowed := map[string]bool{}
	if u, err := url.Parse(idx.URL); err == nil && u.Host != "" {
		allowed[strings.ToLower(u.Host)] = true
	}
	if idx.FilesHost != "" {
		if u, err := url.Parse(idx.FilesHost); err == nil && u.Host != "" {
			allowed[strings.ToLower(u.Host)] = true
		}
	}
	return allowed
}

// proxyRewriteDownloadURL rewrites an absolute download URL to proxyOrigin+path,
// failing closed if its host is not in allowed. Relative URLs are not expected in
// npm/nuget download fields; a non-absolute or non-http(s) value fails closed too.
func proxyRewriteDownloadURL(raw, idxName string, allowed map[string]bool, proxyOrigin string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("upstream: index %q download URL %q is not an absolute http(s) URL (cannot route, refusing to serve)", idxName, raw)
	}
	if !allowed[strings.ToLower(u.Host)] {
		return "", fmt.Errorf("upstream: index %q download URL host %q is unroutable (would bypass scanning)", idxName, u.Host)
	}
	suffix := u.Path
	if u.RawQuery != "" {
		suffix += "?" + u.RawQuery
	}
	return strings.TrimRight(proxyOrigin, "/") + suffix, nil
}

// RewriteRubyGemsGemURI rewrites the gem_uri download field of an EXTRA-index
// RubyGems /api/v1/gems/{name}.json document so a client that follows gem_uri
// (e.g. `gem fetch`) is routed through the proxy's scan pipeline. It is
// JSON-aware so it can FAIL CLOSED if gem_uri's host is neither the serving
// index host nor its configured files host (serving such a doc would let a
// client fetch the .gem directly, bypassing the scan), or if the body is not
// valid JSON. Non-download URLs (homepage_uri, project_uri, …) are untouched.
// Docs WITHOUT a gem_uri pass through unchanged. The DEFAULT index is NOT handled
// here (it keeps the verbatim relay, byte-identical to today).
func RewriteRubyGemsGemURI(body []byte, idx ResolvedIndex, proxyOrigin string) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("upstream: index %q rubygems metadata is not valid JSON (cannot rewrite, refusing to serve): %w", idx.Name, err)
	}
	gu, ok := doc["gem_uri"].(string)
	if !ok || gu == "" {
		return body, nil // nothing to rewrite; relay verbatim
	}
	allowed := downloadHostSet(idx)
	rewritten, err := proxyRewriteDownloadURL(gu, idx.Name, allowed, proxyOrigin)
	if err != nil {
		return nil, err
	}
	doc["gem_uri"] = rewritten
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("upstream: index %q rubygems metadata re-marshal: %w", idx.Name, err)
	}
	return out, nil
}
