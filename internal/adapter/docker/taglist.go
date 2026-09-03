package docker

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
)

// maxTagListBytes caps the tag-list body read from an upstream registry.
// Docker Hub's library/python answers with ~100 KB; the cap bounds what a
// hostile or broken upstream can push into the gate.
const maxTagListBytes = 8 << 20

// maxTagListQueryLen bounds the pagination query. The OCI spec's cursor
// (`last`) is a tag name, so a legitimate query is tiny.
const maxTagListQueryLen = 4096

// Link-header ingest bounds. A Distribution tag-list response carries one
// `rel="next"` link; anything beyond a handful of parts or a few KB is a
// hostile or broken upstream, and the rewrite is skipped rather than run over
// megabytes of header (the body cap does not cover headers).
const (
	maxTagListLinkLen   = 4096
	maxTagListLinkParts = 4
)

// maxInternalTagPage caps a single page served from the internal store, so one
// request can never load an unbounded number of rows. The OCI spec lets a
// registry impose its own page size as long as it advertises `Link`.
const maxInternalTagPage = 5000

// tagListResponse is the OCI Distribution Spec tag-list body.
type tagListResponse struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// handleTagsList answers GET /v2/{name}/tags/list.
//
// The endpoint returns tag *names* only — never a manifest or a blob — so it
// adds no scan-bypass surface. It is per-repository, not index enumeration:
// the name resolves through the same RegistryResolver as manifests and blobs,
// to exactly one upstream, so nothing is merged across registries (the
// ADR-017 whole-index-enumeration limitation does not apply here).
func (a *DockerAdapter) handleTagsList(w http.ResponseWriter, r *http.Request, name string) {
	if err := validateDockerName(name); err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid image name",
			Reason: err.Error(),
		})
		return
	}

	// Internally-pushed namespaces have no upstream to ask — their tags live in
	// docker_tags. Mirrors the manifest/blob serve path: internal store first,
	// fall through to upstream when the name is a pull-through instead.
	pushAllowed := a.pushHandler != nil && a.cfg.Push.Enabled && a.resolver.IsPushAllowed(name)
	if pushAllowed {
		if a.serveInternalTagList(w, r, name) {
			return
		}
	}

	registry, imagePath, upstreamURL, err := a.resolver.Resolve(name)
	if err != nil {
		adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
			Error:  "registry not allowed",
			Reason: err.Error(),
		})
		_ = adapter.WriteAuditLogCtx(r.Context(), a.db, model.AuditEntry{
			EventType:  model.EventBlocked,
			ArtifactID: fmt.Sprintf("docker:%s:tags-list", name),
			ClientIP:   r.RemoteAddr,
			UserAgent:  r.UserAgent(),
			Reason:     err.Error(),
		})
		return
	}

	// Typosquat pre-scan, same as the manifest pull path: a name the policy
	// refuses to serve must not be enumerable through the gate either, and the
	// block has to produce the same audit trail (without this, `crane ls` on a
	// typosquat name reached upstream and left no BLOCKED row).
	if a.blockIfTyposquat(w, r, registry, imagePath, MakeSafeName(registry, imagePath)) {
		return
	}

	// A push-allowed name that missed the internal store is either a fresh push
	// target or a pull-through the gate cannot authenticate to — same reasoning
	// as the manifest HEAD path, so an upstream auth failure means "no tags
	// here" (404) rather than a denial.
	a.proxyTagsList(w, r, registry, imagePath, upstreamURL, name, pushAllowed)
}

// proxyTagsList relays GET /v2/{imagePath}/tags/list from the resolved upstream.
//
// Unlike proxyUpstream it does not pass the upstream response through verbatim:
//   - a 200 body is decoded as an OCI tag list and re-encoded, so the gate can
//     only ever emit tag names under its own `application/json` — a hostile
//     upstream cannot deliver arbitrary bytes (or an arbitrary media type)
//     through the gate's origin. A body that is not a tag list fails closed,
//   - the pagination Link header is rewritten onto the client-facing name (an
//     upstream link would send the client to the wrong repository on the gate,
//     or off to the upstream registry itself),
//   - an upstream 401/403 is answered with the gate's own 403 (or 404 when
//     mapAuthToNotFound, mirroring the manifest HEAD path for push-allowed
//     names) and the upstream Www-Authenticate challenge is dropped — relaying
//     it would point the client's credentials at the upstream token service.
func (a *DockerAdapter) proxyTagsList(w http.ResponseWriter, r *http.Request, registry, imagePath, upstreamURL, name string, mapAuthToNotFound bool) {
	rawQuery, err := sanitizeTagListQuery(r.URL.RawQuery)
	if err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid pagination parameters",
			Reason: err.Error(),
		})
		return
	}

	upstreamPath := "/v2/" + imagePath + "/tags/list"
	resp, errStatus, errMsg := a.doUpstreamGet(r, upstreamURL, registry, upstreamPath, rawQuery)
	if resp == nil {
		http.Error(w, errMsg, errStatus)
		return
	}
	defer resp.Body.Close()

	// Never sniffed, whatever the upstream said.
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		log.Debug().Str("registry", registry).Str("image", imagePath).Int("status", resp.StatusCode).
			Msg("docker: upstream denied tag listing")
		if mapAuthToNotFound {
			http.NotFound(w, r)
			return
		}
		adapter.WriteJSONError(w, http.StatusForbidden, adapter.ErrorResponse{
			Error:  "tag listing denied by upstream",
			Reason: fmt.Sprintf("registry %s returned %d for %s (the gate never forwards client credentials upstream)", registry, resp.StatusCode, imagePath),
		})
		return
	}

	if resp.StatusCode != http.StatusOK {
		// Relay the upstream error envelope (404 NAME_UNKNOWN, 429, …) so
		// clients see the real reason, but never as a renderable media type.
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(strings.ToLower(ct), "json") {
			ct = "text/plain; charset=utf-8"
		}
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, maxTagListBytes))
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTagListBytes+1))
	if err != nil {
		log.Error().Err(err).Str("registry", registry).Str("image", imagePath).
			Msg("docker: reading upstream tag list")
		http.Error(w, "upstream tag list unreadable", http.StatusBadGateway)
		return
	}
	if len(body) > maxTagListBytes {
		log.Error().Str("registry", registry).Str("image", imagePath).Int("cap", maxTagListBytes).
			Msg("docker: upstream tag list exceeds size cap")
		http.Error(w, "upstream tag list too large", http.StatusBadGateway)
		return
	}
	var upstreamList tagListResponse
	if err := json.Unmarshal(body, &upstreamList); err != nil {
		// Fail closed: a 200 that is not an OCI tag list is not something to
		// hand to the client under the gate's own origin.
		log.Error().Err(err).Str("registry", registry).Str("image", imagePath).
			Msg("docker: upstream tag list is not valid OCI JSON")
		http.Error(w, "upstream tag list malformed", http.StatusBadGateway)
		return
	}
	if upstreamList.Tags == nil {
		upstreamList.Tags = []string{}
	}

	if link := rewriteTagListLink(resp.Header.Get("Link"), imagePath, name); link != "" {
		w.Header().Set("Link", link)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(http.StatusOK)
	// The name is reported as the client asked for it, matching the rewritten
	// Link and the internal path (upstream reports its own path, e.g.
	// library/python for a request to /v2/python/tags/list).
	_ = json.NewEncoder(w).Encode(tagListResponse{Name: name, Tags: upstreamList.Tags})
}

// serveInternalTagList answers the tag list for an internally-pushed repository
// from docker_tags. Returns false when the name has no internal repository (or
// no internal tags) so the caller falls through to the upstream registry — a
// push-allowed *shape* like "bitnami/nginx" is most often a Docker Hub
// pull-through, not a reserved internal namespace.
//
// A DB error fails closed (503) rather than falling through: for a name the
// gate may hold internally, a silent upstream answer would report a foreign
// repository's tags under an internal name.
func (a *DockerAdapter) serveInternalTagList(w http.ResponseWriter, r *http.Request, name string) bool {
	repo, err := GetRepository(a.db, "", name)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false // not an internal image → fall through to upstream
		}
		log.Error().Err(err).Str("image", name).Msg("docker: looking up internal repository for tag list")
		http.Error(w, "internal error listing tags", http.StatusServiceUnavailable)
		return true
	}

	// Existence is decided independently of the pagination cursor — a cursor
	// past the last tag must yield an empty page, not an upstream fall-through.
	count, err := CountTags(a.db, repo.ID)
	if err != nil {
		log.Error().Err(err).Str("image", name).Msg("docker: counting internal tags")
		http.Error(w, "internal error listing tags", http.StatusServiceUnavailable)
		return true
	}
	if count == 0 {
		return false // known repo but nothing pushed yet → try upstream
	}

	n, last, err := parseTagListPagination(r.URL.Query())
	if err != nil {
		adapter.WriteJSONError(w, http.StatusBadRequest, adapter.ErrorResponse{
			Error:  "invalid pagination parameters",
			Reason: err.Error(),
		})
		return true
	}

	pageSize := maxInternalTagPage
	if n >= 0 && n < pageSize {
		pageSize = n
	}

	names := []string{}
	truncated := false
	if pageSize > 0 {
		// One extra row tells us whether a next page exists.
		tags, err := ListTagsPage(a.db, repo.ID, last, pageSize+1)
		if err != nil {
			log.Error().Err(err).Str("image", name).Msg("docker: listing internal tags")
			http.Error(w, "internal error listing tags", http.StatusServiceUnavailable)
			return true
		}
		if len(tags) > pageSize {
			tags = tags[:pageSize]
			truncated = true
		}
		for _, t := range tags {
			names = append(names, t.Tag)
		}
	}

	if truncated && len(names) > 0 {
		w.Header().Set("Link", fmt.Sprintf(`</v2/%s/tags/list?n=%d&last=%s>; rel="next"`,
			name, pageSize, url.QueryEscape(names[len(names)-1])))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(tagListResponse{Name: name, Tags: names})
	return true
}

// parseTagListPagination reads the OCI pagination parameters. n is -1 when
// absent (no client-imposed limit); an unparseable or negative n is a 400 per
// the spec's integer-typed `n`.
func parseTagListPagination(q url.Values) (n int, last string, err error) {
	n = -1
	if raw := q.Get("n"); raw != "" {
		parsed, convErr := strconv.Atoi(raw)
		if convErr != nil || parsed < 0 {
			return 0, "", fmt.Errorf("docker: query parameter n=%q must be a non-negative integer", raw)
		}
		n = parsed
	}
	return n, q.Get("last"), nil
}

// paginationQuery reduces a query to the two OCI pagination parameters,
// re-encoded. Everything else is dropped on purpose: a relayed unknown
// parameter can change what the *upstream* resolves (a Distribution registry in
// pull-through-mirror mode honours `?ns=`, escaping the allowlist decision the
// gate just made) and can carry a client credential to a third party.
func paginationQuery(values url.Values) (string, error) {
	n, last, err := parseTagListPagination(values)
	if err != nil {
		return "", err
	}
	out := url.Values{}
	if values.Get("n") != "" {
		out.Set("n", strconv.Itoa(n))
	}
	if last != "" {
		out.Set("last", last)
	}
	return out.Encode(), nil
}

// sanitizeTagListQuery builds the query for the upstream request from the
// client's, keeping only validated pagination parameters. A query can never
// influence the upstream host or path.
func sanitizeTagListQuery(rawQuery string) (string, error) {
	if rawQuery == "" {
		return "", nil
	}
	if len(rawQuery) > maxTagListQueryLen {
		return "", fmt.Errorf("docker: query string too long (%d bytes, max %d)", len(rawQuery), maxTagListQueryLen)
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", fmt.Errorf("docker: malformed query string: %w", err)
	}
	return paginationQuery(values)
}

// rewriteTagListLink maps an upstream pagination Link header onto the
// client-facing image name, so a paginating client keeps talking to the gate.
//
// Returns "" when the header is absent, oversized, or no link has the expected
// `rel="next"` + /v2/{imagePath}/tags/list shape: a rewrite miss drops the link
// (the client simply stops paginating) instead of relaying an upstream URL that
// would bypass the gate or address a different repository through it. Only the
// pagination parameters survive — neither an upstream-chosen query parameter
// nor the upstream's attribute tail is echoed back into the client's next
// request.
func rewriteTagListLink(link, imagePath, name string) string {
	if link == "" || len(link) > maxTagListLinkLen {
		return ""
	}
	parts := strings.Split(link, ",")
	if len(parts) > maxTagListLinkParts {
		return ""
	}
	wantPath := "/v2/" + imagePath + "/tags/list"

	for _, part := range parts {
		part = strings.TrimSpace(part)
		open := strings.Index(part, "<")
		closeIdx := strings.Index(part, ">")
		if open != 0 || closeIdx < 0 {
			continue
		}
		if !strings.Contains(strings.ToLower(part[closeIdx+1:]), "next") {
			continue // only the pagination link is of any use to a client
		}
		target, err := url.Parse(part[1:closeIdx])
		if err != nil || target.Path != wantPath {
			continue
		}
		values, err := url.ParseQuery(target.RawQuery)
		if err != nil {
			continue
		}
		query, err := paginationQuery(values)
		if err != nil {
			continue
		}
		next := "/v2/" + name + "/tags/list"
		if query != "" {
			next += "?" + query
		}
		return "<" + next + `>; rel="next"`
	}

	return ""
}
