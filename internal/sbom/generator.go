package sbom

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/github/go-spdx/v2/spdxexp"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/project"
)

// Generator builds CycloneDX 1.5 JSON SBOMs aggregating every artifact a
// given project has pulled through the proxy. Output is generated fresh on
// each call (no caching) — the underlying data changes with every new pull,
// and a stale SBOM would lie about coverage.
//
// Dependency graph is intentionally omitted (no `dependencies` field): the
// proxy only sees pull events, never resolved dep trees, so any graph it
// invented would be misleading.
type Generator struct {
	db *config.GateDB
	// toolVersion stamps metadata.tools.components[].version. Injected from
	// cmd/shieldoo-gate/main.go (built via -ldflags) so the SBOM is
	// reproducible-attributable to a specific build.
	toolVersion string
	// now is overridable in tests for deterministic timestamps.
	now func() time.Time
	// newUUID is overridable in tests for deterministic serial numbers.
	newUUID func() string
}

// NewGenerator returns a Generator for project SBOMs.
func NewGenerator(db *config.GateDB, toolVersion string) *Generator {
	if toolVersion == "" {
		toolVersion = "dev"
	}
	return &Generator{
		db:          db,
		toolVersion: toolVersion,
		now:         func() time.Time { return time.Now().UTC() },
		newUUID:     func() string { return uuid.NewString() },
	}
}

// ForProject builds the SBOM as a CycloneDX 1.5 JSON document. Empty
// projects produce a valid SBOM with `components: []` — never an error.
func (g *Generator) ForProject(ctx context.Context, p *project.Project) ([]byte, error) {
	if p == nil {
		return nil, fmt.Errorf("sbom: nil project")
	}

	comps, err := g.loadComponents(ctx, p.ID)
	if err != nil {
		return nil, fmt.Errorf("sbom: load components: %w", err)
	}

	doc := cdxBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: "urn:uuid:" + g.newUUID(),
		Version:      1,
		Metadata: cdxBOMMeta{
			Timestamp: g.now().Format(time.RFC3339),
			// SGW is a passive supply-chain proxy: it observes pull events,
			// not build resolution or runtime install state. `discovery` is
			// the CycloneDX 1.5 phase that matches automated/observational
			// SBOM generation; consumers (Dependency-Track et al.) apply
			// different default policies based on this signal.
			Lifecycles: []cdxLifecycle{{Phase: "discovery"}},
			Tools: cdxTools{
				Components: []cdxOutComp{{
					Type:     "application",
					Name:     "shieldoo-gate",
					Version:  g.toolVersion,
					Supplier: &cdxOrgEntity{Name: "Cloudfield"},
				}},
			},
			Component: &cdxOutComp{
				Type:        "application",
				BOMRef:      "project/" + p.Label,
				Name:        p.Label,
				Description: projectDescription(p),
			},
		},
		Components: comps,
	}

	return json.MarshalIndent(doc, "", "  ")
}

// rawRow is the per-artifact join shape consumed by loadComponents.
type rawRow struct {
	Ecosystem    string         `db:"ecosystem"`
	Name         string         `db:"name"`
	Version      string         `db:"version"`
	SHA256       string         `db:"sha256"`
	SizeBytes    int64          `db:"size_bytes"`
	UpstreamURL  string         `db:"upstream_url"`
	CachedAt     time.Time      `db:"cached_at"`
	LicensesJSON sql.NullString `db:"licenses_json"`
	Status       sql.NullString `db:"status"`
	// ReleasedAt is non-NULL when an admin manually released a previously
	// quarantined artifact (handleReleaseArtifact UPSERTs released_at + flips
	// status back to CLEAN). Surfaced in the SBOM as `shieldoo:released_at`
	// so downstream consumers can tell "scanner-clean from day one" apart
	// from "admin-overridden CLEAN".
	ReleasedAt sql.NullTime `db:"released_at"`
}

func (g *Generator) loadComponents(ctx context.Context, projectID int64) ([]cdxOutComp, error) {
	rows, err := g.db.QueryxContext(ctx,
		`SELECT a.ecosystem, a.name, a.version, a.sha256, a.size_bytes, a.upstream_url,
		        a.cached_at,
		        sm.licenses_json AS licenses_json,
		        ast.status       AS status,
		        ast.released_at  AS released_at
		   FROM artifact_project_usage apu
		   JOIN artifacts a              ON a.id = apu.artifact_id
		   LEFT JOIN sbom_metadata sm    ON sm.artifact_id = a.id
		   LEFT JOIN artifact_status ast ON ast.artifact_id = a.id
		  WHERE apu.project_id = ?
		  ORDER BY a.ecosystem, a.name, a.version`,
		projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	// Explicit empty slice (not nil) so empty projects serialize as
	// `"components": []`, matching the documented contract.
	out := make([]cdxOutComp, 0)
	// Defensive enforcement of the CycloneDX bom-ref uniqueness invariant. After
	// bomRef() disambiguates by content digest, a duplicate ref can only arise
	// from two artifact rows with identical purl AND identical sha256 — i.e.
	// byte-identical components — so dropping the later one loses nothing a
	// consumer could tell apart, and guarantees a schema-valid document.
	seen := make(map[string]struct{})
	for rows.Next() {
		var r rawRow
		if err := rows.StructScan(&r); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		c := rowToComponent(r)
		if _, dup := seen[c.BOMRef]; dup {
			continue
		}
		seen[c.BOMRef] = struct{}{}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// rowToComponent maps a DB row to its CycloneDX 1.5 component. Kept pure so
// it can be unit-tested without a database.
func rowToComponent(r rawRow) cdxOutComp {
	purl := BuildPURL(r.Ecosystem, r.Name, r.Version, r.SHA256, r.UpstreamURL)
	c := cdxOutComp{
		Type:    componentType(r.Ecosystem),
		BOMRef:  bomRef(purl, r.Ecosystem, r.Name, r.Version, r.SHA256),
		Name:    r.Name,
		Version: r.Version,
	}

	if purl != "" {
		c.PURL = purl
	}

	if r.SHA256 != "" {
		c.Hashes = []cdxHash{{
			Alg:     "SHA-256",
			Content: stripSHAPrefix(r.SHA256),
		}}
	}

	if r.LicensesJSON.Valid && r.LicensesJSON.String != "" {
		var ids []string
		if err := json.Unmarshal([]byte(r.LicensesJSON.String), &ids); err != nil {
			// Corrupt licenses_json row — log so it's traceable, emit component without licenses.
			log.Warn().Err(err).Str("name", r.Name).Str("version", r.Version).
				Msg("sbom: unmarshal licenses_json failed; component will have no licenses")
		} else {
			c.Licenses = licensesToCDX(ids)
		}
	}

	if r.UpstreamURL != "" {
		c.ExternalReferences = []cdxExtRef{{Type: "distribution", URL: r.UpstreamURL}}
	}

	var props []cdxProperty
	if r.Status.Valid && r.Status.String != "" {
		props = append(props, cdxProperty{Name: "shieldoo:status", Value: r.Status.String})
	}
	if r.SizeBytes > 0 {
		props = append(props, cdxProperty{Name: "shieldoo:size_bytes", Value: strconv.FormatInt(r.SizeBytes, 10)})
	}
	if !r.CachedAt.IsZero() {
		props = append(props, cdxProperty{Name: "shieldoo:cached_at", Value: r.CachedAt.UTC().Format(time.RFC3339)})
	}
	// `released_at` is only set when an admin manually released a previously
	// quarantined artifact. Its presence is the SBOM-visible marker that this
	// component's CLEAN status is admin-overridden rather than scanner-native.
	if r.ReleasedAt.Valid {
		props = append(props, cdxProperty{Name: "shieldoo:released_at", Value: r.ReleasedAt.Time.UTC().Format(time.RFC3339)})
	}
	if len(props) > 0 {
		c.Properties = props
	}

	return c
}

// componentType maps a Shieldoo Gate ecosystem to the CycloneDX 1.5
// component.type enum. Docker is a container; everything else is a library.
func componentType(eco string) string {
	if eco == "docker" {
		return "container"
	}
	return "library"
}

// bomRef derives a document-unique bom-ref for an artifact. CycloneDX mandates
// bom-ref uniqueness within a BOM, but a purl identifies a *package version*,
// not a file: one PyPI/Maven release ships many distribution files (per-platform
// wheels + sdist, jar/sources/javadoc) that legitimately share a single purl.
// Anchoring bom-ref to the bare purl therefore collides — the old
// "(ecosystem, name, version) is unique because loadComponents joins on that
// key" assumption was simply wrong for multi-file ecosystems (a real BOM had
// pkg:pypi/rpds-py@0.30.0 repeated 74×, once per wheel).
//
// The canonical bare purl stays in the component's `purl` field so scanners
// (Dependency-Track, Grype) still reconcile components by package version. For
// the bom-ref we disambiguate with the artifact's content digest — the system's
// true per-file identity and its cache key — appended as the purl-spec
// `checksum` qualifier. That keeps the ref a valid, parseable purl, unique per
// file, and stable across regenerations (no counters or random UUIDs).
// OCI/docker purls already embed the sha256 digest as the version, so they are
// unique as-is and are left untouched.
//
// Falls back to "<ecosystem>:<name>[@<version>][@sha256:<digest>]" when no purl
// can be built (unknown ecosystem, docker without a digest, malformed maven
// coordinates).
func bomRef(purl, eco, name, version, sha256 string) string {
	digest := strings.ToLower(strings.TrimPrefix(sha256, "sha256:"))
	if purl == "" {
		base := eco + ":" + name
		if version != "" {
			base += "@" + version
		}
		if digest != "" {
			base += "@sha256:" + digest
		}
		return base
	}
	// docker/OCI purls already carry the digest as the version → unique as-is.
	// Without a digest there is nothing to disambiguate with, so keep the purl.
	if eco == "docker" || digest == "" {
		return purl
	}
	return purl + "?checksum=sha256:" + digest
}

// licensesToCDX maps the SPDX ID list stored in sbom_metadata.licenses_json
// into the CycloneDX license-choice array. Processing order per token:
//
//  1. URLs (Trivy occasionally emits them alongside the canonical ID) — skipped.
//  2. SPDX expressions (containing AND/OR/WITH or parentheses) — emitted as a
//     standalone `expression` ONLY when they are the single surviving token.
//     CycloneDX `licenseChoice` is a oneOf: a component's `licenses` array is
//     EITHER one-or-more `license` objects OR exactly one `expression` — the
//     two shapes must never be mixed, and the `expression` form is capped at a
//     single element (cyclonedx-cli and Dependency-Track reject a mixed
//     array). So when an expression shares the list with other tokens it is
//     routed to free-text `license.name` verbatim (point 4) — lossless, and
//     in keeping with not fabricating an AND/OR join we can't prove.
//  3. Single tokens that the SPDX license list recognises (via go-spdx) →
//     `license.id`, case-folded to the canonical form (e.g. "apache-2.0" →
//     "Apache-2.0"). Strict validators (cyclonedx-cli, Dependency-Track)
//     accept these.
//  4. Anything the SPDX list does not know — loose author free-text ("BSD",
//     "The MIT License", "Custom Proprietary License") — goes to
//     `license.name` verbatim. We deliberately do NOT guess the author's
//     intent: an unrecognised string is stored as-is rather than
//     reinterpreted as a canonical ID. Policy matching against loose forms is
//     the consumer's normalisation problem, not the SBOM's to invent.
//
// The 1.6-only `acknowledgement` field is intentionally omitted (would fail
// 1.5 schema validation).
func licensesToCDX(ids []string) []cdxLicenseChoice {
	// Drop noise first so the sole-expression decision below sees only real
	// tokens: empty/whitespace-only entries and license URLs (which aren't
	// valid SPDX enum values — the canonical id is already present alongside).
	kept := make([]string, 0, len(ids))
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			continue
		}
		if strings.HasPrefix(id, "http://") || strings.HasPrefix(id, "https://") {
			continue
		}
		kept = append(kept, id)
	}

	// An `expression` may only be emitted when it stands alone (see point 2).
	soleExpression := len(kept) == 1 && isLicenseExpression(kept[0])

	out := make([]cdxLicenseChoice, 0, len(kept))
	for _, id := range kept {
		switch {
		case soleExpression:
			out = append(out, cdxLicenseChoice{Expression: id})
		case isLicenseExpression(id):
			// Expression sharing the array with other tokens — keep the string
			// verbatim in the schema-valid `license.name` slot.
			out = append(out, cdxLicenseChoice{License: &cdxLicenseRef{Name: id}})
		default:
			// Authoritative SPDX check + case-fold. A recognised id lands in the
			// schema-validated `license.id` slot in its canonical casing;
			// everything else stays as free-text `license.name`.
			if norm, ok := spdxCanonicalID(id); ok {
				out = append(out, cdxLicenseChoice{License: &cdxLicenseRef{ID: norm}})
			} else {
				out = append(out, cdxLicenseChoice{License: &cdxLicenseRef{Name: id}})
			}
		}
	}
	return out
}

// spdxCanonicalID validates a single license token against the SPDX license
// list and returns its canonical-cased form. Returns ("", false) for anything
// that isn't a current, canonical SPDX id, so the caller routes it to the
// free-text license.name slot. Rejected:
//
//   - loose forms / vendor strings ("BSD", "Custom Proprietary License") — not
//     in the SPDX list at all;
//   - deprecated ids (e.g. "GPL-2.0", superseded by "GPL-2.0-only") — go-spdx
//     case-folds but does NOT migrate deprecated→current, so emitting them as
//     license.id would put a non-canonical value in the SPDX-enum slot and
//     disagree with the policy/intake path (parser.go), which stores the
//     canonical form (FailDeprecatedLicenses);
//   - LicenseRef-* / DocumentRef-* — valid in SPDX *expressions* but NOT
//     permitted in the CycloneDX license.id enum, so a strict validator would
//     reject the SBOM; free-text name is the safe slot (FailAll*Refs).
//
// Expressions are handled by the caller, so this only sees single tokens:
// exactly one normalised value is expected (FailComplexExpressions).
func spdxCanonicalID(id string) (string, bool) {
	norm, invalid := spdxexp.ValidateAndNormalizeLicensesWithOptions(
		[]string{id},
		spdxexp.ValidateLicensesOptions{
			FailComplexExpressions: true,
			FailDeprecatedLicenses: true,
			FailAllLicenseRefs:     true,
			FailAllDocumentRefs:    true,
		},
	)
	if len(invalid) > 0 || len(norm) != 1 {
		return "", false
	}
	return norm[0], true
}

// isLicenseExpression returns true for strings that look like an SPDX
// expression rather than a single ID — i.e. contain one of the SPDX
// operators or parentheses. Conservative: false positives just downgrade
// an ID into an expression entry, which is still spec-valid.
func isLicenseExpression(s string) bool {
	for _, op := range []string{" AND ", " OR ", " WITH ", "(", ")"} {
		if strings.Contains(s, op) {
			return true
		}
	}
	return false
}

func stripSHAPrefix(s string) string {
	return strings.TrimPrefix(s, "sha256:")
}

// projectDescription combines the project's human-readable metadata for the
// CycloneDX `metadata.component.description` slot. Joined as
// "<display_name> — <description>" when both are set; otherwise whichever
// one is present; empty when neither is. Kept here (not on the Project type)
// because it is SBOM-presentation logic, not domain logic.
func projectDescription(p *project.Project) string {
	switch {
	case p.DisplayName != "" && p.Description != "":
		return p.DisplayName + " — " + p.Description
	case p.DisplayName != "":
		return p.DisplayName
	default:
		return p.Description
	}
}
