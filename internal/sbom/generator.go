package sbom

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

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
}

func (g *Generator) loadComponents(ctx context.Context, projectID int64) ([]cdxOutComp, error) {
	rows, err := g.db.QueryxContext(ctx,
		`SELECT a.ecosystem, a.name, a.version, a.sha256, a.size_bytes, a.upstream_url,
		        a.cached_at,
		        sm.licenses_json AS licenses_json,
		        ast.status       AS status
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
	for rows.Next() {
		var r rawRow
		if err := rows.StructScan(&r); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out = append(out, rowToComponent(r))
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
		BOMRef:  bomRefOrPURL(purl, r.Ecosystem, r.Name, r.Version),
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

// bomRefOrPURL returns the PURL when present (idiomatic CycloneDX —
// `bom-ref ≡ purl` is what most dependency-graph tooling expects), falling
// back to "<ecosystem>:<name>@<version>" when no PURL can be built (unknown
// ecosystem, docker without a sha256 digest, malformed maven coordinates,
// etc.). bom-ref must be unique within the BOM; (ecosystem, name, version)
// is unique because loadComponents joins on the same key from
// artifact_project_usage.
func bomRefOrPURL(purl, eco, name, version string) string {
	if purl != "" {
		return purl
	}
	if version == "" {
		return eco + ":" + name
	}
	return eco + ":" + name + "@" + version
}

// licensesToCDX maps the SPDX ID list stored in sbom_metadata.licenses_json
// into the CycloneDX license-choice array. A token containing whitespace or
// SPDX operators (AND/OR/WITH) is treated as a license expression; otherwise
// we emit `{license: {id: ...}}`. The 1.6-only `acknowledgement` field is
// intentionally omitted (would fail 1.5 schema validation).
func licensesToCDX(ids []string) []cdxLicenseChoice {
	out := make([]cdxLicenseChoice, 0, len(ids))
	for _, id := range ids {
		if id == "" {
			continue
		}
		if isLicenseExpression(id) {
			out = append(out, cdxLicenseChoice{Expression: id})
			continue
		}
		out = append(out, cdxLicenseChoice{License: &cdxLicenseRef{ID: id}})
	}
	return out
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
