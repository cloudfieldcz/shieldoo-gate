package sbom

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/project"
)

func newGeneratorTestDB(t *testing.T) *config.GateDB {
	t.Helper()
	db, err := config.InitDB(config.SQLiteMemoryConfig())
	require.NoError(t, err)
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	return db
}

// stamped wraps NewGenerator with deterministic timestamp + UUID so test
// assertions can compare against fixed strings.
func stamped(g *Generator) *Generator {
	g.now = func() time.Time {
		return time.Date(2026, 5, 28, 12, 34, 56, 0, time.UTC)
	}
	g.newUUID = func() string { return "00000000-0000-4000-8000-000000000000" }
	return g
}

func TestGenerator_EmptyProject_ValidEmptySBOM(t *testing.T) {
	db := newGeneratorTestDB(t)

	// Seed a project row (no artifacts).
	res, err := db.Exec(`INSERT INTO projects (label, display_name, description, created_via, enabled, created_at)
		VALUES ('backend-team', 'Backend Team', 'API services', 'manual', 1, CURRENT_TIMESTAMP)`)
	require.NoError(t, err)
	pid, _ := res.LastInsertId()

	gen := stamped(NewGenerator(db, "1.2.0"))
	out, err := gen.ForProject(context.Background(), &project.Project{
		ID: pid, Label: "backend-team", DisplayName: "Backend Team", Description: "API services",
	})
	require.NoError(t, err)

	var got cdxBOM
	require.NoError(t, json.Unmarshal(out, &got))
	assert.Equal(t, "CycloneDX", got.BOMFormat)
	assert.Equal(t, "1.5", got.SpecVersion)
	assert.Equal(t, "urn:uuid:00000000-0000-4000-8000-000000000000", got.SerialNumber)
	assert.Equal(t, 1, got.Version)
	assert.Equal(t, "2026-05-28T12:34:56Z", got.Metadata.Timestamp)

	// Lifecycle phase signals this is a passively-observed SBOM, not build-time.
	require.Len(t, got.Metadata.Lifecycles, 1)
	assert.Equal(t, "discovery", got.Metadata.Lifecycles[0].Phase)

	// Tool identity is present and uses 1.5 object form.
	require.Len(t, got.Metadata.Tools.Components, 1)
	tool := got.Metadata.Tools.Components[0]
	assert.Equal(t, "application", tool.Type)
	assert.Equal(t, "shieldoo-gate", tool.Name)
	assert.Equal(t, "1.2.0", tool.Version)

	// Subject of the BOM = the project itself.
	require.NotNil(t, got.Metadata.Component)
	assert.Equal(t, "application", got.Metadata.Component.Type)
	assert.Equal(t, "backend-team", got.Metadata.Component.Name)
	assert.Equal(t, "project/backend-team", got.Metadata.Component.BOMRef)
	// `version` deliberately omitted — a Project has no version; identity is
	// captured by name + serialNumber + metadata.timestamp.
	assert.Empty(t, got.Metadata.Component.Version)
	// Both display_name and description are present → joined with em-dash.
	assert.Equal(t, "Backend Team — API services", got.Metadata.Component.Description)

	assert.Empty(t, got.Components, "empty project should produce components: []")
}

func TestGenerator_ProjectWithArtifacts_FullSBOM(t *testing.T) {
	db := newGeneratorTestDB(t)

	// Project.
	res, err := db.Exec(`INSERT INTO projects (label, display_name, description, created_via, enabled, created_at)
		VALUES ('data', '', '', 'manual', 1, CURRENT_TIMESTAMP)`)
	require.NoError(t, err)
	pid, _ := res.LastInsertId()

	// Artifacts (one pypi with licenses, one docker, one with no upstream,
	// and one pypi that was once quarantined and then admin-released).
	_, err = db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path) VALUES
		('pypi:requests:2.31.0','pypi','requests','2.31.0','https://files.pythonhosted.org/packages/requests-2.31.0.tar.gz','aaa111',12345,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'/tmp/a'),
		('docker:r1_docker_io_library_alpine:3.20','docker','r1_docker_io_library_alpine','3.20','https://registry-1.docker.io/v2/library/alpine/manifests/3.20','bbb222',6789,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'/tmp/b'),
		('npm:lodash:4.17.21','npm','lodash','4.17.21','https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz','ccc333',5555,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'/tmp/c'),
		('pypi:once-evil:1.0.0','pypi','once-evil','1.0.0','https://files.pythonhosted.org/packages/once-evil-1.0.0.tar.gz','ddd444',2222,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'/tmp/d')`)
	require.NoError(t, err)

	// artifact_status: pypi CLEAN, docker QUARANTINED, npm no row,
	// once-evil CLEAN-by-release (status flipped back, released_at non-NULL).
	// Literal value uses go-sqlite3's accepted format ('YYYY-MM-DD HH:MM:SS',
	// no 'T' separator, no 'Z' suffix — see SQLiteTimestampFormats); we then
	// assert the RFC3339 form the generator emits.
	_, err = db.Exec(`INSERT INTO artifact_status (artifact_id, status, released_at) VALUES
		('pypi:requests:2.31.0','CLEAN', NULL),
		('docker:r1_docker_io_library_alpine:3.20','QUARANTINED', NULL),
		('pypi:once-evil:1.0.0','CLEAN','2026-05-29 10:00:00')`)
	require.NoError(t, err)

	// sbom_metadata: licenses for pypi only.
	_, err = db.Exec(`INSERT INTO sbom_metadata (artifact_id, format, blob_path, size_bytes, component_count, licenses_json, generated_at, generator) VALUES
		('pypi:requests:2.31.0','cyclonedx-json','sbom/pp/x.json',100,1,'["Apache-2.0","MIT"]',CURRENT_TIMESTAMP,'trivy')`)
	require.NoError(t, err)

	// Link artifacts to project.
	_, err = db.Exec(`INSERT INTO artifact_project_usage (artifact_id, project_id, first_used_at, last_used_at, use_count) VALUES
		('pypi:requests:2.31.0',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,3),
		('docker:r1_docker_io_library_alpine:3.20',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1),
		('npm:lodash:4.17.21',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1),
		('pypi:once-evil:1.0.0',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1)`, pid, pid, pid, pid)
	require.NoError(t, err)

	gen := stamped(NewGenerator(db, "1.2.0"))
	out, err := gen.ForProject(context.Background(), &project.Project{ID: pid, Label: "data"})
	require.NoError(t, err)

	var got cdxBOM
	require.NoError(t, json.Unmarshal(out, &got))
	require.Len(t, got.Components, 4, "all 4 pulled artifacts must appear")

	// Index by name for easier lookup; ORDER BY in the query is
	// (ecosystem, name, version) — docker, npm, pypi alphabetically.
	byName := map[string]cdxOutComp{}
	for _, c := range got.Components {
		byName[c.Name] = c
	}

	// PyPI assertions: library type, MIT+Apache, full PURL, hash, distribution ref.
	pp, ok := byName["requests"]
	require.True(t, ok)
	assert.Equal(t, "library", pp.Type)
	assert.Equal(t, "pkg:pypi/requests@2.31.0", pp.PURL)
	// purl field stays bare (package-version coordinate for scanner reconciliation),
	// while bom-ref is disambiguated by the artifact's content digest so multi-file
	// releases (wheels + sdist sharing one purl) get unique refs. See bomRef().
	assert.Equal(t, "pkg:pypi/requests@2.31.0?checksum=sha256:aaa111", pp.BOMRef)
	require.Len(t, pp.Hashes, 1)
	assert.Equal(t, "SHA-256", pp.Hashes[0].Alg)
	assert.Equal(t, "aaa111", pp.Hashes[0].Content)
	require.Len(t, pp.Licenses, 2)
	// Order in licenses_json is preserved.
	assert.Equal(t, "Apache-2.0", pp.Licenses[0].License.ID)
	assert.Equal(t, "MIT", pp.Licenses[1].License.ID)
	require.Len(t, pp.ExternalReferences, 1)
	assert.Equal(t, "distribution", pp.ExternalReferences[0].Type)
	// Status property present.
	assertProp(t, pp, "shieldoo:status", "CLEAN")
	assertProp(t, pp, "shieldoo:size_bytes", "12345")
	// Scanner-clean from day one → no released_at marker.
	assertPropAbsent(t, pp, "shieldoo:released_at")

	// Docker assertions: container type, OCI purl, QUARANTINED status.
	dk, ok := byName["r1_docker_io_library_alpine"]
	require.True(t, ok)
	assert.Equal(t, "container", dk.Type)
	assert.Contains(t, dk.PURL, "pkg:oci/alpine@sha256:bbb222")
	assert.Contains(t, dk.PURL, "repository_url=registry-1.docker.io%2Flibrary%2Falpine")
	assert.Contains(t, dk.PURL, "tag=3.20")
	assertProp(t, dk, "shieldoo:status", "QUARANTINED")
	// Quarantined (not released) → no released_at marker.
	assertPropAbsent(t, dk, "shieldoo:released_at")

	// npm has no status row → no shieldoo:status property.
	np, ok := byName["lodash"]
	require.True(t, ok)
	assert.Equal(t, "pkg:npm/lodash@4.17.21", np.PURL)
	assert.Nil(t, np.Licenses, "no SBOM row → no licenses")
	for _, p := range np.Properties {
		assert.NotEqual(t, "shieldoo:status", p.Name, "no status row → no status property")
		assert.NotEqual(t, "shieldoo:released_at", p.Name, "no status row → no released_at property")
	}

	// once-evil: was QUARANTINED, admin released → status CLEAN + released_at marker.
	// This is the audit-relevant case: scanners would NOT have produced CLEAN
	// on their own; an admin overrode the verdict. Consumers must be able to
	// tell that apart from a scanner-native CLEAN.
	oe, ok := byName["once-evil"]
	require.True(t, ok)
	assertProp(t, oe, "shieldoo:status", "CLEAN")
	assertProp(t, oe, "shieldoo:released_at", "2026-05-29T10:00:00Z")
}

func TestGenerator_NilProject_Errors(t *testing.T) {
	db := newGeneratorTestDB(t)
	_, err := NewGenerator(db, "").ForProject(context.Background(), nil)
	assert.Error(t, err)
}

func TestProjectDescription_Fallbacks(t *testing.T) {
	cases := []struct {
		name           string
		displayName    string
		description    string
		want           string
	}{
		{"both set", "Backend Team", "API services", "Backend Team — API services"},
		{"display_name only", "Backend Team", "", "Backend Team"},
		{"description only", "", "API services", "API services"},
		{"neither", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := projectDescription(&project.Project{DisplayName: tc.displayName, Description: tc.description})
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRowToComponent_LicenseExpression(t *testing.T) {
	// SBOM metadata storing an SPDX expression (e.g. "MIT OR Apache-2.0")
	// must be emitted as {expression: ...} not {license: {id: ...}}.
	r := rawRow{
		Ecosystem: "pypi", Name: "x", Version: "1.0", SHA256: "abc",
		LicensesJSON: nullString(`["MIT OR Apache-2.0"]`),
	}
	c := rowToComponent(r)
	require.Len(t, c.Licenses, 1)
	assert.Equal(t, "MIT OR Apache-2.0", c.Licenses[0].Expression)
	assert.Nil(t, c.Licenses[0].License)
}

func TestRowToComponent_LicenseURLsSkipped(t *testing.T) {
	// Trivy emits both the SPDX id and a license URL for some ecosystems
	// (NuGet's https://licenses.nuget.org/MIT). URLs aren't valid SPDX
	// enum values, so we must skip them — the SPDX id stays.
	r := rawRow{
		Ecosystem: "nuget", Name: "Newtonsoft.Json", Version: "13.0.3", SHA256: "abc",
		LicensesJSON: nullString(`["MIT","https://licenses.nuget.org/MIT"]`),
	}
	c := rowToComponent(r)
	require.Len(t, c.Licenses, 1, "URL license should have been filtered out")
	assert.Equal(t, "MIT", c.Licenses[0].License.ID)
}

func TestRowToComponent_FreeTextLicense_GoesToName(t *testing.T) {
	// Tokens that don't match a known alias AND don't pass the SPDX charset
	// heuristic must land in license.name rather than license.id — schema
	// strict validators (Dependency-Track, cyclonedx-cli) reject non-enum
	// values in id.
	r := rawRow{
		Ecosystem: "pypi", Name: "x", Version: "1.0", SHA256: "abc",
		LicensesJSON: nullString(`["MIT","Custom Proprietary License","ZPL-2.1","Foo Bar License v1"]`),
	}
	c := rowToComponent(r)
	require.Len(t, c.Licenses, 4)
	// SPDX-shaped, no alias match needed → id
	assert.Equal(t, "MIT", c.Licenses[0].License.ID)
	assert.Empty(t, c.Licenses[0].License.Name)
	// No alias, fails SPDX charset → name
	assert.Empty(t, c.Licenses[1].License.ID)
	assert.Equal(t, "Custom Proprietary License", c.Licenses[1].License.Name)
	// SPDX-shaped, no alias match needed → id
	assert.Equal(t, "ZPL-2.1", c.Licenses[2].License.ID)
	assert.Empty(t, c.Licenses[2].License.Name)
	// No alias, fails SPDX charset → name
	assert.Empty(t, c.Licenses[3].License.ID)
	assert.Equal(t, "Foo Bar License v1", c.Licenses[3].License.Name)
}

func TestRowToComponent_LooseFormLicenses_GoToName(t *testing.T) {
	// SBOM output is honest: loose author free-text ("BSD", "LGPLv3",
	// "The MIT License", "PSF", "Public-Domain") is NOT in the SPDX license
	// list verbatim, so we do not guess the author's intent — it lands in the
	// free-text `license.name` slot as-is. Only strings the SPDX list itself
	// recognises go to `license.id`. (Intake-side alias normalisation for
	// policy matching still lives in parser.go / scanner paths; it just no
	// longer rewrites the SBOM output.)
	r := rawRow{
		Ecosystem: "pypi", Name: "x", Version: "1.0", SHA256: "abc",
		LicensesJSON: nullString(`["BSD","LGPLv3","The MIT License","Apache-2.0","PSF","Public-Domain"]`),
	}
	c := rowToComponent(r)
	require.Len(t, c.Licenses, 6)
	// Loose forms → name verbatim, no id.
	assert.Equal(t, "BSD", c.Licenses[0].License.Name)
	assert.Empty(t, c.Licenses[0].License.ID)
	assert.Equal(t, "LGPLv3", c.Licenses[1].License.Name)
	assert.Empty(t, c.Licenses[1].License.ID)
	assert.Equal(t, "The MIT License", c.Licenses[2].License.Name)
	assert.Empty(t, c.Licenses[2].License.ID)
	// Canonical SPDX id → id, unchanged.
	assert.Equal(t, "Apache-2.0", c.Licenses[3].License.ID)
	assert.Empty(t, c.Licenses[3].License.Name)
	// "PSF" (SPDX only has PSF-2.0) and "Public-Domain" are not valid ids → name.
	assert.Equal(t, "PSF", c.Licenses[4].License.Name)
	assert.Empty(t, c.Licenses[4].License.ID)
	assert.Equal(t, "Public-Domain", c.Licenses[5].License.Name)
	assert.Empty(t, c.Licenses[5].License.ID)
}

func TestRowToComponent_SPDXIDsCaseFolded(t *testing.T) {
	// go-spdx recognises ids case-insensitively and returns the canonical
	// casing. Lowercase/odd-case inputs that ARE valid SPDX ids must be
	// normalised into the `id` slot, not dropped to `name`.
	r := rawRow{
		Ecosystem: "pypi", Name: "x", Version: "1.0", SHA256: "abc",
		LicensesJSON: nullString(`["mit","apache-2.0","bsd-3-clause"]`),
	}
	c := rowToComponent(r)
	require.Len(t, c.Licenses, 3)
	assert.Equal(t, "MIT", c.Licenses[0].License.ID)
	assert.Equal(t, "Apache-2.0", c.Licenses[1].License.ID)
	assert.Equal(t, "BSD-3-Clause", c.Licenses[2].License.ID)
	for i, lc := range c.Licenses {
		assert.Empty(t, lc.License.Name, "license %d should not be in .name", i)
	}
}

func TestRowToComponent_DeprecatedSPDXID_GoesToName(t *testing.T) {
	// Deprecated SPDX ids (e.g. "GPL-2.0", superseded by "GPL-2.0-only") are
	// still in the SPDX list, but go-spdx case-folds without migrating them to
	// the current form. Emitting them into license.id would put a
	// non-canonical value in the SPDX-enum slot and disagree with the
	// policy/intake path. So they must fall through to license.name verbatim,
	// while the current "-only"/"-or-later" forms still go to license.id.
	r := rawRow{
		Ecosystem: "pypi", Name: "x", Version: "1.0", SHA256: "abc",
		LicensesJSON: nullString(`["GPL-2.0","GPL-2.0-only","LGPL-2.1"]`),
	}
	c := rowToComponent(r)
	require.Len(t, c.Licenses, 3)
	// Deprecated → name verbatim, no id.
	assert.Equal(t, "GPL-2.0", c.Licenses[0].License.Name)
	assert.Empty(t, c.Licenses[0].License.ID)
	// Current canonical form → id.
	assert.Equal(t, "GPL-2.0-only", c.Licenses[1].License.ID)
	assert.Empty(t, c.Licenses[1].License.Name)
	// Another deprecated form → name.
	assert.Equal(t, "LGPL-2.1", c.Licenses[2].License.Name)
	assert.Empty(t, c.Licenses[2].License.ID)
}

func TestRowToComponent_LicenseRefAndDocumentRef_GoToName(t *testing.T) {
	// LicenseRef-* / DocumentRef-* are valid inside SPDX *expressions* but are
	// NOT permitted in the CycloneDX license.id enum — a strict validator
	// rejects an SBOM that puts them there. They must land in license.name.
	r := rawRow{
		Ecosystem: "pypi", Name: "x", Version: "1.0", SHA256: "abc",
		LicensesJSON: nullString(`["LicenseRef-MyProprietary","DocumentRef-ext:LicenseRef-Foo"]`),
	}
	c := rowToComponent(r)
	require.Len(t, c.Licenses, 2)
	assert.Equal(t, "LicenseRef-MyProprietary", c.Licenses[0].License.Name)
	assert.Empty(t, c.Licenses[0].License.ID)
	assert.Equal(t, "DocumentRef-ext:LicenseRef-Foo", c.Licenses[1].License.Name)
	assert.Empty(t, c.Licenses[1].License.ID)
}

func TestRowToComponent_WithExceptionExpression(t *testing.T) {
	// A single token carrying a WITH exception (e.g. GPL classpath exception)
	// is a valid SPDX expression, not a bare id — it must be emitted via the
	// `expression` slot, never license.id/license.name.
	r := rawRow{
		Ecosystem: "pypi", Name: "x", Version: "1.0", SHA256: "abc",
		LicensesJSON: nullString(`["GPL-2.0-only WITH Classpath-exception-2.0"]`),
	}
	c := rowToComponent(r)
	require.Len(t, c.Licenses, 1)
	assert.Equal(t, "GPL-2.0-only WITH Classpath-exception-2.0", c.Licenses[0].Expression)
	assert.Nil(t, c.Licenses[0].License)
}

func TestRowToComponent_ExpressionMixedWithLicenses_GoesToName(t *testing.T) {
	// CycloneDX `licenseChoice` is a oneOf: an array of `license` objects OR a
	// single `expression` — never mixed (cyclonedx-cli rejects a mixed array,
	// and the `expression` form is capped at one element). When an expression
	// shares the list with other tokens it must NOT be emitted as `expression`;
	// it is routed verbatim to free-text `license.name` so the whole array is a
	// valid list of `license` objects.
	r := rawRow{
		Ecosystem: "pypi", Name: "x", Version: "1.0", SHA256: "abc",
		LicensesJSON: nullString(`["MIT","Apache-2.0","Apache-2.0 OR BSD-2-Clause","LGPLv3"]`),
	}
	c := rowToComponent(r)
	require.Len(t, c.Licenses, 4)
	// No entry may use the expression slot when mixed.
	for i, lc := range c.Licenses {
		assert.Empty(t, lc.Expression, "entry %d must not be an expression in a mixed array", i)
		require.NotNil(t, lc.License, "entry %d must be a license object", i)
	}
	assert.Equal(t, "MIT", c.Licenses[0].License.ID)
	assert.Equal(t, "Apache-2.0", c.Licenses[1].License.ID)
	// The compound expression lands in name verbatim, not in id and not as expression.
	assert.Equal(t, "Apache-2.0 OR BSD-2-Clause", c.Licenses[2].License.Name)
	assert.Empty(t, c.Licenses[2].License.ID)
	// Free-text loose form stays in name.
	assert.Equal(t, "LGPLv3", c.Licenses[3].License.Name)
}

func TestRowToComponent_WhitespaceOnlyLicense_Skipped(t *testing.T) {
	// Blank / whitespace-only tokens carry no license info and must be dropped
	// entirely — not emitted as a blank license.name entry. The real "MIT"
	// token alongside them must still come through.
	r := rawRow{
		Ecosystem: "pypi", Name: "x", Version: "1.0", SHA256: "abc",
		LicensesJSON: nullString(`["","   ","\t","MIT"]`),
	}
	c := rowToComponent(r)
	require.Len(t, c.Licenses, 1, "only the MIT token should survive")
	assert.Equal(t, "MIT", c.Licenses[0].License.ID)
}

func TestRowToComponent_NoPURL_WhenUnknownEcosystem(t *testing.T) {
	r := rawRow{Ecosystem: "rust", Name: "serde", Version: "1.0"}
	c := rowToComponent(r)
	assert.Empty(t, c.PURL)
	assert.Equal(t, "serde", c.Name)
	// bom-ref must still be set for an unknown ecosystem — falls back to
	// "<eco>:<name>@<version>" so the BOM-level reference contract holds.
	assert.Equal(t, "rust:serde@1.0", c.BOMRef)
}

func TestRowToComponent_NoPURL_WithDigest_AppendsSha(t *testing.T) {
	// Fallback ref for an unknown ecosystem still gets the content digest so two
	// distinct files can't collide on the same bom-ref.
	r := rawRow{Ecosystem: "rust", Name: "serde", Version: "1.0", SHA256: "sha256:deadbeef"}
	c := rowToComponent(r)
	assert.Empty(t, c.PURL)
	assert.Equal(t, "rust:serde@1.0@sha256:deadbeef", c.BOMRef)
}

func TestRowToComponent_MultiFileRelease_UniqueBOMRefs(t *testing.T) {
	// PyPI ships many distribution files per release (per-platform wheels +
	// sdist) that all share ONE purl. CycloneDX requires bom-ref to be unique,
	// so the digest disambiguates while the purl field stays bare for scanner
	// reconciliation.
	wheel := rowToComponent(rawRow{Ecosystem: "pypi", Name: "rpds-py", Version: "0.30.0", SHA256: "aaa"})
	sdist := rowToComponent(rawRow{Ecosystem: "pypi", Name: "rpds-py", Version: "0.30.0", SHA256: "bbb"})

	assert.Equal(t, "pkg:pypi/rpds-py@0.30.0", wheel.PURL)
	assert.Equal(t, wheel.PURL, sdist.PURL, "same package version → same bare purl")
	assert.Equal(t, "pkg:pypi/rpds-py@0.30.0?checksum=sha256:aaa", wheel.BOMRef)
	assert.Equal(t, "pkg:pypi/rpds-py@0.30.0?checksum=sha256:bbb", sdist.BOMRef)
	assert.NotEqual(t, wheel.BOMRef, sdist.BOMRef, "distinct files must get distinct bom-refs")
}

func TestRowToComponent_DockerBOMRef_NoDoubleDigest(t *testing.T) {
	// OCI purls already carry the digest as the version — bomRef must NOT append
	// a second checksum qualifier.
	r := rawRow{
		Ecosystem:   "docker",
		Name:        "r1_docker_io_library_alpine",
		Version:     "3.20",
		SHA256:      "bbb222",
		UpstreamURL: "https://registry-1.docker.io/v2/library/alpine/manifests/3.20",
	}
	c := rowToComponent(r)
	assert.Equal(t, c.PURL, c.BOMRef, "docker bom-ref is the already-unique OCI purl")
	assert.NotContains(t, c.BOMRef, "checksum=", "no redundant checksum qualifier on OCI refs")
}

func TestGenerator_MultiFilePyPIRelease_AllComponentsUniqueRefs(t *testing.T) {
	// End-to-end reproduction of the duplicate-bom-ref bug: three wheels of the
	// same PyPI version, each a distinct artifact (distinct sha256/url), must all
	// appear with unique bom-refs and a schema-valid (collision-free) document.
	db := newGeneratorTestDB(t)
	res, err := db.Exec(`INSERT INTO projects (label, display_name, description, created_via, enabled, created_at)
		VALUES ('data', '', '', 'manual', 1, CURRENT_TIMESTAMP)`)
	require.NoError(t, err)
	pid, _ := res.LastInsertId()

	_, err = db.Exec(`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path) VALUES
		('w1','pypi','rpds-py','0.30.0','https://files.pythonhosted.org/rpds_py-0.30.0-cp313-manylinux.whl','d1',10,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'/tmp/w1'),
		('w2','pypi','rpds-py','0.30.0','https://files.pythonhosted.org/rpds_py-0.30.0-cp313-macosx.whl','d2',11,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'/tmp/w2'),
		('sd','pypi','rpds-py','0.30.0','https://files.pythonhosted.org/rpds_py-0.30.0.tar.gz','d3',12,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'/tmp/sd')`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO artifact_project_usage (artifact_id, project_id, first_used_at, last_used_at, use_count) VALUES
		('w1',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1),
		('w2',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1),
		('sd',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,1)`, pid, pid, pid)
	require.NoError(t, err)

	gen := stamped(NewGenerator(db, "1.2.0"))
	out, err := gen.ForProject(context.Background(), &project.Project{ID: pid, Label: "data"})
	require.NoError(t, err)

	var got cdxBOM
	require.NoError(t, json.Unmarshal(out, &got))
	require.Len(t, got.Components, 3, "all three distinct wheel/sdist artifacts must appear")

	refs := map[string]struct{}{}
	for _, c := range got.Components {
		assert.Equal(t, "pkg:pypi/rpds-py@0.30.0", c.PURL, "purl stays bare for reconciliation")
		_, dup := refs[c.BOMRef]
		assert.False(t, dup, "bom-ref %q duplicated", c.BOMRef)
		refs[c.BOMRef] = struct{}{}
	}
	assert.Len(t, refs, 3, "every component has a unique bom-ref")
}

// --- helpers ---

func assertProp(t *testing.T, c cdxOutComp, name, want string) {
	t.Helper()
	for _, p := range c.Properties {
		if p.Name == name {
			assert.Equal(t, want, p.Value)
			return
		}
	}
	t.Fatalf("property %q not found on component %q", name, c.Name)
}

func assertPropAbsent(t *testing.T, c cdxOutComp, name string) {
	t.Helper()
	for _, p := range c.Properties {
		if p.Name == name {
			t.Fatalf("property %q unexpectedly present on component %q (value=%q)", name, c.Name, p.Value)
		}
	}
}

func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
