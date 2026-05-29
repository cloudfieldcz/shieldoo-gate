package sbom

// CycloneDX 1.5 JSON document — write-side schema (we only marshal, never
// parse this shape). Field names and `omitempty` placement intentionally
// follow https://cyclonedx.org/docs/1.5/json/ so that the marshalled output
// validates against the official schema (bom-1.5.schema.json).
//
// We deliberately keep this minimal — only the fields we actually populate
// for a Project SBOM are modelled. Adding more later means adding a field
// here, not restructuring.

type cdxBOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber,omitempty"`
	Version      int          `json:"version"`
	Metadata     cdxBOMMeta   `json:"metadata"`
	Components   []cdxOutComp `json:"components"`
}

type cdxBOMMeta struct {
	Timestamp  string         `json:"timestamp"`
	Lifecycles []cdxLifecycle `json:"lifecycles,omitempty"`
	Tools      cdxTools       `json:"tools"`
	Component  *cdxOutComp    `json:"component,omitempty"`
}

// cdxLifecycle is the 1.5 metadata.lifecycles[] entry. Phase enum:
// design | pre-build | build | post-build | operations | discovery | decommission.
// We always emit `discovery` — the proxy passively observes pull events; it
// has no view of build-time resolution or runtime install state.
type cdxLifecycle struct {
	Phase string `json:"phase"`
}

// cdxTools uses the 1.5 object-form ({"components": [...]}). The legacy
// array-form is deprecated since 1.5.
type cdxTools struct {
	Components []cdxOutComp `json:"components"`
}

type cdxOutComp struct {
	Type               string             `json:"type"`
	BOMRef             string             `json:"bom-ref,omitempty"`
	Name               string             `json:"name"`
	Version            string             `json:"version,omitempty"`
	Description        string             `json:"description,omitempty"`
	PURL               string             `json:"purl,omitempty"`
	Supplier           *cdxOrgEntity      `json:"supplier,omitempty"`
	Hashes             []cdxHash          `json:"hashes,omitempty"`
	Licenses           []cdxLicenseChoice `json:"licenses,omitempty"`
	ExternalReferences []cdxExtRef        `json:"externalReferences,omitempty"`
	Properties         []cdxProperty      `json:"properties,omitempty"`
}

// cdxOrgEntity is the organizationalEntity shape used by component.supplier.
// 1.5 schema permits name, url, contact. We only emit name.
type cdxOrgEntity struct {
	Name string `json:"name,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// cdxLicenseChoice is the union shape mandated by the CycloneDX schema —
// exactly one of License or Expression is populated per entry.
type cdxLicenseChoice struct {
	License    *cdxLicenseRef `json:"license,omitempty"`
	Expression string         `json:"expression,omitempty"`
}

// cdxLicenseRef mirrors the CycloneDX 1.5 license object — strictly one of
// `id` (SPDX ID) or `name` (free text). The 1.6-only `acknowledgement` field
// is intentionally absent.
type cdxLicenseRef struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type cdxExtRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
