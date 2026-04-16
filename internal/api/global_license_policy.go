package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/license"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
)

// globalLicensePolicyView is the JSON shape for GET /policy/licenses.
type globalLicensePolicyView struct {
	Enabled       bool     `json:"enabled"`
	Blocked       []string `json:"blocked"`
	Warned        []string `json:"warned"`
	Allowed       []string `json:"allowed"`
	UnknownAction string   `json:"unknown_action"`
	OnSBOMError   string   `json:"on_sbom_error"`
	OrSemantics   string   `json:"or_semantics"`
	UpdatedAt     string   `json:"updated_at,omitempty"`
	UpdatedBy     string   `json:"updated_by,omitempty"`
	// Source tells the UI whether the live values were loaded from the DB
	// (runtime edits) or fell back to the YAML config.
	Source string `json:"source"` // "db" | "config"
}

type globalLicensePolicyUpdate struct {
	Enabled       *bool    `json:"enabled,omitempty"`
	Blocked       []string `json:"blocked"`
	Warned        []string `json:"warned"`
	Allowed       []string `json:"allowed"`
	UnknownAction string   `json:"unknown_action"`
	OnSBOMError   string   `json:"on_sbom_error"`
	OrSemantics   string   `json:"or_semantics"`
}

// handleGetGlobalLicensePolicy returns the currently-effective global policy.
// The source field tells the UI whether this came from the DB or the YAML config.
func (s *Server) handleGetGlobalLicensePolicy(w http.ResponseWriter, r *http.Request) {
	row, hasRow, err := loadGlobalLicensePolicyRow(s.db)
	if err != nil {
		log.Error().Err(err).Msg("api: read global license policy failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "read failed"})
		return
	}

	view := globalLicensePolicyView{OrSemantics: string(license.OrAnyAllowed)}
	if hasRow {
		view.Source = "db"
		view.Enabled = row.Enabled
		view.Blocked = decodeJSONList(row.BlockedJSON)
		view.Warned = decodeJSONList(row.WarnedJSON)
		view.Allowed = decodeJSONList(row.AllowedJSON)
		if row.UnknownAction != nil {
			view.UnknownAction = *row.UnknownAction
		}
		if row.OnSBOMError != nil {
			view.OnSBOMError = *row.OnSBOMError
		}
		if row.OrSemantics != nil && *row.OrSemantics != "" {
			view.OrSemantics = *row.OrSemantics
		}
		if row.UpdatedAt != nil {
			view.UpdatedAt = *row.UpdatedAt
		}
		if row.UpdatedBy != nil {
			view.UpdatedBy = *row.UpdatedBy
		}
	} else {
		// No DB row yet — report the resolver's current global (YAML startup).
		view.Source = "config"
		view.Enabled = true
		p := s.licenseResolver.Global()
		view.Blocked = append(view.Blocked, p.Blocked...)
		view.Warned = append(view.Warned, p.Warned...)
		view.Allowed = append(view.Allowed, p.Allowed...)
		if p.UnknownAction != "" {
			view.UnknownAction = string(p.UnknownAction)
		} else {
			view.UnknownAction = string(license.UnknownAllow)
		}
		if p.OrSemantics != "" {
			view.OrSemantics = string(p.OrSemantics)
		}
		if s.policyEngine != nil {
			view.OnSBOMError = string(s.policyEngine.OnSBOMError())
		}
	}
	if view.Blocked == nil {
		view.Blocked = []string{}
	}
	if view.Warned == nil {
		view.Warned = []string{}
	}
	if view.Allowed == nil {
		view.Allowed = []string{}
	}
	writeJSON(w, http.StatusOK, view)
}

// handlePutGlobalLicensePolicy upserts the singleton row, pushes the new
// values into the live resolver + engine, and returns the refreshed view.
func (s *Server) handlePutGlobalLicensePolicy(w http.ResponseWriter, r *http.Request) {
	var body globalLicensePolicyUpdate
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Validate enum fields — keep the set aligned with config.validateLicenses().
	if err := validateLicenseAction(body.UnknownAction, "unknown_action"); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := validateLicenseAction(body.OnSBOMError, "on_sbom_error"); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if body.OrSemantics == "" {
		body.OrSemantics = string(license.OrAnyAllowed)
	}
	if body.OrSemantics != string(license.OrAnyAllowed) && body.OrSemantics != string(license.OrAllAllowed) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "or_semantics must be 'any_allowed' or 'all_allowed'"})
		return
	}

	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}

	blockedJSON, _ := json.Marshal(nilSafeList(body.Blocked))
	warnedJSON, _ := json.Marshal(nilSafeList(body.Warned))
	allowedJSON, _ := json.Marshal(nilSafeList(body.Allowed))

	actor := ""
	if u := auth.UserFromContext(r.Context()); u != nil {
		actor = u.Email
	}

	now := time.Now().UTC()
	_, err := s.db.ExecContext(r.Context(),
		`INSERT INTO global_license_policy
		     (id, enabled, blocked_json, warned_json, allowed_json,
		      unknown_action, on_sbom_error, or_semantics, updated_at, updated_by)
		 VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (id) DO UPDATE SET
		     enabled        = excluded.enabled,
		     blocked_json   = excluded.blocked_json,
		     warned_json    = excluded.warned_json,
		     allowed_json   = excluded.allowed_json,
		     unknown_action = excluded.unknown_action,
		     on_sbom_error  = excluded.on_sbom_error,
		     or_semantics   = excluded.or_semantics,
		     updated_at     = excluded.updated_at,
		     updated_by     = excluded.updated_by`,
		enabled, string(blockedJSON), string(warnedJSON), string(allowedJSON),
		body.UnknownAction, body.OnSBOMError, body.OrSemantics, now, actor,
	)
	if err != nil {
		log.Error().Err(err).Msg("api: write global license policy failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "write failed"})
		return
	}

	// Push to live resolver + engine so subsequent requests use the new policy
	// without a restart.
	newPol := license.Policy{
		Blocked:       nilSafeList(body.Blocked),
		Warned:        nilSafeList(body.Warned),
		Allowed:       nilSafeList(body.Allowed),
		UnknownAction: license.UnknownAction(body.UnknownAction),
		OrSemantics:   license.OrSemantics(body.OrSemantics),
		Source:        "global",
	}
	s.licenseResolver.SetGlobal(newPol)
	if s.policyEngine != nil {
		s.policyEngine.SetOnSBOMError(license.Action(body.OnSBOMError))
	}
	log.Info().Str("actor", actor).Bool("enabled", enabled).
		Int("blocked", len(body.Blocked)).Int("warned", len(body.Warned)).Int("allowed", len(body.Allowed)).
		Msg("global license policy updated")

	// Re-evaluate cached artifacts against the new policy (async).
	s.triggerLicenseReEvaluation(fmt.Sprintf("global policy updated by %s", actor))

	s.handleGetGlobalLicensePolicy(w, r)
}

// handleDeleteGlobalLicensePolicy removes the DB row and reverts the live
// resolver to the YAML values captured at startup. After DELETE, GET returns
// source="config".
func (s *Server) handleDeleteGlobalLicensePolicy(w http.ResponseWriter, r *http.Request) {
	_, err := s.db.ExecContext(r.Context(),
		`DELETE FROM global_license_policy WHERE id = 1`)
	if err != nil {
		log.Error().Err(err).Msg("api: delete global license policy failed")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
		return
	}

	// Swap the live resolver back to the captured YAML values, purge the
	// per-project cache. NOTE: we do not push a runtime change to
	// engine.onSBOMError — the DB-persisted value would simply not apply
	// any more, and the engine keeps whatever was in effect. In practice
	// admins rarely edit on_sbom_error, and a full restart is cheap.
	if s.licenseResolver != nil {
		s.licenseResolver.ResetToYAML()
	}
	actor := ""
	if u := auth.UserFromContext(r.Context()); u != nil {
		actor = u.Email
	}
	log.Info().Str("actor", actor).Msg("global license policy row deleted — resolver reverted to YAML config")

	// Re-evaluate cached artifacts against the reverted policy (async).
	s.triggerLicenseReEvaluation(fmt.Sprintf("global policy deleted by %s — reverted to YAML", actor))

	s.handleGetGlobalLicensePolicy(w, r)
}

// ---- shared helpers + startup loader -----------------------------------

type globalLicensePolicyRow struct {
	Enabled       bool    `db:"enabled"`
	BlockedJSON   *string `db:"blocked_json"`
	WarnedJSON    *string `db:"warned_json"`
	AllowedJSON   *string `db:"allowed_json"`
	UnknownAction *string `db:"unknown_action"`
	OnSBOMError   *string `db:"on_sbom_error"`
	OrSemantics   *string `db:"or_semantics"`
	UpdatedAt     *string `db:"updated_at"`
	UpdatedBy     *string `db:"updated_by"`
}

func loadGlobalLicensePolicyRow(db *config.GateDB) (globalLicensePolicyRow, bool, error) {
	var row globalLicensePolicyRow
	err := db.Get(&row,
		`SELECT enabled, blocked_json, warned_json, allowed_json,
		        unknown_action, on_sbom_error, or_semantics,
		        updated_at, updated_by
		 FROM global_license_policy WHERE id = 1`)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return globalLicensePolicyRow{}, false, nil
		}
		return globalLicensePolicyRow{}, false, err
	}
	return row, true, nil
}

// LoadGlobalLicensePolicyFromDB reads the runtime-mutable global license
// policy row (if any) and applies it to the provided resolver + engine.
// Safe to call at startup. A missing row is NOT an error — the YAML config
// stays in effect.
func LoadGlobalLicensePolicyFromDB(db *config.GateDB, resolver *license.Resolver, engine *policy.Engine) error {
	row, ok, err := loadGlobalLicensePolicyRow(db)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	current := resolver.Global()
	next := license.Policy{
		Blocked:       decodeJSONList(row.BlockedJSON),
		Warned:        decodeJSONList(row.WarnedJSON),
		Allowed:       decodeJSONList(row.AllowedJSON),
		UnknownAction: current.UnknownAction,
		OrSemantics:   current.OrSemantics,
		Source:        "global",
	}
	if row.UnknownAction != nil && *row.UnknownAction != "" {
		next.UnknownAction = license.UnknownAction(*row.UnknownAction)
	}
	if row.OrSemantics != nil && *row.OrSemantics != "" {
		next.OrSemantics = license.OrSemantics(*row.OrSemantics)
	}
	resolver.SetGlobal(next)

	if engine != nil && row.OnSBOMError != nil && *row.OnSBOMError != "" {
		engine.SetOnSBOMError(license.Action(*row.OnSBOMError))
	}
	return nil
}

func decodeJSONList(s *string) []string {
	if s == nil || *s == "" {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(*s), &out)
	return out
}

func nilSafeList(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func validateLicenseAction(a, field string) error {
	switch a {
	case "allow", "warn", "block":
		return nil
	default:
		return errors.New(field + " must be 'allow', 'warn', or 'block'")
	}
}
