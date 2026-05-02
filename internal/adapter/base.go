package adapter

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/alert"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/project"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

// globalAlerter holds the package-level alerter set during initialization.
var globalAlerter atomic.Pointer[alert.Alerter]

// globalAsyncScanner holds the package-level async scanner (e.g. sandbox) set during initialization.
var globalAsyncScanner atomic.Pointer[scanner.AsyncScanner]

// globalProjectSvc is set at startup; when non-nil the audit helpers will
// automatically record per-project artifact usage and stamp audit entries
// with project_id.
var globalProjectSvc atomic.Pointer[project.Service]

// SetProjectService stores the project service so audit + usage helpers can
// use it. Safe to call once during startup.
func SetProjectService(svc project.Service) {
	globalProjectSvc.Store(&svc)
}

// globalSBOMWriter is set at startup (see cmd/shieldoo-gate). When non-nil
// and a ScanResult carries SBOM content, the adapter triggers an async write
// to blob storage after the response is served.
var globalSBOMWriter atomic.Pointer[SBOMAsyncWriter]

// SBOMAsyncWriter is the adapter-side hook used to persist SBOMs without
// blocking the request path. Implemented by a thin wrapper in main.go that
// forwards to sbom.Storage.Write.
type SBOMAsyncWriter interface {
	// Write persists the SBOM blob and metadata. scannerLicenses are the
	// pre-extracted SPDX IDs from the scanner's license extractor — they
	// are merged with whatever Parse() finds in the CycloneDX blob so that
	// metadata is complete even when Trivy produces 0 components (common
	// for single-artifact scans).
	Write(ctx context.Context, artifactID, format string, raw []byte, scannerLicenses []string) error
}

// SetSBOMWriter stores the async SBOM writer.
func SetSBOMWriter(w SBOMAsyncWriter) {
	globalSBOMWriter.Store(&w)
}

// LicenseMetadataWriter persists license-only metadata for artifacts that
// have discovered licenses outside the normal SBOM path (e.g. Maven
// effective-POM resolver).
type LicenseMetadataWriter interface {
	WriteLicensesOnly(ctx context.Context, artifactID string, licenses []string, generator string) error
}

var globalLicenseWriter atomic.Pointer[LicenseMetadataWriter]

// SetLicenseMetadataWriter stores the license metadata writer.
func SetLicenseMetadataWriter(w LicenseMetadataWriter) {
	globalLicenseWriter.Store(&w)
}

// TriggerAsyncLicenseWrite persists license metadata asynchronously for
// artifacts where licenses are discovered without a full SBOM (e.g. Maven
// effective-POM resolver). No-op when no writer is configured or licenses
// are empty.
func TriggerAsyncLicenseWrite(ctx context.Context, artifactID string, licenses []string, generator string) {
	wp := globalLicenseWriter.Load()
	if wp == nil || *wp == nil || len(licenses) == 0 {
		return
	}
	w := *wp
	go func() {
		writeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := w.WriteLicensesOnly(writeCtx, artifactID, licenses, generator); err != nil {
			log.Warn().Err(err).Str("artifact_id", artifactID).Msg("adapter: async license metadata write failed")
		}
	}()
}

// ApplyPolicyWarnings surfaces any non-blocking PolicyResult.Warnings as a
// response header (X-Shieldoo-Warning) and a best-effort audit event. It is
// safe to call from every adapter Allow/AllowWithWarning path — a nil or
// empty warning list is a no-op.
func ApplyPolicyWarnings(w http.ResponseWriter, ctx context.Context, db *config.GateDB, artifactID string, warnings []string) {
	if len(warnings) == 0 {
		return
	}
	// Combine into a single header. Tools that parse this tend to look for
	// substrings ("license:...") rather than structured values.
	w.Header().Set("X-Shieldoo-Warning", strings.Join(warnings, "; "))
	for _, wrn := range warnings {
		// Audit as LICENSE_WARNED for license-flavored warnings, otherwise as
		// a generic ALLOWED_WITH_WARNING so existing dashboards pick them up.
		eventType := model.EventAllowedWithWarning
		if len(wrn) > 8 && wrn[:8] == "license:" {
			eventType = model.EventLicenseWarned
		}
		_ = WriteAuditLogCtx(ctx, db, model.AuditEntry{
			EventType:  eventType,
			ArtifactID: artifactID,
			Reason:     wrn,
		})
	}
}

// CheckCacheHitLicensePolicy evaluates the current license policy against
// stored SBOM metadata for a cached artifact. This is the synchronous gate
// that prevents serving artifacts with blocked licenses from cache.
//
// Returns true if the request was handled (blocked or error). The caller
// should return immediately. Returns false if the artifact may be served.
//
// When the license is blocked, a 403 JSON error is written with a
// LICENSE_BLOCKED audit event. When the license triggers a warning, the
// X-Shieldoo-Warning header is set and serving continues.
func CheckCacheHitLicensePolicy(
	w http.ResponseWriter,
	ctx context.Context,
	policyEngine *policy.Engine,
	db *config.GateDB,
	artifactID string,
) bool {
	if policyEngine == nil {
		return false
	}
	result := policyEngine.EvaluateLicensesOnly(ctx, artifactID)

	if result.Action == policy.ActionBlock {
		_ = WriteAuditLogCtx(ctx, db, model.AuditEntry{
			EventType:  model.EventLicenseBlocked,
			ArtifactID: artifactID,
			Reason:     result.Reason,
		})
		WriteJSONError(w, http.StatusForbidden, ErrorResponse{
			Error:    "blocked by license policy",
			Artifact: artifactID,
			Reason:   result.Reason,
		})
		return true
	}

	// Apply warnings (non-blocking).
	ApplyPolicyWarnings(w, ctx, db, artifactID, result.Warnings)
	return false
}

// TriggerAsyncSBOMWrite scans scanResults for an SBOM (first scanner that
// provides SBOMContent), and if found, writes it asynchronously via the
// configured SBOMAsyncWriter. No-op when no writer is configured or when
// no scanner produced SBOM content.
func TriggerAsyncSBOMWrite(ctx context.Context, artifactID string, scanResults []scanner.ScanResult) {
	wp := globalSBOMWriter.Load()
	if wp == nil || *wp == nil {
		return
	}
	for _, sr := range scanResults {
		if len(sr.SBOMContent) == 0 {
			continue
		}
		w := *wp
		// Detach from request context — the request may be done by the time
		// we finish persisting. Preserve a small timeout so we don't leak
		// goroutines on a broken storage backend.
		raw := sr.SBOMContent
		format := sr.SBOMFormat
		if format == "" {
			format = "cyclonedx-json"
		}
		// Pass scanner-extracted licenses so they get merged into SBOM
		// metadata even when the CycloneDX blob has 0 components (common
		// for single-artifact scans where Trivy doesn't detect packages).
		licenses := sr.Licenses
		go func() {
			writeCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := w.Write(writeCtx, artifactID, format, raw, licenses); err != nil {
				log.Warn().Err(err).Str("artifact_id", artifactID).Msg("adapter: async SBOM write failed")
			}
		}()
		return // first SBOM wins — Trivy is the only scanner producing SBOMs
	}
}

// NewProxyHTTPClient returns an *http.Client with connection pooling tuned for
// high-concurrency upstream proxying. All adapters should use this instead of
// creating bare http.Client instances.
func NewProxyHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			MaxIdleConns:        128,
			MaxIdleConnsPerHost: 64,
			MaxConnsPerHost:     64,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// SetAlerter stores the alerter for use by WriteAuditLog and DispatchAlert.
func SetAlerter(a alert.Alerter) {
	globalAlerter.Store(&a)
}

// SetAsyncScanner stores the async scanner (e.g. sandbox) for use by TriggerAsyncScan.
func SetAsyncScanner(s scanner.AsyncScanner) {
	globalAsyncScanner.Store(&s)
}

// TriggerAsyncScan fires an async sandbox scan after an artifact is served.
// Non-blocking, safe to call when no async scanner is configured.
func TriggerAsyncScan(ctx context.Context, artifact scanner.Artifact, localPath string, db *config.GateDB, policyEngine *policy.Engine) {
	ptr := globalAsyncScanner.Load()
	if ptr == nil {
		return
	}
	s := *ptr
	s.ScanAsync(ctx, artifact, localPath, func(result scanner.ScanResult) {
		if result.Verdict == scanner.VerdictMalicious {
			description := "sandbox behavioral analysis detected malicious behavior"
			if len(result.Findings) > 0 {
				description = "sandbox behavioral analysis: " + result.Findings[0].Description
			}
			_, _ = db.Exec(
				"UPDATE artifact_status SET status = 'QUARANTINED', quarantine_reason = ?, quarantined_at = CURRENT_TIMESTAMP WHERE artifact_id = ?",
				description, artifact.ID)
			_ = WriteAuditLog(db, model.AuditEntry{
				EventType:  model.EventQuarantined,
				ArtifactID: artifact.ID,
				Reason:     "sandbox behavioral analysis detected malicious behavior",
			})
		}
	})
}

// DispatchAlert sends an alert without writing to audit_log.
// Use when audit_log was already written (e.g., in API handler transactions).
func DispatchAlert(entry model.AuditEntry) {
	if a := globalAlerter.Load(); a != nil {
		(*a).Dispatch(context.Background(), entry)
	}
}

// PipelineTimeout is the maximum duration for the download+scan+cache pipeline.
// This timeout is applied to a detached context (context.Background) so that
// operations complete even when the HTTP client disconnects. This is critical
// for cloud storage backends (Azure Blob, S3, GCS) where cache writes are
// network I/O that takes seconds and would be canceled by a dead request context.
const PipelineTimeout = 5 * time.Minute

// PipelineContext creates a context detached from the HTTP request lifecycle.
// Use this for download, scan, and cache write operations that must complete
// regardless of whether the client is still connected.
func PipelineContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), PipelineTimeout)
}

// PipelineContextFrom is the project-aware variant of PipelineContext. It
// copies the per-request project (set by the auth middleware) into the
// detached pipeline context so the policy engine can resolve per-project
// license overrides during scan/policy evaluation. Cancellation is still
// independent of the originating request.
//
// Use this from any adapter that calls policyEngine.Evaluate(...) — without
// it, the engine sees projectID=0 and always falls back to the global
// policy, silently breaking per-project enforcement.
func PipelineContextFrom(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), PipelineTimeout)
	if p := project.FromContext(parent); p != nil {
		ctx = project.WithContext(ctx, p)
	}
	return ctx, cancel
}

// ArtifactLocker provides per-artifact-ID locking so that only one
// download/scan pipeline runs for a given artifact at a time.
// Subsequent requests for the same artifact wait for the first to complete.
var ArtifactLocker artifactLocker

type artifactLocker struct {
	locks sync.Map // map[string]*sync.Mutex
}

// Lock acquires a lock for the given artifact ID.
// Returns an unlock function that must be called when done.
func (al *artifactLocker) Lock(artifactID string) func() {
	val, _ := al.locks.LoadOrStore(artifactID, &sync.Mutex{})
	mu := val.(*sync.Mutex)
	mu.Lock()
	return func() {
		mu.Unlock()
		// Best-effort cleanup: try to remove the entry. If another goroutine
		// stored a new mutex concurrently via LoadOrStore, this deletes the
		// stale entry and the new one remains (no data race — sync.Map is safe).
		al.locks.CompareAndDelete(artifactID, val)
	}
}

// validNameRe matches safe package name characters — no path traversal or shell metacharacters.
var validNameRe = regexp.MustCompile(`^[a-zA-Z0-9._\-]+$`)

// ValidatePackageName returns an error if name contains unsafe characters.
func ValidatePackageName(name string) error {
	if name == "" {
		return fmt.Errorf("adapter: package name must not be empty")
	}
	if !validNameRe.MatchString(name) {
		return fmt.Errorf("adapter: package name %q contains invalid characters", name)
	}
	return nil
}

// ValidateVersion returns an error if version contains unsafe characters.
func ValidateVersion(version string) error {
	if version == "" {
		return fmt.Errorf("adapter: version must not be empty")
	}
	if !validNameRe.MatchString(version) {
		return fmt.Errorf("adapter: version %q contains invalid characters", version)
	}
	return nil
}

// ErrorResponse is the JSON body returned for blocked or quarantined requests.
type ErrorResponse struct {
	Error    string `json:"error"`
	Artifact string `json:"artifact,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// WriteJSONError writes a JSON-encoded ErrorResponse with the given HTTP status.
func WriteJSONError(w http.ResponseWriter, status int, resp ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// WriteAuditLogCtx inserts an AuditEntry with project_id extracted from ctx
// (if a project is present) and also records artifact usage for the project.
// This is the preferred variant for adapter serve/block/quarantine paths.
//
// As a convenience the generic BLOCKED event is auto-promoted to the more
// specific LICENSE_BLOCKED when the reason indicates a license-policy
// rejection. Adapters can keep emitting `model.EventBlocked` for every
// policy.ActionBlock case without needing to discriminate themselves.
func WriteAuditLogCtx(ctx context.Context, db *config.GateDB, entry model.AuditEntry) error {
	if p := project.FromContext(ctx); p != nil {
		id := p.ID
		entry.ProjectID = &id
		// Track usage (debounced). Only when we have a real artifact id.
		if entry.ArtifactID != "" && entry.EventType == model.EventServed {
			if svcPtr := globalProjectSvc.Load(); svcPtr != nil && *svcPtr != nil {
				(*svcPtr).RecordUsage(p.ID, entry.ArtifactID)
			}
		}
	}
	if entry.EventType == model.EventBlocked && isLicenseReason(entry.Reason) {
		entry.EventType = model.EventLicenseBlocked
	}
	return WriteAuditLog(db, entry)
}

// isLicenseReason returns true when the reason string came from the license
// policy evaluator (e.g. `license "GPL-3.0-only" blocked by …`). Kept as a
// prefix match — the evaluator emits a stable shape, no need for regex.
func isLicenseReason(reason string) bool {
	return strings.HasPrefix(reason, "license ") ||
		strings.HasPrefix(reason, "license:") ||
		strings.HasPrefix(reason, "license: ")
}

// WriteAuditLog inserts an AuditEntry into the audit_log table.
// Timestamp is set to now if zero.
// NOTE: For adapter serve paths with a request context, prefer WriteAuditLogCtx
// so the project_id and usage tracking are populated automatically.
func WriteAuditLog(db *config.GateDB, entry model.AuditEntry) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}
	_, err := db.Exec(
		`INSERT INTO audit_log (ts, event_type, artifact_id, client_ip, user_agent, reason, metadata_json, user_email, project_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Timestamp,
		entry.EventType,
		entry.ArtifactID,
		entry.ClientIP,
		entry.UserAgent,
		entry.Reason,
		entry.MetadataJSON,
		entry.UserEmail,
		entry.ProjectID,
	)
	if err != nil {
		return fmt.Errorf("adapter: writing audit log: %w", err)
	}
	if a := globalAlerter.Load(); a != nil {
		(*a).Dispatch(context.Background(), entry)
	}
	return nil
}

// UpdateLastAccessedAt bumps the last_accessed_at timestamp for a cached artifact.
// This keeps the rescan scheduler priority ordering accurate.
func UpdateLastAccessedAt(db *config.GateDB, artifactID string) {
	_, err := db.Exec(
		`UPDATE artifacts SET last_accessed_at = ? WHERE id = ?`,
		time.Now().UTC(), artifactID,
	)
	if err != nil {
		// Non-critical — log and continue.
		log.Warn().Err(err).Str("artifact", artifactID).Msg("adapter: failed to update last_accessed_at")
	}
}

// GetArtifactStatus retrieves the current status of an artifact by ID.
// Returns (nil, nil) when no row is found.
func GetArtifactStatus(db *config.GateDB, artifactID string) (*model.ArtifactStatus, error) {
	var status model.ArtifactStatus
	err := db.Get(&status,
		`SELECT artifact_id, status, quarantine_reason, quarantined_at, released_at, rescan_due_at, last_scan_id
		 FROM artifact_status WHERE artifact_id = ?`, artifactID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("adapter: getting artifact status for %s: %w", artifactID, err)
	}
	return &status, nil
}

// InsertScanResults persists a slice of scanner.ScanResult rows for the given artifactID.
// All rows are inserted in a single transaction to reduce round-trips.
func InsertScanResults(db *config.GateDB, artifactID string, results []scanner.ScanResult) error {
	tx, err := db.Beginx()
	if err != nil {
		return fmt.Errorf("adapter: beginning scan results transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	for _, r := range results {
		findingsJSON, err := json.Marshal(r.Findings)
		if err != nil {
			return fmt.Errorf("adapter: marshalling findings for %s: %w", artifactID, err)
		}
		_, err = tx.Exec(
			`INSERT INTO scan_results (artifact_id, scanned_at, scanner_name, scanner_version, verdict, confidence, findings_json, duration_ms)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			artifactID,
			r.ScannedAt,
			r.ScannerID,
			r.ScannerVersion,
			string(r.Verdict),
			r.Confidence,
			string(findingsJSON),
			r.Duration.Milliseconds(),
		)
		if err != nil {
			return fmt.Errorf("adapter: inserting scan result for %s/%s: %w", artifactID, r.ScannerID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("adapter: committing scan results for %s: %w", artifactID, err)
	}
	return nil
}

// InsertArtifact transactionally inserts the artifact row and its initial status row.
func InsertArtifact(db *config.GateDB, artifactID string, artifact model.Artifact, status model.ArtifactStatus) error {
	tx, err := db.Beginx()
	if err != nil {
		return fmt.Errorf("adapter: beginning transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	_, err = tx.Exec(
		`INSERT INTO artifacts (id, ecosystem, name, version, upstream_url, sha256, size_bytes, cached_at, last_accessed_at, storage_path)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (id) DO UPDATE SET
		     ecosystem = EXCLUDED.ecosystem, name = EXCLUDED.name, version = EXCLUDED.version,
		     upstream_url = EXCLUDED.upstream_url, sha256 = EXCLUDED.sha256, size_bytes = EXCLUDED.size_bytes,
		     cached_at = EXCLUDED.cached_at, last_accessed_at = EXCLUDED.last_accessed_at, storage_path = EXCLUDED.storage_path`,
		artifactID,
		artifact.Ecosystem,
		artifact.Name,
		artifact.Version,
		artifact.UpstreamURL,
		artifact.SHA256,
		artifact.SizeBytes,
		artifact.CachedAt,
		artifact.LastAccessedAt,
		artifact.StoragePath,
	)
	if err != nil {
		return fmt.Errorf("adapter: inserting artifact %s: %w", artifactID, err)
	}

	_, err = tx.Exec(
		`INSERT INTO artifact_status (artifact_id, status, quarantine_reason, quarantined_at, released_at, rescan_due_at, last_scan_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT (artifact_id) DO UPDATE SET
		     status = EXCLUDED.status, quarantine_reason = EXCLUDED.quarantine_reason,
		     quarantined_at = EXCLUDED.quarantined_at, released_at = EXCLUDED.released_at,
		     rescan_due_at = EXCLUDED.rescan_due_at, last_scan_id = EXCLUDED.last_scan_id`,
		artifactID,
		status.Status,
		status.QuarantineReason,
		status.QuarantinedAt,
		status.ReleasedAt,
		status.RescanDueAt,
		status.LastScanID,
	)
	if err != nil {
		return fmt.Errorf("adapter: inserting artifact status for %s: %w", artifactID, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("adapter: committing artifact insert for %s: %w", artifactID, err)
	}
	return nil
}

// TyposquatPlaceholderVersion is the sentinel version stored on synthetic
// artifact rows produced by the typosquat pre-scan when the request did not
// include a version (e.g. npm metadata fetches). When an admin clicks Release
// on such a row, the API creates a package-scoped policy override.
const TyposquatPlaceholderVersion = "*"

// PersistTyposquatBlock writes a synthetic artifact + status + scan_results
// triple representing a typosquat pre-scan block. The artifact carries empty
// upstream_url / sha256 / storage_path and size_bytes=0 because no file was
// fetched; the row exists purely so admins can see and override the block via
// the Artifacts pane.
//
// artifactID is the row's primary key — callers should pre-sanitize it to
// match the convention used by their full-scan persistence path (e.g. npm
// replaces "/" and "@" so scoped packages get IDs like "npm:scope_pkg:*").
// rawName is stored verbatim in artifacts.name so that override matching
// (which compares against scanner.Artifact.Name) works correctly.
//
// Pass version=TyposquatPlaceholderVersion when the pre-scan ran on a
// name-only request, or the actual version string when the block happened on
// a tarball/version-scoped request. Repeated calls for the same artifactID
// are idempotent: the existing row is refreshed and an additional
// scan_results row is appended (matching full-scan persistence).
func PersistTyposquatBlock(db *config.GateDB, artifactID string, ecosystem scanner.Ecosystem, rawName, version string, result scanner.ScanResult, now time.Time) error {
	if version == "" {
		version = TyposquatPlaceholderVersion
	}
	art := model.Artifact{
		Ecosystem:      string(ecosystem),
		Name:           rawName,
		Version:        version,
		UpstreamURL:    "",
		SHA256:         "",
		SizeBytes:      0,
		CachedAt:       now,
		LastAccessedAt: now,
		StoragePath:    "",
	}

	reason := "typosquat pre-scan: " + string(result.Verdict)
	if len(result.Findings) > 0 {
		reason = "typosquat: " + result.Findings[0].Description
	}

	quarantinedAt := now
	status := model.ArtifactStatus{
		ArtifactID:       artifactID,
		Status:           model.StatusQuarantined,
		QuarantineReason: reason,
		QuarantinedAt:    &quarantinedAt,
	}

	if err := InsertArtifact(db, artifactID, art, status); err != nil {
		return err
	}
	if err := InsertScanResults(db, artifactID, []scanner.ScanResult{result}); err != nil {
		return err
	}
	return nil
}

// ComputeSHA256 returns the hex-encoded SHA256 hash of the file at the given path.
func ComputeSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("integrity: opening file %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("integrity: reading file %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyCacheIntegrity verifies that the cached file at localPath matches
// the SHA256 stored in the artifacts table. FAIL-CLOSED: returns error on
// any failure (DB error, IO error, mismatch). On SHA256 mismatch, the
// artifact is automatically quarantined and an INTEGRITY_VIOLATION audit
// event is written.
func VerifyCacheIntegrity(db *config.GateDB, artifactID, localPath string) error {
	var dbSHA256 string
	err := db.Get(&dbSHA256, `SELECT sha256 FROM artifacts WHERE id = ?`, artifactID)
	if err != nil {
		return fmt.Errorf("integrity: reading SHA256 for %s: %w", artifactID, err)
	}

	fileSHA256, err := ComputeSHA256(localPath)
	if err != nil {
		return fmt.Errorf("integrity: computing SHA256 for %s: %w", artifactID, err)
	}

	if dbSHA256 != fileSHA256 {
		reason := fmt.Sprintf("INTEGRITY VIOLATION: cached file SHA256 mismatch (expected=%s, got=%s)", dbSHA256, fileSHA256)
		now := time.Now().UTC()
		if _, qErr := db.Exec(
			`UPDATE artifact_status SET status = ?, quarantine_reason = ?, quarantined_at = ? WHERE artifact_id = ?`,
			string(model.StatusQuarantined), reason, now, artifactID,
		); qErr != nil {
			log.Error().Err(qErr).Str("artifact", artifactID).Msg("CRITICAL: failed to quarantine after integrity violation")
		}
		if aErr := WriteAuditLog(db, model.AuditEntry{
			EventType:    model.EventIntegrityViolation,
			ArtifactID:   artifactID,
			Reason:       reason,
			MetadataJSON: fmt.Sprintf(`{"expected_sha256":%q,"actual_sha256":%q,"source":"cache"}`, dbSHA256, fileSHA256),
		}); aErr != nil {
			log.Error().Err(aErr).Str("artifact", artifactID).Msg("CRITICAL: failed to write integrity violation audit log")
		}
		return fmt.Errorf("%s", reason)
	}
	return nil
}

// VerifyUpstreamIntegrity checks whether a newly downloaded artifact's SHA256
// matches a previously recorded SHA256 in the DB. If the artifact is unknown
// (no DB record), returns nil — this is a first download. On mismatch, the
// artifact is quarantined and an INTEGRITY_VIOLATION event is written.
// FAIL-CLOSED: DB errors return an error (do not serve).
func VerifyUpstreamIntegrity(db *config.GateDB, artifactID, newSHA256 string) error {
	var existingSHA256 string
	err := db.Get(&existingSHA256, `SELECT sha256 FROM artifacts WHERE id = ?`, artifactID)
	if err != nil {
		if err == sql.ErrNoRows {
			// No prior record — first download, nothing to compare.
			return nil
		}
		return fmt.Errorf("integrity: reading SHA256 for %s: %w", artifactID, err)
	}

	if existingSHA256 != newSHA256 {
		reason := fmt.Sprintf("INTEGRITY VIOLATION: upstream content changed (known=%s, downloaded=%s)", existingSHA256, newSHA256)
		now := time.Now().UTC()
		if _, qErr := db.Exec(
			`UPDATE artifact_status SET status = ?, quarantine_reason = ?, quarantined_at = ? WHERE artifact_id = ?`,
			string(model.StatusQuarantined), reason, now, artifactID,
		); qErr != nil {
			log.Error().Err(qErr).Str("artifact", artifactID).Msg("CRITICAL: failed to quarantine after upstream integrity violation")
		}
		if aErr := WriteAuditLog(db, model.AuditEntry{
			EventType:    model.EventIntegrityViolation,
			ArtifactID:   artifactID,
			Reason:       reason,
			MetadataJSON: fmt.Sprintf(`{"known_sha256":%q,"upstream_sha256":%q,"source":"upstream"}`, existingSHA256, newSHA256),
		}); aErr != nil {
			log.Error().Err(aErr).Str("artifact", artifactID).Msg("CRITICAL: failed to write upstream integrity violation audit log")
		}
		return fmt.Errorf("%s", reason)
	}
	return nil
}
