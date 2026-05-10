package component

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/rs/zerolog/log"
)

// ScanServiceConfig holds runtime configuration for the scan service.
type ScanServiceConfig struct {
	SBOMLimits SBOMLimits
}

func (c ScanServiceConfig) withDefaults() ScanServiceConfig {
	if c.SBOMLimits.MaxBytes == 0 {
		c.SBOMLimits = DefaultSBOMLimits()
	}
	return c
}

// AuditWriter is the contract for emitting audit_log rows. Decoupled here so the
// scan service can be tested without pulling in the alerter.
type AuditWriter interface {
	WriteVulnEvent(ctx context.Context, entry model.AuditEntry) error
}

// ScannerInvoker is the contract for invoking the manifest scanners on a stored SBOM.
// In Phase 1 this stays a stub that returns no findings; Phase 2 replaces with a real
// implementation rooted at internal/scanner/manifest.
type ScannerInvoker interface {
	Scan(ctx context.Context, run *ScanRun, sbom []byte) (*ScanResult, error)
}

// AnomalyEvaluator is the optional contract used post-commit to surface 3σ CVE-count
// spikes against a Component's baseline. Implemented by ai.AnomalyDetector. Nil-safe.
type AnomalyEvaluator interface {
	Evaluate(ctx context.Context, componentID, runID int64, currentCriticalHigh int64) error
}

// ScanResult is the post-aggregation, post-suppression output of the scanner pipeline.
type ScanResult struct {
	Findings        []*ScanFinding
	ScannerStatus   map[string]string
	ComponentCount  int64
	CriticalCount   int64
	HighCount       int64
	MediumCount     int64
	LowCount        int64
}

// scanServiceImpl implements ScanService.
type scanServiceImpl struct {
	cfg       ScanServiceConfig
	db        *config.GateDB
	store     *Store
	blob      cache.BlobStore
	scanner   ScannerInvoker
	audit     AuditWriter
	deltaFunc func(ctx context.Context, run *ScanRun, prev *ScanRun, current []*ScanFinding) (newCritical, newHigh int64, alerts []model.AuditEntry, err error)
	anomaly   AnomalyEvaluator
}

// ScanServiceDeps wires the scan service to its collaborators.
type ScanServiceDeps struct {
	DB      *config.GateDB
	Store   *Store
	Blob    cache.BlobStore
	Scanner ScannerInvoker // optional; nil = no-op (Phase 1 default)
	Audit   AuditWriter
	// DeltaFunc computes the delta vs the previous successful run; nil = no delta.
	DeltaFunc func(ctx context.Context, run *ScanRun, prev *ScanRun, current []*ScanFinding) (int64, int64, []model.AuditEntry, error)
	// Anomaly is the optional 3σ baseline evaluator (AI feature). Nil = skip.
	Anomaly AnomalyEvaluator
}

// NewScanService constructs a ScanService.
func NewScanService(cfg ScanServiceConfig, deps ScanServiceDeps) ScanService {
	return &scanServiceImpl{
		cfg:       cfg.withDefaults(),
		db:        deps.DB,
		store:     deps.Store,
		blob:      deps.Blob,
		scanner:   deps.Scanner,
		audit:     deps.Audit,
		deltaFunc: deps.DeltaFunc,
		anomaly:   deps.Anomaly,
	}
}

// Submit ingests an SBOM stream and inserts a pending scan_run row.
func (s *scanServiceImpl) Submit(ctx context.Context, componentID int64, sbom io.Reader, sizeHint int64, contentType, trigger, byEmail string) (*ScanRun, error) {
	if err := ValidateContentType(contentType); err != nil {
		return nil, err
	}
	body, err := ReadAllLimited(sbom, s.cfg.SBOMLimits.MaxBytes)
	if err != nil {
		return nil, err
	}
	componentCount, err := ValidateSBOMStructure(body, s.cfg.SBOMLimits)
	if err != nil {
		return nil, err
	}
	_ = componentCount // count is recomputed by the scanner pipeline

	// Compute SHA-256 of the canonical body for tamper detection.
	sum := sha256.Sum256(body)
	sha := hex.EncodeToString(sum[:])

	// Insert pending scan_run row first; we need the id for the blob path.
	run, err := s.store.CreateScanRun(ctx, componentID, trigger, "", sha, "cyclonedx-json", int64(len(body)))
	if err != nil {
		return nil, err
	}
	blobPath := fmt.Sprintf("sboms/components/%d/runs/%d.json", componentID, run.ID)
	if err := s.blob.PutBlob(ctx, blobPath, body); err != nil {
		return nil, fmt.Errorf("scan_service: blob put: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE scan_runs SET sbom_blob_path = ? WHERE id = ?`, blobPath, run.ID); err != nil {
		return nil, fmt.Errorf("scan_service: update blob path: %w", err)
	}
	run.SBOMBlobPath = blobPath

	// Audit-log the upload.
	if s.audit != nil {
		_ = s.audit.WriteVulnEvent(ctx, model.AuditEntry{
			EventType:   model.EventSBOMUploaded,
			ComponentID: ptrInt64(componentID),
			ScanRunID:   ptrInt64(run.ID),
			UserEmail:   byEmail,
			Reason:      fmt.Sprintf("trigger=%s sha=%s size=%d", trigger, sha[:12], len(body)),
		})
	}
	return run, nil
}

// Run executes the scan synchronously: fetches the SBOM blob, invokes the scanner
// pipeline, persists findings and counters, computes delta. When the scanner is nil
// (Phase 1 wiring), the run is closed with zero findings.
func (s *scanServiceImpl) Run(ctx context.Context, runID int64) error {
	run, err := s.store.GetScanRun(ctx, runID)
	if err != nil {
		return err
	}
	if run.Status != StatusPending {
		return nil // idempotent
	}
	// Mark running.
	if _, err := s.db.ExecContext(ctx,
		`UPDATE scan_runs SET status = 'running' WHERE id = ?`, run.ID); err != nil {
		return err
	}

	body, err := s.blob.GetBlob(ctx, run.SBOMBlobPath)
	if err != nil {
		return s.failRun(ctx, run, fmt.Sprintf("fetch blob: %v", err))
	}
	// Re-verify SHA-256 to catch on-disk tampering between Submit and Run.
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != run.SBOMSHA256 {
		_ = s.store.MarkIntegrityViolated(ctx, run.ID)
		return s.failRun(ctx, run, "sbom integrity violation")
	}

	var result *ScanResult
	if s.scanner != nil {
		result, err = s.scanner.Scan(ctx, run, body)
		if err != nil {
			log.Warn().Err(err).Int64("run_id", run.ID).Msg("scan_service: scanner failure (fail-open)")
			result = &ScanResult{ScannerStatus: map[string]string{"engine": "error: " + err.Error()}}
		}
	} else {
		result = &ScanResult{ScannerStatus: map[string]string{"engine": "noop"}}
	}

	// Apply existing active ignores to the just-collected findings.
	if err := s.applyExistingIgnores(ctx, run, result); err != nil {
		log.Warn().Err(err).Msg("scan_service: applying ignores")
	}

	// Persist findings.
	for _, f := range result.Findings {
		f.ScanRunID = run.ID
		f.ComponentID = run.ComponentID
	}
	if err := s.store.InsertFindings(ctx, result.Findings); err != nil {
		return s.failRun(ctx, run, fmt.Sprintf("insert findings: %v", err))
	}

	// Recompute denormalized severity counts after suppression.
	var crit, high, med, low int64
	for _, f := range result.Findings {
		if f.IsSuppressed {
			continue
		}
		switch f.Severity {
		case SeverityCritical:
			crit++
		case SeverityHigh:
			high++
		case SeverityMedium:
			med++
		case SeverityLow:
			low++
		}
	}

	// Delta vs previous run.
	var newCritical, newHigh int64
	var alerts []model.AuditEntry
	if s.deltaFunc != nil {
		prev, prevErr := s.store.FindPreviousSuccessfulRun(ctx, run.ComponentID, run.ID)
		if prevErr != nil && !errors.Is(prevErr, sql.ErrNoRows) {
			log.Warn().Err(prevErr).Msg("scan_service: previous run lookup")
		}
		if prevErr == nil {
			newCritical, newHigh, alerts, err = s.deltaFunc(ctx, run, prev, result.Findings)
			if err != nil {
				log.Warn().Err(err).Msg("scan_service: delta compute")
			}
		}
	}

	if err := s.store.UpdateScanRunStatus(ctx, run.ID, StatusDone,
		result.ScannerStatus, "",
		crit, high, med, low,
		newCritical, newHigh, result.ComponentCount); err != nil {
		return err
	}
	_ = s.store.SetLastScanID(ctx, run.ComponentID, run.ID)

	// Emit alerts out-of-band.
	if s.audit != nil {
		for _, a := range alerts {
			a.ComponentID = ptrInt64(run.ComponentID)
			a.ScanRunID = ptrInt64(run.ID)
			_ = s.audit.WriteVulnEvent(ctx, a)
		}
	}

	// 3σ anomaly evaluation against the BaselineDays-window baseline. Errors are
	// non-fatal — the run already succeeded and the AI surface is opt-in.
	if s.anomaly != nil {
		if evalErr := s.anomaly.Evaluate(ctx, run.ComponentID, run.ID, crit+high); evalErr != nil {
			log.Warn().Err(evalErr).Int64("run_id", run.ID).Msg("scan_service: anomaly evaluate")
		}
	}
	return nil
}

// failRun transitions the run to failed and writes scan_run_failed audit row.
func (s *scanServiceImpl) failRun(ctx context.Context, run *ScanRun, reason string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE scan_runs SET status = 'failed', finished_at = ?, error_message = ? WHERE id = ?`,
		now, reason, run.ID)
	if s.audit != nil {
		_ = s.audit.WriteVulnEvent(ctx, model.AuditEntry{
			EventType:   model.EventScanRunFailed,
			ComponentID: ptrInt64(run.ComponentID),
			ScanRunID:   ptrInt64(run.ID),
			Reason:      reason,
		})
	}
	return err
}

func (s *scanServiceImpl) applyExistingIgnores(ctx context.Context, run *ScanRun, result *ScanResult) error {
	mapping, err := s.store.FindActiveIgnoresForRun(ctx, run.ID)
	if err != nil {
		return err
	}
	if len(mapping) == 0 || len(result.Findings) == 0 {
		return nil
	}
	for _, f := range result.Findings {
		if id, ok := mapping[f.CVEID+"|"+f.PackageName]; ok {
			f.IsSuppressed = true
			f.SuppressedBy = ptrInt64(id)
		}
	}
	return nil
}

// Get returns a scan run.
func (s *scanServiceImpl) Get(ctx context.Context, runID int64) (*ScanRun, error) {
	return s.store.GetScanRun(ctx, runID)
}

// ListByComponent returns recent runs for a component, optionally paginated
// via a keyset cursor on scan_runs.id (DESC).
func (s *scanServiceImpl) ListByComponent(ctx context.Context, componentID int64, cursor int64, limit int) ([]*ScanRun, error) {
	return s.store.ListScanRunsByComponent(ctx, componentID, cursor, limit)
}

// GetSBOM returns the raw SBOM bytes from BlobStore. Verifies SHA-256 on read.
func (s *scanServiceImpl) GetSBOM(ctx context.Context, runID int64) ([]byte, error) {
	run, err := s.store.GetScanRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	if run.IntegrityViolated {
		return nil, fmt.Errorf("scan_service: sbom integrity violated for run %d", runID)
	}
	body, err := s.blob.GetBlob(ctx, run.SBOMBlobPath)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != run.SBOMSHA256 {
		_ = s.store.MarkIntegrityViolated(ctx, runID)
		return nil, fmt.Errorf("scan_service: sbom integrity violation on download")
	}
	return body, nil
}

// Findings returns all findings for a run.
func (s *scanServiceImpl) Findings(ctx context.Context, runID int64) ([]*ScanFinding, error) {
	return s.store.FindingsByRun(ctx, runID)
}

func ptrInt64(v int64) *int64 { return &v }
