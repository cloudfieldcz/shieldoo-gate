package main

import (
	"context"
	"os"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/alert"
	"github.com/cloudfieldcz/shieldoo-gate/internal/api"
	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/component"
	"github.com/cloudfieldcz/shieldoo-gate/internal/component/ai"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/project"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/manifest"
	manifestosv "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/manifest/osv"
	manifesttrivy "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/manifest/trivy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scheduler"
	"github.com/rs/zerolog/log"
)

// setupVulnScan wires up the vulnerability-scan pipeline: component services, scan
// service, rescan scheduler, retention reaper, ignore expiry watcher, AI surfaces.
// Mutates apiServer in place via SetVulnDeps + SetAIDeps.
func setupVulnScan(ctx context.Context, cfg *config.Config, db *config.GateDB, blobStore cache.BlobStore, projectSvc project.Service, apiServer *api.Server, alerter alert.Alerter, gd *guarddog.GuardDogScanner) {
	_ = projectSvc

	store := component.NewStore(db)
	auditWriter := auth.NewAuditWriter(db).WithAlerter(alerter)

	componentSvc := component.NewService(component.ServiceConfig{
		MaxComponentsPerProject: cfg.VulnScan.MaxComponentsPerProject,
		StaleThreshold:          parseDurationOr(cfg.VulnScan.StaleThreshold, 30*24*time.Hour),
	}, store)

	// Manifest scanner engine.
	scanners := []manifest.ManifestScanner{}
	if cfg.VulnScan.Scanners.OSV.APIURL != "" || cfg.VulnScan.Scanners.OSV.Timeout != "" {
		osvScanner := manifestosv.New(manifestosv.Config{
			APIURL:    cfg.VulnScan.Scanners.OSV.APIURL,
			Timeout:   parseDurationOr(cfg.VulnScan.Scanners.OSV.Timeout, 30*time.Second),
			ChunkSize: cfg.VulnScan.Scanners.OSV.ChunkSize,
			CacheTTL:  parseDurationOr(cfg.VulnScan.Scanners.OSV.CacheTTL, time.Hour),
		})
		scanners = append(scanners, osvScanner)
	}
	if cfg.VulnScan.Scanners.Trivy.BinaryPath != "" {
		trivyScanner := manifesttrivy.New(manifesttrivy.Config{
			BinaryPath: cfg.VulnScan.Scanners.Trivy.BinaryPath,
			Timeout:    parseDurationOr(cfg.VulnScan.Scanners.Trivy.Timeout, 5*time.Minute),
		})
		scanners = append(scanners, trivyScanner)
	}
	engine := manifest.NewEngine(scanners, parseDurationOr(cfg.VulnScan.Rescan.Timeout, 5*time.Minute))
	invoker := &component.ManifestScanInvoker{Engine: engine}

	// AI surfaces (gated by ai_features.enabled). Anomaly detector is wired into the
	// scan service when enabled so that every successful run runs a 3σ check post-commit.
	var anomalyDetector *ai.AnomalyDetector
	var fixPath *ai.FixPathAnalyzer
	var drafter *ai.IgnoreReasonDrafter
	var baselineCache *ai.BaselineCache
	if cfg.AIFeatures.Enabled {
		anomalyDetector = ai.NewAnomalyDetector(ai.AnomalyConfig{
			BaselineDays:       cfg.AIFeatures.AnomalyDetection.BaselineDays,
			MinBaselineSamples: cfg.AIFeatures.AnomalyDetection.MinBaselineSamples,
			SigmaThreshold:     cfg.AIFeatures.AnomalyDetection.SigmaThreshold,
		}, db, auditWriter)
		// Pre-aggregate baselines once a day so per-Evaluate calls become a
		// cache lookup. The cache survives the process; the daily scheduler
		// keeps it fresh.
		baselineCache = ai.NewBaselineCache(25 * time.Hour)
		anomalyDetector = anomalyDetector.WithBaselineCache(baselineCache)
		fixPath = ai.NewFixPathAnalyzer(db)
		drafter = ai.NewIgnoreReasonDrafter(cfg.AIFeatures.IgnoreReasonDrafter.Enabled)
		// Translate the configured per-day token budget into a per-day call
		// ceiling using the configured MaxDraftTokens. Both fall back to safe
		// defaults so a thin config block still gets enforcement.
		dailyTokens := cfg.AIFeatures.IgnoreReasonDrafter.DailyTokenBudget
		if dailyTokens <= 0 {
			dailyTokens = 5_000_000
		}
		maxDraftTokens := cfg.AIFeatures.IgnoreReasonDrafter.MaxDraftTokens
		if maxDraftTokens <= 0 {
			maxDraftTokens = 200
		}
		maxCallsPerDay := int(dailyTokens / int64(maxDraftTokens))
		drafter = drafter.WithTokenBudget(ai.NewTokenBudget(maxCallsPerDay))
		// Reuse the GuardDog scanner-bridge connection (same Unix socket) for
		// the DraftIgnoreReason RPC. Without GuardDog the drafter stays in
		// disabled mode — UI panel hides via 503.
		if gd != nil {
			drafter = drafter.WithBridge(ai.NewBridgeAdapter(gd.BridgeClient()))
			log.Info().Msg("ai drafter wired to scanner-bridge")
		} else {
			log.Info().Msg("ai drafter enabled but scanner-bridge not configured — Draft returns 503")
		}
	}

	// Scan service with delta computation.
	scanDeps := component.ScanServiceDeps{
		DB:        db,
		Store:     store,
		Blob:      blobStore,
		Scanner:   invoker,
		Audit:     auditWriter,
		DeltaFunc: component.DeltaFunc(store),
	}
	if anomalyDetector != nil {
		scanDeps.Anomaly = anomalyEvaluatorAdapter{detector: anomalyDetector}
	}
	// Apply config-provided SBOM caps when set; otherwise withDefaults()
	// inside NewScanService falls back to DefaultSBOMLimits().
	scanCfg := component.ScanServiceConfig{}
	if cfg.VulnScan.MaxSBOMBytes > 0 || cfg.VulnScan.MaxComponents > 0 {
		scanCfg.SBOMLimits = component.DefaultSBOMLimits()
		if cfg.VulnScan.MaxSBOMBytes > 0 {
			scanCfg.SBOMLimits.MaxBytes = cfg.VulnScan.MaxSBOMBytes
		}
		if cfg.VulnScan.MaxComponents > 0 {
			scanCfg.SBOMLimits.MaxComponents = cfg.VulnScan.MaxComponents
		}
	}
	scanSvc := component.NewScanService(scanCfg, scanDeps)

	ignoreSvc := component.NewIgnoreService(component.IgnoreServiceConfig{}, store, auditWriter)

	apiServer.SetVulnDeps(api.VulnDeps{
		Component:    componentSvc,
		ScanService:  scanSvc,
		Ignore:       ignoreSvc,
		Store:        store,
		Audit:        auditWriter,
		MaxSBOMBytes: scanCfg.SBOMLimits.MaxBytes,
	})
	apiServer.SetScanConcurrency(cfg.VulnScan.MaxConcurrentScans)

	// Vuln-scan rate-limit dimensions, added to the base limiter from main.go.
	uploadsPerHour := rateOrDefault(cfg.VulnScan.RateLimit.UploadsPerHour, 60)
	apiServer.RateLimiter().
		WithDimensionLimit("scan-upload", uploadsPerHour, 10).
		WithDimensionLimit("ignore-create-token", 200.0/3600.0, 5).
		WithDimensionLimit("ignore-create-comp", 30.0/3600.0, 3).
		WithDimensionLimit("rescan", 10.0/60.0, 3).
		WithDimensionLimit("ai-draft", 1.0/60.0, 1)

	// Schedulers.
	rescanCfg := scheduler.ManifestRescanConfig{
		Interval:      parseDurationOr(cfg.VulnScan.Rescan.Interval, 6*time.Hour),
		MaxConcurrent: cfg.VulnScan.Rescan.MaxConcurrent,
		Timeout:       parseDurationOr(cfg.VulnScan.Rescan.Timeout, 5*time.Minute),
	}
	rescanScheduler := scheduler.NewManifestRescanScheduler(rescanCfg, db, store, scanSvc)
	rescanScheduler.Start(ctx)

	retentionCfg := scheduler.ScanRunRetentionConfig{
		KeepN:       cfg.VulnScan.Retention.KeepN,
		Interval:    parseDurationOr(cfg.VulnScan.Retention.Interval, time.Hour),
		GracePeriod: parseDurationOr(cfg.VulnScan.Retention.GracePeriod, 5*time.Minute),
	}
	retention := scheduler.NewScanRunRetentionReaper(retentionCfg, db, blobStore)
	retention.Start(ctx)

	expiryWatcher := scheduler.NewIgnoreExpiryWatcher(scheduler.IgnoreExpiryConfig{Interval: time.Hour}, db, ignoreSvc, auditWriter)
	expiryWatcher.Start(ctx)

	orphan := scheduler.NewOrphanBlobSweeper(db, blobStore, "sboms/components/")
	go func() {
		if _, err := orphan.Sweep(ctx); err != nil {
			log.Warn().Err(err).Msg("orphan blob sweeper: startup sweep failed")
		}
	}()

	// Daily baseline pre-aggregation for the 3σ anomaly detector. Skipped
	// when AI is disabled — the cache wouldn't have a consumer.
	if anomalyDetector != nil && baselineCache != nil {
		baselineRecomputer := scheduler.NewBaselineRecomputer(
			scheduler.BaselineRecomputeConfig{Interval: 24 * time.Hour},
			db, anomalyDetector, baselineCache,
		)
		baselineRecomputer.Start(ctx)
	}

	// Register AI deps with the API server (routes off when disabled).
	if cfg.AIFeatures.Enabled {
		apiServer.SetAIDeps(api.AIDeps{
			Enabled: true,
			Anomaly: anomalyDetector,
			FixPath: fixPath,
			Drafter: drafter,
		})
		log.Info().Msg("ai features enabled")
	}

	log.Info().Msg("vuln scan pipeline enabled")
	_ = os.Stdin // silence unused import linter complaints in some build configurations
}

// anomalyEvaluatorAdapter implements component.AnomalyEvaluator over *ai.AnomalyDetector.
// The Detector returns (*Anomaly, error); we drop the result here since the scan
// service only needs the side-effect (anomaly + audit row persisted).
type anomalyEvaluatorAdapter struct {
	detector *ai.AnomalyDetector
}

func (a anomalyEvaluatorAdapter) Evaluate(ctx context.Context, componentID, runID int64, currentCriticalHigh int64) error {
	if a.detector == nil {
		return nil
	}
	_, err := a.detector.Evaluate(ctx, componentID, runID, currentCriticalHigh)
	return err
}

func parseDurationOr(raw string, fallback time.Duration) time.Duration {
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return d
}

func rateOrDefault(perHour int, fallback int) float64 {
	if perHour <= 0 {
		perHour = fallback
	}
	return float64(perHour) / 3600.0
}
