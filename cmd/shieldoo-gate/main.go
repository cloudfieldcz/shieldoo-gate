// cmd/shieldoo-gate/main.go
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/npm"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/nuget"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/pypi"
	"github.com/cloudfieldcz/shieldoo-gate/internal/api"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/builtin"
	guarddog "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog"
	osvscanner "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/osv"
	trivyscanner "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/trivy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/threatfeed"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to configuration file")
	flag.Parse()

	// Load config
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	if err := cfg.Validate(); err != nil {
		log.Fatal().Err(err).Msg("invalid config")
	}

	// Setup logger
	level, err := zerolog.ParseLevel(cfg.Log.Level)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	if cfg.Log.Format == "text" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	}

	// Init database
	db, err := config.InitDB(cfg.Database.SQLite.Path)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize database")
	}
	defer db.Close()

	// Init local cache store
	cacheStore, err := local.NewLocalCacheStore(cfg.Cache.Local.Path, cfg.Cache.Local.MaxSizeGB)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize cache store")
	}

	// Init scanners: 6 built-in scanners
	scanners := []scanner.Scanner{
		builtin.NewHashVerifier(),
		builtin.NewInstallHookAnalyzer(),
		builtin.NewObfuscationDetector(),
		builtin.NewExfilDetector(),
		builtin.NewPTHInspector(),
		builtin.NewThreatFeedChecker(db),
	}

	// Optional: GuardDog scanner
	if cfg.Scanners.GuardDog.Enabled {
		gd, err := guarddog.NewGuardDogScanner(cfg.Scanners.GuardDog.BridgeSocket)
		if err != nil {
			log.Warn().Err(err).Msg("guarddog scanner disabled: failed to init")
		} else {
			scanners = append(scanners, gd)
			log.Info().Str("socket", cfg.Scanners.GuardDog.BridgeSocket).Msg("guarddog scanner enabled")
		}
	}

	// Optional: Trivy scanner
	if cfg.Scanners.Trivy.Enabled {
		timeout := parseDuration(cfg.Scanners.Timeout, 30*time.Second)
		trivy := trivyscanner.NewTrivyScanner(cfg.Scanners.Trivy.Binary, cfg.Scanners.Trivy.CacheDir, timeout)
		scanners = append(scanners, trivy)
		log.Info().Str("binary", cfg.Scanners.Trivy.Binary).Msg("trivy scanner enabled")
	}

	// Optional: OSV scanner
	if cfg.Scanners.OSV.Enabled {
		timeout := parseDuration(cfg.Scanners.Timeout, 30*time.Second)
		apiURL := cfg.Scanners.OSV.APIURL
		if apiURL == "" {
			apiURL = "https://api.osv.dev"
		}
		osv := osvscanner.NewOSVScanner(apiURL, timeout)
		scanners = append(scanners, osv)
		log.Info().Str("api_url", apiURL).Msg("osv scanner enabled")
	}

	// Init scanner engine
	scanTimeout := parseDuration(cfg.Scanners.Timeout, 30*time.Second)
	scanEngine := scanner.NewEngine(scanners, scanTimeout)
	log.Info().Int("scanner_count", len(scanners)).Msg("scanner engine initialized")

	// Init policy engine from config
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.Verdict(cfg.Policy.BlockIfVerdict),
		QuarantineIfVerdict: scanner.Verdict(cfg.Policy.QuarantineIfVerdict),
		MinimumConfidence:   cfg.Policy.MinimumConfidence,
		Allowlist:           cfg.Policy.Allowlist,
	}, db)

	// Init threat feed client with periodic refresh (if enabled)
	if cfg.ThreatFeed.Enabled && cfg.ThreatFeed.URL != "" {
		feedClient := threatfeed.NewClient(db, cfg.ThreatFeed.URL)
		refreshInterval := parseDuration(cfg.ThreatFeed.RefreshInterval, 1*time.Hour)

		// Initial refresh in background; errors are logged, not fatal
		go func() {
			ctx := context.Background()
			if err := feedClient.Refresh(ctx); err != nil {
				log.Warn().Err(err).Msg("threat feed initial refresh failed")
			} else {
				log.Info().Msg("threat feed initial refresh completed")
			}

			ticker := time.NewTicker(refreshInterval)
			defer ticker.Stop()
			for range ticker.C {
				if err := feedClient.Refresh(ctx); err != nil {
					log.Warn().Err(err).Msg("threat feed periodic refresh failed")
				} else {
					log.Info().Msg("threat feed periodic refresh completed")
				}
			}
		}()
		log.Info().Str("url", cfg.ThreatFeed.URL).Dur("interval", refreshInterval).Msg("threat feed client started")
	}

	// Resolve upstream URLs with sensible defaults
	pypiUpstream := fallback(cfg.Upstreams.PyPI, "https://pypi.org")
	npmUpstream := fallback(cfg.Upstreams.NPM, "https://registry.npmjs.org")
	nugetUpstream := fallback(cfg.Upstreams.NuGet, "https://api.nuget.org")
	dockerUpstream := fallback(cfg.Upstreams.Docker, "https://registry-1.docker.io")

	// Init all 4 adapters
	pypiAdapter := pypi.NewPyPIAdapter(db, cacheStore, scanEngine, policyEngine, pypiUpstream)
	npmAdapter := npm.NewNPMAdapter(db, cacheStore, scanEngine, policyEngine, npmUpstream)
	nugetAdapter := nuget.NewNuGetAdapter(db, cacheStore, scanEngine, policyEngine, nugetUpstream)
	dockerAdapter := docker.NewDockerAdapter(db, cacheStore, scanEngine, policyEngine, dockerUpstream)

	// Init admin API server
	apiServer := api.NewServer(db, cacheStore, scanEngine, policyEngine)

	host := cfg.Server.Host
	if host == "" {
		host = "0.0.0.0"
	}

	// Build HTTP servers
	servers := []struct {
		name    string
		port    int
		handler http.Handler
	}{
		{"pypi", cfg.Ports.PyPI, pypiAdapter},
		{"npm", cfg.Ports.NPM, npmAdapter},
		{"nuget", cfg.Ports.NuGet, nugetAdapter},
		{"docker", cfg.Ports.Docker, dockerAdapter},
		{"admin", cfg.Ports.Admin, apiServer.Routes()},
	}

	log.Info().Msg("shieldoo-gate starting")

	// Graceful shutdown context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start 5 HTTP servers using errgroup
	g, gctx := errgroup.WithContext(ctx)

	httpServers := make([]*http.Server, len(servers))
	for i, s := range servers {
		i, s := i, s
		addr := fmt.Sprintf("%s:%d", host, s.port)
		srv := &http.Server{
			Addr:              addr,
			Handler:           s.handler,
			ReadHeaderTimeout: 30 * time.Second,
		}
		httpServers[i] = srv

		g.Go(func() error {
			log.Info().Str("service", s.name).Str("addr", addr).Msg("listening")
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				return fmt.Errorf("%s listener: %w", s.name, err)
			}
			return nil
		})
	}

	// Wait for shutdown signal
	go func() {
		select {
		case sig := <-sigCh:
			log.Info().Str("signal", sig.String()).Msg("shutdown signal received")
		case <-gctx.Done():
		}

		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()

		for _, srv := range httpServers {
			if err := srv.Shutdown(shutdownCtx); err != nil {
				log.Warn().Err(err).Str("addr", srv.Addr).Msg("error during server shutdown")
			}
		}
	}()

	if err := g.Wait(); err != nil {
		log.Error().Err(err).Msg("server error")
	}

	log.Info().Msg("shieldoo-gate stopped")
}

// parseDuration parses a duration string, returning the fallback on error.
func parseDuration(s string, fallbackDur time.Duration) time.Duration {
	if s == "" {
		return fallbackDur
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallbackDur
	}
	return d
}

// fallback returns val if non-empty, otherwise defaultVal.
func fallback(val, defaultVal string) string {
	if val != "" {
		return val
	}
	return defaultVal
}
