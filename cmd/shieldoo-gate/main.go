// cmd/shieldoo-gate/main.go
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/docker"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/gomod"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/maven"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/npm"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/nuget"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/pypi"
	"github.com/cloudfieldcz/shieldoo-gate/internal/adapter/rubygems"
	"github.com/cloudfieldcz/shieldoo-gate/internal/alert"
	"github.com/cloudfieldcz/shieldoo-gate/internal/api"
	"github.com/cloudfieldcz/shieldoo-gate/internal/auth"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache"
	"github.com/cloudfieldcz/shieldoo-gate/internal/cache/local"
	azureblobcache "github.com/cloudfieldcz/shieldoo-gate/internal/cache/azureblob"
	gcscache "github.com/cloudfieldcz/shieldoo-gate/internal/cache/gcs"
	s3cache "github.com/cloudfieldcz/shieldoo-gate/internal/cache/s3"
	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
	"github.com/cloudfieldcz/shieldoo-gate/internal/model"
	"github.com/cloudfieldcz/shieldoo-gate/internal/policy"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scheduler"
	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/builtin"
	aiscanner "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/ai"
	guarddog "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog"
	osvscanner "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/osv"
	sandboxscanner "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/sandbox"
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

	var logWriter io.Writer = os.Stderr
	if cfg.Log.File != "" {
		f, err := os.OpenFile(cfg.Log.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			log.Fatal().Err(err).Str("path", cfg.Log.File).Msg("failed to open log file")
		}
		defer f.Close()
		logWriter = io.MultiWriter(os.Stderr, f)
	}
	if cfg.Log.Format == "text" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: logWriter})
	} else {
		log.Logger = log.Output(logWriter)
	}

	// Init database
	db, err := config.InitDB(cfg.Database)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize database")
	}
	defer db.Close()

	// Init cache store
	var cacheStore cache.CacheStore
	switch cfg.Cache.Backend {
	case "s3":
		cacheStore, err = s3cache.NewS3CacheStore(cfg.Cache.S3)
	case "azure_blob":
		cacheStore, err = azureblobcache.NewAzureBlobStore(cfg.Cache.AzureBlob)
	case "gcs":
		cacheStore, err = gcscache.NewGCSCacheStore(cfg.Cache.GCS)
	case "local", "":
		cacheStore, err = local.NewLocalCacheStore(cfg.Cache.Local.Path, cfg.Cache.Local.MaxSizeGB)
	default:
		err = fmt.Errorf("unknown cache backend: %s", cfg.Cache.Backend)
	}
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

	// Optional: AI scanner (LLM-based, synchronous)
	if cfg.Scanners.AI.Enabled {
		aiCfg := aiscanner.AIConfig{
			Enabled:  true,
			Timeout:  parseDuration(cfg.Scanners.AI.Timeout, 15*time.Second),
			Socket:   cfg.Scanners.AI.BridgeSocket,
			Provider: cfg.Scanners.AI.Provider,
			Model:    cfg.Scanners.AI.Model,
		}
		if aiCfg.Socket == "" {
			aiCfg.Socket = cfg.Scanners.GuardDog.BridgeSocket // reuse same bridge socket
		}
		ai, err := aiscanner.NewAIScanner(aiCfg)
		if err != nil {
			log.Warn().Err(err).Msg("ai scanner disabled: failed to init")
		} else {
			scanners = append(scanners, ai)
			log.Info().Str("model", cfg.Scanners.AI.Model).Str("provider", cfg.Scanners.AI.Provider).Msg("ai scanner enabled")
		}
	}

	// Init scanner engine
	scanTimeout := parseDuration(cfg.Scanners.Timeout, 30*time.Second)
	scanEngine := scanner.NewEngine(scanners, scanTimeout)
	log.Info().Int("scanner_count", len(scanners)).Msg("scanner engine initialized")

	// Optional: Sandbox scanner (async, runs outside the synchronous scan path)
	var sandboxScanner *sandboxscanner.SandboxScanner
	if cfg.Scanners.Sandbox.Enabled {
		sbCfg := sandboxscanner.SandboxConfig{
			Enabled:       cfg.Scanners.Sandbox.Enabled,
			RuntimeBinary: cfg.Scanners.Sandbox.RuntimeBinary,
			Timeout:       cfg.Scanners.Sandbox.Timeout,
			NetworkPolicy: cfg.Scanners.Sandbox.NetworkPolicy,
			MaxConcurrent: cfg.Scanners.Sandbox.MaxConcurrent,
		}
		sb, sbErr := sandboxscanner.NewSandboxScanner(sbCfg)
		if sbErr != nil {
			log.Warn().Err(sbErr).Msg("sandbox scanner unavailable, continuing without it")
		} else {
			sandboxScanner = sb
			sandboxScanner.CleanupOrphans()
			log.Info().Str("runtime", cfg.Scanners.Sandbox.RuntimeBinary).Msg("sandbox scanner enabled (async)")
		}
	}
	if sandboxScanner != nil {
		adapter.SetAsyncScanner(sandboxScanner)
	}

	// Init policy engine from config
	policyEngine := policy.NewEngine(policy.EngineConfig{
		BlockIfVerdict:      scanner.Verdict(cfg.Policy.BlockIfVerdict),
		QuarantineIfVerdict: scanner.Verdict(cfg.Policy.QuarantineIfVerdict),
		MinimumConfidence:   cfg.Policy.MinimumConfidence,
		Allowlist:           cfg.Policy.Allowlist,
	}, db)

	// Init alerter from config.
	var alerterInstance alert.Alerter
	if cfg.Alerts.Webhook.Enabled || cfg.Alerts.Slack.Enabled || cfg.Alerts.Email.Enabled {
		var workers []alert.ChannelConfig
		if cfg.Alerts.Webhook.Enabled {
			secret := []byte(os.Getenv(cfg.Alerts.Webhook.SecretEnv))
			sender := alert.NewWebhookSender(cfg.Alerts.Webhook.URL, secret)
			var eventFilter []model.EventType
			for _, ev := range cfg.Alerts.Webhook.On {
				eventFilter = append(eventFilter, model.EventType(ev))
			}
			workers = append(workers, alert.ChannelConfig{
				Channel:     sender,
				EventFilter: eventFilter,
			})
		}
		// Slack and Email senders will be added in later tasks.
		alerterInstance = alert.NewMultiAlerter(workers)
	} else {
		alerterInstance = alert.NewMultiAlerter(nil) // no-op alerter
	}
	adapter.SetAlerter(alerterInstance)
	defer func() {
		if err := alerterInstance.Close(); err != nil {
			log.Error().Err(err).Msg("alerter shutdown error")
		}
	}()

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
	mavenUpstream := fallback(cfg.Upstreams.Maven, "https://repo1.maven.org/maven2")
	rubygemsUpstream := fallback(cfg.Upstreams.RubyGems, "https://rubygems.org")
	gomodUpstream := fallback(cfg.Upstreams.GoMod, "https://proxy.golang.org")
	// Init all 7 adapters
	tagMutCfg := cfg.Policy.TagMutability
	pypiAdapter := pypi.NewPyPIAdapter(db, cacheStore, scanEngine, policyEngine, pypiUpstream, tagMutCfg)
	npmAdapter := npm.NewNPMAdapter(db, cacheStore, scanEngine, policyEngine, npmUpstream, tagMutCfg)
	nugetAdapter := nuget.NewNuGetAdapter(db, cacheStore, scanEngine, policyEngine, nugetUpstream, tagMutCfg)
	dockerAdapter := docker.NewDockerAdapter(db, cacheStore, scanEngine, policyEngine, cfg.Upstreams.Docker)
	mavenAdapter := maven.NewMavenAdapter(db, cacheStore, scanEngine, policyEngine, mavenUpstream)
	rubygemsAdapter := rubygems.NewRubyGemsAdapter(db, cacheStore, scanEngine, policyEngine, rubygemsUpstream)
	gomodAdapter := gomod.NewGoModAdapter(db, cacheStore, scanEngine, policyEngine, gomodUpstream)

	// Init admin API server
	apiServer := api.NewServer(db, cacheStore, scanEngine, policyEngine)
	apiServer.SetDockerConfig(cfg.Upstreams.Docker)
	apiServer.SetPublicURLs(cfg.PublicURLs)

	// Init OIDC authentication (if enabled).
	if cfg.Auth.Enabled {
		authCfg := auth.AuthConfig{
			Enabled:         true,
			IssuerURL:       cfg.Auth.IssuerURL,
			ClientID:        cfg.Auth.ClientID,
			ClientSecretEnv: cfg.Auth.ClientSecretEnv,
			RedirectURL:     cfg.Auth.RedirectURL,
			Scopes:          cfg.Auth.Scopes,
		}
		oidcMw, err := auth.NewOIDCMiddleware(context.Background(), cfg.Auth.IssuerURL, cfg.Auth.ClientID)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to initialize OIDC middleware")
		}
		authHandlers, err := auth.NewAuthHandlers(authCfg)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to initialize auth handlers")
		}
		apiServer.SetAuth(oidcMw, authHandlers)
		log.Info().Str("issuer", cfg.Auth.IssuerURL).Msg("OIDC authentication enabled for admin API")
	} else {
		log.Warn().Msg("Admin API is UNAUTHENTICATED. Set auth.enabled=true for production.")
	}

	// Init proxy auth middleware (if enabled).
	var apiKeyMw *auth.APIKeyMiddleware
	if cfg.ProxyAuth.Enabled {
		globalToken := ""
		if cfg.ProxyAuth.GlobalTokenEnv != "" {
			globalToken = os.Getenv(cfg.ProxyAuth.GlobalTokenEnv)
		}
		apiKeyMw = auth.NewAPIKeyMiddleware(db, globalToken)
		log.Info().Msg("proxy API key authentication enabled")
	}
	// SetProxyAuth on apiServer so it can conditionally register API key management endpoints.
	apiServer.SetProxyAuth(cfg.ProxyAuth.Enabled, cfg.Auth.Enabled)

	host := cfg.Server.Host
	if host == "" {
		host = "0.0.0.0"
	}

	// wrapProxy applies the API key middleware to a handler if proxy auth is enabled.
	wrapProxy := func(h http.Handler) http.Handler {
		if apiKeyMw != nil {
			return apiKeyMw.Authenticate(h)
		}
		return h
	}

	// Build HTTP servers
	servers := []struct {
		name    string
		port    int
		handler http.Handler
	}{
		{"pypi", cfg.Ports.PyPI, wrapProxy(pypiAdapter)},
		{"npm", cfg.Ports.NPM, wrapProxy(npmAdapter)},
		{"nuget", cfg.Ports.NuGet, wrapProxy(nugetAdapter)},
		{"docker", cfg.Ports.Docker, wrapProxy(dockerAdapter)},
		{"maven", cfg.Ports.Maven, wrapProxy(mavenAdapter)},
		{"rubygems", cfg.Ports.RubyGems, wrapProxy(rubygemsAdapter)},
		{"gomod", cfg.Ports.GoMod, wrapProxy(gomodAdapter)},
		{"admin", cfg.Ports.Admin, apiServer.Routes()},
	}

	log.Info().Msg("shieldoo-gate starting")

	// Graceful shutdown context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start Docker sync service (if enabled). Uses ctx for graceful shutdown.
	if cfg.Upstreams.Docker.Sync.Enabled {
		resolver := docker.NewRegistryResolver(cfg.Upstreams.Docker)
		syncSvc := docker.NewSyncService(db, cacheStore, scanEngine, policyEngine, resolver, cfg.Upstreams.Docker.Sync)
		apiServer.SetSyncService(syncSvc)
		go syncSvc.Start(ctx)
		log.Info().Msg("docker sync service enabled")
	}

	// Start rescan scheduler (if enabled).
	if cfg.Rescan.Enabled {
		rescanScheduler := scheduler.NewRescanScheduler(db, cacheStore, scanEngine, policyEngine, cfg.Rescan)
		rescanScheduler.Start()
		defer rescanScheduler.Stop()
		apiServer.SetRescanNotifier(rescanScheduler.Notify)
		log.Info().Msg("rescan scheduler enabled")
	}

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

	// Flush pending last_used_at updates before exit.
	if apiKeyMw != nil {
		apiKeyMw.Stop()
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
