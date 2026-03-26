// cmd/shieldoo-gate/main.go
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/cloudfieldcz/shieldoo-gate/internal/config"
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

	log.Info().Msg("shieldoo-gate starting")

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// TODO: Phase 8 will add multi-port HTTP listeners and full component wiring here

	select {
	case sig := <-sigCh:
		log.Info().Str("signal", sig.String()).Msg("shutting down")
		cancel()
	case <-ctx.Done():
	}

	log.Info().Msg("shieldoo-gate stopped")
}
