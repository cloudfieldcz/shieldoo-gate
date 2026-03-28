package main

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Configure zerolog for console output.
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	log.Info().Msg("Hello from Shieldoo Gate Go example!")
	log.Info().Str("library", "zerolog").Str("version", "v1.33.0").Msg("Dependency loaded successfully")
	log.Warn().Msg("This is a sample warning message")
	log.Info().Msg("Done!")
}
