package main

// Version is set at build time via -ldflags "-X main.Version=v1.x.y".
// Defaults to "dev" for unstamped local builds. Used by the SBOM generator
// to stamp metadata.tools.components[].version on every per-project SBOM.
var Version = "dev"
