// Package main is the shdg CLI — Shieldoo Gate's CI helper for uploading
// CycloneDX SBOMs to the vulnerability scan API.
//
// Subcommands:
//
//	shdg scan      — generate (or re-use) an SBOM and upload it
//	shdg version   — print version info
//
// Auth:  SHIELDOO_TOKEN (env, required for scan)
// URL:   SHIELDOO_URL   (env, required for scan; e.g. https://gate.example.com)
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "version", "--version", "-v":
		os.Exit(runVersion(os.Args[2:]))
	case "help", "-h", "--help":
		usage(os.Stdout)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "shdg: unknown subcommand %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, `shdg — Shieldoo Gate vulnerability-scan CLI

USAGE:
  shdg scan     --project <label> --component <name> [--sbom path.json] [--ecosystem auto|pypi|npm|docker|go|multi]
  shdg version
  shdg help

ENVIRONMENT:
  SHIELDOO_TOKEN   PAT with scan:upload scope (or global super-token)
  SHIELDOO_URL     Base URL of the gate (e.g. https://gate.example.com)

See https://github.com/cloudfieldcz/shieldoo-gate/tree/main/docs`)
}
