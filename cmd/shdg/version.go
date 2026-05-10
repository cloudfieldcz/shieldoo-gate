package main

import (
	"fmt"
	"io"
	"os"
	"runtime"
)

// Version is set at build time via -ldflags "-X main.Version=v1.x.y".
// Defaults to "dev" for unstamped local builds.
var Version = "dev"

// Commit is the short git SHA, set via -ldflags "-X main.Commit=abc1234".
var Commit = "unknown"

func runVersion(args []string) int {
	return runVersionTo(os.Stdout, args)
}

func runVersionTo(w io.Writer, _ []string) int {
	fmt.Fprintf(w, "shdg %s (%s) — %s %s/%s\n",
		Version, Commit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return 0
}
