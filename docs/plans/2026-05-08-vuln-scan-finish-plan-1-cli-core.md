# Vulnerability Scan — Final Polish — Phase 1: `shdg` CLI core

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a `bin/shdg` binary with `scan` and `version` subcommands. `scan` accepts either `--sbom path.json` (skip generation) or auto-generates a CycloneDX SBOM via a bundled, version-pinned Trivy that the CLI downloads + checksum-verifies on first run. Default behavior is fire-and-forget (returns once the upload returns 202); `--wait` is added in Phase 2.

**Architecture:** Pure Go stdlib — `flag.NewFlagSet` for subcommand dispatch, `net/http` for upload, `archive/tar` + `compress/gzip` for the Trivy tarball. No cobra/urfave. Trivy binaries cached at `~/.cache/shdg/trivy-<version>/trivy` (Linux/macOS) or `%LOCALAPPDATA%\shdg\trivy-<version>\trivy.exe` (Windows). Auth via env: `SHIELDOO_TOKEN` (PAT with `scan:upload` scope or super-token), `SHIELDOO_URL` (base URL like `https://gate.example.com`).

**Tech Stack:** Go 1.25+ stdlib only. No new go.mod dependencies.

**Index:** [`plan-index.md`](./2026-05-08-vuln-scan-finish-plan-index.md)

---

## File map

| Path | Action | Responsibility |
|------|--------|----------------|
| `cmd/shdg/main.go` | Create | Subcommand dispatcher, root flags (`-h`, `--version`), env loader. |
| `cmd/shdg/version.go` | Create | `shdg version` — prints version + commit + Go version. |
| `cmd/shdg/scan.go` | Create | `shdg scan` — orchestrates ecosystem detect → SBOM gen → upload. |
| `cmd/shdg/ecosystem.go` | Create | Detect project type from working dir (Dockerfile, package.json, requirements.txt, pyproject.toml, go.mod). |
| `cmd/shdg/trivy.go` | Create | Pinned-version Trivy auto-download with SHA-256 checksum verification + cache. |
| `cmd/shdg/upload.go` | Create | HTTP POST CycloneDX SBOM to `/api/v1/projects/{label}/components/{name}/scans`. |
| `cmd/shdg/version_test.go` | Create | Unit test version output. |
| `cmd/shdg/ecosystem_test.go` | Create | Unit tests for detection in tmp dirs. |
| `cmd/shdg/trivy_test.go` | Create | Unit tests for cache-path computation, checksum verify (mocked HTTP). |
| `cmd/shdg/upload_test.go` | Create | Unit tests with `httptest.Server` round-trip. |
| `cmd/shdg/scan_test.go` | Create | Integration test wiring detect+upload (mocked Trivy + httptest gate). |
| `Makefile` | Modify | Add `build-shdg` target + add to `build`. |
| `internal/version/version.go` | Verify | Re-use existing version constant if one exists; otherwise inline a `var Version = "dev"` in `cmd/shdg/version.go` set via `-ldflags`. |

**Pinned Trivy version:** `v0.70.0` (latest stable as of 2026-01).

---

## Task 1: Scaffold `cmd/shdg/main.go` with subcommand dispatch

**Files:**
- Create: `cmd/shdg/main.go`

- [ ] **Step 1: Write the file**

```go
// Package main is the shdg CLI — Shieldoo Gate's CI helper for uploading
// CycloneDX SBOMs to the vulnerability scan API.
//
// Subcommands:
//
//   shdg scan      — generate (or re-use) an SBOM and upload it
//   shdg version   — print version info
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

See https://github.com/cloudfieldcz/shieldoo-gate/blob/main/docs/cli/shdg.md`)
}
```

- [ ] **Step 2: Verify build**

Run: `go build ./cmd/shdg`
Expected: PASS (binary not yet runnable end-to-end since `runScan` and `runVersion` are not defined; we'll add them in tasks 2 + 3)

- [ ] **Step 3: Commit (deferred to end of Task 3)**

We'll commit after `version` and `scan` skeletons are in place.

---

## Task 2: Implement `shdg version`

**Files:**
- Create: `cmd/shdg/version.go`
- Create: `cmd/shdg/version_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunVersion_PrintsBuildInfo_ReturnsZero(t *testing.T) {
	var buf bytes.Buffer
	rc := runVersionTo(&buf, nil)
	if rc != 0 {
		t.Fatalf("runVersionTo returned %d, want 0", rc)
	}
	out := buf.String()
	if !strings.Contains(out, "shdg") {
		t.Errorf("output missing 'shdg' marker: %q", out)
	}
	if !strings.Contains(out, "go") {
		t.Errorf("output missing go runtime marker: %q", out)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/shdg/ -run TestRunVersion -v`
Expected: FAIL — `runVersionTo` undefined.

- [ ] **Step 3: Implement `version.go`**

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./cmd/shdg/ -run TestRunVersion -v`
Expected: PASS.

---

## Task 3: Stub `shdg scan` (flags only, no execution yet)

**Files:**
- Create: `cmd/shdg/scan.go`

- [ ] **Step 1: Write the stub**

```go
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

// scanOpts holds parsed CLI flags for the scan subcommand.
type scanOpts struct {
	project    string
	component  string
	sbomPath   string
	ecosystem  string
	dir        string
	verbose    bool

	// Phase 2 additions (populated but unused in Phase 1):
	wait    bool
	failOn  string
	timeout string
}

// parseScanFlags parses argv (without the leading "scan") and returns opts +
// any unconsumed positional args. Returns non-nil error on parse failure.
func parseScanFlags(args []string, errW io.Writer) (scanOpts, error) {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(errW)
	var o scanOpts
	fs.StringVar(&o.project, "project", "", "Project label (required)")
	fs.StringVar(&o.component, "component", "", "Component name (required)")
	fs.StringVar(&o.sbomPath, "sbom", "", "Path to a pre-built CycloneDX JSON SBOM (skips Trivy)")
	fs.StringVar(&o.ecosystem, "ecosystem", "auto", "Ecosystem: auto|pypi|npm|docker|go|multi")
	fs.StringVar(&o.dir, "dir", ".", "Project directory to scan (when --sbom not given)")
	fs.BoolVar(&o.verbose, "verbose", false, "Verbose log output to stderr")
	fs.BoolVar(&o.wait, "wait", false, "Wait for scan to complete (Phase 2)")
	fs.StringVar(&o.failOn, "fail-on", "none", "Exit non-zero on new findings: critical|high|none (Phase 2; requires --wait)")
	fs.StringVar(&o.timeout, "timeout", "10m", "Wait timeout (Phase 2; requires --wait)")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.project == "" || o.component == "" {
		fs.Usage()
		return o, fmt.Errorf("--project and --component are required")
	}
	return o, nil
}

func runScan(args []string) int {
	opts, err := parseScanFlags(args, os.Stderr)
	if err != nil {
		return 2
	}
	_ = opts // wired in tasks 4-7
	fmt.Fprintln(os.Stderr, "shdg: scan not yet implemented (skeleton)")
	return 1
}
```

- [ ] **Step 2: Verify build**

Run: `go build ./cmd/shdg`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add cmd/shdg/
git commit -m "feat(shdg): scaffold CLI with version + scan flag skeleton"
```

---

## Task 4: Ecosystem detection

**Files:**
- Create: `cmd/shdg/ecosystem.go`
- Create: `cmd/shdg/ecosystem_test.go`

Detection priority (first match wins):

1. `Dockerfile` or `Containerfile` → `docker`
2. `go.mod` → `go`
3. `package.json` → `npm`
4. `requirements.txt` or `pyproject.toml` → `pypi`
5. else → `multi`

When `--ecosystem` is explicit (`pypi|npm|docker|go|multi`), skip detection.

- [ ] **Step 1: Write the failing tests**

```go
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDetectEcosystem_Dockerfile_ReturnsDocker(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile")
	got, err := detectEcosystem(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "docker" {
		t.Errorf("got %q, want docker", got)
	}
}

func TestDetectEcosystem_GoMod_ReturnsGo(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "go.mod")
	got, _ := detectEcosystem(dir)
	if got != "go" {
		t.Errorf("got %q, want go", got)
	}
}

func TestDetectEcosystem_PackageJSON_ReturnsNpm(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json")
	got, _ := detectEcosystem(dir)
	if got != "npm" {
		t.Errorf("got %q, want npm", got)
	}
}

func TestDetectEcosystem_RequirementsTxt_ReturnsPypi(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "requirements.txt")
	got, _ := detectEcosystem(dir)
	if got != "pypi" {
		t.Errorf("got %q, want pypi", got)
	}
}

func TestDetectEcosystem_PyprojectToml_ReturnsPypi(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "pyproject.toml")
	got, _ := detectEcosystem(dir)
	if got != "pypi" {
		t.Errorf("got %q, want pypi", got)
	}
}

func TestDetectEcosystem_DockerWinsOverGo(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile")
	writeFile(t, dir, "go.mod")
	got, _ := detectEcosystem(dir)
	if got != "docker" {
		t.Errorf("got %q, want docker (priority order)", got)
	}
}

func TestDetectEcosystem_NothingRecognised_ReturnsMulti(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "README.md")
	got, _ := detectEcosystem(dir)
	if got != "multi" {
		t.Errorf("got %q, want multi (fallback)", got)
	}
}

func TestResolveEcosystem_ExplicitOverridesDetection(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile")
	got, err := resolveEcosystem("npm", dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != "npm" {
		t.Errorf("got %q, want npm (explicit override)", got)
	}
}

func TestResolveEcosystem_InvalidValue_Errors(t *testing.T) {
	if _, err := resolveEcosystem("scala", "."); err == nil {
		t.Errorf("expected error for unsupported ecosystem")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/shdg/ -run Ecosystem -v`
Expected: FAIL — `detectEcosystem`, `resolveEcosystem` undefined.

- [ ] **Step 3: Implement `ecosystem.go`**

```go
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Allowed values mirror the API's `?ecosystem=` query param.
var validEcosystems = map[string]bool{
	"pypi": true, "npm": true, "docker": true, "go": true, "multi": true,
}

// detectEcosystem returns one of {docker,go,npm,pypi,multi} based on the
// presence of well-known marker files in dir. The order encodes precedence.
func detectEcosystem(dir string) (string, error) {
	type marker struct {
		file string
		eco  string
	}
	markers := []marker{
		{"Dockerfile", "docker"},
		{"Containerfile", "docker"},
		{"go.mod", "go"},
		{"package.json", "npm"},
		{"requirements.txt", "pypi"},
		{"pyproject.toml", "pypi"},
	}
	for _, m := range markers {
		if _, err := os.Stat(filepath.Join(dir, m.file)); err == nil {
			return m.eco, nil
		}
	}
	return "multi", nil
}

// resolveEcosystem returns explicit when explicit != "auto", else falls back
// to detection. Errors when explicit is set but invalid.
func resolveEcosystem(explicit, dir string) (string, error) {
	if explicit != "" && explicit != "auto" {
		if !validEcosystems[explicit] {
			return "", fmt.Errorf("unsupported ecosystem %q (allowed: pypi|npm|docker|go|multi|auto)", explicit)
		}
		return explicit, nil
	}
	return detectEcosystem(dir)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/shdg/ -run Ecosystem -v`
Expected: PASS for all 9 test cases.

- [ ] **Step 5: Commit**

```bash
git add cmd/shdg/ecosystem.go cmd/shdg/ecosystem_test.go
git commit -m "feat(shdg): ecosystem auto-detection from project markers"
```

---

## Task 5: Trivy auto-download with checksum verification

**Files:**
- Create: `cmd/shdg/trivy.go`
- Create: `cmd/shdg/trivy_test.go`

Implementation contract:

- Pinned version constant: `const trivyVersion = "0.70.0"`.
- Cache path: on Linux/macOS `~/.cache/shdg/trivy-<v>/trivy`; on Windows `%LOCALAPPDATA%\shdg\trivy-<v>\trivy.exe`. Override via env `SHDG_CACHE_DIR`.
- Platform tarball naming follows upstream releases:
  - `linux/amd64`  → `trivy_<v>_Linux-64bit.tar.gz`
  - `linux/arm64`  → `trivy_<v>_Linux-ARM64.tar.gz`
  - `darwin/amd64` → `trivy_<v>_macOS-64bit.tar.gz`
  - `darwin/arm64` → `trivy_<v>_macOS-ARM64.tar.gz`
  - `windows/amd64` → `trivy_<v>_windows-64bit.zip` (zip handled separately; if windows/amd64 not requested by current platform, the function may return `ErrUnsupportedPlatform` — Phase 1 ships with Linux + macOS support; Windows is a follow-up).
- Download URL pattern: `https://github.com/aquasecurity/trivy/releases/download/v<v>/<asset>`.
- Checksum URL: `https://github.com/aquasecurity/trivy/releases/download/v<v>/trivy_<v>_checksums.txt`. The CLI parses the file (`<sha256>  <asset>` lines) and verifies the downloaded tarball.
- Pinned baseline checksums for v0.70.0 are **also** baked into a small `expectedChecksums` map and compared to the freshly downloaded checksums file as a defense-in-depth pin (per CLAUDE.md security invariant 4 — pinned scanner deps).

> **Source for checksums:** `curl -L https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_checksums.txt` and copy the four Linux/macOS lines into the map. Implementer must paste the actual SHA-256 values.

- [ ] **Step 1: Write the failing tests**

```go
package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTrivyCachePath_HonoursOverride(t *testing.T) {
	t.Setenv("SHDG_CACHE_DIR", "/tmp/shdg-test")
	got := trivyCachePath("0.70.0")
	if !strings.HasPrefix(got, "/tmp/shdg-test/trivy-0.70.0") {
		t.Errorf("path %q missing override prefix", got)
	}
}

func TestParseChecksums_FindsAsset(t *testing.T) {
	raw := `aaaa1111  trivy_0.70.0_Linux-64bit.tar.gz
bbbb2222  trivy_0.70.0_macOS-ARM64.tar.gz`
	got, err := parseChecksums(raw, "trivy_0.70.0_macOS-ARM64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if got != "bbbb2222" {
		t.Errorf("got %q, want bbbb2222", got)
	}
}

func TestParseChecksums_AssetMissing_Errors(t *testing.T) {
	if _, err := parseChecksums("aaaa  other.tar.gz", "trivy_0.70.0_Linux-64bit.tar.gz"); err == nil {
		t.Errorf("expected error for missing asset")
	}
}

func TestVerifySHA256_MatchAndMismatch(t *testing.T) {
	// SHA-256 of "hello\n" = 5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03
	tmp := t.TempDir()
	p := filepath.Join(tmp, "x")
	if err := os.WriteFile(p, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256(p, "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"); err != nil {
		t.Errorf("expected match: %v", err)
	}
	if err := verifySHA256(p, "deadbeef"); err == nil {
		t.Errorf("expected mismatch error")
	}
}

// TestExpectedChecksums_AllPinned is a build-gate. The map MUST contain a
// real 64-char lowercase hex SHA-256 for every supported platform; any
// REPLACE_ME placeholder fails the build, preventing the placeholder from
// silently shipping (security-review requirement).
func TestExpectedChecksums_AllPinned(t *testing.T) {
	required := []string{
		"trivy_0.70.0_Linux-64bit.tar.gz",
		"trivy_0.70.0_Linux-ARM64.tar.gz",
		"trivy_0.70.0_macOS-64bit.tar.gz",
		"trivy_0.70.0_macOS-ARM64.tar.gz",
	}
	for _, asset := range required {
		v, ok := expectedChecksums[asset]
		if !ok {
			t.Errorf("expectedChecksums missing entry for %s", asset)
			continue
		}
		if strings.HasPrefix(v, "REPLACE_ME") {
			t.Errorf("expectedChecksums[%s] is still a placeholder: %q", asset, v)
		}
		if len(v) != 64 {
			t.Errorf("expectedChecksums[%s] is not 64 chars (sha256 hex): len=%d value=%q", asset, len(v), v)
		}
		for _, c := range v {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("expectedChecksums[%s] has non-hex char %q in %q", asset, c, v)
				break
			}
		}
	}
}

// TestExtractTrivyBinary_RejectsSymlink — guard against a crafted tarball
// where the "trivy" entry is a symlink to e.g. /etc/passwd.
func TestExtractTrivyBinary_RejectsSymlink(t *testing.T) {
	tmp := t.TempDir()
	tarPath := filepath.Join(tmp, "evil.tar.gz")
	target := filepath.Join(tmp, "trivy")

	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{Name: "trivy", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink, Size: 0}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()
	f.Close()

	if err := extractTrivyBinary(tarPath, target); err == nil {
		t.Errorf("expected extractTrivyBinary to reject symlink entry")
	}
}

// TestExtractTrivyBinary_RejectsDotDotName — ../trivy must not slip past via filepath.Base.
func TestExtractTrivyBinary_RejectsDotDotName(t *testing.T) {
	tmp := t.TempDir()
	tarPath := filepath.Join(tmp, "evil.tar.gz")
	target := filepath.Join(tmp, "trivy")

	f, _ := os.Create(tarPath)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{Name: "../trivy", Typeflag: tar.TypeReg, Size: 4}
	_ = tw.WriteHeader(hdr)
	_, _ = tw.Write([]byte("fake"))
	tw.Close()
	gz.Close()
	f.Close()

	if err := extractTrivyBinary(tarPath, target); err == nil {
		t.Errorf("expected extractTrivyBinary to reject ../trivy entry")
	}
}

func TestEnsureTrivy_ReusesCachedBinary(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("SHDG_CACHE_DIR", tmp)
	cachePath := trivyCachePath("0.70.0")
	if err := os.MkdirAll(filepath.Dir(cachePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cachePath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("ensureTrivy should not download when binary already cached")
	}))
	defer srv.Close()
	got, err := ensureTrivy("0.70.0", srv.URL)
	if err != nil {
		t.Fatalf("ensureTrivy: %v", err)
	}
	if got != cachePath {
		t.Errorf("got %q, want %q", got, cachePath)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/shdg/ -run "Trivy|Checksums|SHA256" -v`
Expected: FAIL — symbols undefined.

- [ ] **Step 3: Implement `trivy.go`**

```go
package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	// trivyVersion is the pinned Trivy release shdg downloads at first run.
	// Bumping requires updating expectedChecksums below.
	trivyVersion = "0.70.0"

	// defaultTrivyBaseURL is the GitHub releases host. Override via the second
	// arg to ensureTrivy in tests.
	defaultTrivyBaseURL = "https://github.com/aquasecurity/trivy/releases/download"
)

// expectedChecksums pins the SHA-256 of each platform tarball at the
// trivyVersion above. **This is the primary trust anchor** — github.com is
// fetched over TLS but a CA compromise could swap both tarball and the live
// checksums.txt file. The pinned hex below is the only thing that defeats
// that. CLAUDE.md security invariant 4: pinned scanner deps.
//
// IMPLEMENTER: replace the placeholders below with real values from
//   curl -L https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_checksums.txt
//
// A unit test (TestExpectedChecksums_AllPinned) FAILS the build if any value
// is missing or still starts with the placeholder, so the placeholder cannot
// ship to production.
var expectedChecksums = map[string]string{
	"trivy_0.70.0_Linux-64bit.tar.gz": "8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9",
	"trivy_0.70.0_Linux-ARM64.tar.gz": "2f6bb988b553a1bbac6bdd1ce890f5e412439564e17522b88a4541b4f364fc8d",
	"trivy_0.70.0_macOS-64bit.tar.gz": "52d531452b19e7593da29366007d02a810e1e0080d02f9cf6a1afb46c35aaa93",
	"trivy_0.70.0_macOS-ARM64.tar.gz": "68e543c51dcc96e1c344053a4fde9660cf602c25565d9f09dc17dd41e13b838a",
}

// ErrUnsupportedPlatform is returned when shdg runs on a (GOOS, GOARCH) for
// which Trivy publishes no tarball — current Phase 1 covers Linux/macOS amd64+arm64.
var ErrUnsupportedPlatform = errors.New("unsupported platform for bundled Trivy")

// platformAsset returns the tarball name for the current GOOS/GOARCH.
func platformAsset(version string) (string, error) {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "linux/amd64":
		return fmt.Sprintf("trivy_%s_Linux-64bit.tar.gz", version), nil
	case "linux/arm64":
		return fmt.Sprintf("trivy_%s_Linux-ARM64.tar.gz", version), nil
	case "darwin/amd64":
		return fmt.Sprintf("trivy_%s_macOS-64bit.tar.gz", version), nil
	case "darwin/arm64":
		return fmt.Sprintf("trivy_%s_macOS-ARM64.tar.gz", version), nil
	default:
		return "", fmt.Errorf("%w: %s/%s", ErrUnsupportedPlatform, runtime.GOOS, runtime.GOARCH)
	}
}

// trivyCachePath returns the absolute path where the bundled Trivy binary is cached.
func trivyCachePath(version string) string {
	if dir := os.Getenv("SHDG_CACHE_DIR"); dir != "" {
		return filepath.Join(dir, "trivy-"+version, "trivy")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.TempDir()
	}
	return filepath.Join(home, ".cache", "shdg", "trivy-"+version, "trivy")
}

// ensureTrivy returns a path to a runnable Trivy binary, downloading +
// verifying it on first call and re-using the cache on subsequent calls.
func ensureTrivy(version, baseURL string) (string, error) {
	target := trivyCachePath(version)
	if st, err := os.Stat(target); err == nil && st.Mode()&0o111 != 0 {
		return target, nil
	}
	asset, err := platformAsset(version)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return "", fmt.Errorf("mkdir cache: %w", err)
	}

	tarballURL := fmt.Sprintf("%s/v%s/%s", baseURL, version, asset)
	checksumsURL := fmt.Sprintf("%s/v%s/trivy_%s_checksums.txt", baseURL, version, version)

	// 1. Resolve the pinned SHA-256 from expectedChecksums. This is the
	// primary trust anchor — fail closed when missing or placeholder is
	// still in place (defense-in-depth against a build that forgot to fill
	// the pin).
	pinned, ok := expectedChecksums[asset]
	if !ok {
		return "", fmt.Errorf("no pinned checksum for %s — refusing to download", asset)
	}
	if strings.HasPrefix(pinned, "REPLACE_ME") || len(pinned) != 64 {
		return "", fmt.Errorf("pinned checksum for %s is not a real SHA-256 (got %q) — refusing to download", asset, pinned)
	}

	// 2. Fetch the live checksums.txt and confirm it agrees with the pin.
	// The live file is fetched from the same origin as the tarball; on its
	// own it provides no real protection. Pinning catches a compromised
	// origin; the live file mostly catches *upstream republishing* of the
	// same version (which would also be a security concern but a different
	// failure mode).
	checksumsRaw, err := httpGet(checksumsURL)
	if err != nil {
		return "", fmt.Errorf("fetch checksums: %w", err)
	}
	live, err := parseChecksums(string(checksumsRaw), asset)
	if err != nil {
		return "", fmt.Errorf("parse checksums: %w", err)
	}
	if live != pinned {
		return "", fmt.Errorf("checksum drift for %s: pinned=%s live=%s", asset, pinned, live)
	}

	// 2. Download tarball to a temp file next to the cache target.
	tarPath := target + ".tar.gz"
	if err := download(tarballURL, tarPath); err != nil {
		return "", fmt.Errorf("download tarball: %w", err)
	}
	if err := verifySHA256(tarPath, pinned); err != nil {
		_ = os.Remove(tarPath)
		return "", fmt.Errorf("verify tarball: %w", err)
	}

	// 3. Extract just the `trivy` binary.
	if err := extractTrivyBinary(tarPath, target); err != nil {
		return "", fmt.Errorf("extract: %w", err)
	}
	_ = os.Remove(tarPath)
	if err := os.Chmod(target, 0o755); err != nil {
		return "", err
	}
	return target, nil
}

func httpGet(url string) ([]byte, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func download(url, path string) error {
	c := &http.Client{Timeout: 5 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, io.LimitReader(resp.Body, 200<<20))
	return err
}

func parseChecksums(raw, asset string) (string, error) {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[len(fields)-1] == asset {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("asset %q not in checksums file", asset)
}

func verifySHA256(path, want string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != strings.ToLower(want) {
		return fmt.Errorf("sha256 mismatch: got %s want %s", got, want)
	}
	return nil
}

func extractTrivyBinary(tarPath, target string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		// Defense-in-depth — a compromised tarball must not be able to
		// influence the target path or follow a symlink we don't expect:
		//   1. exact-name match (not filepath.Base — `../trivy` would slip)
		//   2. only regular files (no symlinks / hardlinks / devices)
		//   3. no '..' anywhere in the entry name
		//   4. per-entry size cap (50 MiB — Trivy v0.58 binary is ~70 MB
		//      compressed but ~150 MB raw; pick a value above the real binary
		//      and below "abuse"). The outer 200 MiB cap on the on-disk
		//      tarball is independent.
		if h.Name != "trivy" {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return fmt.Errorf("tar entry 'trivy' is not a regular file (typeflag=%d) — refusing", h.Typeflag)
		}
		if strings.Contains(h.Name, "..") {
			return fmt.Errorf("tar entry name contains '..' — refusing")
		}
		const perEntryCap = 200 << 20
		out, err := os.Create(target)
		if err != nil {
			return err
		}
		n, err := io.Copy(out, io.LimitReader(tr, perEntryCap))
		if err != nil {
			out.Close()
			return err
		}
		if n == perEntryCap {
			out.Close()
			return fmt.Errorf("tar entry 'trivy' hit %d-byte cap — refusing potential bomb", perEntryCap)
		}
		return out.Close()
	}
	return errors.New("trivy binary not found in tarball")
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/shdg/ -run "Trivy|Checksums|SHA256" -v`
Expected: PASS for all 5 test cases.

- [ ] **Step 5: Verify the pinned checksums against the live release**

Sanity-check the four hashes already pasted into `expectedChecksums`:

```bash
curl -fsSL https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_checksums.txt \
  | grep -E "Linux-64bit\.tar\.gz|Linux-ARM64\.tar\.gz|macOS-64bit\.tar\.gz|macOS-ARM64\.tar\.gz"
```

Expected (current as of 2026-05-08):

```
8b4376d5d6befe5c24d503f10ff136d9e0c49f9127a4279fd110b727929a5aa9  trivy_0.70.0_Linux-64bit.tar.gz
2f6bb988b553a1bbac6bdd1ce890f5e412439564e17522b88a4541b4f364fc8d  trivy_0.70.0_Linux-ARM64.tar.gz
52d531452b19e7593da29366007d02a810e1e0080d02f9cf6a1afb46c35aaa93  trivy_0.70.0_macOS-64bit.tar.gz
68e543c51dcc96e1c344053a4fde9660cf602c25565d9f09dc17dd41e13b838a  trivy_0.70.0_macOS-ARM64.tar.gz
```

If the live values do not match, do **not** merge — investigate first (republish, supply-chain compromise, or version bump needed).

- [ ] **Step 6: Commit**

```bash
git add cmd/shdg/trivy.go cmd/shdg/trivy_test.go
git commit -m "feat(shdg): bundled Trivy v0.70.0 with SHA-256-pinned auto-download"
```

---

## Task 6: HTTP upload to gate

**Files:**
- Create: `cmd/shdg/upload.go`
- Create: `cmd/shdg/upload_test.go`

- [ ] **Step 1: Write the failing tests**

```go
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUploadSBOM_HappyPath_Returns202(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("method %q want POST", r.Method)
		}
		if r.URL.Path != "/api/v1/projects/myproj/components/web/scans" {
			t.Errorf("path %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer t0k3n" {
			t.Errorf("missing Bearer header")
		}
		if r.Header.Get("Content-Type") != "application/vnd.cyclonedx+json" {
			t.Errorf("wrong content-type")
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "CycloneDX") {
			t.Errorf("body missing SBOM marker")
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"scan_run_id": 42, "component_id": 7})
	}))
	defer srv.Close()
	resp, err := uploadSBOM(srv.URL, "t0k3n", "myproj", "web", "multi",
		strings.NewReader(`{"bomFormat":"CycloneDX","components":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.ScanRunID != 42 {
		t.Errorf("got scan_run_id %d, want 42", resp.ScanRunID)
	}
}

func TestUploadSBOM_5xx_ReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := uploadSBOM(srv.URL, "t", "p", "c", "multi", strings.NewReader("{}")); err == nil {
		t.Errorf("expected error on 5xx")
	}
}

func TestUploadSBOM_ComponentNameInvalid_Returns400(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid component name"}`))
	}))
	defer srv.Close()
	_, err := uploadSBOM(srv.URL, "t", "p", "BAD NAME", "multi", strings.NewReader("{}"))
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Errorf("expected 400 error, got %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/shdg/ -run UploadSBOM -v`
Expected: FAIL — `uploadSBOM` undefined.

- [ ] **Step 3: Implement `upload.go`**

```go
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// UploadResponse mirrors the gate's 202 body.
type UploadResponse struct {
	ScanRunID   int64  `json:"scan_run_id"`
	ComponentID int64  `json:"component_id"`
	DetailURL   string `json:"detail_url"`
}

// uploadSBOM POSTs sbom to /api/v1/projects/{label}/components/{name}/scans?ecosystem=...
// and returns the parsed 202 body. Any non-2xx response is returned as an error
// containing the status code and (best-effort) body excerpt.
func uploadSBOM(baseURL, token, project, component, ecosystem string, sbom io.Reader) (*UploadResponse, error) {
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("baseURL must start with http(s)://: %q", baseURL)
	}
	u := strings.TrimRight(baseURL, "/") +
		fmt.Sprintf("/api/v1/projects/%s/components/%s/scans",
			url.PathEscape(project), url.PathEscape(component))
	if ecosystem != "" {
		u += "?ecosystem=" + url.QueryEscape(ecosystem)
	}
	req, err := http.NewRequest("POST", u, sbom)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/vnd.cyclonedx+json")

	c := &http.Client{Timeout: 60 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("upload failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out UploadResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w (body=%s)", err, string(body))
	}
	return &out, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/shdg/ -run UploadSBOM -v`
Expected: PASS for all 3 test cases.

- [ ] **Step 5: Commit**

```bash
git add cmd/shdg/upload.go cmd/shdg/upload_test.go
git commit -m "feat(shdg): SBOM upload client with bearer auth + ecosystem query"
```

---

## Task 7: Wire `runScan` end-to-end

**Files:**
- Modify: `cmd/shdg/scan.go`
- Create: `cmd/shdg/scan_test.go`

`runScan` flow:

1. Parse flags (already in place).
2. Resolve ecosystem (`--ecosystem auto` → `detectEcosystem(--dir)`).
3. Open SBOM source:
   - If `--sbom path.json`: open the file.
   - Else: ensure Trivy is cached (`ensureTrivy(trivyVersion, defaultTrivyBaseURL)`), invoke it appropriately for the ecosystem (file system scan: `trivy fs --format cyclonedx --quiet --output -`; image scan: `trivy image --format cyclonedx --quiet --output - <ref>` — for `docker` ecosystem the user must pass `--image`, deferred to Phase 2; v1 docker support is via `trivy fs` on the Dockerfile dir), capture stdout.
4. Read `SHIELDOO_TOKEN`, `SHIELDOO_URL` from env. Fail fast with actionable error messages.
5. Call `uploadSBOM(...)`.
6. Print the response as JSON to stdout (so CI can `jq` for `.scan_run_id`).
7. Return 0.

For Phase 1, the `docker` ecosystem branch falls back to `trivy fs --format cyclonedx`. A separate `--image <ref>` flag is **out of scope** here — added in Phase 2 alongside `--wait`.

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunScan_WithSbomFlag_PostsToGate(t *testing.T) {
	tmp := t.TempDir()
	sbomPath := filepath.Join(tmp, "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	got := struct {
		called bool
		auth   string
		eco    string
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.called = true
		got.auth = r.Header.Get("Authorization")
		got.eco = r.URL.Query().Get("ecosystem")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"scan_run_id": 1, "component_id": 1})
	}))
	defer srv.Close()

	t.Setenv("SHIELDOO_URL", srv.URL)
	t.Setenv("SHIELDOO_TOKEN", "tok")

	rc := runScan([]string{
		"--project", "myproj",
		"--component", "web",
		"--sbom", sbomPath,
		"--ecosystem", "pypi",
	})
	if rc != 0 {
		t.Fatalf("rc=%d, want 0", rc)
	}
	if !got.called {
		t.Errorf("gate never called")
	}
	if got.auth != "Bearer tok" {
		t.Errorf("auth=%q", got.auth)
	}
	if got.eco != "pypi" {
		t.Errorf("ecosystem=%q", got.eco)
	}
}

func TestRunScan_NoToken_Returns2(t *testing.T) {
	t.Setenv("SHIELDOO_URL", "http://x")
	t.Setenv("SHIELDOO_TOKEN", "")
	rc := runScan([]string{"--project", "p", "--component", "c", "--sbom", "/dev/null"})
	if rc == 0 {
		t.Errorf("expected non-zero rc")
	}
}

func TestRunScan_MissingFlags_Returns2(t *testing.T) {
	rc := runScan([]string{"--project", "p"}) // missing --component
	if rc != 2 {
		t.Errorf("rc=%d, want 2", rc)
	}
}

func TestRunScan_AutoEcosystem_DetectsAndPasses(t *testing.T) {
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "go.mod"), []byte("module x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sbomPath := filepath.Join(tmp, "sbom.json")
	if err := os.WriteFile(sbomPath, []byte(`{"bomFormat":"CycloneDX","components":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	gotEco := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotEco = r.URL.Query().Get("ecosystem")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"scan_run_id":1,"component_id":1}`))
	}))
	defer srv.Close()
	t.Setenv("SHIELDOO_URL", srv.URL)
	t.Setenv("SHIELDOO_TOKEN", "x")
	rc := runScan([]string{
		"--project", "p", "--component", "c",
		"--sbom", sbomPath, "--dir", tmp, "--ecosystem", "auto",
	})
	if rc != 0 {
		t.Fatalf("rc=%d, output via go test -v", rc)
	}
	if gotEco != "go" {
		t.Errorf("ecosystem=%q, want go (from go.mod)", gotEco)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/shdg/ -run RunScan -v`
Expected: FAIL — current `runScan` returns 1 with "not yet implemented".

- [ ] **Step 3: Implement the body of `runScan` in `scan.go`**

Replace the stub `runScan` with:

```go
func runScan(args []string) int {
	opts, err := parseScanFlags(args, os.Stderr)
	if err != nil {
		return 2
	}
	if err := executeScan(opts, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "shdg: %v\n", err)
		return 1
	}
	return 0
}

func executeScan(opts scanOpts, out, errW io.Writer) error {
	token := os.Getenv("SHIELDOO_TOKEN")
	if token == "" {
		return fmt.Errorf("SHIELDOO_TOKEN env required")
	}
	baseURL := os.Getenv("SHIELDOO_URL")
	if baseURL == "" {
		return fmt.Errorf("SHIELDOO_URL env required (e.g. https://gate.example.com)")
	}

	eco, err := resolveEcosystem(opts.ecosystem, opts.dir)
	if err != nil {
		return err
	}

	var sbom io.Reader
	if opts.sbomPath != "" {
		f, err := os.Open(opts.sbomPath)
		if err != nil {
			return fmt.Errorf("open --sbom: %w", err)
		}
		defer f.Close()
		sbom = f
	} else {
		// Lazily download Trivy and shell out for SBOM generation.
		bin, err := ensureTrivy(trivyVersion, defaultTrivyBaseURL)
		if err != nil {
			return fmt.Errorf("ensure trivy: %w", err)
		}
		if opts.verbose {
			fmt.Fprintf(errW, "shdg: using trivy %s at %s\n", trivyVersion, bin)
		}
		out, err := generateSBOM(bin, opts.dir)
		if err != nil {
			return fmt.Errorf("generate sbom: %w", err)
		}
		sbom = bytes.NewReader(out)
	}

	resp, err := uploadSBOM(baseURL, token, opts.project, opts.component, eco, sbom)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(resp)
}

// generateSBOM shells out to trivy and returns the raw CycloneDX JSON.
func generateSBOM(trivyBin, dir string) ([]byte, error) {
	cmd := exec.Command(trivyBin, "fs",
		"--format", "cyclonedx",
		"--quiet",
		"--output", "-",
		dir,
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy fs: %w (stderr=%s)", err, stderr.String())
	}
	return stdout.Bytes(), nil
}
```

Add the new imports at the top of `scan.go`:

```go
import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/shdg/ -run RunScan -v`
Expected: PASS for all 4 test cases (note: the test that doesn't pass `--sbom` would shell out to Trivy; we only test the `--sbom` path here. The Trivy-based path is exercised in the E2E shell test).

- [ ] **Step 5: Run full Go build + vet**

Run: `go build ./... && go vet ./...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add cmd/shdg/scan.go cmd/shdg/scan_test.go
git commit -m "feat(shdg): wire scan end-to-end (env auth, ecosystem, sbom or trivy)"
```

---

## Task 8: Makefile target

**Files:**
- Modify: `Makefile`

- [ ] **Step 1: Add a `build-shdg` target and include it in `build`**

Apply two edits to `Makefile` — they must both land or neither, otherwise `.PHONY` duplicates.

**Edit 1** — replace the existing `.PHONY` line (line 3):

```diff
-.PHONY: build test test-e2e test-e2e-containerized lint clean proto
+.PHONY: build build-gate build-shdg test test-e2e test-e2e-containerized lint clean proto
```

**Edit 2** — replace the existing `build:` target (lines 13-14):

```diff
-build:
-	go build -o bin/$(BINARY) $(CMD_DIR)
+build: build-gate build-shdg
+
+build-gate:
+	go build -o bin/$(BINARY) $(CMD_DIR)
+
+build-shdg:
+	go build -ldflags "-X main.Version=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev) -X main.Commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)" -o bin/shdg ./cmd/shdg
```

After both edits, `make build` produces `bin/shieldoo-gate` AND `bin/shdg`. `make clean` already wipes `bin/` so no new clean rule is needed.

- [ ] **Step 2: Verify**

Run: `make build`
Expected: produces both `bin/shieldoo-gate` and `bin/shdg`.

Run: `bin/shdg version`
Expected: `shdg <git-describe> (<short-sha>) — go1.25.x linux/amd64` (or your platform).

Run: `bin/shdg scan` (no args)
Expected: usage message on stderr, exit 2.

- [ ] **Step 3: Commit**

```bash
git add Makefile
git commit -m "build(shdg): make build now produces bin/shdg with -ldflags version stamp"
```

---

## Phase 1 verification

- [ ] **Step 1: Re-run all tests**

```bash
go build ./...
go vet ./...
go test ./cmd/shdg/... -v -race
```

Expected: all PASS.

- [ ] **Step 2: Smoke test the binary**

```bash
SHIELDOO_TOKEN=fake-token \
SHIELDOO_URL=http://127.0.0.1:1 \
bin/shdg scan --project p --component c --sbom /dev/null
```

Expected: exits 1 with "upload failed: dial tcp 127.0.0.1:1: connect: connection refused" or similar — confirming it reached the upload step.

- [ ] **Step 3: Update IMPLEMENTATION_STATUS line for Phase 8** (defer to Phase 5 of THIS plan)
