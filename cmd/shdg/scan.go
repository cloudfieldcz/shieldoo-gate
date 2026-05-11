package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// scanOpts holds parsed CLI flags for the scan subcommand.
type scanOpts struct {
	project   string
	component string
	sbomPath  string
	ecosystem string
	dir       string
	image     string // image reference for `trivy image` scan; mutually exclusive with --sbom/--dir
	verbose   bool

	// Phase 2 additions:
	wait         bool
	failOn       string
	timeout      string
	pollInterval string

	// Set by parseScanFlags via fs.Visit so we can tell user-supplied
	// --dir/--sbom from their default values. Needed for the --image
	// exclusivity check: with --dir defaulting to ".", a naive
	// `opts.dir != ""` test would trip on every --image invocation.
	dirSet  bool
	sbomSet bool
}

// imageIncompatibleEcosystems holds explicit --ecosystem values that
// misrepresent an image-source SBOM in the dashboard. Allowed values
// when --image is set: "" (unset), "auto", "docker", "multi".
var imageIncompatibleEcosystems = map[string]bool{
	"pypi": true, "npm": true, "go": true,
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
	fs.StringVar(&o.dir, "dir", ".", "Project directory to scan (when --sbom and --image not given)")
	fs.StringVar(&o.image, "image", "", "Image reference to scan (e.g. myorg/api:1.4.2); shells out to `trivy image`")
	fs.BoolVar(&o.verbose, "verbose", false, "Verbose log output to stderr")
	fs.BoolVar(&o.wait, "wait", false, "Wait for scan to complete")
	fs.StringVar(&o.failOn, "fail-on", "none", "Exit non-zero on new findings: critical|high|none (requires --wait)")
	fs.StringVar(&o.timeout, "timeout", "10m", "Wait timeout (requires --wait)")
	fs.StringVar(&o.pollInterval, "poll-interval", "2s", "Poll interval when --wait is set")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	// fs.Visit only walks flags the user actually set — distinguishes
	// "user passed --dir" from "default value of --dir". Needed for the
	// --image exclusivity check below.
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "dir":
			o.dirSet = true
		case "sbom":
			o.sbomSet = true
		}
	})
	if o.project == "" || o.component == "" {
		fs.Usage()
		return o, fmt.Errorf("--project and --component are required")
	}
	// Validate --fail-on value first so a typo reports its own error before
	// the wait/fail-on combination check below.
	switch o.failOn {
	case "", "none", "high", "critical":
		// ok
	default:
		fs.Usage()
		return o, fmt.Errorf("--fail-on=%q must be one of: none, high, critical", o.failOn)
	}
	// CI safety: silently ignoring --fail-on without --wait would hide
	// vulnerabilities. Make the misuse loud.
	if !o.wait && o.failOn != "none" && o.failOn != "" {
		fs.Usage()
		return o, fmt.Errorf("--fail-on=%s requires --wait", o.failOn)
	}
	// --image validation and exclusivity. Done after the required-flag
	// check so a user with both missing required flags AND a bad --image
	// sees the required-flag error first.
	if o.image != "" || imageFlagPresent(fs) {
		if err := validateImageRef(o.image); err != nil {
			fs.Usage()
			return o, err
		}
		if o.sbomSet {
			fs.Usage()
			return o, fmt.Errorf("--image and --sbom are mutually exclusive — pick one source")
		}
		if o.dirSet {
			fs.Usage()
			return o, fmt.Errorf("--image and --dir are mutually exclusive — --dir is meaningless for an image scan")
		}
		if imageIncompatibleEcosystems[o.ecosystem] {
			fs.Usage()
			return o, fmt.Errorf("--ecosystem=%s misrepresents an image SBOM in the dashboard; with --image use auto, docker, or multi", o.ecosystem)
		}
	}
	return o, nil
}

// imageFlagPresent returns true when --image was supplied on the command
// line, even if the value is empty (so `--image ""` reaches the syntactic
// guard below instead of falling through silently).
func imageFlagPresent(fs *flag.FlagSet) bool {
	seen := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "image" {
			seen = true
		}
	})
	return seen
}

// validateImageRef catches the small set of inputs that would either be
// parsed as a flag by Trivy (leading dash) or break the subprocess
// boundary (NUL, newline). Real OCI-reference grammar validation is left
// to Trivy itself — a Go-side regex would either be too strict
// (rejecting valid tags) or too loose (no protection added).
func validateImageRef(ref string) error {
	if ref == "" {
		return fmt.Errorf("--image value is empty")
	}
	if strings.HasPrefix(ref, "-") {
		return fmt.Errorf("--image value %q starts with '-'; would be parsed as a trivy flag", ref)
	}
	if strings.ContainsAny(ref, "\x00\n\r") {
		return fmt.Errorf("--image value contains a NUL or newline character")
	}
	return nil
}

func runScan(args []string) int {
	opts, err := parseScanFlags(args, os.Stderr)
	if err != nil {
		return 2
	}
	rc, err := executeScan(opts, os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shdg: %v\n", err)
		if rc != 0 {
			return rc
		}
		return 1
	}
	return rc
}

func executeScan(opts scanOpts, out, errW io.Writer) (int, error) {
	token := os.Getenv("SHIELDOO_TOKEN")
	if token == "" {
		return 2, fmt.Errorf("SHIELDOO_TOKEN env required")
	}
	baseURL := os.Getenv("SHIELDOO_URL")
	if baseURL == "" {
		return 2, fmt.Errorf("SHIELDOO_URL env required (e.g. https://gate.example.com)")
	}

	eco, err := resolveEcosystem(opts.ecosystem, opts.dir, opts.image != "")
	if err != nil {
		return 2, err
	}

	// Validate wait-related durations up-front so bad input fails fast,
	// before we shell out to Trivy or POST the SBOM.
	var (
		timeout  time.Duration
		interval time.Duration
	)
	if opts.wait {
		timeout, err = time.ParseDuration(opts.timeout)
		if err != nil {
			return 2, fmt.Errorf("invalid --timeout: %w", err)
		}
		interval, err = time.ParseDuration(opts.pollInterval)
		if err != nil {
			return 2, fmt.Errorf("invalid --poll-interval: %w", err)
		}
	}

	var sbom io.Reader
	switch {
	case opts.sbomPath != "":
		f, err := os.Open(opts.sbomPath)
		if err != nil {
			return 1, fmt.Errorf("open --sbom: %w", err)
		}
		defer f.Close()
		sbom = f
	case opts.image != "":
		// Lazily download Trivy and shell out to `trivy image <ref>`.
		bin, err := ensureTrivy(trivyVersion, defaultTrivyBaseURL)
		if err != nil {
			return 1, fmt.Errorf("ensure trivy: %w", err)
		}
		if opts.verbose {
			fmt.Fprintf(errW, "shdg: using trivy %s at %s\n", trivyVersion, bin)
			fmt.Fprintf(errW, "shdg: trivy image %s (registry pull may take minutes)\n", opts.image)
		}
		sbomBytes, err := generateImageSBOM(bin, opts.image)
		if err != nil {
			return 1, fmt.Errorf("generate sbom: %w", err)
		}
		sbom = bytes.NewReader(sbomBytes)
	default:
		// Lazily download Trivy and shell out to `trivy fs <dir>`.
		bin, err := ensureTrivy(trivyVersion, defaultTrivyBaseURL)
		if err != nil {
			return 1, fmt.Errorf("ensure trivy: %w", err)
		}
		if opts.verbose {
			fmt.Fprintf(errW, "shdg: using trivy %s at %s\n", trivyVersion, bin)
		}
		sbomBytes, err := generateSBOM(bin, opts.dir)
		if err != nil {
			return 1, fmt.Errorf("generate sbom: %w", err)
		}
		sbom = bytes.NewReader(sbomBytes)
	}

	resp, err := uploadSBOM(baseURL, token, opts.project, opts.component, eco, sbom)
	if err != nil {
		return 1, err
	}

	if !opts.wait {
		return 0, json.NewEncoder(out).Encode(resp)
	}

	st, err := pollUntilTerminal(baseURL, token, resp.ScanRunID, interval, timeout)
	if err != nil {
		_ = json.NewEncoder(out).Encode(map[string]any{"scan_run_id": resp.ScanRunID, "status": st.Status, "error": err.Error()})
		return 4, err
	}
	_ = json.NewEncoder(out).Encode(st)
	return exitCodeFor(st, opts.failOn), nil
}

// generateSBOM shells out to trivy and returns the raw CycloneDX JSON.
//
// Trivy 0.70.0's `fs --format cyclonedx --output -` produces an empty stdout
// (silent regression: stdout writes are dropped when --format=cyclonedx is
// combined with `-`). To stay robust across Trivy versions, write to a
// tempfile and read it back. The empty-output check below also catches any
// future quirk where Trivy succeeds (rc=0) but emits nothing — that would
// have surfaced in the gate as `422: empty body`, which is a poor CI signal.
func generateSBOM(trivyBin, dir string) ([]byte, error) {
	tmp, err := os.CreateTemp("", "shdg-sbom-*.json")
	if err != nil {
		return nil, fmt.Errorf("create tempfile: %w", err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	cmd := exec.Command(trivyBin, "fs",
		"--format", "cyclonedx",
		"--quiet",
		"--output", tmpPath,
		dir,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy fs: %w (stderr=%s)", err, stderr.String())
	}
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("read trivy output: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("trivy produced empty SBOM for dir=%s (stderr=%s)", dir, stderr.String())
	}
	return data, nil
}

// generateImageSBOM shells out to `trivy image <ref>` and returns the
// raw CycloneDX JSON. Mirrors generateSBOM's tempfile-then-read pattern
// (Trivy 0.70.0's `--output -` quirk affects image as it does fs) and
// the empty-output guard (a future Trivy regression that exits 0 without
// writing must not silently upload an empty body).
//
// imageRef is forwarded verbatim as a separate argv slot — exec.Command
// does not invoke a shell, so there is no injection vector. The syntactic
// validation in validateImageRef catches the leading-dash case at parse
// time; here we only rely on argv-not-shell.
func generateImageSBOM(trivyBin, imageRef string) ([]byte, error) {
	tmp, err := os.CreateTemp("", "shdg-sbom-*.json")
	if err != nil {
		return nil, fmt.Errorf("create tempfile: %w", err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	cmd := exec.Command(trivyBin, "image",
		"--format", "cyclonedx",
		"--quiet",
		"--output", tmpPath,
		imageRef,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("trivy image: %w (stderr=%s)", err, stderr.String())
	}
	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("read trivy output: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("trivy produced empty SBOM for image=%s (stderr=%s)", imageRef, stderr.String())
	}
	return data, nil
}
