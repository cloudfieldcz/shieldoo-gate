package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// scanOpts holds parsed CLI flags for the scan subcommand.
type scanOpts struct {
	project   string
	component string
	sbomPath  string
	ecosystem string
	dir       string
	verbose   bool

	// Phase 2 additions:
	wait         bool
	failOn       string
	timeout      string
	pollInterval string
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
	fs.BoolVar(&o.wait, "wait", false, "Wait for scan to complete")
	fs.StringVar(&o.failOn, "fail-on", "none", "Exit non-zero on new findings: critical|high|none (requires --wait)")
	fs.StringVar(&o.timeout, "timeout", "10m", "Wait timeout (requires --wait)")
	fs.StringVar(&o.pollInterval, "poll-interval", "2s", "Poll interval when --wait is set")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
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
	return o, nil
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

	eco, err := resolveEcosystem(opts.ecosystem, opts.dir)
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
	if opts.sbomPath != "" {
		f, err := os.Open(opts.sbomPath)
		if err != nil {
			return 1, fmt.Errorf("open --sbom: %w", err)
		}
		defer f.Close()
		sbom = f
	} else {
		// Lazily download Trivy and shell out for SBOM generation.
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
