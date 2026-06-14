// Package trivy implements a ManifestScanner that consumes a CycloneDX SBOM via
// `trivy sbom --format json <file>` (Trivy's first-class SBOM-consumer mode).
package trivy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner/manifest"
)

// TrivyManifestScanner shells out to the trivy binary in `sbom` mode.
type TrivyManifestScanner struct {
	binaryPath string
	timeout    time.Duration
}

// Config holds runtime configuration.
type Config struct {
	BinaryPath string
	Timeout    time.Duration
}

// New constructs a TrivyManifestScanner.
func New(cfg Config) *TrivyManifestScanner {
	if cfg.BinaryPath == "" {
		cfg.BinaryPath = "trivy"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Minute
	}
	return &TrivyManifestScanner{binaryPath: cfg.BinaryPath, timeout: cfg.Timeout}
}

func (s *TrivyManifestScanner) Name() string    { return "trivy" }
func (s *TrivyManifestScanner) Version() string { return "1.0" }

// HealthCheck verifies the binary is callable.
func (s *TrivyManifestScanner) HealthCheck(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, s.binaryPath, "--version")
	return cmd.Run()
}

// trivyOutput is the minimal subset of trivy's JSON output we consume.
type trivyOutput struct {
	Results []struct {
		Target          string         `json:"Target"`
		Vulnerabilities []trivyVulnRow `json:"Vulnerabilities"`
	} `json:"Results"`
}

type trivyVulnRow struct {
	VulnerabilityID  string    `json:"VulnerabilityID"`
	PkgName          string    `json:"PkgName"`
	InstalledVersion string    `json:"InstalledVersion"`
	FixedVersion     string    `json:"FixedVersion"`
	Severity         string    `json:"Severity"`
	Title            string    `json:"Title"`
	PrimaryURL       string    `json:"PrimaryURL"`
	CVSS             trivyCVSS `json:"CVSS"`
}

type trivyCVSS struct {
	Nvd struct {
		V3Score float64 `json:"V3Score"`
	} `json:"nvd"`
	Redhat struct {
		V3Score float64 `json:"V3Score"`
	} `json:"redhat"`
}

// Scan invokes `trivy sbom --format json` on the SBOM bytes.
func (s *TrivyManifestScanner) Scan(ctx context.Context, m manifest.Manifest) (manifest.ScanOutcome, error) {
	start := time.Now()
	out := manifest.ScanOutcome{ScannerID: s.Name(), ScannerVersion: s.Version()}

	if len(m.SBOMBytes) == 0 && m.SBOMPath == "" {
		out.Status = "ok"
		out.Duration = time.Since(start)
		return out, nil
	}

	// Isolate all Trivy scratch (decompression/analyzer temp + the SBOM temp
	// file below) under a process-owned shieldoo-trivy-scratch-* dir exported as
	// TMPDIR, so the tmpjanitor can reclaim it under the shieldoo-trivy- prefix
	// if this process is hard-killed mid-scan. The happy path removes it via the
	// deferred RemoveAll.
	scratchDir, scratchErr := os.MkdirTemp("", "shieldoo-trivy-scratch-*")
	if scratchErr == nil {
		defer os.RemoveAll(scratchDir)
	}

	// Prefer in-memory bytes via a temp file; trivy doesn't accept stdin for SBOMs reliably.
	sbomPath := m.SBOMPath
	if sbomPath == "" {
		// Place the SBOM temp inside the scratch dir so RemoveAll reclaims it.
		// If the scratch dir could not be created, fall back to the legacy
		// shieldoo-sbom-*.json name in /tmp so the janitor's shieldoo-sbom- rule
		// still matches it, and remove it explicitly.
		var f *os.File
		var err error
		if scratchErr == nil {
			f, err = os.CreateTemp(scratchDir, "sbom-*.json")
		} else {
			f, err = os.CreateTemp("", "shieldoo-sbom-*.json")
		}
		if err != nil {
			out.Status = "error"
			out.Duration = time.Since(start)
			return out, err
		}
		_, _ = f.Write(m.SBOMBytes)
		_ = f.Close()
		sbomPath = f.Name()
		if scratchErr != nil {
			defer os.Remove(sbomPath)
		}
	}

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	//nolint:gosec // binaryPath is operator-controlled config, not user input
	cmd := exec.CommandContext(ctx, s.binaryPath, "sbom", "--format", "json", "--quiet", sbomPath)
	if scratchErr == nil {
		// Additive env (never a bare cmd.Env) — a bare slice would strip
		// PATH/HOME/proxy/DB-download config and fail-open every scan.
		cmd.Env = append(os.Environ(), "TMPDIR="+scratchDir)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// If the timeout fired, kill the process group.
		if ctx.Err() == context.DeadlineExceeded {
			out.Status = "timeout"
		} else {
			out.Status = "error"
		}
		out.Error = fmt.Errorf("trivy sbom: %w (stderr=%s)", err, strings.TrimSpace(stderr.String()))
		out.Duration = time.Since(start)
		return out, out.Error
	}

	var parsed trivyOutput
	if err := json.NewDecoder(&stdout).Decode(&parsed); err != nil {
		out.Status = "error"
		out.Error = fmt.Errorf("trivy sbom: parse output: %w", err)
		out.Duration = time.Since(start)
		return out, out.Error
	}
	for _, r := range parsed.Results {
		for _, v := range r.Vulnerabilities {
			score := v.CVSS.Nvd.V3Score
			if score == 0 {
				score = v.CVSS.Redhat.V3Score
			}
			severity := manifest.SeverityFromString(v.Severity)
			if severity == "" || severity == "INFO" {
				severity = manifest.SeverityFromCVSS(score)
			}
			out.Findings = append(out.Findings, manifest.Finding{
				CVEID:          v.VulnerabilityID,
				PackageName:    v.PkgName,
				PackageVersion: v.InstalledVersion,
				FixedVersion:   v.FixedVersion,
				Severity:       severity,
				CVSSScore:      score,
				Summary:        v.Title,
				URL:            v.PrimaryURL,
			})
		}
	}
	out.Status = "ok"
	out.Duration = time.Since(start)
	return out, nil
}
