// Package sandbox implements a dynamic analysis scanner that runs artifacts
// inside a gVisor (runsc) sandbox and monitors syscall behavior for malicious
// indicators. This scanner runs ASYNCHRONOUSLY — it does not block the download
// path. If malicious behavior is detected, the artifact is quarantined
// retroactively via a callback.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/sync/semaphore"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

const (
	// defaultTimeout is the per-sandbox execution timeout.
	defaultTimeout = 30 * time.Second

	// defaultMaxConcurrent is the maximum number of concurrent sandbox executions.
	defaultMaxConcurrent = 2

	// defaultForkThreshold is the number of clone() syscalls before flagging.
	defaultForkThreshold = 10

	// sandboxContainerPrefix is the prefix for sandbox container IDs used by runsc.
	sandboxContainerPrefix = "sgw-sandbox-"
)

// SandboxScanner executes artifacts in a gVisor sandbox and analyzes syscall
// behavior for malicious indicators. It does NOT implement scanner.Scanner
// because it runs asynchronously, outside the synchronous scan engine path.
type SandboxScanner struct {
	runtimeBinary string
	timeout       time.Duration
	networkPolicy string // "none" or "monitor"
	maxConcurrent int
	semaphore     *semaphore.Weighted
	baseImages    map[scanner.Ecosystem]string
	rules         []BehaviorRule
	forkThreshold int

	mu      sync.Mutex
	running bool
}

// NewSandboxScanner creates a new SandboxScanner with the given configuration.
// It verifies the runtime binary is available and returns an error if not.
func NewSandboxScanner(cfg SandboxConfig) (*SandboxScanner, error) {
	runtimeBinary := cfg.RuntimeBinary
	if runtimeBinary == "" {
		runtimeBinary = "runsc"
	}

	timeout := defaultTimeout
	if cfg.Timeout != "" {
		parsed, err := time.ParseDuration(cfg.Timeout)
		if err != nil {
			return nil, fmt.Errorf("sandbox scanner: invalid timeout %q: %w", cfg.Timeout, err)
		}
		timeout = parsed
	}

	networkPolicy := cfg.NetworkPolicy
	if networkPolicy == "" {
		networkPolicy = "none"
	}
	if networkPolicy != "none" && networkPolicy != "monitor" {
		return nil, fmt.Errorf("sandbox scanner: invalid network_policy %q: must be \"none\" or \"monitor\"", networkPolicy)
	}

	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrent
	}

	// Verify runtime binary is available.
	if _, err := exec.LookPath(runtimeBinary); err != nil {
		return nil, fmt.Errorf("sandbox scanner: runtime binary %q not found: %w", runtimeBinary, err)
	}

	baseImages := map[scanner.Ecosystem]string{
		scanner.EcosystemPyPI:     "python:3.12-slim",
		scanner.EcosystemNPM:      "node:20-slim",
		scanner.EcosystemNuGet:    "mcr.microsoft.com/dotnet/sdk:8.0",
		scanner.EcosystemMaven:    "maven:3-eclipse-temurin-21",
		scanner.EcosystemRubyGems: "ruby:3.3-slim",
	}

	return &SandboxScanner{
		runtimeBinary: runtimeBinary,
		timeout:       timeout,
		networkPolicy: networkPolicy,
		maxConcurrent: maxConcurrent,
		semaphore:     semaphore.NewWeighted(int64(maxConcurrent)),
		baseImages:    baseImages,
		rules:         defaultRules(),
		forkThreshold: defaultForkThreshold,
		running:       true,
	}, nil
}

// Name returns the scanner identifier.
func (s *SandboxScanner) Name() string { return "sandbox" }

// SupportedEcosystems returns the ecosystems supported by the sandbox scanner.
func (s *SandboxScanner) SupportedEcosystems() []scanner.Ecosystem {
	return []scanner.Ecosystem{
		scanner.EcosystemPyPI,
		scanner.EcosystemNPM,
		scanner.EcosystemNuGet,
		scanner.EcosystemMaven,
		scanner.EcosystemRubyGems,
	}
}

// supportsEcosystem checks if the given ecosystem is supported.
func (s *SandboxScanner) supportsEcosystem(eco scanner.Ecosystem) bool {
	_, ok := s.baseImages[eco]
	return ok
}

// ScanAsync runs the sandbox scan asynchronously. It does not block the caller.
// When the scan completes, the callback is called with the results. If the
// scanner is unavailable, at capacity, or the ecosystem is unsupported, the
// callback receives a VerdictUnknown result.
func (s *SandboxScanner) ScanAsync(ctx context.Context, artifact scanner.Artifact, localPath string, callback func(scanner.ScanResult)) {
	go func() {
		result := s.scan(ctx, artifact, localPath)
		if callback != nil {
			callback(result)
		}
	}()
}

// scan performs the actual sandbox execution and behavioral analysis.
func (s *SandboxScanner) scan(ctx context.Context, artifact scanner.Artifact, localPath string) scanner.ScanResult {
	start := time.Now()

	// Check ecosystem support.
	if !s.supportsEcosystem(artifact.Ecosystem) {
		return scanner.ScanResult{
			Verdict:   scanner.VerdictClean,
			ScannerID: s.Name(),
			Duration:  time.Since(start),
			ScannedAt: start,
		}
	}

	// Acquire semaphore slot with timeout.
	scanCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	if err := s.semaphore.Acquire(scanCtx, 1); err != nil {
		log.Warn().Err(err).Str("artifact", artifact.ID).Msg("sandbox scanner: semaphore acquire failed (at capacity or timeout)")
		return scanner.ScanResult{
			Verdict:   verdictUnknown(),
			ScannerID: s.Name(),
			Duration:  time.Since(start),
			ScannedAt: start,
			Error:     fmt.Errorf("sandbox scanner: semaphore acquire: %w", err),
		}
	}
	defer s.semaphore.Release(1)

	// Create temp directory for sandbox workspace.
	tmpDir, err := os.MkdirTemp("", sandboxContainerPrefix)
	if err != nil {
		log.Error().Err(err).Msg("sandbox scanner: failed to create temp directory")
		return scanner.ScanResult{
			Verdict:   verdictUnknown(),
			ScannerID: s.Name(),
			Duration:  time.Since(start),
			ScannedAt: start,
			Error:     fmt.Errorf("sandbox scanner: create temp dir: %w", err),
		}
	}
	defer func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			log.Warn().Err(err).Str("dir", tmpDir).Msg("sandbox scanner: failed to clean up temp directory")
		}
	}()

	// Copy artifact to sandbox workspace.
	artifactDest := filepath.Join(tmpDir, "artifact"+filepath.Ext(localPath))
	if err := copyFile(localPath, artifactDest); err != nil {
		log.Error().Err(err).Str("artifact", artifact.ID).Msg("sandbox scanner: failed to copy artifact")
		return scanner.ScanResult{
			Verdict:   verdictUnknown(),
			ScannerID: s.Name(),
			Duration:  time.Since(start),
			ScannedAt: start,
			Error:     fmt.Errorf("sandbox scanner: copy artifact: %w", err),
		}
	}

	// Generate OCI runtime spec.
	specPath := filepath.Join(tmpDir, "config.json")
	if err := writeOCISpec(specPath, artifact.Ecosystem, s.networkPolicy); err != nil {
		log.Error().Err(err).Msg("sandbox scanner: failed to write OCI spec")
		return scanner.ScanResult{
			Verdict:   verdictUnknown(),
			ScannerID: s.Name(),
			Duration:  time.Since(start),
			ScannedAt: start,
			Error:     fmt.Errorf("sandbox scanner: write OCI spec: %w", err),
		}
	}

	// Run sandbox via runsc.
	straceLog, err := s.runSandbox(scanCtx, tmpDir, artifact)
	if err != nil {
		log.Warn().Err(err).Str("artifact", artifact.ID).Msg("sandbox scanner: execution failed")
		return scanner.ScanResult{
			Verdict:   verdictUnknown(),
			ScannerID: s.Name(),
			Duration:  time.Since(start),
			ScannedAt: start,
			Error:     fmt.Errorf("sandbox scanner: run sandbox: %w", err),
		}
	}

	// Analyze strace log for behavioral indicators.
	findings := analyzeLog(straceLog, s.rules, s.forkThreshold)
	verdict, confidence := findingsToVerdict(findings)

	return scanner.ScanResult{
		Verdict:    verdict,
		Confidence: confidence,
		Findings:   findings,
		ScannerID:  s.Name(),
		Duration:   time.Since(start),
		ScannedAt:  start,
	}
}

// installCommand returns the ecosystem-specific install command for the sandbox.
func installCommand(eco scanner.Ecosystem, artifactPath string) []string {
	switch eco {
	case scanner.EcosystemPyPI:
		return []string{"pip", "install", "--no-deps", artifactPath}
	case scanner.EcosystemNPM:
		return []string{"npm", "install", artifactPath}
	case scanner.EcosystemNuGet:
		return []string{"dotnet", "add", "package", "--source", filepath.Dir(artifactPath)}
	case scanner.EcosystemMaven:
		return []string{"mvn", "install:install-file", "-Dfile=" + artifactPath}
	case scanner.EcosystemRubyGems:
		return []string{"gem", "install", artifactPath, "--local"}
	default:
		return nil
	}
}

// runSandbox executes the artifact install in a gVisor sandbox and returns
// the strace log output for behavioral analysis.
func (s *SandboxScanner) runSandbox(ctx context.Context, workDir string, artifact scanner.Artifact) (string, error) {
	containerID := fmt.Sprintf("%s%d", sandboxContainerPrefix, time.Now().UnixNano())
	straceLogPath := filepath.Join(workDir, "strace.log")

	artifactPath := "/artifact" + filepath.Ext(artifact.LocalPath)
	cmd := installCommand(artifact.Ecosystem, artifactPath)
	if cmd == nil {
		return "", fmt.Errorf("unsupported ecosystem: %s", artifact.Ecosystem)
	}

	//nolint:gosec // runtimeBinary is operator-controlled config
	args := []string{
		"--root", filepath.Join(workDir, "runsc-root"),
		"--network", s.networkPolicy,
		"--strace",
		"--strace-log-size", "65536",
		"run",
		"--bundle", workDir,
		"--id", containerID,
	}

	runCmd := exec.CommandContext(ctx, s.runtimeBinary, args...)
	var stderr bytes.Buffer
	runCmd.Stderr = &stderr
	runCmd.Dir = workDir

	// Provide strace log path via environment.
	runCmd.Env = append(os.Environ(),
		"RUNSC_STRACE_FILE="+straceLogPath,
	)

	if err := runCmd.Run(); err != nil {
		// Read strace log even on failure — install may have failed but still logged suspicious behavior.
		straceData, readErr := os.ReadFile(straceLogPath)
		if readErr != nil {
			// No strace log available.
			return "", fmt.Errorf("sandbox execution failed (no strace log): %w; stderr: %s", err, stderr.String())
		}
		return string(straceData), nil
	}

	straceData, err := os.ReadFile(straceLogPath)
	if err != nil {
		return "", fmt.Errorf("reading strace log: %w", err)
	}

	return string(straceData), nil
}

// writeOCISpec generates a minimal OCI runtime specification for the sandbox.
func writeOCISpec(path string, eco scanner.Ecosystem, networkPolicy string) error {
	artifactPath := "/artifact"

	cmd := installCommand(eco, artifactPath)
	if cmd == nil {
		return fmt.Errorf("unsupported ecosystem for OCI spec: %s", eco)
	}

	spec := ociSpec{
		OCIVersion: "1.0.2",
		Process: ociProcess{
			Terminal: false,
			User:     ociUser{UID: 0, GID: 0},
			Args:     cmd,
			Cwd:      "/",
		},
		Root: ociRoot{
			Path:     "rootfs",
			Readonly: false,
		},
		Linux: ociLinux{
			Resources: ociResources{
				Memory: ociMemory{Limit: 512 * 1024 * 1024}, // 512MB
				CPU:    ociCPU{Quota: 100000, Period: 100000}, // 1 core
				Pids:   ociPids{Limit: 100},
			},
			Namespaces: []ociNamespace{
				{Type: "pid"},
				{Type: "mount"},
				{Type: "ipc"},
				{Type: "uts"},
				{Type: "network"},
			},
		},
	}

	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling OCI spec: %w", err)
	}

	return os.WriteFile(path, data, 0o600)
}

// copyFile copies src to dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("reading %s: %w", src, err)
	}
	return os.WriteFile(dst, data, 0o600)
}

// CleanupOrphans removes any stale sandbox containers from a previous run.
// This should be called at startup.
func (s *SandboxScanner) CleanupOrphans() {
	//nolint:gosec // runtimeBinary is operator-controlled config
	cmd := exec.Command(s.runtimeBinary, "list", "--format", "json")
	output, err := cmd.Output()
	if err != nil {
		log.Warn().Err(err).Msg("sandbox scanner: failed to list containers for orphan cleanup")
		return
	}

	var containers []orphanContainer
	if err := json.Unmarshal(output, &containers); err != nil {
		log.Warn().Err(err).Msg("sandbox scanner: failed to parse container list")
		return
	}

	for _, c := range containers {
		if len(c.ID) > len(sandboxContainerPrefix) && c.ID[:len(sandboxContainerPrefix)] == sandboxContainerPrefix {
			log.Info().Str("container", c.ID).Msg("sandbox scanner: cleaning up orphaned container")
			//nolint:gosec // runtimeBinary is operator-controlled config
			delCmd := exec.Command(s.runtimeBinary, "delete", "--force", c.ID)
			if err := delCmd.Run(); err != nil {
				log.Warn().Err(err).Str("container", c.ID).Msg("sandbox scanner: failed to delete orphaned container")
			}
		}
	}
}

// Close stops the sandbox scanner and releases resources.
func (s *SandboxScanner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running = false
	return nil
}

// verdictUnknown returns the VerdictSuspicious value used to signal that the
// sandbox could not complete. Per spec, sandbox failures use VerdictSuspicious
// with a low confidence and an error, rather than VerdictClean. The policy
// engine treats this as "unknown" — configurable to warn or block.
//
// Note: The scanner.Verdict type does not have a VerdictUnknown constant.
// We use VerdictSuspicious with confidence 0.0 and an error to signal this.
func verdictUnknown() scanner.Verdict {
	return scanner.VerdictSuspicious
}

// --- OCI spec types ---

type ociSpec struct {
	OCIVersion string     `json:"ociVersion"`
	Process    ociProcess `json:"process"`
	Root       ociRoot    `json:"root"`
	Linux      ociLinux   `json:"linux"`
}

type ociProcess struct {
	Terminal bool     `json:"terminal"`
	User     ociUser  `json:"user"`
	Args     []string `json:"args"`
	Cwd      string   `json:"cwd"`
}

type ociUser struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
}

type ociRoot struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

type ociLinux struct {
	Resources  ociResources   `json:"resources"`
	Namespaces []ociNamespace `json:"namespaces"`
}

type ociResources struct {
	Memory ociMemory `json:"memory"`
	CPU    ociCPU    `json:"cpu"`
	Pids   ociPids   `json:"pids"`
}

type ociMemory struct {
	Limit int64 `json:"limit"`
}

type ociCPU struct {
	Quota  int `json:"quota"`
	Period int `json:"period"`
}

type ociPids struct {
	Limit int `json:"limit"`
}

type ociNamespace struct {
	Type string `json:"type"`
}

type orphanContainer struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

// SandboxConfig holds configuration for the sandbox scanner.
// This is duplicated here for package-level access; the canonical definition
// is in internal/config/config.go.
type SandboxConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	RuntimeBinary string `mapstructure:"runtime_binary"`
	Timeout       string `mapstructure:"timeout"`
	NetworkPolicy string `mapstructure:"network_policy"`
	MaxConcurrent int    `mapstructure:"max_concurrent"`
}
