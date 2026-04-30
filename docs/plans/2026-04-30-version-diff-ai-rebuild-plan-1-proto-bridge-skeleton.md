# Version-Diff AI Rebuild — Phase 1: Proto + bridge handler skeleton

> **For agentic workers:** REQUIRED SUB-SKILL: Use cf-powers:subagent-driven-development (recommended) or cf-powers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lay down the gRPC contract for `ScanArtifactDiff` and a placeholder Python handler that returns `UNKNOWN`. No AI logic yet — only an addressable gRPC endpoint.

**Architecture:** Add one new RPC + two messages to [scanner-bridge/proto/scanner.proto](../../scanner-bridge/proto/scanner.proto). Regenerate Go + Python stubs. Add a placeholder handler in [scanner-bridge/main.py](../../scanner-bridge/main.py) wired to a stub `diff_scanner.scan` function. The Go side is untouched in this phase.

**Tech Stack:** Protobuf 3, grpcio-tools 1.68.1, Python 3.12. The `make proto` target already exists (Makefile:`proto:` target generates Go stubs into `internal/scanner/guarddog/proto/`; bridge `Dockerfile` regenerates Python stubs at image build time using `python -m grpc_tools.protoc`).

**Index:** [`plan-index.md`](./2026-04-30-version-diff-ai-rebuild-plan-index.md)

---

## Context for executor

The scanner-bridge is a Python gRPC server that listens on a Unix socket. The Go core dials it from `internal/scanner/ai/client.go`. We are adding a third RPC named `ScanArtifactDiff` alongside the existing `ScanArtifact` (GuardDog) and `ScanArtifactAI` (single-version LLM). The existing pattern at [main.py:137-170](../../scanner-bridge/main.py#L137-L170) (`ScanArtifactAI` handler) is the template — we copy its structure with a stub return value.

**Why a placeholder phase?** Decouples the proto/build pipeline from the implementation. Once the proto is regenerated and the bridge starts, we can verify the wire works (`grpcurl`) before any AI logic exists. Phase 5 replaces the placeholder with real logic.

---

### Task 1: Extend `scanner.proto` with `ScanArtifactDiff`

**Files:**
- Modify: [scanner-bridge/proto/scanner.proto](../../scanner-bridge/proto/scanner.proto)

- [ ] **Step 1: Add the RPC and messages**

In [scanner-bridge/proto/scanner.proto](../../scanner-bridge/proto/scanner.proto), inside `service ScannerBridge {}`, add the new RPC line **after** `rpc ScanArtifactAI` and **before** `rpc TriageFindings`:

```protobuf
service ScannerBridge {
    rpc ScanArtifact(ScanRequest) returns (ScanResponse);
    rpc ScanArtifactAI(AIScanRequest) returns (AIScanResponse);
    rpc ScanArtifactDiff(DiffScanRequest) returns (DiffScanResponse);
    rpc TriageFindings(TriageRequest) returns (TriageResponse);
    rpc HealthCheck(HealthRequest) returns (HealthResponse);
}
```

Then add two new message definitions at the bottom of the file (after `HealthResponse`):

```protobuf
message DiffScanRequest {
    string artifact_id            = 1;
    string ecosystem              = 2;   // pypi, npm, nuget, maven, rubygems, go
    string name                   = 3;
    string version                = 4;
    string previous_version       = 5;
    string local_path             = 6;   // path to NEW artifact on disk (in shared volume)
    string previous_path          = 7;   // path to PREVIOUS artifact on disk
    string original_filename      = 8;
    string local_path_sha256      = 9;   // expected hash, bridge re-verifies before extraction (TOCTOU)
    string previous_path_sha256   = 10;  // expected hash, bridge re-verifies before extraction
    string prompt_version         = 11;  // SHA256[:12] of system prompt — bridge attaches to response
}

message DiffScanResponse {
    string verdict          = 1;   // CLEAN | SUSPICIOUS | MALICIOUS | UNKNOWN
    float  confidence       = 2;
    repeated string findings = 3;
    string explanation      = 4;
    string model_used       = 5;
    int32  tokens_used      = 6;
    int32  files_added      = 7;   // counts so Go can persist without re-parsing payload
    int32  files_modified   = 8;
    int32  files_removed    = 9;
    string prompt_version   = 10;  // SHA256[:12] of system prompt at scan time — Go uses for idempotency cache key (so prompt edits invalidate cache)
    bool   input_truncated  = 11;  // bridge sets true when token budget cut content; Go uses for confidence cap defense-in-depth
}
```

- [ ] **Step 2: Run `make proto` to regenerate Go stubs**

```bash
make proto
```

Expected: regenerates `internal/scanner/guarddog/proto/scanner.pb.go` and `scanner_grpc.pb.go`. No errors.

- [ ] **Step 3: Verify Go stubs compile**

```bash
go build ./internal/scanner/guarddog/proto/...
```

Expected: success, no diagnostics.

- [ ] **Step 4: Verify generated Go file contains the new types**

```bash
grep -E "DiffScanRequest|DiffScanResponse|ScanArtifactDiff" internal/scanner/guarddog/proto/scanner.pb.go internal/scanner/guarddog/proto/scanner_grpc.pb.go | head -20
```

Expected: at least 6 matches (struct, getter methods, RPC method name on client + server interfaces).

- [ ] **Step 5: Commit**

```bash
git add scanner-bridge/proto/scanner.proto internal/scanner/guarddog/proto/scanner.pb.go internal/scanner/guarddog/proto/scanner_grpc.pb.go
git commit -m "feat(proto): add ScanArtifactDiff RPC for AI-driven version-diff scanner"
```

---

### Task 2: Regenerate Python proto stubs locally for development

**Files:**
- Generated: `scanner-bridge/proto/scanner_pb2.py`
- Generated: `scanner-bridge/proto/scanner_pb2_grpc.py`

The Dockerfile regenerates these at image build time, but for local development with `uv run pytest` and direct Python execution we need them on disk. They're typically not checked in (verify with `git status` after generation).

- [ ] **Step 1: Create/refresh the bridge venv**

```bash
cd scanner-bridge
uv venv .venv
uv pip install -r requirements.txt
```

Expected: venv created at `scanner-bridge/.venv/`, dependencies installed (with hashes per CLAUDE.md).

- [ ] **Step 2: Regenerate Python stubs**

```bash
cd scanner-bridge
uv run python -m grpc_tools.protoc \
    -I proto \
    --python_out=proto \
    --grpc_python_out=proto \
    proto/scanner.proto
```

Expected: refreshed `scanner-bridge/proto/scanner_pb2.py` and `scanner_pb2_grpc.py` with `DiffScanRequest`, `DiffScanResponse`, `ScanArtifactDiff` symbols.

- [ ] **Step 3: Verify Python imports**

```bash
cd scanner-bridge
uv run python -c "from proto.scanner_pb2 import DiffScanRequest, DiffScanResponse; from proto.scanner_pb2_grpc import ScannerBridgeServicer; print('ok')"
```

Expected: prints `ok`. No `ImportError` or `AttributeError`.

- [ ] **Step 4: Verify generated Python files are git-ignored (do not commit)**

```bash
git status scanner-bridge/proto/scanner_pb2.py scanner-bridge/proto/scanner_pb2_grpc.py
```

Expected: either `not tracked` (ignored) or already tracked. If tracked, leave as-is for this task. If not tracked, do not add — they regenerate from Dockerfile.

(No commit in this task.)

---

### Task 3: Create stub `diff_scanner.scan` returning UNKNOWN

**Files:**
- Create: `scanner-bridge/diff_scanner.py`

- [ ] **Step 1: Write the stub module**

Create [scanner-bridge/diff_scanner.py](../../scanner-bridge/diff_scanner.py) with:

```python
"""Version-Diff AI scanner — placeholder. Real implementation lands in Phase 5."""

import logging

logger = logging.getLogger(__name__)


async def scan(request) -> dict:
    """Entry point called from the gRPC handler.

    Phase 1: returns UNKNOWN unconditionally so the wire path can be exercised.
    Phase 5 replaces this with extraction + LLM call.
    """
    logger.info(
        "diff_scanner: placeholder invoked for artifact_id=%s ecosystem=%s",
        getattr(request, "artifact_id", ""),
        getattr(request, "ecosystem", ""),
    )
    return _unknown("diff_scanner placeholder — Phase 5 not implemented yet")


def _unknown(explanation: str) -> dict:
    return {
        "verdict": "UNKNOWN",
        "confidence": 0.0,
        "findings": [],
        "explanation": explanation,
        "model_used": "none",
        "tokens_used": 0,
        "files_added": 0,
        "files_modified": 0,
        "files_removed": 0,
    }
```

- [ ] **Step 2: Verify it imports cleanly**

```bash
cd scanner-bridge
uv run python -c "import diff_scanner; print('ok')"
```

Expected: prints `ok`.

(No commit yet — combined with Task 4.)

---

### Task 4: Wire `ScanArtifactDiff` handler into `main.py`

**Files:**
- Modify: [scanner-bridge/main.py](../../scanner-bridge/main.py) (between [main.py:137-170](../../scanner-bridge/main.py#L137-L170) and [main.py:172-207](../../scanner-bridge/main.py#L172-L207))

- [ ] **Step 1: Add handler method on `ScannerBridgeServicer`**

In [scanner-bridge/main.py](../../scanner-bridge/main.py), add a new method `ScanArtifactDiff` immediately after the existing `ScanArtifactAI` method (around line 170, before `def TriageFindings`):

```python
    def ScanArtifactDiff(self, request, context):
        """AI-driven version-diff analysis between two consecutive package versions."""
        if self._ai_scanner is None:
            return scanner_pb2.DiffScanResponse(
                verdict="UNKNOWN",
                confidence=0.0,
                explanation="AI scanner not enabled",
                model_used="none",
                tokens_used=0,
            )

        try:
            import diff_scanner
            future = asyncio.run_coroutine_threadsafe(
                diff_scanner.scan(request), self._ai_loop
            )
            result = future.result(timeout=50)

            return scanner_pb2.DiffScanResponse(
                verdict=result.get("verdict", "UNKNOWN"),
                confidence=result.get("confidence", 0.0),
                findings=result.get("findings", []),
                explanation=result.get("explanation", ""),
                model_used=result.get("model_used", ""),
                tokens_used=result.get("tokens_used", 0),
                files_added=result.get("files_added", 0),
                files_modified=result.get("files_modified", 0),
                files_removed=result.get("files_removed", 0),
                prompt_version=result.get("prompt_version", ""),
                input_truncated=result.get("input_truncated", False),
            )
        except Exception as e:
            logger.error("Diff scan error for %s: %s", request.artifact_id, e)
            return scanner_pb2.DiffScanResponse(
                verdict="UNKNOWN",
                confidence=0.0,
                explanation=f"Diff scan error: {e}",
                model_used="none",
                tokens_used=0,
            )
```

- [ ] **Step 2: Bump the bridge `ThreadPoolExecutor` to 64 workers**

In [scanner-bridge/main.py:223](../../scanner-bridge/main.py#L223), change:

```python
server = grpc.server(futures.ThreadPoolExecutor(max_workers=32))
```

to:

```python
server = grpc.server(futures.ThreadPoolExecutor(max_workers=64))
```

Why: engine semaphore `MaxConcurrentScans=32` × 2 parallel AI scanners (ai-scanner + version-diff) per artifact = up to 64 simultaneous gRPC calls. The current 32 would cause `RESOURCE_EXHAUSTED` under burst load.

- [ ] **Step 3: Smoke-test the bridge starts**

```bash
cd scanner-bridge
AI_SCANNER_ENABLED=false BRIDGE_SOCKET=/tmp/test-bridge.sock uv run python main.py &
sleep 2
ls -la /tmp/test-bridge.sock
kill %1
```

Expected: socket file appears in `/tmp/`, no exceptions in stderr. After kill, socket is gone (server cleans up on next start).

- [ ] **Step 4: Smoke-test with `grpcurl` (optional, requires `grpcurl` installed)**

Skip this step if `grpcurl` is not available locally — the test in Phase 5 covers wire-end-to-end with reflection or a Python client.

```bash
# Start the bridge with AI enabled (env vars must point to a valid Azure OpenAI deployment)
cd scanner-bridge
AI_SCANNER_ENABLED=true BRIDGE_SOCKET=/tmp/test-bridge.sock \
  AI_SCANNER_PROVIDER=azure_openai \
  AI_SCANNER_AZURE_ENDPOINT=... \
  AI_SCANNER_API_KEY=... \
  uv run python main.py &
sleep 3

grpcurl -plaintext -unix /tmp/test-bridge.sock \
  -d '{"artifact_id":"pypi:test:1.0","ecosystem":"pypi","name":"test","version":"1.0","previous_version":"0.9","local_path":"/dev/null","previous_path":"/dev/null"}' \
  scanner.ScannerBridge/ScanArtifactDiff
```

Expected: response with `"verdict": "UNKNOWN"` and `"explanation": "diff_scanner placeholder — ..."`.

- [ ] **Step 5: Run existing bridge tests to ensure nothing regressed**

```bash
cd scanner-bridge
uv run pytest tests/ -v
```

Expected: all existing tests pass (`test_ai_scanner.py`, `test_extractors.py`).

- [ ] **Step 6: Run Go build + lint**

```bash
make build
make lint
```

Expected: success. Ensures the Go side still compiles with the regenerated proto stubs.

- [ ] **Step 7: Commit**

```bash
git add scanner-bridge/diff_scanner.py scanner-bridge/main.py
git commit -m "feat(bridge): wire ScanArtifactDiff handler with placeholder backend"
```

---

## Verification — phase-end

```bash
# Proto contract is in place
grep -c "ScanArtifactDiff" scanner-bridge/proto/scanner.proto    # → 1
grep -c "DiffScanRequest\|DiffScanResponse" scanner-bridge/proto/scanner.proto    # → 2

# Go compiles against the new types
go build ./...

# Python module imports cleanly
cd scanner-bridge && uv run python -c "import diff_scanner; print('ok')"

# Bridge boots without error
AI_SCANNER_ENABLED=false BRIDGE_SOCKET=/tmp/x.sock uv run python scanner-bridge/main.py &
sleep 2 && [ -S /tmp/x.sock ] && echo "socket ok" && kill %1
```

## What this phase ships

- A new `ScanArtifactDiff` gRPC method addressable from the Go side (which we wire up in Phase 6).
- Bridge thread pool sized for the parallel AI scanner workload (32 → 64).
- A stub `diff_scanner.scan()` that returns `UNKNOWN` so callers can exercise the wire without crashing.

## What this phase deliberately does NOT ship

- No extraction logic (Phases 3–4).
- No LLM call (Phase 5).
- No Go scanner changes (Phases 6a–6c).
- No DB schema changes (Phase 2 — independent).

## Risks during this phase

- **Stale generated Python stubs in CI:** the Dockerfile regenerates them at build time. If a developer runs the bridge locally without re-generating, they'll see `AttributeError: module has no attribute 'DiffScanRequest'`. Mitigation: Task 2 documents the local regen command.
- **Breaking the Go build via stale proto:** if the proto file diverges from `internal/scanner/guarddog/proto/scanner.pb.go`, downstream builds fail. Mitigation: `make proto` is run in Task 1 Step 2 and verified in Step 3.
- **`AI_SCANNER_ENABLED=false` makes the handler return UNKNOWN forever:** correct behavior — Phase 5 fixes it. Phase 1 deliberately ships the handler in this state.
