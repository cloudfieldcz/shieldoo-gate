"""Tests for per-scan temp directory isolation and cleanup."""

import os
import tempfile
import types
import sys

# Stub out heavy dependencies so we can import main without needing
# openai, guarddog, etc.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

for mod_name in ("openai", "guarddog", "guarddog.PypiPackageScanner",
                 "guarddog.NPMPackageScanner"):
    if mod_name not in sys.modules:
        sys.modules[mod_name] = types.ModuleType(mod_name)

ai_scanner_stub = types.ModuleType("ai_scanner")
ai_scanner_stub._client = None
ai_scanner_stub._model = "stub"
ai_scanner_stub._build_client = lambda: (None, "stub")
sys.modules["ai_scanner"] = ai_scanner_stub

diff_scanner_stub = types.ModuleType("diff_scanner")
sys.modules["diff_scanner"] = diff_scanner_stub


class TestScanTempIsolation:
    """Verify that ScanArtifact uses an isolated temp directory and cleans it up."""

    def test_scan_cleans_temp_dir_after_completion(self, tmp_path, monkeypatch):
        """After a scan completes, the per-scan scratch dir should be removed."""
        import proto.scanner_pb2 as scanner_pb2

        # Track directories created via tempfile.mkdtemp.
        created_dirs = []
        original_mkdtemp = tempfile.mkdtemp

        def tracking_mkdtemp(**kwargs):
            d = original_mkdtemp(**kwargs)
            created_dirs.append(d)
            return d

        monkeypatch.setattr(tempfile, "mkdtemp", tracking_mkdtemp)

        # Create a mock servicer that bypasses __init__ (no real GuardDog).
        from main import ScannerBridgeServicer

        servicer = object.__new__(ScannerBridgeServicer)
        servicer._ai_scanner = None
        servicer._ai_loop = None

        # Mock scanner that records whether tempfile.tempdir was set.
        class FakeScanner:
            def scan_local(self, path):
                # Create a temp file to simulate GuardDog leaving scratch data.
                f = tempfile.NamedTemporaryFile(delete=False, prefix="guarddog-scratch-")
                f.close()
                return {"results": {}}

        servicer.pypi_scanner = FakeScanner()
        servicer.npm_scanner = FakeScanner()

        request = scanner_pb2.ScanRequest(
            artifact_path="/dev/null",
            ecosystem="pypi",
            package_name="test-pkg",
            version="1.0.0",
        )

        result = servicer.ScanArtifact(request, None)

        assert result.verdict == "CLEAN"
        # The scratch directory should have been cleaned up.
        for d in created_dirs:
            if "shieldoo-guarddog-scratch" in d:
                assert not os.path.exists(d), f"Scratch dir {d} was not cleaned up"

    def test_scan_cleans_up_on_exception(self, tmp_path, monkeypatch):
        """Even if GuardDog raises, the scratch dir should be cleaned up."""
        import proto.scanner_pb2 as scanner_pb2

        created_dirs = []
        original_mkdtemp = tempfile.mkdtemp

        def tracking_mkdtemp(**kwargs):
            d = original_mkdtemp(**kwargs)
            created_dirs.append(d)
            return d

        monkeypatch.setattr(tempfile, "mkdtemp", tracking_mkdtemp)

        from main import ScannerBridgeServicer

        servicer = object.__new__(ScannerBridgeServicer)
        servicer._ai_scanner = None
        servicer._ai_loop = None

        class CrashingScanner:
            def scan_local(self, path):
                # Simulate GuardDog crash leaving temp files behind.
                tempfile.mkdtemp(prefix="guarddog-internal-")
                raise RuntimeError("simulated crash")

        servicer.pypi_scanner = CrashingScanner()
        servicer.npm_scanner = CrashingScanner()

        request = scanner_pb2.ScanRequest(
            artifact_path="/dev/null",
            ecosystem="pypi",
            package_name="crash-pkg",
            version="2.0.0",
        )

        result = servicer.ScanArtifact(request, None)

        # Should fail open (return CLEAN) on error.
        assert result.verdict == "CLEAN"
        assert result.confidence == 0.0
        # All scratch directories should be cleaned up.
        for d in created_dirs:
            if "shieldoo-guarddog-scratch" in d:
                assert not os.path.exists(d), f"Scratch dir {d} was not cleaned up"
