"""Tests for the startup sweep that cleans stale scratch from the socket directory."""

import os
import importlib
import sys
import types

# Stub out heavy dependencies so we can import main._cleanup_stale_scratch
# without needing openai, guarddog, etc.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Create minimal stubs for modules that main.py imports transitively.
for mod_name in ("openai", "guarddog", "guarddog.PypiPackageScanner",
                 "guarddog.NPMPackageScanner"):
    if mod_name not in sys.modules:
        sys.modules[mod_name] = types.ModuleType(mod_name)

# Stub ai_scanner with required attributes.
ai_scanner_stub = types.ModuleType("ai_scanner")
ai_scanner_stub._client = None
ai_scanner_stub._model = "stub"
ai_scanner_stub._build_client = lambda: (None, "stub")
sys.modules["ai_scanner"] = ai_scanner_stub

# Stub diff_scanner.
diff_scanner_stub = types.ModuleType("diff_scanner")
sys.modules["diff_scanner"] = diff_scanner_stub

from main import _cleanup_stale_scratch


class TestCleanupStaleScratch:
    """Verify _cleanup_stale_scratch removes orphaned files/dirs but preserves the socket."""

    def test_removes_stale_files_and_dirs(self, tmp_path):
        socket_path = str(tmp_path / "shieldoo-bridge.sock")

        # Create stale scratch that should be removed.
        (tmp_path / "getter-abc123").mkdir()
        (tmp_path / "getter-abc123" / "data.bin").write_bytes(b"x" * 100)
        (tmp_path / "trivy-xyz").mkdir()
        (tmp_path / "shieldoo-azblob-cache-001").write_text("cache")
        (tmp_path / "analyzer-fs-999").mkdir()

        _cleanup_stale_scratch(str(tmp_path), socket_path)

        # All stale entries should be gone.
        remaining = os.listdir(str(tmp_path))
        assert remaining == []

    def test_preserves_socket_file(self, tmp_path):
        socket_path = str(tmp_path / "shieldoo-bridge.sock")

        # Create a fake socket file (regular file for testing purposes).
        with open(socket_path, "w") as f:
            f.write("")

        # Create stale scratch.
        (tmp_path / "getter-old").mkdir()

        _cleanup_stale_scratch(str(tmp_path), socket_path)

        # Socket should still exist; stale dir should be gone.
        remaining = os.listdir(str(tmp_path))
        assert remaining == ["shieldoo-bridge.sock"]

    def test_handles_empty_directory(self, tmp_path):
        socket_path = str(tmp_path / "shieldoo-bridge.sock")

        # Should not raise.
        _cleanup_stale_scratch(str(tmp_path), socket_path)

        assert os.listdir(str(tmp_path)) == []

    def test_handles_nonexistent_directory(self):
        # Should not raise when directory doesn't exist.
        _cleanup_stale_scratch("/nonexistent/path", "/nonexistent/path/sock")
