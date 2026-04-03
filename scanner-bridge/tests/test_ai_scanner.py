"""Tests for ai_scanner module (with mocked LLM client)."""

import json
import os
import sys
import types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _make_request(ecosystem="pypi", name="test-pkg", version="1.0.0",
                  local_path="/tmp/test.whl", artifact_id="pypi:test-pkg:1.0.0"):
    """Create a mock AIScanRequest-like object."""
    req = types.SimpleNamespace()
    req.ecosystem = ecosystem
    req.name = name
    req.version = version
    req.local_path = local_path
    req.artifact_id = artifact_id
    return req


class TestBuildPrompt:
    def test_basic_prompt_construction(self):
        from ai_scanner import _build_prompt
        req = _make_request()
        extracted = {"setup.py": "from setuptools import setup; setup()"}
        result = _build_prompt(req, extracted)
        assert "Package: test-pkg 1.0.0" in result
        assert "=== FILE: setup.py ===" in result
        assert "from setuptools import setup" in result

    def test_truncation_on_large_input(self):
        from ai_scanner import _build_prompt, MAX_INPUT_CHARS
        req = _make_request()
        # Create content larger than MAX_INPUT_CHARS.
        large_content = "x" * (MAX_INPUT_CHARS + 10000)
        extracted = {"huge.py": large_content}
        result = _build_prompt(req, extracted)
        assert len(result) <= MAX_INPUT_CHARS + 200  # allow small overhead
        assert "[TRUNCATED]" in result

    def test_multiple_files(self):
        from ai_scanner import _build_prompt
        req = _make_request()
        extracted = {
            "setup.py": "setup()",
            "evil.pth": "import os; os.system('hack')",
        }
        result = _build_prompt(req, extracted)
        assert "setup.py" in result
        assert "evil.pth" in result


class TestCleanAndUnknown:
    def test_clean_response(self):
        from ai_scanner import _clean
        result = _clean("no scripts")
        assert result["verdict"] == "CLEAN"
        assert result["confidence"] == 0.5
        assert result["model_used"] == "none"

    def test_unknown_response(self):
        from ai_scanner import _unknown
        result = _unknown("unsupported")
        assert result["verdict"] == "UNKNOWN"
        assert result["confidence"] == 0.0


@pytest.mark.asyncio
class TestScanFunction:
    async def test_unsupported_ecosystem_returns_unknown(self):
        from ai_scanner import scan
        req = _make_request(ecosystem="docker")
        result = await scan(req)
        assert result["verdict"] == "UNKNOWN"
        assert "not supported" in result["explanation"]

    async def test_no_extracted_files_returns_clean(self):
        from ai_scanner import scan
        req = _make_request(local_path="/nonexistent/path.whl")
        result = await scan(req)
        assert result["verdict"] == "CLEAN"
        assert "no install-time scripts" in result["explanation"]
