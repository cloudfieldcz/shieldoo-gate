"""Tests for diff_scanner module."""

import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

_EXPECTED_KEYS = {
    "verdict",
    "confidence",
    "findings",
    "explanation",
    "model_used",
    "tokens_used",
    "files_added",
    "files_modified",
    "files_removed",
    "prompt_version",
    "input_truncated",
}


def _make_request(artifact_id="pypi:test-pkg:1.0.0", ecosystem="pypi"):
    """Create a minimal mock DiffScanRequest-like object."""
    req = types.SimpleNamespace()
    req.artifact_id = artifact_id
    req.ecosystem = ecosystem
    return req


class TestUnknown:
    def test_returns_all_expected_keys(self):
        from diff_scanner import _unknown
        result = _unknown("some explanation")
        assert set(result.keys()) == _EXPECTED_KEYS

    def test_explanation_is_threaded(self):
        from diff_scanner import _unknown
        msg = "diff_scanner placeholder — Phase 5 not implemented yet"
        result = _unknown(msg)
        assert result["explanation"] == msg

    def test_verdict_is_unknown(self):
        from diff_scanner import _unknown
        result = _unknown("x")
        assert result["verdict"] == "UNKNOWN"

    def test_confidence_is_zero(self):
        from diff_scanner import _unknown
        result = _unknown("x")
        assert result["confidence"] == 0.0

    def test_prompt_version_is_empty_string(self):
        from diff_scanner import _unknown
        result = _unknown("x")
        assert result["prompt_version"] == ""

    def test_input_truncated_is_false(self):
        from diff_scanner import _unknown
        result = _unknown("x")
        assert result["input_truncated"] is False

    def test_findings_is_empty_list(self):
        from diff_scanner import _unknown
        result = _unknown("x")
        assert result["findings"] == []


@pytest.mark.asyncio
class TestScan:
    async def test_scan_returns_unknown_verdict(self):
        from diff_scanner import scan
        req = _make_request()
        result = await scan(req)
        assert result["verdict"] == "UNKNOWN"

    async def test_scan_returns_all_expected_keys(self):
        from diff_scanner import scan
        req = _make_request()
        result = await scan(req)
        assert set(result.keys()) == _EXPECTED_KEYS

    async def test_scan_contains_placeholder_explanation(self):
        from diff_scanner import scan
        req = _make_request()
        result = await scan(req)
        assert "placeholder" in result["explanation"]

    async def test_scan_does_not_raise_with_minimal_request(self):
        from diff_scanner import scan
        req = _make_request(artifact_id="npm:lodash:4.17.21", ecosystem="npm")
        result = await scan(req)
        assert isinstance(result, dict)
