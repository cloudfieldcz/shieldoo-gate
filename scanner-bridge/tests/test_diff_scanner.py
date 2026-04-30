"""Tests for scanner-bridge/diff_scanner.py.

Mocks ai_scanner._client to avoid real OpenAI calls. Inspects the prompt that
would be sent to verify priority ordering, redaction, anti-injection delimiters.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import zipfile
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import ai_scanner  # noqa: E402  load module so we can monkey-patch _client/_model
import diff_scanner  # noqa: E402


@dataclass
class FakeReq:
    artifact_id: str = "pypi:foo:1.1"
    ecosystem: str = "pypi"
    name: str = "foo"
    version: str = "1.1"
    previous_version: str = "1.0"
    local_path: str = ""
    previous_path: str = ""
    original_filename: str = ""
    local_path_sha256: str = ""
    previous_path_sha256: str = ""
    prompt_version: str = "abc123"


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _make_pypi_pair(tmp_path, new_files: dict[str, str], old_files: dict[str, str]) -> tuple[str, str]:
    new = tmp_path / "new.whl"
    old = tmp_path / "old.whl"
    with zipfile.ZipFile(new, "w") as zf:
        for n, c in new_files.items():
            zf.writestr(n, c)
    with zipfile.ZipFile(old, "w") as zf:
        for n, c in old_files.items():
            zf.writestr(n, c)
    return str(new), str(old)


def _patch_llm_with_response(monkeypatch, response_dict: dict):
    """Replace ai_scanner._client with a mock returning the given parsed JSON."""
    captured = {}

    class FakeResp:
        class FakeChoice:
            class FakeMessage:
                content = json.dumps(response_dict)
            message = FakeMessage()
        choices = [FakeChoice()]

        class FakeUsage:
            total_tokens = 1234
        usage = FakeUsage()

    async def fake_create(**kwargs):
        captured["kwargs"] = kwargs
        return FakeResp()

    fake_client = MagicMock()
    fake_client.chat.completions.create = AsyncMock(side_effect=fake_create)
    monkeypatch.setattr(ai_scanner, "_client", fake_client)
    monkeypatch.setattr(ai_scanner, "_model", "gpt-test")
    return captured


# --- High-level integration tests -------------------------------------------

class TestDiffScanner:
    @pytest.mark.asyncio
    async def test_unsupported_ecosystem(self):
        req = FakeReq(ecosystem="docker")
        out = await diff_scanner.scan(req)
        assert out["verdict"] == "UNKNOWN"

    @pytest.mark.asyncio
    async def test_path_sha256_mismatch(self, tmp_path):
        new, old = _make_pypi_pair(
            tmp_path,
            {"setup.py": "import os"},
            {"setup.py": "import os"},
        )
        req = FakeReq(
            local_path=new, previous_path=old,
            local_path_sha256="0" * 64,           # wrong
            previous_path_sha256=_sha256(old),
        )
        out = await diff_scanner.scan(req)
        assert out["verdict"] == "UNKNOWN"
        assert "SHA256" in out["explanation"]

    @pytest.mark.asyncio
    async def test_strict_empty_diff_returns_clean_no_llm(self, tmp_path, monkeypatch):
        new, old = _make_pypi_pair(
            tmp_path,
            {"setup.py": "x=1"},
            {"setup.py": "x=1"},
        )
        captured = _patch_llm_with_response(monkeypatch, {"verdict": "MALICIOUS", "confidence": 0.99})
        req = FakeReq(
            local_path=new, previous_path=old,
            local_path_sha256=_sha256(new), previous_path_sha256=_sha256(old),
        )
        out = await diff_scanner.scan(req)
        assert out["verdict"] == "CLEAN"
        ai_scanner._client.chat.completions.create.assert_not_called()
        assert "kwargs" not in captured

    @pytest.mark.asyncio
    async def test_only_tests_changed_calls_llm(self, tmp_path, monkeypatch):
        new, old = _make_pypi_pair(
            tmp_path,
            {"pkg/__init__.py": "x=1", "pkg/tests/test_x.py": "evil"},
            {"pkg/__init__.py": "x=1", "pkg/tests/test_x.py": "good"},
        )
        captured = _patch_llm_with_response(monkeypatch,
            {"verdict": "CLEAN", "confidence": 0.5, "findings": [],
             "explanation": "all changes outside inspected paths"})
        req = FakeReq(
            local_path=new, previous_path=old,
            local_path_sha256=_sha256(new), previous_path_sha256=_sha256(old),
        )
        out = await diff_scanner.scan(req)
        assert out["verdict"] == "CLEAN"
        # LLM IS called (no shortcut, raw_counts > 0)
        ai_scanner._client.chat.completions.create.assert_awaited_once()
        prompt = captured["kwargs"]["messages"][1]["content"]
        assert "ignored_changed_paths" in prompt
        assert "tests/test_x.py" in prompt

    @pytest.mark.asyncio
    async def test_anti_injection_delimiters_present(self, tmp_path, monkeypatch):
        new, old = _make_pypi_pair(
            tmp_path,
            {"setup.py": "import os; print('hi')"},
            {"setup.py": "import os"},
        )
        captured = _patch_llm_with_response(monkeypatch,
            {"verdict": "CLEAN", "confidence": 0.6, "findings": [], "explanation": "ok"})
        req = FakeReq(
            local_path=new, previous_path=old,
            local_path_sha256=_sha256(new), previous_path_sha256=_sha256(old),
        )
        await diff_scanner.scan(req)
        prompt = captured["kwargs"]["messages"][1]["content"]
        assert "<package_diff>" in prompt
        assert "</package_diff>" in prompt
        assert "<context>" in prompt
        assert "</context>" in prompt

    @pytest.mark.asyncio
    async def test_install_hook_priority(self, tmp_path, monkeypatch):
        # Setup: install hook present plus tons of unrelated top-level code.
        new_files = {"setup.py": "import os; subprocess.call(['curl'])"}
        old_files = {"setup.py": "import os"}
        # Add many top-level files in NEW only to push past budget.
        for i in range(500):
            new_files[f"mod_{i}.py"] = "x = " + "Z" * 100
        new, old = _make_pypi_pair(tmp_path, new_files, old_files)

        captured = _patch_llm_with_response(monkeypatch,
            {"verdict": "SUSPICIOUS", "confidence": 0.7, "findings": ["subprocess in setup.py"], "explanation": "ok"})
        req = FakeReq(
            local_path=new, previous_path=old,
            local_path_sha256=_sha256(new), previous_path_sha256=_sha256(old),
        )
        await diff_scanner.scan(req)
        prompt = captured["kwargs"]["messages"][1]["content"]
        # Install hook MUST be in the prompt even when other content was truncated.
        assert "MODIFIED INSTALL HOOK: setup.py" in prompt
        assert "subprocess.call" in prompt

    @pytest.mark.asyncio
    async def test_aws_key_redacted(self, tmp_path, monkeypatch):
        new, old = _make_pypi_pair(
            tmp_path,
            {"setup.py": "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"},
            {"setup.py": "AWS_KEY = 'PLACEHOLDER'"},
        )
        captured = _patch_llm_with_response(monkeypatch,
            {"verdict": "CLEAN", "confidence": 0.6, "findings": [], "explanation": "ok"})
        req = FakeReq(
            local_path=new, previous_path=old,
            local_path_sha256=_sha256(new), previous_path_sha256=_sha256(old),
        )
        await diff_scanner.scan(req)
        prompt = captured["kwargs"]["messages"][1]["content"]
        assert "AKIAIOSFODNN7EXAMPLE" not in prompt
        assert "[REDACTED:AWS_KEY]" in prompt

    @pytest.mark.asyncio
    async def test_openai_key_redacted(self, tmp_path, monkeypatch):
        """OpenAI keys MUST be redacted — we're sending content to OpenAI itself."""
        key = "sk-" + "A" * 48
        new, old = _make_pypi_pair(
            tmp_path,
            {"setup.py": f"OPENAI = '{key}'"},
            {"setup.py": "OPENAI = ''"},
        )
        captured = _patch_llm_with_response(monkeypatch,
            {"verdict": "CLEAN", "confidence": 0.6, "findings": [], "explanation": "ok"})
        req = FakeReq(
            local_path=new, previous_path=old,
            local_path_sha256=_sha256(new), previous_path_sha256=_sha256(old),
        )
        await diff_scanner.scan(req)
        prompt = captured["kwargs"]["messages"][1]["content"]
        assert key not in prompt
        assert "[REDACTED:OPENAI_KEY]" in prompt

    @pytest.mark.asyncio
    async def test_github_pat_fg_redacted(self, tmp_path, monkeypatch):
        pat = "github_pat_" + "X" * 82
        new, old = _make_pypi_pair(
            tmp_path,
            {"setup.py": f"TOKEN = '{pat}'"},
            {"setup.py": "TOKEN = ''"},
        )
        captured = _patch_llm_with_response(monkeypatch,
            {"verdict": "CLEAN", "confidence": 0.6, "findings": [], "explanation": "ok"})
        req = FakeReq(
            local_path=new, previous_path=old,
            local_path_sha256=_sha256(new), previous_path_sha256=_sha256(old),
        )
        await diff_scanner.scan(req)
        prompt = captured["kwargs"]["messages"][1]["content"]
        assert pat not in prompt
        assert "[REDACTED:GH_PAT_FG]" in prompt

    @pytest.mark.asyncio
    async def test_truncated_suspicious_low_conf_downgrades_to_clean(self, tmp_path, monkeypatch):
        """SUSPICIOUS verdict on truncated input with confidence < 0.85 must become CLEAN."""
        # Build a payload large enough to trigger truncation.
        new_files = {"setup.py": "import os; subprocess.call(['curl'])"}
        old_files = {"setup.py": "import os"}
        for i in range(2000):
            new_files[f"mod_{i}.py"] = "Z" * 1000   # 2 MB worth of files
        new, old = _make_pypi_pair(tmp_path, new_files, old_files)

        _patch_llm_with_response(monkeypatch,
            {"verdict": "SUSPICIOUS", "confidence": 0.65, "findings": ["weak"], "explanation": "ok"})
        req = FakeReq(
            local_path=new, previous_path=old,
            local_path_sha256=_sha256(new), previous_path_sha256=_sha256(old),
        )
        result = await diff_scanner.scan(req)
        assert result["verdict"] == "CLEAN"
        assert "truncated" in result["explanation"].lower()

    @pytest.mark.asyncio
    async def test_jwt_redacted(self, tmp_path, monkeypatch):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        new, old = _make_pypi_pair(
            tmp_path,
            {"setup.py": f"TOKEN = '{jwt}'"},
            {"setup.py": "TOKEN = 'placeholder'"},
        )
        captured = _patch_llm_with_response(monkeypatch,
            {"verdict": "CLEAN", "confidence": 0.6, "findings": [], "explanation": "ok"})
        req = FakeReq(
            local_path=new, previous_path=old,
            local_path_sha256=_sha256(new), previous_path_sha256=_sha256(old),
        )
        await diff_scanner.scan(req)
        prompt = captured["kwargs"]["messages"][1]["content"]
        assert jwt not in prompt
        assert "[REDACTED:JWT]" in prompt

    @pytest.mark.asyncio
    async def test_invalid_json_returns_unknown(self, tmp_path, monkeypatch):
        new, old = _make_pypi_pair(
            tmp_path,
            {"setup.py": "import os; print('hi')"},
            {"setup.py": "import os"},
        )

        # Override the patcher to return non-JSON text.
        class FakeResp:
            class FakeChoice:
                class FakeMessage:
                    content = "this is not json"
                message = FakeMessage()
            choices = [FakeChoice()]
            class FakeUsage:
                total_tokens = 100
            usage = FakeUsage()

        async def fake_create(**kwargs):
            return FakeResp()

        fake_client = MagicMock()
        fake_client.chat.completions.create = AsyncMock(side_effect=fake_create)
        monkeypatch.setattr(ai_scanner, "_client", fake_client)
        monkeypatch.setattr(ai_scanner, "_model", "gpt-test")

        req = FakeReq(
            local_path=new, previous_path=old,
            local_path_sha256=_sha256(new), previous_path_sha256=_sha256(old),
        )
        out = await diff_scanner.scan(req)
        assert out["verdict"] == "UNKNOWN"
        assert "JSON" in out["explanation"]

    @pytest.mark.asyncio
    async def test_malicious_verdict_passes_through(self, tmp_path, monkeypatch):
        """Bridge does not downgrade MALICIOUS — Go side does."""
        new, old = _make_pypi_pair(
            tmp_path,
            {"setup.py": "import subprocess; subprocess.call(['curl', 'evil'])"},
            {"setup.py": "import subprocess"},
        )
        _patch_llm_with_response(monkeypatch,
            {"verdict": "MALICIOUS", "confidence": 0.95, "findings": ["subprocess+curl"], "explanation": "ok"})
        req = FakeReq(
            local_path=new, previous_path=old,
            local_path_sha256=_sha256(new), previous_path_sha256=_sha256(old),
        )
        out = await diff_scanner.scan(req)
        assert out["verdict"] == "MALICIOUS"
        assert out["confidence"] == 0.95

    @pytest.mark.asyncio
    async def test_log_only_prompt_hash(self, tmp_path, monkeypatch, caplog):
        new, old = _make_pypi_pair(
            tmp_path,
            {"setup.py": "import os"},
            {"setup.py": ""},
        )
        _patch_llm_with_response(monkeypatch,
            {"verdict": "CLEAN", "confidence": 0.6, "findings": [], "explanation": "ok"})
        req = FakeReq(
            local_path=new, previous_path=old,
            local_path_sha256=_sha256(new), previous_path_sha256=_sha256(old),
        )
        with caplog.at_level("INFO"):
            await diff_scanner.scan(req)
        # The implementation logs "user_prompt_sha=<hash>" — assert that the
        # hash field is logged but the raw prompt content (containing
        # "<package_diff>") is NOT.
        assert any("user_prompt_sha=" in rec.message for rec in caplog.records)
        # The actual prompt content (which contains "<package_diff>") must NOT be logged.
        assert not any("<package_diff>" in rec.message for rec in caplog.records)
