"""Tests for vuln_drafter module (with mocked LLM client)."""

import json
import os
import sys
import types

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import vuln_drafter  # noqa: E402


def _make_request(**kw):
    req = types.SimpleNamespace(
        component_id=42,
        cve_id="CVE-2024-1",
        package_name="requests",
        package_version="2.31.0",
        ecosystem="pypi",
        cve_summary="HTTP request smuggling via Transfer-Encoding header",
        repo_url="https://github.com/psf/requests",
        operator_email="ops@example.com",
    )
    for k, v in kw.items():
        setattr(req, k, v)
    return req


class _FakeChatCompletions:
    def __init__(self, content: str, tokens_used: int = 100):
        self._content = content
        self._tokens_used = tokens_used

    async def create(self, **kw):  # noqa: ANN001
        # Mimic the openai async client response shape.
        ns = types.SimpleNamespace
        return ns(
            choices=[ns(message=ns(content=self._content))],
            usage=ns(total_tokens=self._tokens_used),
        )


class _FakeClient:
    def __init__(self, content: str, tokens_used: int = 100):
        self.chat = types.SimpleNamespace(
            completions=_FakeChatCompletions(content, tokens_used)
        )


@pytest.mark.asyncio
async def test_draft_returns_clean_reason():
    payload = json.dumps({"reason": "Not exploitable in our usage — vulnerable function never called from API surface."})
    client = _FakeClient(payload, tokens_used=130)
    result = await vuln_drafter.draft(_make_request(), client, "gpt-5")
    assert result["reason"].startswith("Not exploitable")
    assert result["model_used"] == "gpt-5"
    assert result["tokens_used"] == 130
    assert result["from_cache"] is False


@pytest.mark.asyncio
async def test_draft_strips_code_fences():
    # Some models wrap JSON in ```json ... ``` — drafter must recover.
    payload = "```json\n" + json.dumps({"reason": "Bounded blast radius — only used for static asset version pinning."}) + "\n```"
    client = _FakeClient(payload, tokens_used=80)
    result = await vuln_drafter.draft(_make_request(), client, "gpt-5")
    assert "Bounded blast radius" in result["reason"]


@pytest.mark.asyncio
async def test_draft_truncates_oversized_reason():
    huge = "x" * 1500  # well over MAX_REASON_CHARS=500
    payload = json.dumps({"reason": huge})
    client = _FakeClient(payload, tokens_used=50)
    result = await vuln_drafter.draft(_make_request(), client, "gpt-5")
    assert len(result["reason"]) == vuln_drafter.MAX_REASON_CHARS


@pytest.mark.asyncio
async def test_draft_sanitizes_html_and_control_bytes():
    # Prompt-injection attempt: <script> tag + control chars in the reason.
    payload = json.dumps({"reason": "Safe<script>alert(1)</script>\x00 because reasons."})
    client = _FakeClient(payload, tokens_used=60)
    result = await vuln_drafter.draft(_make_request(), client, "gpt-5")
    # Sanitizer strips HTML tags and control bytes; "<script>...</script>" → "alert(1)"
    # but the literal "Safe" prefix and " because reasons." suffix stay intact.
    assert "<script>" not in result["reason"]
    assert "\x00" not in result["reason"]
    assert "Safe" in result["reason"]
    assert "because reasons." in result["reason"]


@pytest.mark.asyncio
async def test_draft_returns_empty_on_invalid_json():
    # Non-JSON output → drafter returns empty reason, never raises.
    client = _FakeClient("absolute garbage with no json")
    result = await vuln_drafter.draft(_make_request(), client, "gpt-5")
    assert result["reason"] == ""
    assert result["tokens_used"] == 0


@pytest.mark.asyncio
async def test_draft_returns_empty_when_reason_field_missing():
    # JSON without the "reason" field → empty (operator gets the 503 path).
    payload = json.dumps({"explanation": "wrong schema"})
    client = _FakeClient(payload, tokens_used=10)
    result = await vuln_drafter.draft(_make_request(), client, "gpt-5")
    assert result["reason"] == ""


@pytest.mark.asyncio
async def test_draft_returns_empty_on_client_error():
    class _Err:
        async def create(self, **kw):
            raise RuntimeError("simulated upstream failure")
    client = types.SimpleNamespace(chat=types.SimpleNamespace(completions=_Err()))
    result = await vuln_drafter.draft(_make_request(), client, "gpt-5")
    # Failure path must NEVER propagate the raw exception text.
    assert result["reason"] == ""
    assert result["model_used"] == "gpt-5"
    assert result["tokens_used"] == 0
