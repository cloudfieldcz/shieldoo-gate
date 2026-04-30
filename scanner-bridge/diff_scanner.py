"""Version-Diff AI scanner — calls LLM with a structured diff payload.

Pipeline:
  1. Re-verify SHA256 of both archive paths (TOCTOU defense).
  2. Run the per-ecosystem extractor (extractors_diff.<eco>).
  3. Strict empty-diff shortcut: if raw_counts == (0,0,0), return CLEAN.
  4. Redact known secret patterns from inspected content.
  5. Build the prompt under MAX_INPUT_CHARS, reserving 32 KB for install hooks.
  6. Single-shot LLM call (temperature=0, JSON response_format).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import pathlib
import re

from extractors_diff import EXTRACTORS, DiffPayload, empty_payload

import ai_scanner  # shared OpenAI client + model

logger = logging.getLogger(__name__)

PROMPTS_DIR = pathlib.Path(__file__).parent / "prompts"
MAX_INPUT_CHARS = 128_000               # ~32k tokens for gpt-5.4-mini
INSTALL_HOOK_RESERVATION = 32 * 1024    # bytes reserved for install hooks
LLM_TIMEOUT_SECONDS = 40.0              # bridge handler timeout is 50 s; this is the openai call cap
PROMPT_VERSION_PREFIX_LEN = 12          # SHA256[:12] of system prompt — Go uses for cache key


def _system_prompt_text() -> str:
    return (PROMPTS_DIR / "version_diff_analyst.txt").read_text(encoding="utf-8")


def _system_prompt_version() -> str:
    """Stable identity hash of the current system prompt content.

    Read fresh on each call so a prompt edit on disk is picked up without
    bridge restart (operators can hot-swap the prompt during shadow mode).
    The Go side persists this in version_diff_results.ai_prompt_version,
    making it part of the idempotency cache key — a prompt edit invalidates
    cache automatically.
    """
    return hashlib.sha256(_system_prompt_text().encode("utf-8")).hexdigest()[:PROMPT_VERSION_PREFIX_LEN]


# --- Secret redaction --------------------------------------------------------

_SECRET_PATTERNS = [
    # AWS
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED:AWS_KEY]"),
    (re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"]([A-Za-z0-9/+=]{40})['\"]"),
     "aws_secret_access_key=[REDACTED:AWS_SECRET]"),
    # GitHub — classic and fine-grained
    (re.compile(r"\bgh[ps]_[A-Za-z0-9]{36,}\b"), "[REDACTED:GH_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"), "[REDACTED:GH_PAT_FG]"),
    # GitLab
    (re.compile(r"\bglpat-[A-Za-z0-9_-]{20}\b"), "[REDACTED:GITLAB_PAT]"),
    # Slack
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED:SLACK_TOKEN]"),
    # OpenAI (ironic — the destination is OpenAI itself)
    (re.compile(r"\bsk-[A-Za-z0-9]{48}\b"), "[REDACTED:OPENAI_KEY]"),
    (re.compile(r"\bsk-proj-[A-Za-z0-9_-]{40,}\b"), "[REDACTED:OPENAI_PROJ_KEY]"),
    # Stripe
    (re.compile(r"\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{24,}\b"), "[REDACTED:STRIPE_KEY]"),
    # Twilio
    (re.compile(r"\bSK[a-f0-9]{32}\b"), "[REDACTED:TWILIO_KEY]"),
    # Google API key
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "[REDACTED:GOOGLE_KEY]"),
    # JWT (three base64 segments separated by dots). Real JWT headers can be
    # as short as 17 chars after the eyJ prefix (e.g. "eyJhbGciOiJIUzI1NiJ9"
    # used by the HS256/none algorithms with no extra header fields), so the
    # first-segment threshold is intentionally relaxed.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{20,}\b"),
     "[REDACTED:JWT]"),
    # PEM private keys (RSA/EC/OPENSSH/DSA/PKCS#8 unencrypted) — non-greedy across newlines
    (re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |)PRIVATE KEY-----"
        r"[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED |)PRIVATE KEY-----",
        re.MULTILINE,
    ), "[REDACTED:PRIVATE_KEY]"),
    # PuTTY
    (re.compile(r"PuTTY-User-Key-File-\d+:[\s\S]+?Private-MAC: [a-f0-9]+", re.MULTILINE),
     "[REDACTED:PUTTY_KEY]"),
    # Azure storage connection string
    (re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=[^\s\"']+"),
     "[REDACTED:AZURE_CONN_STR]"),
    # Generic password=/api_key=/secret= with quoted value (>=8 chars).
    # Negative lookahead after the opening quote prevents re-redacting already-
    # redacted values left behind by specific patterns above (e.g. JWT/GH_PAT
    # both leave "[REDACTED:...]" inside the quotes; without the guard the
    # generic pattern would clobber them and lose the specific redaction tag).
    (re.compile(r"(?i)(password|api[_-]?key|secret|token)\s*[:=]\s*['\"](?!\[REDACTED:)[^'\"\n]{8,}['\"]"),
     r"\1=[REDACTED:GENERIC_SECRET]"),
]


def _redact(text: str) -> str:
    out = text
    for pattern, replacement in _SECRET_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def _redact_payload(payload: DiffPayload) -> None:
    """In-place redaction of payload.added and payload.modified."""
    payload["added"] = {p: _redact(c) for p, c in payload["added"].items()}
    payload["modified"] = {
        p: (_redact(diff_text), tail)
        for p, (diff_text, tail) in payload["modified"].items()
    }


# --- Path SHA256 verification -----------------------------------------------

def _verify_sha256(path: str, expected: str) -> bool:
    """Return True if SHA256 of file at path equals expected hex digest. Empty expected = skip."""
    if not expected:
        return True
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(64 * 1024), b""):
                h.update(chunk)
        return hmac.compare_digest(h.hexdigest(), expected.lower())
    except Exception as e:
        logger.warning("diff_scanner: sha256 verify failed for %s: %s", path, e)
        return False


# --- Prompt builder ----------------------------------------------------------

def _build_prompt(req, payload: DiffPayload) -> tuple[str, bool]:
    """Build the user-message content from a DiffPayload.

    Returns (prompt_text, was_truncated). Honors INSTALL_HOOK_RESERVATION:
    install hooks get a reserved 32 KB slice of MAX_INPUT_CHARS, with the
    remainder available for other sections. Unused install-hook budget is
    NOT refunded to other sections — this keeps the budget reasoning simple
    and predictable when many install hooks come in mixed with bulk code.
    """
    truncated = payload["partial"]

    context = {
        "name": req.name,
        "version": req.version,
        "previous_version": req.previous_version,
        "ecosystem": req.ecosystem,
        "raw_counts": list(payload["raw_counts"]),
        "inspected_counts": list(payload["inspected_counts"]),
        "install_hook_paths": payload["install_hook_paths"],
        "top_level_code_paths": payload["top_level_code_paths"],
        "ignored_changed_paths": payload["ignored_changed_paths"][:50],   # cap list noise
        "removed": payload["removed"][:50],
        "truncated_files": payload["truncated_files"][:50],
    }

    header = f"<context>\n{json.dumps(context, indent=2)}\n</context>\n\n"
    diff_open = "<package_diff>\n"
    diff_close = "\n</package_diff>"
    fixed_overhead = len(header) + len(diff_open) + len(diff_close) + 64  # truncation marker

    available = MAX_INPUT_CHARS - fixed_overhead

    install_hook_set = set(payload["install_hook_paths"])

    def _sections() -> list[tuple[str, str]]:
        """Ordered sections (label, content) before budgeting."""
        sec: list[tuple[str, str]] = []
        # Priority a: added install hooks (full content)
        for p in payload["install_hook_paths"]:
            if p in payload["added"]:
                sec.append((f"=== ADDED INSTALL HOOK: {p} ===\n", payload["added"][p]))
        # Priority b: modified install hooks (unified diff)
        for p in payload["install_hook_paths"]:
            if p in payload["modified"]:
                diff_text = payload["modified"][p][0]
                sec.append((f"=== MODIFIED INSTALL HOOK: {p} ===\n", diff_text))
        # Priority c: added top-level code
        for p in payload["top_level_code_paths"]:
            if p in payload["added"]:
                sec.append((f"=== ADDED TOP-LEVEL CODE: {p} ===\n", payload["added"][p]))
        # Priority d: modified top-level code
        for p in payload["top_level_code_paths"]:
            if p in payload["modified"]:
                diff_text = payload["modified"][p][0]
                sec.append((f"=== MODIFIED TOP-LEVEL CODE: {p} ===\n", diff_text))
        # Priority e: anything else in added/modified that's not yet covered
        seen = install_hook_set | set(payload["top_level_code_paths"])
        for p, content in payload["added"].items():
            if p not in seen:
                sec.append((f"=== ADDED OTHER: {p} ===\n", content))
        for p, (diff_text, _) in payload["modified"].items():
            if p not in seen:
                sec.append((f"=== MODIFIED OTHER: {p} ===\n", diff_text))
        return sec

    sections = _sections()

    # Reserve install hook budget. Budget = max(INSTALL_HOOK_RESERVATION, 0).
    install_hook_budget = INSTALL_HOOK_RESERVATION
    install_hook_used = 0
    install_hook_chunks: list[str] = []
    other_chunks: list[str] = []
    other_budget = available - install_hook_budget
    if other_budget < 0:
        other_budget = 0
    other_used = 0

    for label, content in sections:
        # Determine if this section relates to an install hook by inspecting label.
        is_hook_section = "INSTALL HOOK" in label
        chunk = label + content + "\n"
        chunk_len = len(chunk)

        if is_hook_section:
            remaining = install_hook_budget - install_hook_used
            if remaining <= 0:
                # Install hook budget exhausted — fall through to general budget.
                pass
            else:
                if chunk_len <= remaining:
                    install_hook_chunks.append(chunk)
                    install_hook_used += chunk_len
                    continue
                truncated = True
                cut = chunk[:max(0, remaining - 32)] + "\n[INPUT_TRUNCATED]\n"
                install_hook_chunks.append(cut)
                install_hook_used += len(cut)
                continue

        # General budget
        remaining = other_budget - other_used
        if remaining <= 0:
            truncated = True
            break
        if chunk_len <= remaining:
            other_chunks.append(chunk)
            other_used += chunk_len
        else:
            truncated = True
            cut = chunk[:max(0, remaining - 32)] + "\n[INPUT_TRUNCATED]\n"
            other_chunks.append(cut)
            other_used += len(cut)
            break

    body = "".join(install_hook_chunks) + "".join(other_chunks)
    if truncated and "[INPUT_TRUNCATED]" not in body:
        body += "\n[INPUT_TRUNCATED]\n"

    prompt = header + diff_open + body + diff_close
    return prompt, truncated


# --- LLM call ---------------------------------------------------------------

async def _call_llm(prompt: str, prompt_version: str) -> dict:
    """Single-shot LLM call. Returns dict with verdict/confidence/etc.

    Logs only the user-prompt SHA hash, never raw content. prompt_version
    is the SHA[:12] of the system prompt — recorded on the response so the
    Go side can persist it as part of the idempotency cache key.
    """
    system_prompt = _system_prompt_text()

    prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]
    logger.info(
        "diff_scanner: calling LLM model=%s prompt_chars=%d user_prompt_sha=%s system_prompt_version=%s",
        ai_scanner._model, len(prompt), prompt_hash, prompt_version,
    )

    try:
        resp = await ai_scanner._client.chat.completions.create(
            model=ai_scanner._model,
            max_completion_tokens=1024,
            temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            timeout=LLM_TIMEOUT_SECONDS,
        )
        raw = resp.choices[0].message.content
        if raw is None:
            return _unknown("LLM returned empty content (finish_reason=length or content_filter)")
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.error("diff_scanner: LLM returned invalid JSON: %s", e)
        return _unknown(f"LLM returned invalid JSON: {e}")
    except Exception as e:
        logger.error("diff_scanner: LLM call failed: %s", e)
        return _unknown(f"LLM call failed: {e}")

    parsed.setdefault("verdict", "UNKNOWN")
    parsed.setdefault("confidence", 0.0)
    parsed.setdefault("findings", [])
    parsed.setdefault("explanation", "")
    parsed["model_used"] = ai_scanner._model
    parsed["tokens_used"] = resp.usage.total_tokens if resp.usage else 0
    parsed["prompt_version"] = prompt_version  # echoed back so Go can persist as ai_prompt_version
    return parsed


# --- Result helpers ---------------------------------------------------------

def _unknown(explanation: str, *, files_added: int = 0, files_modified: int = 0, files_removed: int = 0) -> dict:
    return {
        "verdict": "UNKNOWN",
        "confidence": 0.0,
        "findings": [],
        "explanation": explanation,
        "model_used": "none",
        "tokens_used": 0,
        "files_added": files_added,
        "files_modified": files_modified,
        "files_removed": files_removed,
        "prompt_version": "",
        "input_truncated": False,
    }


def _clean(explanation: str, *, files_added: int, files_modified: int, files_removed: int) -> dict:
    return {
        "verdict": "CLEAN",
        "confidence": 0.5,
        "findings": [],
        "explanation": explanation,
        "model_used": "none",
        "tokens_used": 0,
        "files_added": files_added,
        "files_modified": files_modified,
        "files_removed": files_removed,
        "prompt_version": _system_prompt_version(),
        "input_truncated": False,
    }


# --- Entry point ------------------------------------------------------------

async def scan(request) -> dict:
    """Entry point invoked from the gRPC handler in main.py."""
    extractor = EXTRACTORS.get(request.ecosystem)
    if extractor is None:
        return _unknown(f"ecosystem '{request.ecosystem}' not supported for diff analysis")

    # 1. SHA256 verification (TOCTOU defense).
    expect_new = getattr(request, "local_path_sha256", "") or ""
    expect_old = getattr(request, "previous_path_sha256", "") or ""
    if not _verify_sha256(request.local_path, expect_new):
        return _unknown("local_path SHA256 mismatch")
    if not _verify_sha256(request.previous_path, expect_old):
        return _unknown("previous_path SHA256 mismatch")

    # 2. Extract.
    try:
        payload = extractor(request.local_path, request.previous_path,
                            original_filename=getattr(request, "original_filename", "") or "")
    except Exception as e:
        logger.exception("diff_scanner: extractor failed for %s", request.artifact_id)
        return _unknown(f"extraction failed: {e}")

    if payload.get("error"):
        return _unknown(payload["error"])

    raw_added, raw_modified, raw_removed = payload["raw_counts"]

    # 3. Strict empty-diff shortcut: raw_counts AFTER nothing-was-filtered means archive bytes are equal.
    if raw_added == 0 and raw_modified == 0 and raw_removed == 0:
        return _clean(
            "no file changes between versions (raw_counts == 0)",
            files_added=0, files_modified=0, files_removed=0,
        )

    # 4. If everything is filtered (only changes in tests/docs), still call LLM but with low expectation.
    #    The prompt instructs CLEAN@0.5 if only ignored_changed_paths changed.

    # 5. Redact secrets in payload before prompt building.
    _redact_payload(payload)

    # 6. Build prompt + call LLM. The system prompt's SHA[:12] is the canonical
    # prompt_version — read fresh from disk so a hot-swap on shadow rollout
    # automatically invalidates idempotency cache. The request.prompt_version
    # is ignored here (it's a Go-side hint, not authoritative).
    prompt, truncated = _build_prompt(request, payload)
    prompt_version = _system_prompt_version()
    result = await _call_llm(prompt, prompt_version)

    # Merge counts and truncation flag.
    result["files_added"] = raw_added
    result["files_modified"] = raw_modified
    result["files_removed"] = raw_removed
    result["input_truncated"] = truncated

    # Defense-in-depth on truncated input: a SUSPICIOUS verdict on partial
    # data is structurally weak — downgrade to CLEAN unless confidence is
    # very high (>= 0.85, which the prompt instructs against on truncation).
    # Also cap MALICIOUS confidence so the Go side's downgrade still fires.
    if truncated:
        v = result.get("verdict", "UNKNOWN")
        c = result.get("confidence", 0.0)
        if v == "SUSPICIOUS" and c < 0.85:
            result["verdict"] = "CLEAN"
            result["confidence"] = 0.5
            result["findings"] = []
            result["explanation"] = (
                "[input truncated; SUSPICIOUS@%.2f below truncation-confidence threshold] %s"
                % (c, result.get("explanation", ""))
            )[:500]
        elif c > 0.7:
            result["confidence"] = 0.7
    return result
