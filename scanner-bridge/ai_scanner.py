"""AI Scanner — LLM-based supply chain security analysis.

Uses a single-pass gpt-5.4-mini call to analyze extracted install-time scripts
for malicious patterns. Communicates with Azure OpenAI or OpenAI API.
"""

import json
import logging
import os
import pathlib

from openai import AsyncAzureOpenAI, AsyncOpenAI

from extractors import EXTRACTORS

logger = logging.getLogger(__name__)

MAX_INPUT_CHARS = 128_000  # ~32 000 tokens

PROMPTS_DIR = pathlib.Path(__file__).parent / "prompts"


def _build_client() -> tuple:
    """Build the appropriate OpenAI client based on environment configuration.

    Returns (client, model) tuple. Supports both Azure OpenAI and standard OpenAI.
    """
    provider = os.environ.get("AI_SCANNER_PROVIDER", "azure_openai")
    model = os.environ.get("AI_SCANNER_MODEL", "gpt-5.4-mini")

    if provider == "azure_openai":
        endpoint = os.environ.get("AI_SCANNER_AZURE_ENDPOINT", "")
        deployment = os.environ.get("AI_SCANNER_AZURE_DEPLOYMENT", model)
        api_key = os.environ.get("AI_SCANNER_API_KEY", "")
        api_version = os.environ.get("AI_SCANNER_AZURE_API_VERSION", "2025-04-01-preview")
        client = AsyncAzureOpenAI(
            azure_endpoint=endpoint,
            azure_deployment=deployment,
            api_key=api_key,
            api_version=api_version,
        )
        return client, deployment
    else:
        api_key = os.environ.get("AI_SCANNER_API_KEY", "")
        client = AsyncOpenAI(api_key=api_key)
        return client, model


# Module-level client and model, initialized once on import.
_client, _model = _build_client()


async def scan(request) -> dict:
    """Main entry point called from the gRPC handler.

    Args:
        request: AIScanRequest protobuf message with ecosystem, name, version, local_path.

    Returns:
        dict with verdict, confidence, findings, explanation, model_used, tokens_used.
    """
    extractor = EXTRACTORS.get(request.ecosystem)
    if not extractor:
        return _unknown(f"ecosystem '{request.ecosystem}' not supported for AI analysis")

    try:
        extracted = extractor(request.local_path)
    except Exception as e:
        logger.error("ai_scanner: extraction failed for %s: %s", request.artifact_id, e)
        return _unknown(f"extraction failed: {e}")

    if not extracted:
        return _clean("no install-time scripts found")

    prompt_content = _build_prompt(request, extracted)
    return await _call_llm(prompt_content)


async def _call_llm(content: str) -> dict:
    """Call the LLM with the extracted content and parse the response."""
    system_prompt_path = PROMPTS_DIR / "security_analyst.txt"
    system_prompt = system_prompt_path.read_text(encoding="utf-8")

    try:
        resp = await _client.chat.completions.create(
            model=_model,
            max_completion_tokens=1024,
            temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": content},
            ],
            timeout=15.0,
        )

        parsed = json.loads(resp.choices[0].message.content)
        # Ensure required fields.
        parsed.setdefault("verdict", "UNKNOWN")
        parsed.setdefault("confidence", 0.0)
        parsed.setdefault("findings", [])
        parsed.setdefault("explanation", "")
        parsed["model_used"] = _model
        parsed["tokens_used"] = resp.usage.total_tokens if resp.usage else 0
        return parsed

    except json.JSONDecodeError as e:
        logger.error("ai_scanner: failed to parse LLM response: %s", e)
        return _unknown(f"LLM returned invalid JSON: {e}")
    except Exception as e:
        logger.error("ai_scanner: LLM call failed: %s", e)
        return _unknown(f"LLM call failed: {e}")


def _build_prompt(req, extracted: dict[str, str]) -> str:
    """Build the user prompt from extracted files, respecting token limits."""
    parts = [f"Package: {req.name} {req.version} (ecosystem: {req.ecosystem})\n"]
    total = len(parts[0])

    for filename, content in extracted.items():
        chunk = f"\n=== FILE: {filename} ===\n{content}\n"
        if total + len(chunk) > MAX_INPUT_CHARS:
            remaining = MAX_INPUT_CHARS - total - 100
            if remaining > 0:
                chunk = chunk[:remaining] + "\n[TRUNCATED]"
            else:
                break
        parts.append(chunk)
        total += len(chunk)
        if total >= MAX_INPUT_CHARS:
            break

    return "".join(parts)


def _clean(explanation: str) -> dict:
    return {
        "verdict": "CLEAN",
        "confidence": 0.5,
        "findings": [],
        "explanation": explanation,
        "model_used": "none",
        "tokens_used": 0,
    }


def _unknown(explanation: str) -> dict:
    return {
        "verdict": "UNKNOWN",
        "confidence": 0.0,
        "findings": [],
        "explanation": explanation,
        "model_used": "none",
        "tokens_used": 0,
    }
