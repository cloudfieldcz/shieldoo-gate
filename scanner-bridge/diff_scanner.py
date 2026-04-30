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
        "prompt_version": "",
        "input_truncated": False,
    }
