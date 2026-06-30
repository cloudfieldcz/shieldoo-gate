"""Unit tests for classify_guarddog_result — the GuardDog 3.0 verdict mapping.

GuardDog 3.0 replaced the semgrep engine with a native threat/capability model:
scan_local() now returns descriptive ``capability-*`` detectors (which fire on
legitimate packages) alongside real ``threat-*`` / metadata detectors, plus an
aggregate ``risk_score`` with a ``label``. The bridge must treat capability-only
results as CLEAN (else it false-positive-blocks any package that touches the
network or a subprocess) while still flagging real threats. The fixtures below
are trimmed copies of actual ``guarddog==3.0.2`` output.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import classify_guarddog_result  # noqa: E402


# Real guarddog==3.0.2 output for a package doing base64-exec + download-and-run.
MALICIOUS_PYPI = {
    "results": {
        "threat-process-download-exec": 1,
        "threat-runtime-obfuscation-base64exec": 1,
        "capability-process-spawn": 1,
        "capability-network-lolbas": 1,
    },
    "errors": {},
    "issues": 10,
    "risk_score": {"score": 8.8, "label": "high_risk", "findings_count": 4},
    "risks": [
        {
            "name": "risk.process.spawn",
            "category": "process",
            "severity": "high",
            "mitre_tactics": ["execution"],
            "threat_rule": "threat-process-download-exec",
            "threat_description": "Detects download-and-execute patterns",
            "threat_location": "evilpkg/__init__.py:4",
            "threat_match": "subprocess.Popen(",
        },
        {
            "name": "risk.runtime.obfuscation",
            "category": "runtime",
            "severity": "high",
            "mitre_tactics": ["defense-evasion"],
            "threat_rule": "threat-runtime-obfuscation-base64exec",
            "threat_description": "Detects base64-decoded exec",
            "threat_location": "evilpkg/__init__.py:3",
            "threat_match": "exec(base64.b64decode(",
        },
    ],
}

# Real guarddog==3.0.2 output for a benign package that uses subprocess + urllib.
BENIGN_CAPABILITY_ONLY = {
    "results": {
        "capability-filesystem-read": 1,
        "capability-network-download": 1,
        "capability-process-spawn": 1,
        "capability-network-outbound": 1,
    },
    "errors": {},
    "issues": 6,
    "risk_score": {"score": 0.0, "label": "no_risks_detected", "findings_count": 4},
    "risks": [],
}


def test_classify_guarddog_result_capability_only_returns_clean():
    """A package whose only detectors are capability-* must NOT be MALICIOUS."""
    verdict, confidence, findings = classify_guarddog_result(BENIGN_CAPABILITY_ONLY)
    assert verdict == "CLEAN"
    assert confidence == 1.0
    assert findings == []


def test_classify_guarddog_result_threat_rules_returns_malicious():
    verdict, confidence, findings = classify_guarddog_result(MALICIOUS_PYPI)
    assert verdict == "MALICIOUS"
    assert confidence == 0.95
    categories = {f["category"] for f in findings}
    # Real threats are reported...
    assert "threat-process-download-exec" in categories
    assert "threat-runtime-obfuscation-base64exec" in categories
    # ...capabilities are NOT promoted to findings.
    assert not any(c.startswith("capability-") for c in categories)


def test_classify_guarddog_result_findings_carry_structured_detail():
    _, _, findings = classify_guarddog_result(MALICIOUS_PYPI)
    by_rule = {f["category"]: f for f in findings}
    f = by_rule["threat-process-download-exec"]
    assert f["severity"] == "HIGH"
    assert f["location"] == "evilpkg/__init__.py:4"
    assert "subprocess.Popen(" in f["iocs"]
    assert "execution" in f["iocs"]  # mitre tactic carried into iocs


def test_classify_guarddog_result_metadata_threat_without_score_returns_malicious():
    """Metadata threats (e.g. typosquatting) must flag even if risk_score is benign.

    Guards against under-blocking: a non-capability detector fired, so the
    verdict must be MALICIOUS regardless of the numeric risk_score label.
    """
    result = {
        "results": {"typosquatting": ["requests"], "capability-network-outbound": 1},
        "risk_score": {"score": 0.0, "label": "no_risks_detected"},
        "risks": [],
    }
    verdict, confidence, findings = classify_guarddog_result(result)
    assert verdict == "MALICIOUS"
    categories = {f["category"] for f in findings}
    assert "typosquatting" in categories
    assert "capability-network-outbound" not in categories


def test_classify_guarddog_result_risky_score_without_detail_still_flags():
    """risk_score says risky but no rule/risks detail — fail toward MALICIOUS."""
    result = {"results": {}, "risk_score": {"score": 5.0, "label": "medium_risk"}, "risks": []}
    verdict, _, findings = classify_guarddog_result(result)
    assert verdict == "MALICIOUS"
    assert len(findings) == 1
    assert findings[0]["category"] == "guarddog"


def test_classify_guarddog_result_empty_returns_clean():
    for empty in ({}, {"results": {}}, {"results": {}, "risk_score": {}}):
        verdict, confidence, findings = classify_guarddog_result(empty)
        assert verdict == "CLEAN"
        assert findings == []


def test_classify_guarddog_result_non_dict_input_returns_clean():
    """Defensive: an unexpected shape must not crash and must not over-flag."""
    verdict, _, findings = classify_guarddog_result(None)
    assert verdict == "CLEAN"
    assert findings == []


def test_classify_guarddog_result_skips_empty_rule_matches():
    """Rules present but with empty match collections are not findings."""
    result = {"results": {"threat-x": [], "capability-y": 1}, "risk_score": {"label": "no_risks_detected"}}
    verdict, _, findings = classify_guarddog_result(result)
    assert verdict == "CLEAN"
    assert findings == []
