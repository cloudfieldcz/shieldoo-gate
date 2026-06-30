"""GuardDog + AI scanner bridge — gRPC server for Shieldoo Gate."""

import asyncio
import logging
import os
import time
from concurrent import futures

import grpc

# Generated proto imports (generate with: python -m grpc_tools.protoc ...)
import proto.scanner_pb2 as scanner_pb2
import proto.scanner_pb2_grpc as scanner_pb2_grpc
import diff_scanner
import scratch_janitor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-5s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

GUARDDOG_VERSION = "3.0.2"

# AI scanner is optional — only loaded when enabled via environment.
AI_SCANNER_ENABLED = os.environ.get("AI_SCANNER_ENABLED", "false").lower() == "true"

# gRPC server thread-pool size = the number of scans that may run concurrently.
# Each worker runs GuardDog's source-code + metadata analysis, which is CPU- and
# memory-heavy; on a small host a burst (e.g. a full `npm ci`) fanning out to
# all 64 default workers oversubscribes the CPU, so individual scans slow past
# the gate's scanner timeout and a required scanner fails closed (503). Cap it
# via BRIDGE_MAX_WORKERS to match the host so each scan gets enough CPU to
# finish inside the deadline.
DEFAULT_MAX_WORKERS = 64

# GuardDog 3.0 emits two detector families in scan_local()["results"]:
#   - "capability-*": descriptive capabilities (network / process-spawn /
#     filesystem use). These fire on plenty of LEGITIMATE packages and are NOT,
#     on their own, evidence of malice — GuardDog folds them into risk_score
#     separately rather than treating them as findings.
#   - everything else ("threat-*" source-code threats + metadata threats such as
#     "typosquatting" / "deceptive_author" / "metadata_mismatch"): real findings.
# GuardDog 2.x (semgrep-based) had no capability family, so the bridge treated
# any non-empty rule match as MALICIOUS. Under 3.0 that over-blocks every package
# touching the network or a subprocess, so we now ignore capability-only results
# and key the verdict off real detectors plus GuardDog's own aggregate
# risk_score["label"] ("no_risks_detected" vs "low/medium/high_risk").
GUARDDOG_CAPABILITY_PREFIX = "capability-"


def classify_guarddog_result(results):
    """Map a GuardDog 3.0 scan_local() result to (verdict, confidence, findings).

    ``findings`` is a list of plain dicts (severity/category/description/
    location/iocs) so this stays pure and unit-testable without the proto layer.

    Returns ("CLEAN", 1.0, []) for benign or capability-only results, and
    ("MALICIOUS", 0.95, [...]) when a real (non-capability) detector fired OR
    GuardDog scored the package as risky. The dual condition still catches
    metadata threats that may not move the numeric score while ignoring
    capability-only noise.
    """
    if not isinstance(results, dict):
        results = {"results": results or {}}

    rule_results = results.get("results", {}) or {}
    risk_score = results.get("risk_score") or {}
    risk_label = (risk_score.get("label") or "").strip()

    threat_rules = {
        name: matches
        for name, matches in rule_results.items()
        if matches and not name.startswith(GUARDDOG_CAPABILITY_PREFIX)
    }
    scored_risky = bool(risk_label) and risk_label != "no_risks_detected"

    if not threat_rules and not scored_risky:
        return "CLEAN", 1.0, []

    findings = []
    covered = set()
    # Prefer GuardDog's structured risk objects (rich severity / location / MITRE).
    for risk in results.get("risks") or []:
        if not isinstance(risk, dict):
            continue
        rule = risk.get("threat_rule") or risk.get("name") or "guarddog"
        covered.add(rule)
        iocs = []
        if risk.get("threat_match"):
            iocs.append(str(risk["threat_match"]))
        iocs.extend(str(t) for t in (risk.get("mitre_tactics") or []))
        findings.append({
            "severity": (risk.get("severity") or "high").upper(),
            "category": rule,
            "description": risk.get("threat_description") or rule,
            "location": risk.get("threat_location") or "",
            "iocs": iocs,
        })
    # Cover non-capability detectors not represented in risks[] (e.g. metadata
    # threats like typosquatting, which need not populate the structured array).
    for name in threat_rules:
        if name in covered:
            continue
        findings.append({
            "severity": "HIGH",
            "category": name,
            "description": f"GuardDog detector {name} matched",
            "location": "",
            "iocs": [],
        })
    # risk_score flagged risk but produced no detail — still surface a finding.
    if not findings:
        findings.append({
            "severity": "HIGH",
            "category": "guarddog",
            "description": f"GuardDog risk_score label={risk_label or 'risk'}",
            "location": "",
            "iocs": [],
        })
    return "MALICIOUS", 0.95, findings


def _max_workers_from_env():
    """Resolve gRPC worker-pool size from BRIDGE_MAX_WORKERS (default 64).

    A non-numeric or non-positive value falls back to the default rather than
    crashing the bridge on a typo'd deployment env var.
    """
    raw = os.environ.get("BRIDGE_MAX_WORKERS", "")
    if not raw:
        return DEFAULT_MAX_WORKERS
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "BRIDGE_MAX_WORKERS=%r is not an integer; using default %d",
            raw, DEFAULT_MAX_WORKERS,
        )
        return DEFAULT_MAX_WORKERS
    if value <= 0:
        logger.warning(
            "BRIDGE_MAX_WORKERS=%d is not positive; using default %d",
            value, DEFAULT_MAX_WORKERS,
        )
        return DEFAULT_MAX_WORKERS
    return value


class ScannerBridgeServicer(scanner_pb2_grpc.ScannerBridgeServicer):
    def __init__(self):
        try:
            from guarddog import PypiPackageScanner, NPMPackageScanner as NpmPackageScanner
            self.pypi_scanner = PypiPackageScanner()
            self.npm_scanner = NpmPackageScanner()
            logger.info("GuardDog scanners initialized")
        except ImportError:
            logger.error("GuardDog not installed")
            raise

        # Initialize AI scanner module (lazy — only import when enabled).
        # The async OpenAI client must be used from a single persistent event loop
        # to keep its internal HTTP connection pool working correctly.
        self._ai_scanner = None
        self._ai_loop = None
        if AI_SCANNER_ENABLED:
            try:
                self._ai_loop = asyncio.new_event_loop()
                import threading
                threading.Thread(
                    target=self._ai_loop.run_forever,
                    daemon=True,
                    name="ai-scanner-loop",
                ).start()

                import ai_scanner
                self._ai_scanner = ai_scanner
                # Re-initialize the OpenAI client inside the persistent loop so the
                # underlying httpx connection pool is bound to the correct loop.
                asyncio.run_coroutine_threadsafe(
                    self._reinit_ai_client(), self._ai_loop
                ).result(timeout=10)
                logger.info("AI scanner module loaded (model: %s)", ai_scanner._model)
            except Exception as e:
                logger.error("AI scanner failed to initialize: %s", e)

    @staticmethod
    async def _reinit_ai_client():
        """Re-create the OpenAI client inside the persistent event loop."""
        import ai_scanner
        ai_scanner._client, ai_scanner._model = ai_scanner._build_client()

    def ScanArtifact(self, request, context):
        start = time.time()
        try:
            if request.ecosystem == "pypi":
                results = self.pypi_scanner.scan_local(request.artifact_path)
            elif request.ecosystem == "npm":
                results = self.npm_scanner.scan_local(request.artifact_path)
            else:
                return scanner_pb2.ScanResponse(
                    verdict="CLEAN",
                    confidence=1.0,
                    scanner_version=GUARDDOG_VERSION,
                    duration_ms=int((time.time() - start) * 1000),
                )

            # GuardDog 3.0 scan_local returns {"results": {rule: matches},
            # "risk_score": {...}, "risks": [...], "issues": int, "errors": ...}.
            risk_score = results.get("risk_score") if isinstance(results, dict) else None
            logger.info(
                "GuardDog raw results for %s:%s — risk_score=%s results=%s",
                request.package_name, request.version,
                str(risk_score)[:300],
                str(results.get("results") if isinstance(results, dict) else results)[:700],
            )

            verdict, confidence, finding_dicts = classify_guarddog_result(results)
            findings = [
                scanner_pb2.Finding(
                    severity=f["severity"],
                    category=f["category"],
                    description=f["description"],
                    location=f["location"] or request.artifact_path,
                    iocs=f["iocs"],
                )
                for f in finding_dicts
            ]
            if verdict == "MALICIOUS":
                logger.info(
                    "GuardDog flagged %s:%s as MALICIOUS — risk_label=%s, %d finding(s): %s",
                    request.package_name, request.version,
                    (risk_score or {}).get("label"), len(findings),
                    ", ".join(f["category"] for f in finding_dicts),
                )

            duration_ms = int((time.time() - start) * 1000)
            return scanner_pb2.ScanResponse(
                verdict=verdict,
                confidence=confidence,
                findings=findings,
                scanner_version=GUARDDOG_VERSION,
                duration_ms=duration_ms,
            )

        except Exception as e:
            logger.error("Scan error: %s", e)
            duration_ms = int((time.time() - start) * 1000)
            # GuardDog failed internally — we did NOT determine the artifact is
            # clean. Return UNKNOWN (not CLEAN) so the Go side classifies this as
            # a scanner error and a required guarddog scanner fails closed instead
            # of the artifact being served unscanned. (CLEAN/0.0 here was a silent
            # fail-open bypass: the aggregator dropped the 0.0-confidence result.)
            return scanner_pb2.ScanResponse(
                verdict="UNKNOWN",
                confidence=0.0,
                scanner_version=GUARDDOG_VERSION,
                duration_ms=duration_ms,
            )

    def ScanArtifactAI(self, request, context):
        """AI-based security analysis of a package artifact."""
        if self._ai_scanner is None:
            return scanner_pb2.AIScanResponse(
                verdict="UNKNOWN",
                confidence=0.0,
                explanation="AI scanner not enabled",
                model_used="none",
                tokens_used=0,
            )

        try:
            future = asyncio.run_coroutine_threadsafe(
                self._ai_scanner.scan(request), self._ai_loop
            )
            result = future.result(timeout=50)

            return scanner_pb2.AIScanResponse(
                verdict=result.get("verdict", "UNKNOWN"),
                confidence=result.get("confidence", 0.0),
                findings=result.get("findings", []),
                explanation=result.get("explanation", ""),
                model_used=result.get("model_used", ""),
                tokens_used=result.get("tokens_used", 0),
            )
        except Exception as e:
            logger.error("AI scan error for %s: %s", request.artifact_id, e)
            return scanner_pb2.AIScanResponse(
                verdict="UNKNOWN",
                confidence=0.0,
                explanation=f"AI scan error: {e}",
                model_used="none",
                tokens_used=0,
            )

    def ScanArtifactDiff(self, request, context):
        """AI-driven version-diff analysis between two consecutive package versions."""
        if self._ai_scanner is None:
            return scanner_pb2.DiffScanResponse(
                verdict="UNKNOWN",
                confidence=0.0,
                explanation="AI scanner not enabled",
                model_used="none",
                tokens_used=0,
            )

        try:
            future = asyncio.run_coroutine_threadsafe(
                diff_scanner.scan(request), self._ai_loop
            )
            result = future.result(timeout=50)

            return scanner_pb2.DiffScanResponse(
                verdict=result.get("verdict", "UNKNOWN"),
                confidence=result.get("confidence", 0.0),
                findings=result.get("findings", []),
                explanation=result.get("explanation", ""),
                model_used=result.get("model_used", ""),
                tokens_used=result.get("tokens_used", 0),
                files_added=result.get("files_added", 0),
                files_modified=result.get("files_modified", 0),
                files_removed=result.get("files_removed", 0),
                prompt_version=result.get("prompt_version", ""),
                input_truncated=result.get("input_truncated", False),
            )
        except Exception as e:
            logger.error("Diff scan error for %s: %s", request.artifact_id, e)
            return scanner_pb2.DiffScanResponse(
                verdict="UNKNOWN",
                confidence=0.0,
                explanation=f"Diff scan error: {e}",
                model_used="none",
                tokens_used=0,
            )

    def TriageFindings(self, request, context):
        """AI-based triage of vulnerability findings for balanced policy mode."""
        if self._ai_scanner is None:
            return scanner_pb2.TriageResponse(
                decision="QUARANTINE",
                confidence=0.0,
                explanation="AI scanner not enabled — cannot triage",
                model_used="none",
                tokens_used=0,
            )

        try:
            import ai_triage
            future = asyncio.run_coroutine_threadsafe(
                ai_triage.triage(request, self._ai_scanner._client, self._ai_scanner._model),
                self._ai_loop,
            )
            result = future.result(timeout=10)

            return scanner_pb2.TriageResponse(
                decision=result.get("decision", "QUARANTINE"),
                confidence=result.get("confidence", 0.0),
                explanation=result.get("explanation", ""),
                model_used=result.get("model_used", ""),
                tokens_used=result.get("tokens_used", 0),
            )
        except Exception as e:
            logger.error("AI triage error for %s/%s@%s: %s",
                         request.ecosystem, request.name, request.version, e)
            return scanner_pb2.TriageResponse(
                decision="QUARANTINE",
                confidence=0.0,
                explanation=f"Triage error: {e}",
                model_used="none",
                tokens_used=0,
            )

    def DraftIgnoreReason(self, request, context):
        """Generate a 1-2 sentence justification draft for a CVE ignore.

        Returns an empty `reason` when AI is not configured — Go side surfaces
        503 to the UI which then hides the panel cleanly.
        """
        if self._ai_scanner is None:
            return scanner_pb2.DraftIgnoreReasonResponse(
                reason="",
                model_used="none",
                tokens_used=0,
                from_cache=False,
            )
        try:
            import vuln_drafter
            future = asyncio.run_coroutine_threadsafe(
                vuln_drafter.draft(request, self._ai_scanner._client, self._ai_scanner._model),
                self._ai_loop,
            )
            result = future.result(timeout=15)
            return scanner_pb2.DraftIgnoreReasonResponse(
                reason=result.get("reason", ""),
                model_used=result.get("model_used", ""),
                tokens_used=result.get("tokens_used", 0),
                from_cache=result.get("from_cache", False),
            )
        except Exception as e:
            # Operator log only — never propagate raw exception text to the
            # caller (it can include Azure deployment hints).
            logger.error("DraftIgnoreReason error for %s/%s@%s: %s",
                         request.ecosystem, request.package_name, request.package_version, e)
            return scanner_pb2.DraftIgnoreReasonResponse(
                reason="",
                model_used="none",
                tokens_used=0,
                from_cache=False,
            )

    def HealthCheck(self, request, context):
        return scanner_pb2.HealthResponse(
            healthy=True,
            version=GUARDDOG_VERSION,
        )


def serve():
    socket_path = os.environ.get("BRIDGE_SOCKET", "/tmp/shieldoo-bridge.sock")
    max_workers = _max_workers_from_env()

    # Clean up stale socket
    if os.path.exists(socket_path):
        os.unlink(socket_path)

    # Isolate GuardDog scratch into a bridge-owned dir and start the age-based
    # janitor BEFORE serving — tempfile.tempdir must be set once, before any of
    # the scan threads run (Constraint 2). The janitor backstops the hard-kill
    # leak the per-scan cleanup cannot cover.
    scratch_dir = scratch_janitor.setup_scratch_dir()
    if scratch_dir:
        scratch_janitor.start_scratch_janitor(scratch_dir)

    logger.info("Scanner bridge starting with max_workers=%d", max_workers)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=max_workers))
    scanner_pb2_grpc.add_ScannerBridgeServicer_to_server(
        ScannerBridgeServicer(), server
    )
    server.add_insecure_port(f"unix:{socket_path}")
    server.start()
    # Allow access from the gate container which runs as a non-root user (sgw).
    # The socket is only reachable within the shared Docker volume.
    os.chmod(socket_path, 0o666)
    logger.info("Scanner bridge listening on %s", socket_path)
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
