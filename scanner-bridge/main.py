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

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

GUARDDOG_VERSION = "2.9.0"

# AI scanner is optional — only loaded when enabled via environment.
AI_SCANNER_ENABLED = os.environ.get("AI_SCANNER_ENABLED", "false").lower() == "true"


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

            findings = []
            verdict = "CLEAN"
            confidence = 1.0

            # GuardDog scan_local returns {"results": {rule: matches}, "path": str}
            rule_results = results.get("results", {}) if isinstance(results, dict) else results
            logger.info(
                "GuardDog raw results for %s:%s — %s",
                request.package_name, request.version, str(rule_results)[:1000],
            )

            if rule_results:
                for rule_name, matches in rule_results.items():
                    # Skip rules with no actual matches (empty dict/list).
                    if not matches:
                        continue
                    severity = "HIGH"
                    logger.info(
                        "GuardDog rule %s triggered for %s:%s — %s",
                        rule_name, request.package_name, request.version,
                        str(matches)[:500],
                    )
                    findings.append(scanner_pb2.Finding(
                        severity=severity,
                        category=rule_name,
                        description=f"GuardDog rule {rule_name} matched",
                        location=request.artifact_path,
                    ))
                if findings:
                    verdict = "MALICIOUS"
                    confidence = 0.95

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
            return scanner_pb2.ScanResponse(
                verdict="CLEAN",
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

    def HealthCheck(self, request, context):
        return scanner_pb2.HealthResponse(
            healthy=True,
            version=GUARDDOG_VERSION,
        )


def serve():
    socket_path = os.environ.get("BRIDGE_SOCKET", "/tmp/shieldoo-bridge.sock")

    # Clean up stale socket
    if os.path.exists(socket_path):
        os.unlink(socket_path)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=32))
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
