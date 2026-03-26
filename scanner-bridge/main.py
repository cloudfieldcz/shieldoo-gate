"""GuardDog scanner bridge — gRPC server for Shieldoo Gate."""

import logging
import os
import sys
import time
from concurrent import futures

import grpc

# Generated proto imports (generate with: python -m grpc_tools.protoc ...)
import proto.scanner_pb2 as scanner_pb2
import proto.scanner_pb2_grpc as scanner_pb2_grpc

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

GUARDDOG_VERSION = "0.1.17"


class ScannerBridgeServicer(scanner_pb2_grpc.ScannerBridgeServicer):
    def __init__(self):
        try:
            from guarddog import PypiPackageScanner, NpmPackageScanner
            self.pypi_scanner = PypiPackageScanner()
            self.npm_scanner = NpmPackageScanner()
            logger.info("GuardDog scanners initialized")
        except ImportError:
            logger.error("GuardDog not installed")
            raise

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

            if results:
                for rule_name, matches in results.items():
                    severity = "HIGH"
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

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    scanner_pb2_grpc.add_ScannerBridgeServicer_to_server(
        ScannerBridgeServicer(), server
    )
    server.add_insecure_port(f"unix:{socket_path}")
    server.start()
    logger.info("Scanner bridge listening on %s", socket_path)
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
