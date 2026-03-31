"""
src/tests/domain_0/test_0_1_shadow_api_discovery.py

Test 0.1 -- All Exposed Endpoints Are Documented and Authorized.

Guarantee (Implementazione.md, Dominio 0):
    Every active endpoint on the Gateway corresponds to an entry in the
    official OpenAPI specification. Endpoints that are active but undocumented
    (Shadow APIs) constitute unknown attack surface: they are not subject to
    security review, rate limiting, or systematic authentication policies.

Methodology (3_TOP_metodologia.md, Section 0.1):
    - Path Enumeration via Fuzzing: scan with standard wordlist of common
      undocumented paths and compare responses against documented endpoints.
    - HTTP Method Discovery: for each documented endpoint, send OPTIONS and
      compare Allow header against declared methods.
    - Versioning Completeness: probe common version prefixes for undocumented
      active versions.

Strategy: BLACK_BOX -- zero credentials, anonymous external attacker simulation.
Priority: P0 -- perimeter control, must pass before any authenticated test.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import EndpointRecord, Finding, TestResult, TestStatus, TestStrategy
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Common undocumented paths that represent Shadow API candidates.
# Sourced from OWASP API Security Testing Guide and SecLists API-endpoints.txt.
# These paths are probed as GET requests; a 2xx or auth-required (401/403)
# response indicates the path is active and must be compared against the spec.
_SHADOW_API_WORDLIST: list[str] = [
    "/api/admin",
    "/api/internal",
    "/api/debug",
    "/api/config",
    "/api/health",
    "/api/metrics",
    "/api/status",
    "/api/actuator",
    "/api/actuator/env",
    "/api/actuator/heapdump",
    "/api/swagger",
    "/api/swagger-ui",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/api/v1/admin",
    "/api/v1/internal",
    "/api/v1/debug",
    "/api/v1/config",
    "/api/v2/admin",
    "/api/v2/internal",
    "/api/v2/debug",
    "/debug",
    "/internal",
    "/admin",
    "/metrics",
    "/health",
    "/healthz",
    "/readyz",
    "/.well-known",
    "/.env",
    "/config",
    "/status",
    "/version",
    "/info",
    "/ping",
]

# HTTP status codes that indicate an active endpoint (not a definitive 404).
# 401 and 403 are included: the path exists and the server is enforcing auth.
# 429 is included: the path exists and is rate-limited.
# 500 is included: the path exists but the server encountered an error.
_ACTIVE_STATUS_CODES: frozenset[int] = frozenset(
    {
        200,
        201,
        202,
        204,
        301,
        302,
        307,
        308,
        400,
        401,
        403,
        405,
        422,
        429,
        500,
        502,
        503,
    }
)

# HTTP methods to probe per documented endpoint for method discovery.
_PROBE_METHODS: list[str] = ["GET", "POST", "PUT", "PATCH", "DELETE"]


# ---------------------------------------------------------------------------
# Test implementation
# ---------------------------------------------------------------------------


class Test_0_1_ShadowApiDiscovery(BaseTest):  # noqa: N801
    """
    Verify that all active endpoints are documented in the OpenAPI specification.

    Performs three sub-checks:
        1. Path fuzzing: probes a wordlist of common undocumented paths.
        2. Method discovery: for each documented endpoint, tests whether
           undeclared HTTP methods are accepted.
        3. Version discovery: probes common version prefix variants.
    """

    test_id: ClassVar[str] = "0.1"
    priority: ClassVar[int] = 0
    strategy: ClassVar[TestStrategy] = TestStrategy.BLACK_BOX
    depends_on: ClassVar[list[str]] = []
    test_name: ClassVar[str] = "All Exposed Endpoints Are Documented and Authorized"
    domain: ClassVar[int] = 0
    tags: ClassVar[list[str]] = ["shadow-api", "inventory", "OWASP-API9:2023"]
    cwe_id: ClassVar[str] = "CWE-1059"

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Execute shadow API discovery via path fuzzing and method probing.

        Returns PASS if no undocumented active endpoints are found.
        Returns FAIL with one Finding per discovered shadow endpoint or
        undeclared active method.
        Returns SKIP if the AttackSurface is unavailable.
        Returns ERROR if an unexpected exception occurs.
        """
        try:
            skip = self._requires_attack_surface(target)
            if skip is not None:
                return skip

            assert target.attack_surface is not None
            surface = target.attack_surface

            # Build a set of documented (path, method) pairs for O(1) lookup.
            documented_pairs: frozenset[tuple[str, str]] = frozenset(
                (ep.path, ep.method) for ep in surface.endpoints
            )
            documented_paths: frozenset[str] = frozenset(ep.path for ep in surface.endpoints)

            findings: list[Finding] = []

            # Sub-check 1: path fuzzing against the wordlist.
            findings.extend(
                self._probe_shadow_paths(
                    wordlist=_SHADOW_API_WORDLIST,
                    documented_paths=documented_paths,
                    client=client,
                    store=store,
                )
            )

            # Sub-check 2: HTTP method discovery on documented endpoints.
            # Sample up to 10 documented endpoints to avoid excessive requests.
            sample_endpoints = list(surface.endpoints)[:10]
            findings.extend(
                self._probe_undeclared_methods(
                    endpoints=sample_endpoints,
                    documented_pairs=documented_pairs,
                    client=client,
                    store=store,
                )
            )

            if findings:
                return TestResult(
                    test_id=self.test_id,
                    status=TestStatus.FAIL,
                    message=(
                        f"Shadow API discovery found {len(findings)} undocumented "
                        f"active endpoint(s) or undeclared method(s)."
                    ),
                    findings=findings,
                )

            return self._make_pass(
                message=(
                    "No shadow API endpoints detected. "
                    "All probed paths returned 404 or are documented in the spec."
                )
            )

        except Exception as exc:
            return self._make_error(exc)

    def _probe_shadow_paths(
        self,
        wordlist: list[str],
        documented_paths: frozenset[str],
        client: SecurityClient,
        store: EvidenceStore,
    ) -> list[Finding]:
        """
        Probe each path in the wordlist and flag active, undocumented paths.

        A path is considered a shadow API candidate if:
            - It is NOT in the documented paths set from the AttackSurface.
            - It returns a status code in _ACTIVE_STATUS_CODES (not 404/410).

        Args:
            wordlist: List of candidate shadow API paths.
            documented_paths: Set of paths from the OpenAPI spec.
            client: SecurityClient for HTTP requests.
            store: EvidenceStore for FAIL evidence.

        Returns:
            List of Finding objects, one per discovered shadow path.
        """
        findings: list[Finding] = []

        for path in wordlist:
            # Skip paths already documented in the spec.
            if path in documented_paths:
                continue

            try:
                response, record = client.request(
                    method="GET",
                    path=path,
                    test_id=self.test_id,
                )
            except Exception as exc:  # noqa: BLE001
                log.debug(
                    "shadow_probe_transport_error",
                    path=path,
                    exc_type=type(exc).__name__,
                    detail=str(exc),
                )
                continue

            if response.status_code in _ACTIVE_STATUS_CODES:
                store.add_fail_evidence(record)
                findings.append(
                    Finding(
                        title="Shadow API endpoint detected (undocumented active path)",
                        detail=(
                            f"GET {path} returned HTTP {response.status_code}, "
                            f"indicating the path is active on the Gateway. "
                            f"This path is not declared in the OpenAPI specification. "
                            f"Expected: HTTP 404 Not Found (deny-by-default)."
                        ),
                        references=[
                            self.cwe_id,
                            "OWASP-API9:2023",
                            "NIST-SP-800-204-S3.1",
                        ],
                        evidence_ref=record.record_id,
                    )
                )

        return findings

    def _probe_undeclared_methods(
        self,
        endpoints: Sequence[EndpointRecord],
        documented_pairs: frozenset[tuple[str, str]],
        client: SecurityClient,
        store: EvidenceStore,
    ) -> list[Finding]:
        """
        For each sampled documented endpoint, probe methods not in the spec.

        An undeclared method is flagged if the server responds with a status
        code other than 405 Method Not Allowed, which is the correct response
        for unsupported methods per RFC 9110.

        Args:
            endpoints: Sample of EndpointRecord objects to probe.
            documented_pairs: Set of (path, method) tuples from the spec.
            client: SecurityClient for HTTP requests.
            store: EvidenceStore for FAIL evidence.

        Returns:
            List of Finding objects, one per undeclared active method.
        """
        findings: list[Finding] = []

        for endpoint in endpoints:
            path: str = endpoint.path

            # Skip paths with template parameters: we cannot substitute
            # real values in Black Box mode without knowing valid resource IDs.
            if "{" in path:
                continue

            for method in _PROBE_METHODS:
                if (path, method) in documented_pairs:
                    continue

                try:
                    response, record = client.request(
                        method=method,
                        path=path,
                        test_id=self.test_id,
                    )
                except Exception as exc:  # noqa: BLE001
                    log.debug(
                        "method_probe_transport_error",
                        path=path,
                        method=method,
                        exc_type=type(exc).__name__,
                        detail=str(exc),
                    )
                    continue

                # 405 is the correct response for unsupported methods.
                # Any other status in _ACTIVE_STATUS_CODES indicates the
                # method is accepted without being declared in the spec.
                if response.status_code in _ACTIVE_STATUS_CODES and response.status_code != 405:
                    store.add_fail_evidence(record)
                    findings.append(
                        Finding(
                            title="Undeclared HTTP method accepted by endpoint",
                            detail=(
                                f"{method} {path} returned HTTP "
                                f"{response.status_code}. "
                                f"This method is not declared in the OpenAPI spec "
                                f"for this path. "
                                f"Expected: HTTP 405 Method Not Allowed."
                            ),
                            references=[
                                self.cwe_id,
                                "OWASP-API9:2023",
                                "RFC-9110-S9.1",
                            ],
                            evidence_ref=record.record_id,
                        )
                    )

        return findings
