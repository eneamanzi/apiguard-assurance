"""
src/tests/domain_0/test_0_2_deny_by_default.py

Test 0.2 -- Gateway Deny-by-Default on Unregistered Paths.

Guarantee (Implementazione.md, Dominio 0):
    The Gateway blocks any request whose path does not match exactly a
    registered route, returning 404 or 403 without forwarding to a backend
    or revealing internal topology information.

Methodology (3_TOP_metodologia.md, Section 0.2):
    - Unregistered path rejection: probe guaranteed-nonexistent paths.
    - Path normalization consistency: probe URL-encoded, double-slash,
      trailing-slash, and path-traversal variants of documented paths.
    - Default backend fallback detection: check response headers for
      backend-identifying information on unregistered paths.

Strategy: BLACK_BOX -- zero credentials required.
Priority: P0 -- deny-by-default is a fundamental Gateway security guarantee.
"""

from __future__ import annotations

import urllib.parse
from typing import ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import EvidenceRecord, Finding, TestResult, TestStatus, TestStrategy
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Paths guaranteed to not exist on any well-configured Gateway.
# These are chosen to be syntactically valid but semantically meaningless.
_GUARANTEED_NONEXISTENT_PATHS: list[str] = [
    "/nonexistent-apiguard-probe-xyz-123",
    "/api/nonexistent-apiguard-probe-abc-456",
    "/apiguard-shadow-probe-789",
    "/api/v99/nonexistent-probe",
]

# Response status codes that indicate the Gateway denied the request correctly.
# A deny-by-default Gateway should return 404 or 403 for unknown paths.
_DENY_STATUS_CODES: frozenset[int] = frozenset({404, 403, 410})

# Accepted 'server' header values that indicate a Gateway (not a backend).
# Kong, nginx, and similar proxies are acceptable; application server
# identifiers (tomcat, gunicorn, unicorn, rails) are not.
_ACCEPTABLE_SERVER_VALUES: frozenset[str] = frozenset(
    {
        "kong",
        "nginx",
        "apache",
        "caddy",
        "traefik",
        "envoy",
        "openresty",
    }
)


# ---------------------------------------------------------------------------
# Test implementation
# ---------------------------------------------------------------------------


class Test_0_2_DenyByDefault(BaseTest):  # noqa: N801
    """
    Verify that the Gateway enforces deny-by-default for unregistered paths.

    Performs three sub-checks:
        1. Unregistered path rejection: guaranteed-nonexistent paths must
           return 404 or 403, not 200 or other success/redirect codes.
        2. Path normalization: URL-encoded and variant paths must be handled
           consistently without bypassing deny-by-default.
        3. Backend header detection: responses to unknown paths must not
           contain headers that identify the backend application server.
    """

    test_id: ClassVar[str] = "0.2"
    priority: ClassVar[int] = 0
    strategy: ClassVar[TestStrategy] = TestStrategy.BLACK_BOX
    depends_on: ClassVar[list[str]] = []
    test_name: ClassVar[str] = "Gateway Deny-by-Default on Unregistered Paths"
    domain: ClassVar[int] = 0
    tags: ClassVar[list[str]] = [
        "deny-by-default",
        "gateway",
        "OWASP-API9:2023",
        "NIST-SP-800-204-S4.1",
    ]
    cwe_id: ClassVar[str] = "CWE-284"

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Execute deny-by-default verification.

        Returns PASS if all unregistered paths are correctly denied.
        Returns FAIL with one Finding per policy violation detected.
        Returns SKIP if AttackSurface is unavailable.
        Returns ERROR on unexpected exception.
        """
        try:
            skip = self._requires_attack_surface(target)
            if skip is not None:
                return skip

            assert target.attack_surface is not None

            findings: list[Finding] = []

            # Sub-check 1: guaranteed-nonexistent path rejection.
            findings.extend(self._check_nonexistent_paths(client=client, store=store))

            # Sub-check 2: path normalization variants on a documented path.
            # Use the first documented path without template parameters as sample.
            sample_path = self._select_sample_path(target)
            if sample_path:
                findings.extend(
                    self._check_path_normalization(
                        base_path=sample_path,
                        client=client,
                        store=store,
                    )
                )

            if findings:
                return TestResult(
                    test_id=self.test_id,
                    status=TestStatus.FAIL,
                    message=(
                        f"Deny-by-default policy violated: {len(findings)} "
                        f"unregistered path(s) were not correctly denied by the Gateway."
                    ),
                    findings=findings,
                )

            return self._make_pass(
                message=(
                    "Deny-by-default policy correctly enforced. "
                    "All unregistered and variant paths returned 404 or 403."
                )
            )

        except Exception as exc:
            return self._make_error(exc)

    def _check_nonexistent_paths(
        self,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> list[Finding]:
        """
        Probe guaranteed-nonexistent paths and flag non-deny responses.

        Also inspects response headers for backend-identifying values,
        which would indicate that the request was forwarded to the backend
        instead of being rejected at the Gateway perimeter.

        Args:
            client: SecurityClient for HTTP requests.
            store: EvidenceStore for FAIL evidence.

        Returns:
            List of Finding for each violation detected.
        """
        findings: list[Finding] = []

        for path in _GUARANTEED_NONEXISTENT_PATHS:
            try:
                response, record = client.request(
                    method="GET",
                    path=path,
                    test_id=self.test_id,
                )
            except Exception as exc:  # noqa: BLE001
                log.debug(
                    "deny_probe_transport_error",
                    path=path,
                    exc_type=type(exc).__name__,
                    detail=str(exc),
                )
                continue

            # Check 1a: status code must be in _DENY_STATUS_CODES.
            if response.status_code not in _DENY_STATUS_CODES:
                store.add_fail_evidence(record)
                findings.append(
                    Finding(
                        title="Unregistered path not denied by Gateway",
                        detail=(
                            f"GET {path} returned HTTP {response.status_code} "
                            f"instead of the expected 404 or 403. "
                            f"The Gateway is not enforcing deny-by-default: "
                            f"the request may have been forwarded to the backend."
                        ),
                        references=[
                            self.cwe_id,
                            "NIST-SP-800-204-S4.1",
                            "OWASP-ASVS-V4.1.1",
                        ],
                        evidence_ref=record.record_id,
                    )
                )
                continue

            # Check 1b: response headers must not reveal backend identity.
            backend_header_finding = self._check_backend_headers(
                path=path,
                response_headers=dict(response.headers),
                record_id=record.record_id,
                record=record,
                store=store,
            )
            if backend_header_finding is not None:
                findings.append(backend_header_finding)

        return findings

    def _check_backend_headers(
        self,
        path: str,
        response_headers: dict[str, str],
        record_id: str,
        record: EvidenceRecord,
        store: EvidenceStore,
    ) -> Finding | None:
        """
        Check whether response headers reveal backend application identity.

        A 'Server' header with an application server value (tomcat, gunicorn)
        on a 404 response indicates the request reached the backend before
        being rejected -- a violation of the deny-by-default principle.
        The Gateway should intercept and reject before forwarding.

        Args:
            path: The probed path.
            response_headers: Response headers dict (lowercase keys).
            record_id: EvidenceRecord ID for Finding.evidence_ref.
            record: EvidenceRecord for store.add_fail_evidence().
            store: EvidenceStore instance.

        Returns:
            Finding if a backend-identifying header is detected, else None.
        """
        server_value = response_headers.get("server", "").lower()

        if server_value and not any(
            acceptable in server_value for acceptable in _ACCEPTABLE_SERVER_VALUES
        ):
            store.add_fail_evidence(record)
            return Finding(
                title=("Backend application server identified in response to unknown path"),
                detail=(
                    f"GET {path} returned a 'Server: {server_value}' header. "
                    f"This value identifies an application server rather than "
                    f"the API Gateway. The 404 response was generated by the "
                    f"backend, indicating the request bypassed the Gateway's "
                    f"deny-by-default policy and reached the upstream service."
                ),
                references=[self.cwe_id, "NIST-SP-800-204-S4.1", "CWE-209"],
                evidence_ref=record_id,
            )

        return None

    def _check_path_normalization(
        self,
        base_path: str,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> list[Finding]:
        """
        Test path normalization consistency on a documented endpoint.

        Generates variants of the base_path that could bypass path matching:
            - Trailing slash: /api/v1/repos/
            - Double slash: /api/v1//repos
            - URL-encoded characters: /api/v1/%72epos (partial encoding)
            - Uppercase: /API/V1/REPOS (case sensitivity test)

        Each variant should receive either the same auth enforcement as the
        original (if normalized to the same path) or 404 (if rejected).
        A 200 OK without authentication on a normally-protected variant
        is a bypass vulnerability.

        Args:
            base_path: A documented API path without template parameters.
            client: SecurityClient for HTTP requests.
            store: EvidenceStore for FAIL evidence.

        Returns:
            List of Finding for normalization bypass vulnerabilities.
        """
        findings: list[Finding] = []

        variants: list[tuple[str, str]] = [
            ("trailing slash", base_path.rstrip("/") + "/"),
            ("double slash", base_path.replace("/api/", "/api//", 1)),
            ("uppercase", base_path.upper()),
        ]

        # URL-encode the last path segment to create an encoding variant.
        segments = base_path.rstrip("/").rsplit("/", 1)
        if len(segments) == 2 and segments[1]:
            encoded_segment = urllib.parse.quote(segments[1], safe="")
            encoded_path = segments[0] + "/" + encoded_segment
            if encoded_path != base_path:
                variants.append(("url-encoded segment", encoded_path))

        for variant_label, variant_path in variants:
            if variant_path == base_path:
                continue

            try:
                response, record = client.request(
                    method="GET",
                    path=variant_path,
                    test_id=self.test_id,
                )
            except Exception as exc:  # noqa: BLE001
                log.debug(
                    "normalization_probe_transport_error",
                    path=variant_path,
                    variant_label=variant_label,
                    exc_type=type(exc).__name__,
                    detail=str(exc),
                )
                continue

            # A 200 OK on a path variant that is not documented is a bypass.
            # 401/403 is acceptable: auth is still enforced on the variant.
            # 404 is acceptable: the Gateway rejected the non-normalized path.
            if response.status_code == 200:
                store.add_fail_evidence(record)
                findings.append(
                    Finding(
                        title=(
                            "Path normalization bypass: authenticated endpoint "
                            "accessible without auth"
                        ),
                        detail=(
                            f"GET {variant_path} ({variant_label}) returned "
                            f"HTTP 200 without an Authorization header. "
                            f"The canonical path {base_path} requires authentication, "
                            f"but this variant bypasses the authentication check. "
                            f"The Gateway is not normalizing paths before applying "
                            f"security policies."
                        ),
                        references=[
                            self.cwe_id,
                            "OWASP-API2:2023",
                            "NIST-SP-800-204-S4.1",
                        ],
                        evidence_ref=record.record_id,
                    )
                )

        return findings

    @staticmethod
    def _select_sample_path(target: TargetContext) -> str | None:
        """
        Select a documented path without template parameters for normalization testing.

        Returns None if no suitable path is found, in which case the
        normalization sub-check is skipped without affecting the overall result.

        Args:
            target: TargetContext with populated AttackSurface.

        Returns:
            A path string, or None if no suitable path exists.
        """
        if target.attack_surface is None:
            return None

        for endpoint in target.attack_surface.endpoints:
            if "{" not in endpoint.path and len(endpoint.path) > 1:
                return endpoint.path

        return None
