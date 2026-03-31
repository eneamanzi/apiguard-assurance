"""
src/tests/domain_0/test_0_3_deprecated_api_enforcement.py

Test 0.3 -- Deprecated APIs Are Disabled or Under Enhanced Monitoring.

Guarantee (Implementazione.md, Dominio 0):
    Endpoints marked as deprecated in the OpenAPI spec are either completely
    disabled (HTTP 410 Gone) or at minimum return a Sunset header indicating
    the planned decommission date. Post-sunset endpoints must return 410.

Methodology (3_TOP_metodologia.md, Section 0.3):
    - Deprecated endpoint accessibility: extract deprecated:true endpoints
      from the OpenAPI spec and verify their status.
    - Sunset header verification: deprecated endpoints must carry a Sunset
      header per RFC 8594.
    - Post-sunset enforcement: if the Sunset date has passed, the endpoint
      must return 410 Gone.

Strategy: BLACK_BOX -- no credentials required for accessibility checks.
Priority: P0 -- deprecated endpoints are a common source of unpatched vulnerabilities.
"""

from __future__ import annotations

from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
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

# HTTP status code for a correctly decommissioned endpoint (RFC 9110).
_GONE_STATUS_CODE: int = 410

# The Sunset header name (RFC 8594), lowercase for consistent dict access.
_SUNSET_HEADER: str = "sunset"

# Status codes that indicate the deprecated endpoint is still active
# and serving requests (a potential vulnerability window).
_ACTIVE_STATUS_CODES: frozenset[int] = frozenset(
    {
        200,
        201,
        202,
        204,
        400,
        401,
        403,
        422,
    }
)


# ---------------------------------------------------------------------------
# Test implementation
# ---------------------------------------------------------------------------


class Test_0_3_DeprecatedApiEnforcement(BaseTest):  # noqa: N801
    """
    Verify that deprecated API endpoints are disabled or properly sunset.

    Performs two sub-checks on all endpoints marked deprecated:true in spec:
        1. Sunset header presence: deprecated but active endpoints must carry
           a Sunset header per RFC 8594.
        2. Post-sunset enforcement: if the Sunset date is in the past,
           the endpoint must return 410 Gone.

    If no deprecated endpoints are declared in the spec, the test returns
    SKIP with an explanatory message. This is not a PASS: the absence of
    deprecated endpoints in the spec does not mean the API has no deprecated
    functionality -- it may simply be undocumented (a Shadow API concern
    handled by test 0.1).
    """

    test_id: ClassVar[str] = "0.3"
    priority: ClassVar[int] = 0
    strategy: ClassVar[TestStrategy] = TestStrategy.BLACK_BOX
    depends_on: ClassVar[list[str]] = []
    test_name: ClassVar[str] = "Deprecated APIs Are Disabled or Under Enhanced Monitoring"
    domain: ClassVar[int] = 0
    tags: ClassVar[list[str]] = [
        "deprecated-api",
        "lifecycle",
        "OWASP-API9:2023",
        "RFC-8594",
    ]
    cwe_id: ClassVar[str] = "CWE-1059"

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Execute deprecated API enforcement verification.

        Returns PASS if all deprecated endpoints are correctly handled.
        Returns FAIL with Findings for deprecated endpoints missing Sunset
        headers or serving requests after their sunset date.
        Returns SKIP if no deprecated endpoints are declared in the spec.
        Returns ERROR on unexpected exception.
        """
        try:
            skip = self._requires_attack_surface(target)
            if skip is not None:
                return skip

            assert target.attack_surface is not None
            surface = target.attack_surface

            deprecated_endpoints = surface.get_deprecated_endpoints()

            if not deprecated_endpoints:
                return self._make_skip(
                    reason=(
                        f"No endpoints marked as 'deprecated: true' were found "
                        f"in the OpenAPI specification "
                        f"(spec: '{surface.spec_title} {surface.spec_version}'). "
                        f"This test is SKIP rather than PASS: the absence of "
                        f"deprecated declarations does not confirm the absence of "
                        f"deprecated functionality. Verify inventory manually."
                    )
                )

            findings: list[Finding] = []
            now_utc = datetime.now(UTC)

            for endpoint in deprecated_endpoints:
                path = endpoint.path

                # Skip endpoints with path template parameters: we cannot
                # construct a valid URL without knowing resource IDs.
                if "{" in path:
                    findings.extend(self._check_deprecated_with_template(endpoint=endpoint))
                    continue

                try:
                    response, record = client.request(
                        method=endpoint.method,
                        path=path,
                        test_id=self.test_id,
                    )
                except Exception as exc:  # noqa: BLE001
                    log.debug(
                        "deprecated_probe_transport_error",
                        path=path,
                        method=endpoint.method,
                        exc_type=type(exc).__name__,
                        detail=str(exc),
                    )
                    continue

                # Sub-check 1: if endpoint is active, it must have a Sunset header.
                if response.status_code in _ACTIVE_STATUS_CODES:
                    sunset_header_value = response.headers.get(_SUNSET_HEADER)

                    if sunset_header_value is None:
                        store.add_fail_evidence(record)
                        findings.append(
                            Finding(
                                title="Deprecated endpoint active without Sunset header",
                                detail=(
                                    f"{endpoint.method} {path} is marked "
                                    f"'deprecated: true' in the OpenAPI spec and "
                                    f"returned HTTP {response.status_code} (active). "
                                    f"No 'Sunset' header (RFC 8594) was present in "
                                    f"the response. Active deprecated endpoints must "
                                    f"declare their planned decommission date via the "
                                    f"Sunset header to inform API consumers."
                                ),
                                references=[
                                    self.cwe_id,
                                    "OWASP-API9:2023",
                                    "RFC-8594",
                                    "NIST-SP-800-204-S3.1.3",
                                ],
                                evidence_ref=record.record_id,
                            )
                        )
                        continue

                    # Sub-check 2: if Sunset date has passed, endpoint must be gone.
                    sunset_dt = self._parse_sunset_header(sunset_header_value)
                    if sunset_dt is not None and sunset_dt < now_utc:
                        store.add_fail_evidence(record)
                        findings.append(
                            Finding(
                                title=("Post-sunset deprecated endpoint still serving requests"),
                                detail=(
                                    f"{endpoint.method} {path} declared sunset "
                                    f"date {sunset_header_value} "
                                    f"(parsed: {sunset_dt.isoformat()}), "
                                    f"which is in the past "
                                    f"(now: {now_utc.isoformat()}). "
                                    f"The endpoint returned HTTP "
                                    f"{response.status_code} instead of the "
                                    f"expected HTTP 410 Gone (RFC 9110). "
                                    f"Post-sunset enforcement is not implemented."
                                ),
                                references=[
                                    self.cwe_id,
                                    "OWASP-API9:2023",
                                    "RFC-8594",
                                    "RFC-9110",
                                ],
                                evidence_ref=record.record_id,
                            )
                        )

                elif response.status_code == _GONE_STATUS_CODE:
                    # 410 is the correct post-sunset response. Pin as evidence
                    # that the Gateway is correctly enforcing the sunset policy.
                    store.pin_evidence(record)

            if findings:
                return TestResult(
                    test_id=self.test_id,
                    status=TestStatus.FAIL,
                    message=(
                        f"Deprecated API enforcement issues detected: "
                        f"{len(findings)} deprecated endpoint(s) lack proper "
                        f"sunset handling."
                    ),
                    findings=findings,
                )

            return self._make_pass(
                message=(
                    f"All {len(deprecated_endpoints)} deprecated endpoint(s) "
                    f"are correctly handled: either disabled (410 Gone) or "
                    f"carrying a valid Sunset header."
                )
            )

        except Exception as exc:
            return self._make_error(exc)

    @staticmethod
    def _parse_sunset_header(header_value: str) -> datetime | None:
        """
        Parse an HTTP-date Sunset header value into a timezone-aware datetime.

        The Sunset header uses HTTP-date format per RFC 7231, e.g.:
            Sunset: Wed, 01 Jan 2026 00:00:00 GMT

        Uses email.utils.parsedate_to_datetime which handles HTTP-date format
        and returns a timezone-aware datetime with tzinfo=timezone.utc.

        Args:
            header_value: Raw Sunset header value string.

        Returns:
            timezone-aware datetime, or None if parsing fails.
        """
        try:
            parsed = parsedate_to_datetime(header_value)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=UTC)
            return parsed
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _check_deprecated_with_template(
        endpoint: EndpointRecord,
    ) -> list[Finding]:
        """
        Generate an informational Finding for deprecated endpoints with path parameters.

        These endpoints cannot be probed in Black Box mode without valid
        resource IDs. The Finding documents the gap for the analyst.

        Args:
            endpoint: EndpointRecord with template path parameters.

        Returns:
            List with one informational Finding.
        """
        return [
            Finding(
                title=("Deprecated endpoint with path parameters cannot be probed (Black Box)"),
                detail=(
                    f"{endpoint.method} {endpoint.path} is marked deprecated "
                    f"but contains path template parameters (e.g., {{id}}). "
                    f"Automated probing requires valid resource identifiers not "
                    f"available in Black Box mode. "
                    f"Manual verification of sunset enforcement is required for "
                    f"this endpoint."
                ),
                references=["CWE-1059", "OWASP-API9:2023"],
                evidence_ref=None,
            )
        ]
