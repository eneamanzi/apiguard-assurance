"""
src/tests/domain_0/test_0_3_deprecated_api_enforcement.py

Test 0.3 -- Deprecated APIs Are Disabled or Under Enhanced Monitoring.

Guarantee (Implementazione.md, Dominio 0):
    Endpoints marked as deprecated in the OpenAPI spec are either completely
    disabled (HTTP 410 Gone) or carry a Sunset header (RFC 8594) declaring
    the planned decommission date. Post-sunset endpoints must return 410 Gone.

Methodology (3_TOP_metodologia.md, Section 0.3):
    - Deprecated endpoint accessibility: extract all endpoints with
      deprecated:true from the OpenAPI spec and check their live status.
    - Sunset header presence: active deprecated endpoints must carry a
      Sunset header (RFC 8594) to notify API consumers of the timeline.
    - Post-sunset enforcement: if the Sunset date is in the past, the
      endpoint must return 410 Gone (RFC 9110), not any active status.

Strategy: BLACK_BOX -- no credentials required for accessibility checks.
    Deprecated endpoints are probed unauthenticated. Any active response
    (2xx, 4xx from app logic) is a signal that the endpoint exists and
    serves traffic, which is sufficient to check Sunset header presence
    and post-sunset status without credentials.

Priority: P0 -- deprecated endpoints are a known source of unpatched
    vulnerabilities: they receive less security scrutiny while remaining
    reachable.

Coverage gap policy:
-------------------
Deprecated endpoints containing path template parameters (e.g. {owner},
{repo}) cannot be probed in Black Box mode: valid resource identifiers are
unavailable without an authenticated session. These endpoints are NOT
treated as security failures. The gap is documented in the result message.

Verdict mapping:
    FAIL  -> HTTP evidence of a violated guarantee:
             (a) active deprecated endpoint without Sunset header, or
             (b) active deprecated endpoint whose Sunset date has passed.
    PASS  -> All probed deprecated endpoints are correctly handled
             (either 410 Gone, or active with a valid future Sunset header).
             Coverage gaps (parametric paths) are noted in the message.
    SKIP  -> No deprecated endpoints declared in the spec at all.
             This is SKIP rather than PASS: absence of declarations does
             not confirm absence of deprecated functionality -- that concern
             belongs to Test 0.1 (Shadow API Discovery).
    ERROR -> Unexpected exception during execution.

EvidenceStore policy:
    FAIL transactions (missing Sunset, post-sunset active):
        store.add_fail_evidence(record) at call site,
        then _log_transaction(is_fail=True).
    Correctly decommissioned (410 Gone):
        store.pin_evidence(record) -- positive enforcement signal retained
        in evidence.json as a documented compliance artefact.
    Transport errors: logged via structlog only. SecurityClientError does not
        carry an EvidenceRecord (the record is created only after a successful
        HTTP exchange), so _log_transaction() cannot be called.
    All other statuses: _log_transaction() only.
"""

from __future__ import annotations

from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
from src.core.models import (
    EndpointRecord,
    EvidenceRecord,
    Finding,
    TestResult,
    TestStatus,
    TestStrategy,
)
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants -- response classification
# ---------------------------------------------------------------------------

# HTTP status for a correctly decommissioned endpoint (RFC 9110 Section 15.5.11).
_HTTP_GONE: int = 410

# The Sunset header name (RFC 8594), lowercase for consistent dict access.
_SUNSET_HEADER: str = "sunset"

# Status codes that indicate the deprecated endpoint is still ACTIVE.
# These codes confirm the endpoint is serving application-layer traffic:
# 2xx  -- success responses
# 400  -- request validation error (endpoint exists and parsed the request)
# 401  -- authentication required (endpoint exists and enforces auth)
# 403  -- authorization denied (endpoint exists and enforces authz)
# 422  -- semantic validation error (endpoint exists and processed the body)
# Note: 404 is intentionally excluded -- it may mean the route no longer exists
# on the backend, even if the gateway still accepts the path.
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
# Constants -- oracle state labels for TransactionSummary.oracle_state
# ---------------------------------------------------------------------------

_STATE_SUNSET_MISSING: str = "SUNSET_MISSING"
_STATE_POST_SUNSET_ACTIVE: str = "POST_SUNSET_ACTIVE"
_STATE_DEPRECATED_ACTIVE_SUNSET_OK: str = "DEPRECATED_ACTIVE_SUNSET_OK"
_STATE_CORRECTLY_DECOMMISSIONED: str = "CORRECTLY_DECOMMISSIONED"
_STATE_OTHER_STATUS: str = "OTHER_STATUS"
# Note: there is intentionally no _STATE_TRANSPORT_ERROR constant here.
# SecurityClientError does not carry an EvidenceRecord (the record is created
# only after a successful HTTP exchange), so _log_transaction() cannot be
# called on transport failures. They are logged via structlog only.

# ---------------------------------------------------------------------------
# Constants -- standard references
# ---------------------------------------------------------------------------

_REFERENCES: list[str] = [
    "CWE-1059",
    "OWASP-API9:2023",
    "RFC-8594",
    "NIST-SP-800-204-S3.1.3",
]


# ---------------------------------------------------------------------------
# Test implementation
# ---------------------------------------------------------------------------


class Test03DeprecatedApiEnforcement(BaseTest):
    """
    Verify that deprecated API endpoints are disabled or properly sunset.

    Probes all endpoints marked deprecated:true in the OpenAPI spec that do
    NOT contain path template parameters (Black Box limitation). For each
    probeable endpoint, two sub-checks are performed:

        Sub-check 1 -- Sunset header presence:
            If the endpoint is active (status in _ACTIVE_STATUS_CODES), it
            must carry a Sunset header (RFC 8594). Absence of the header means
            API consumers cannot determine the decommission timeline.

        Sub-check 2 -- Post-sunset enforcement:
            If the Sunset date has passed, the endpoint must return 410 Gone
            (RFC 9110). An active response after the sunset date means the
            lifecycle enforcement is not implemented.

    Endpoints with path template parameters cannot be probed in Black Box
    mode and are counted as coverage gaps. They are documented in the result
    message but do NOT contribute to FAIL findings.
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

        Returns:
            TestResult(SKIP)  if no deprecated endpoints are in the spec.
            TestResult(FAIL)  if any active deprecated endpoint is missing a
                              Sunset header, or is active after its sunset date.
            TestResult(PASS)  if all probed deprecated endpoints are correctly
                              handled. Coverage gaps are noted in the message.
            TestResult(ERROR) on unexpected exception.
        """
        try:
            skip = self._requires_attack_surface(target)
            if skip is not None:
                return skip

            assert target.attack_surface is not None  # noqa: S101 -- type narrowing only
            surface = target.attack_surface

            deprecated_endpoints = surface.get_deprecated_endpoints()

            if not deprecated_endpoints:
                return self._make_skip(
                    reason=(
                        f"No endpoints marked 'deprecated: true' were found in the "
                        f"OpenAPI specification "
                        f"(spec: '{surface.spec_title} {surface.spec_version}'). "
                        f"This test returns SKIP rather than PASS: the absence of "
                        f"deprecated declarations does not confirm the absence of "
                        f"deprecated functionality. Verify inventory manually, or "
                        f"run Test 0.1 (Shadow API Discovery) to surface undeclared "
                        f"endpoints."
                    )
                )

            # Partition endpoints into probeable (no path parameters) and
            # coverage gaps (parametric paths, cannot construct a valid URL
            # in Black Box mode without resource identifiers).
            probeable: list[EndpointRecord] = []
            coverage_gaps: list[str] = []

            for endpoint in deprecated_endpoints:
                if "{" in endpoint.path:
                    gap_label = f"{endpoint.method} {endpoint.path}"
                    coverage_gaps.append(gap_label)
                    log.debug(
                        "deprecated_endpoint_coverage_gap",
                        path=endpoint.path,
                        method=endpoint.method,
                        reason=(
                            "Path contains template parameters. Cannot construct a valid "
                            "URL in Black Box mode. Counted as a coverage gap, not a failure."
                        ),
                    )
                else:
                    probeable.append(endpoint)

            # Probe all non-parametric deprecated endpoints.
            now_utc = datetime.now(UTC)
            findings = self._probe_deprecated_endpoints(
                endpoints=probeable,
                now_utc=now_utc,
                client=client,
                store=store,
            )

            probed_count = len(probeable)
            gap_count = len(coverage_gaps)

            # Edge case: all deprecated endpoints are parametric.
            # Zero probes means zero evidence -- a PASS verdict would be misleading
            # ("All 0 probed endpoints correctly handled" is vacuously true and
            # communicates nothing useful). Return SKIP with an explanatory note
            # that distinguishes this from the "no deprecated endpoints at all" SKIP.
            if probed_count == 0:
                sep = ", "
                return self._make_skip(
                    reason=(
                        f"All {gap_count} deprecated endpoint(s) declared in the spec "
                        f"contain path template parameters "
                        f"({sep.join(coverage_gaps)}) and cannot be probed in "
                        f"Black Box mode: valid resource identifiers are unavailable "
                        f"without an authenticated session. "
                        f"No HTTP evidence was collected. "
                        f"Manual verification of these endpoints is required."
                    )
                )

            if findings:
                gap_note = (
                    f" Additionally, {gap_count} deprecated endpoint(s) with path "
                    f"parameters were not probed in Black Box mode (coverage gap)."
                    if gap_count
                    else ""
                )
                return TestResult(
                    test_id=self.test_id,
                    status=TestStatus.FAIL,
                    message=(
                        f"Deprecated API enforcement issues: {len(findings)} violation(s) "
                        f"detected among {probed_count} probed deprecated endpoint(s)."
                        f"{gap_note}"
                    ),
                    findings=findings,
                    transaction_log=list(self._transaction_log),
                    **self._metadata_kwargs(),
                )

            # All probeable endpoints passed. Build an informative PASS message.
            pass_parts: list[str] = [
                f"All {probed_count} probed deprecated endpoint(s) are correctly handled: "
                f"either disabled (410 Gone) or carrying a valid future Sunset header."
            ]
            if gap_count:
                pass_parts.append(
                    f"{gap_count} deprecated endpoint(s) with path parameters "
                    f"({', '.join(coverage_gaps)}) were not probed in Black Box mode. "
                    f"Manual verification recommended for these endpoints."
                )

            return self._make_pass(message=" ".join(pass_parts))

        except Exception as exc:  # noqa: BLE001
            return self._make_error(exc)

    # ------------------------------------------------------------------
    # Private: probe loop
    # ------------------------------------------------------------------

    def _probe_deprecated_endpoints(
        self,
        endpoints: list[EndpointRecord],
        now_utc: datetime,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> list[Finding]:
        """
        Probe each non-parametric deprecated endpoint and collect violations.

        For each endpoint:
            1. Send an unauthenticated HTTP request.
            2. If the response status is in _ACTIVE_STATUS_CODES:
               a. Check for Sunset header presence (RFC 8594).
               b. If Sunset header is present and parseable, check whether
                  the date is in the past (post-sunset enforcement).
            3. If the response status is 410 Gone: correctly decommissioned,
               pin evidence as a compliance artefact.
            4. Transport errors: log to audit trail, skip without finding.

        Args:
            endpoints: Non-parametric deprecated endpoints to probe.
            now_utc:   Current UTC datetime for sunset date comparison.
            client:    Centralized HTTP client.
            store:     EvidenceStore for FAIL and pinned transactions.

        Returns:
            List of Finding, one per violation detected.
        """
        findings: list[Finding] = []

        for endpoint in endpoints:
            path = endpoint.path

            try:
                response, record = client.request(
                    method=endpoint.method,
                    path=path,
                    test_id=self.test_id,
                )
            except SecurityClientError as exc:
                # Transport-layer failure: the endpoint may not be reachable.
                # Log to the audit trail so the analyst knows a probe was
                # attempted and failed, but do not treat it as a finding.
                log.debug(
                    "deprecated_probe_transport_error",
                    path=path,
                    method=endpoint.method,
                    exc_type=type(exc).__name__,
                    detail=str(exc),
                )
                # SecurityClientError does not carry an EvidenceRecord; we cannot
                # call _log_transaction here without a record. Log via structlog
                # only and move to the next endpoint.
                continue

            status = response.status_code

            if status in _ACTIVE_STATUS_CODES:
                # Endpoint is active: check Sunset header and post-sunset enforcement.
                finding = self._check_active_deprecated_endpoint(
                    endpoint=endpoint,
                    status=status,
                    record=record,
                    now_utc=now_utc,
                    store=store,
                )
                if finding is not None:
                    findings.append(finding)

            elif status == _HTTP_GONE:
                # Correctly decommissioned. Pin as positive compliance evidence.
                store.pin_evidence(record)
                self._log_transaction(record, oracle_state=_STATE_CORRECTLY_DECOMMISSIONED)
                log.debug(
                    "deprecated_endpoint_decommissioned",
                    path=path,
                    method=endpoint.method,
                )

            else:
                # Any other status (404, 301, 5xx, etc.): neither an active signal
                # nor a confirmed 410 enforcement. Log for the audit trail.
                self._log_transaction(record, oracle_state=_STATE_OTHER_STATUS)
                log.debug(
                    "deprecated_probe_other_status",
                    path=path,
                    method=endpoint.method,
                    status=status,
                )

        return findings

    def _check_active_deprecated_endpoint(
        self,
        endpoint: EndpointRecord,
        status: int,
        record: EvidenceRecord,
        now_utc: datetime,
        store: EvidenceStore,
    ) -> Finding | None:
        """
        Check a confirmed-active deprecated endpoint for lifecycle compliance.

        Two sequential checks:
            1. Sunset header must be present (RFC 8594).
               If absent: FAIL -- consumers cannot determine the decommission date.
            2. If Sunset header is present and parseable, and the date is in
               the past: FAIL -- the endpoint must be 410 Gone by now.
            3. If Sunset header is present and the date is in the future:
               PASS for this endpoint (correctly in active deprecation window).

        store.add_fail_evidence is called here (not in a deeper helper) because
        this is the single call site with both the record and the finding
        decision, maintaining a clear evidence-writing boundary.

        Args:
            endpoint: EndpointRecord for the deprecated endpoint.
            status:   HTTP status code of the response (in _ACTIVE_STATUS_CODES).
            record:   EvidenceRecord from SecurityClient.request().
            now_utc:  Current UTC datetime for sunset date comparison.
            store:    EvidenceStore for FAIL transactions.

        Returns:
            Finding if a violation is detected, else None.
        """
        sunset_value = record.response_headers.get(_SUNSET_HEADER)

        # Check 1: Sunset header must be present on any active deprecated endpoint.
        if sunset_value is None:
            store.add_fail_evidence(record)
            self._log_transaction(record, oracle_state=_STATE_SUNSET_MISSING, is_fail=True)
            return Finding(
                title="Active deprecated endpoint missing Sunset header",
                detail=(
                    f"{endpoint.method} {endpoint.path} is marked 'deprecated: true' "
                    f"in the OpenAPI spec and returned HTTP {status} (active). "
                    f"No 'Sunset' header (RFC 8594) was present in the response. "
                    f"Active deprecated endpoints must declare their planned decommission "
                    f"date via the Sunset header to notify API consumers. "
                    f"Without a Sunset header, consumers have no mechanism to anticipate "
                    f"the removal and update their integrations proactively."
                ),
                references=_REFERENCES,
                evidence_ref=record.record_id,
            )

        # Check 2: if Sunset date has passed, endpoint must return 410 Gone.
        sunset_dt = _parse_sunset_header(sunset_value)

        if sunset_dt is not None and sunset_dt < now_utc:
            store.add_fail_evidence(record)
            self._log_transaction(record, oracle_state=_STATE_POST_SUNSET_ACTIVE, is_fail=True)
            return Finding(
                title="Post-sunset deprecated endpoint still serving requests",
                detail=(
                    f"{endpoint.method} {endpoint.path} declared sunset date "
                    f"'{sunset_value}' (parsed: {sunset_dt.isoformat()}), "
                    f"which is in the past (assessment time: {now_utc.isoformat()}). "
                    f"The endpoint returned HTTP {status} instead of the expected "
                    f"HTTP 410 Gone (RFC 9110 Section 15.5.11). "
                    f"Post-sunset enforcement is not implemented: the endpoint "
                    f"continues to serve traffic after its declared end-of-life."
                ),
                references=_REFERENCES + ["RFC-9110"],
                evidence_ref=record.record_id,
            )

        # Sunset header present with a future date (or unparseable date):
        # endpoint is correctly in its active deprecation window.
        self._log_transaction(record, oracle_state=_STATE_DEPRECATED_ACTIVE_SUNSET_OK)
        log.debug(
            "deprecated_endpoint_sunset_ok",
            path=endpoint.path,
            method=endpoint.method,
            sunset=sunset_value,
        )
        return None


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _parse_sunset_header(header_value: str) -> datetime | None:
    """
    Parse an HTTP-date Sunset header value into a timezone-aware datetime.

    The Sunset header (RFC 8594) uses HTTP-date format per RFC 7231, e.g.:
        Sunset: Wed, 01 Jan 2026 00:00:00 GMT

    Uses email.utils.parsedate_to_datetime, which handles the HTTP-date
    format and returns a timezone-aware datetime (tzinfo=UTC) when the
    value is well-formed.

    Args:
        header_value: Raw Sunset header value string.

    Returns:
        Timezone-aware datetime if parsing succeeds, else None.
        None is treated by the caller as "unparseable: skip date check".
    """
    try:
        parsed = parsedate_to_datetime(header_value)
        # parsedate_to_datetime can return naive datetimes for some formats.
        # Always ensure tzinfo is set before comparison with now_utc (UTC-aware).
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed
    except Exception:  # noqa: BLE001
        return None
