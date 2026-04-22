"""
src/tests/domain_4/test_4_2_timeout_config_audit.py

Test 4.2 -- Timeout Configuration Audit: Prevention of Resource Lock.

Guarantee (3_TOP_metodologia.md, Section 4.2):
    Every I/O operation (DB query, outbound HTTP call) must have a configured
    timeout. Without timeouts, a single blocked thread occupies a slot in the
    connection pool indefinitely; accumulated blocked threads exhaust the pool
    and prevent the server from accepting new requests.

    This test audits Kong service timeout configuration via the Admin API,
    verifying that connect_timeout, read_timeout, and write_timeout are all
    set and within the oracle bounds defined by the methodology:

        connect_timeout  <=  5 000 ms  (NIST SP 800-204A Section 4.3: <= 5 s)
        read_timeout     <= 30 000 ms  (NIST SP 800-204A Section 4.3: <= 30 s)
        write_timeout    <= 30 000 ms

Strategy: WHITE_BOX -- Configuration Audit.
    The methodology (section 4.2) explicitly prescribes White Box for this
    control: "Il tester ha accesso in lettura ai file di configurazione del
    Gateway (Admin API)." Verifying timeout enforcement empirically from the
    outside would require injecting a mock slow-responding backend -- a
    significantly more complex and environment-dependent approach that provides
    no additional security assurance over a direct audit of the Gateway
    configuration values.

Priority: P1 -- a missing timeout on any upstream service is a resource-lock
    vulnerability that cascades into full pool exhaustion (CWE-400).

Sub-tests (executed in this fixed order):
--------------------------------------------------------------------------
Sub-test 1 -- Service Enumeration
    Retrieves all Kong services via Admin API (GET /services).
    If no services are registered, returns SKIP (nothing to audit).

Sub-test 2 -- Timeout Value Validation (per service)
    For every service returned, verifies three fields:
        a. connect_timeout: must be > 0 and <= max_connect_timeout_ms
        b. read_timeout:    must be > 0 and <= max_read_timeout_ms
        c. write_timeout:   must be > 0 and <= max_write_timeout_ms

    Each violation produces an independent Finding with the service name,
    field name, observed value, and oracle threshold. A service whose all
    three timeouts are within bounds contributes zero findings.

    Oracle (per field):
        value in (0, max_value_ms]  -> compliant
        value == 0                  -> Finding: "timeout not configured"
        value > max_value_ms        -> Finding: "timeout exceeds oracle threshold"

EvidenceStore policy:
    WHITE_BOX configuration audit tests make no HTTP requests to the target
    API, therefore no EvidenceRecord is produced and _log_transaction() is
    never called. Findings contain the service name and field values as
    evidence_ref=None (no HTTP transaction to reference). The full audit
    result is documented in the Finding.detail field.
--------------------------------------------------------------------------
"""  # noqa: N999

from __future__ import annotations

from typing import Any, ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import Finding, TestResult, TestStatus, TestStrategy
from src.tests.base import BaseTest
from src.tests.helpers.kong_admin import KongAdminError, get_services

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Kong timeout field names as returned by the Admin API.
_FIELD_CONNECT_TIMEOUT: str = "connect_timeout"
_FIELD_READ_TIMEOUT: str = "read_timeout"
_FIELD_WRITE_TIMEOUT: str = "write_timeout"

# A timeout value of zero means "not configured" in Kong's Admin API.
# Kong actually defaults all three to 60 000 ms if not explicitly set,
# so a zero should never appear in practice, but we guard against it
# explicitly to produce a clear finding rather than a confusing comparison.
_TIMEOUT_UNCONFIGURED: int = 0

# OWASP/NIST references cited in every Finding produced by this test.
_REFERENCES: list[str] = [
    "OWASP-API4:2023",
    "CWE-400",
    "NIST-SP-800-204A-Section-4.3",
    "OWASP-ASVS-v5.0.0-V16.5.2",
]


class Test42TimeoutConfigAudit(BaseTest):
    """
    Test 4.2 -- Timeout Configuration Audit: Prevention of Resource Lock.

    Audits Kong service timeout parameters (connect_timeout, read_timeout,
    write_timeout) via the Admin API. Produces one Finding per field per
    service that violates the oracle thresholds defined in the methodology.

    This is a WHITE_BOX configuration audit: no HTTP requests are made to
    the target API. All evidence is derived from the Admin API response.
    """

    # ------------------------------------------------------------------
    # BaseTest class-level contract
    # ------------------------------------------------------------------

    test_id: ClassVar[str] = "4.2"
    test_name: ClassVar[str] = "Timeout Configuration Audit -- Prevention of Resource Lock"
    domain: ClassVar[int] = 4
    priority: ClassVar[int] = 1
    strategy: ClassVar[TestStrategy] = TestStrategy.WHITE_BOX
    depends_on: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = [
        "availability",
        "timeout",
        "resource-lock",
        "white-box",
        "OWASP-API4",
    ]
    cwe_id: ClassVar[str] = "CWE-400"

    # ------------------------------------------------------------------
    # execute
    # ------------------------------------------------------------------

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Audit Kong service timeout configuration via the Admin API.

        Execution flow:
            1. Guard: requires Admin API to be configured (_requires_admin_api).
            2. Fetch all Kong services via get_services().
            3. If no services found, return SKIP.
            4. For each service, validate connect_timeout, read_timeout,
               write_timeout against the configured oracle thresholds.
            5. Return PASS if all services are compliant, FAIL with findings
               otherwise.

        No HTTP requests are made to the target API. No _log_transaction()
        calls are needed because there are no EvidenceRecords.

        Returns:
            TestResult with status PASS, FAIL, SKIP, or ERROR.
        """
        try:
            skip_guard = self._requires_admin_api(target)
            if skip_guard is not None:
                return skip_guard

            admin_base_url = target.admin_endpoint_base_url()
            # admin_endpoint_base_url() returns None only when admin_api_url
            # is None, which is already caught by _requires_admin_api() above.
            # This assertion keeps mypy and static analysis happy.
            assert admin_base_url is not None, (  # noqa: S101
                "admin_endpoint_base_url() returned None despite admin_api_available=True. "
                "This is a TargetContext invariant violation."
            )

            cfg = target.tests_config.test_4_2

            log.info(
                "test_4_2_starting",
                admin_base_url=admin_base_url,
                max_connect_timeout_ms=cfg.max_connect_timeout_ms,
                max_read_timeout_ms=cfg.max_read_timeout_ms,
                max_write_timeout_ms=cfg.max_write_timeout_ms,
            )

            # Sub-test 1: fetch services
            services = self._fetch_services(admin_base_url)
            if services is None:
                # KongAdminError was raised and converted to ERROR result
                return self._make_error(
                    RuntimeError(
                        "Kong Admin API call failed -- see structured log for details. "
                        "Verify that admin_api_url is correct and the Kong Admin API "
                        "is reachable from this host."
                    )
                )

            if not services:
                return self._make_skip(
                    reason=(
                        "No Kong services registered. GET /services returned an empty list. "
                        "There is nothing to audit for timeout configuration. "
                        "Verify that Kong is configured with at least one service "
                        "before running this test."
                    )
                )

            log.info("test_4_2_services_retrieved", service_count=len(services))

            # Sub-test 2: validate each service
            findings = self._audit_service_timeouts(services, cfg)

            if findings:
                return TestResult(
                    test_id=self.test_id,
                    status=TestStatus.FAIL,
                    message=(
                        f"Timeout audit found {len(findings)} violation(s) across "
                        f"{len(services)} service(s). "
                        "Services with missing or over-threshold timeouts expose the gateway "
                        "to resource exhaustion via connection pool starvation."
                    ),
                    findings=findings,
                    transaction_log=list(self._transaction_log),
                    **self._metadata_kwargs(),
                )

            return self._make_pass(
                message=(
                    f"All {len(services)} Kong service(s) have compliant timeout configuration: "
                    f"connect_timeout <= {cfg.max_connect_timeout_ms} ms, "
                    f"read_timeout <= {cfg.max_read_timeout_ms} ms, "
                    f"write_timeout <= {cfg.max_write_timeout_ms} ms."
                )
            )

        except Exception as exc:  # noqa: BLE001
            log.exception("test_4_2_unexpected_error", error=str(exc))
            return self._make_error(exc)

    # ------------------------------------------------------------------
    # Sub-test 1: service fetch
    # ------------------------------------------------------------------

    def _fetch_services(self, admin_base_url: str) -> list[dict[str, Any]] | None:
        """
        Retrieve all Kong services from the Admin API.

        Wraps get_services() in a try/except to convert KongAdminError into
        a structured log entry. Returns None on error so the caller can
        detect the failure and produce an appropriate ERROR result without
        catching the exception again.

        Args:
            admin_base_url: Kong Admin API base URL without trailing slash.

        Returns:
            List of Kong service dicts (may be empty), or None on Admin API error.
        """
        try:
            services = get_services(admin_base_url)
            log.debug(
                "test_4_2_services_fetched",
                count=len(services),
            )
            return services
        except KongAdminError as exc:
            log.error(
                "test_4_2_admin_api_error",
                path="/services",
                status_code=exc.status_code,
                error=str(exc),
            )
            return None

    # ------------------------------------------------------------------
    # Sub-test 2: timeout validation
    # ------------------------------------------------------------------

    def _audit_service_timeouts(
        self,
        services: list[dict[str, Any]],
        cfg: Any,  # RuntimeTest42Config -- typed as Any to avoid circular import issues  # noqa: ANN401, E501
    ) -> list[Finding]:
        """
        Validate timeout fields on every Kong service dict.

        For each service, three fields are checked:
            connect_timeout, read_timeout, write_timeout.

        Each field produces at most one Finding:
            - If the field is absent from the service dict (should not occur
              in a healthy Kong instance but is guarded defensively): Finding.
            - If the field value is 0 ("not configured"): Finding.
            - If the field value exceeds the oracle threshold: Finding.

        Args:
            services: List of Kong service objects from GET /services.
            cfg:      RuntimeTest42Config carrying the oracle thresholds.

        Returns:
            Flat list of all findings across all services. Empty if all are
            compliant.
        """
        findings: list[Finding] = []

        # (field_name, oracle_threshold, label_for_messages)
        field_checks: list[tuple[str, int, str]] = [
            (_FIELD_CONNECT_TIMEOUT, cfg.max_connect_timeout_ms, "connect_timeout"),
            (_FIELD_READ_TIMEOUT, cfg.max_read_timeout_ms, "read_timeout"),
            (_FIELD_WRITE_TIMEOUT, cfg.max_write_timeout_ms, "write_timeout"),
        ]

        for service in services:
            service_name: str = service.get("name") or service.get("id", "<unknown>")

            for field_name, max_value_ms, label in field_checks:
                finding = self._check_single_timeout(
                    service_name=service_name,
                    service=service,
                    field_name=field_name,
                    label=label,
                    max_value_ms=max_value_ms,
                )
                if finding is not None:
                    findings.append(finding)
                    log.warning(
                        "test_4_2_timeout_violation",
                        service_name=service_name,
                        field=field_name,
                        observed=service.get(field_name),
                        oracle_max_ms=max_value_ms,
                    )
                else:
                    log.debug(
                        "test_4_2_timeout_compliant",
                        service_name=service_name,
                        field=field_name,
                        value_ms=service.get(field_name),
                    )

        return findings

    def _check_single_timeout(
        self,
        service_name: str,
        service: dict[str, Any],
        field_name: str,
        label: str,
        max_value_ms: int,
    ) -> Finding | None:
        """
        Check one timeout field on a single Kong service dict.

        Three conditions produce a Finding:
            1. Field absent from the service dict.
            2. Field value equals 0 (sentinel for "not configured").
            3. Field value exceeds max_value_ms (oracle threshold).

        Args:
            service_name: Display name of the Kong service (for Finding detail).
            service:      Kong service dict from the Admin API.
            field_name:   Key to look up (e.g. 'connect_timeout').
            label:        Human-readable field label for the Finding title.
            max_value_ms: Maximum acceptable value in milliseconds.

        Returns:
            Finding if the field is non-compliant, None if compliant.
        """
        raw_value = service.get(field_name)

        # Condition 1: field absent from response (Kong Admin API bug or
        # unexpected response structure -- guard defensively).
        if raw_value is None:
            return Finding(
                title=f"Timeout Field Absent: {label} on service '{service_name}'",
                detail=(
                    f"The field '{field_name}' is absent from the Kong Admin API response "
                    f"for service '{service_name}'. Expected an integer timeout value in "
                    f"milliseconds. This may indicate a Kong version incompatibility or a "
                    f"corrupted service configuration. Without this field, timeout enforcement "
                    f"for this service is unknown and cannot be audited."
                ),
                references=_REFERENCES,
                evidence_ref=None,
            )

        value_ms = int(raw_value)

        # Condition 2: value is 0 (not configured).
        if value_ms == _TIMEOUT_UNCONFIGURED:
            return Finding(
                title=f"Timeout Not Configured: {label} == 0 on service '{service_name}'",
                detail=(
                    f"Service '{service_name}' has {field_name} = 0, which indicates "
                    f"the timeout is not configured. Kong's default for an unconfigured "
                    f"timeout is platform-dependent and may be indefinitely long. "
                    f"An unconfigured timeout on a backend service means a single slow "
                    f"or unresponsive dependency can block a connection-pool thread "
                    f"indefinitely, leading to pool exhaustion and denial of service. "
                    f"Oracle: {field_name} must be > 0 and <= {max_value_ms} ms "
                    f"(NIST SP 800-204A Section 4.3)."
                ),
                references=_REFERENCES,
                evidence_ref=None,
            )

        # Condition 3: value exceeds oracle threshold.
        if value_ms > max_value_ms:
            return Finding(
                title=(
                    f"Timeout Exceeds Oracle Threshold: {label} = {value_ms} ms "
                    f"on service '{service_name}'"
                ),
                detail=(
                    f"Service '{service_name}' has {field_name} = {value_ms} ms, "
                    f"which exceeds the oracle threshold of {max_value_ms} ms "
                    f"({max_value_ms / 1000:.0f} s) from NIST SP 800-204A Section 4.3. "
                    f"A {label} of {value_ms / 1000:.1f} s means the Gateway will wait "
                    f"up to {value_ms / 1000:.1f} s before aborting the upstream connection. "
                    f"Under load ({100} concurrent requests blocked for {value_ms / 1000:.0f} s "
                    f"each), the connection pool saturates and the Gateway stops accepting new "
                    f"requests entirely, producing a self-inflicted denial of service. "
                    f"Recommended action: reduce {field_name} to <= {max_value_ms} ms in the "
                    f"Kong service configuration."
                ),
                references=_REFERENCES,
                evidence_ref=None,
            )

        # Value is within bounds -- no finding.
        return None
