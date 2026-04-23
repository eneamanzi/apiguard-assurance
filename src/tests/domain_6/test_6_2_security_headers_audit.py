"""
src/tests/domain_6/test_6_2_security_headers_audit.py

Test 6.2 -- Security Header Configuration Audit.

Guarantee (3_TOP_metodologia.md, Section 6.2):
    HTTP security headers constitute defense-in-depth against client-side
    attacks.  Their presence and correctness are a Gateway configuration
    requirement, not an application-level concern.  A missing or misconfigured
    header is a compliance gap that a correctly configured Gateway must close
    by injecting the header on every outbound response.

    Required headers and their oracles (OWASP ASVS v5.0.0 V3.4, Mozilla
    Observatory Security Headers Best Practices):

        Strict-Transport-Security
            Must contain 'max-age=' followed by a value >=
            hsts_min_max_age_seconds (default: 31 536 000 s = 1 year).
            Must include 'includeSubDomains' (best practice, ASVS V3.4.1).
            Absence or a max-age below the minimum is a FAIL.

        X-Content-Type-Options
            Must be exactly 'nosniff' (ASVS V3.4.4).
            Prevents MIME-type sniffing in legacy browsers.

        X-Frame-Options
            Must be 'DENY' or 'SAMEORIGIN' (ASVS V3.4.6).
            The deprecated 'ALLOW-FROM' value is a FAIL (RFC 9110).

        Content-Security-Policy
            Must be present and must NOT contain 'default-src *', which
            nullifies the policy (ASVS V3.4.3).

        Permissions-Policy
            Must be present with any non-empty value.
            Disables unused browser features (geolocation, camera, mic).

    Leaky headers that must be absent (or version-free):
        X-Powered-By   -- always a FAIL when present.
        Server         -- FAIL only when the value carries a version string
                          (e.g. 'nginx/1.18.0' is leaky; 'nginx' is acceptable).

    Cross-endpoint consistency check:
        The same headers are verified on a configurable sample of endpoints.
        Any endpoint whose security header set differs from the reference
        (first sampled endpoint) produces an additional FAIL finding
        documenting the inconsistency, because selective application of
        security headers is itself a misconfiguration.

Strategy: WHITE_BOX -- Configuration Audit (methodology section 6.2).
    Unlike tests 4.2 and 4.3, this test does NOT require Admin API access.
    The methodology labels 6.2 as WHITE_BOX to reflect its configuration-
    audit nature: we verify Gateway-injected response headers rather than
    testing empirical security behaviour.  The actual mechanism is a regular
    GET request to each sampled endpoint, with no authentication header, so
    that the Gateway returns a 401 or public response whose headers are
    inspectable.  The _requires_admin_api guard is intentionally NOT applied.

Priority: P3 -- compliance and static best-practice (methodology matrix).
    A missing security header is a defence-in-depth gap, not an immediately
    exploitable vulnerability.  P3 tests run last and do not affect fail-fast.

Sub-tests (executed in this order):
--------------------------------------------------------------------------
Sub-test 1 -- Reference endpoint header audit
    Selects the reference endpoint (first usable GET endpoint from the
    AttackSurface), sends a GET with no Authorization header, and inspects
    the response headers against the full security header checklist.

    Oracle:
        All required headers present and valid + no leaky headers -> PASS
        Any required header missing or invalid                    -> FAIL finding
        Any leaky header present                                  -> FAIL finding

Sub-test 2 -- HSTS max-age value validation
    Specifically validates the numeric max-age value in the HSTS header
    against the configured hsts_min_max_age_seconds threshold.  Separated
    from sub-test 1 because the value check requires numeric parsing beyond
    the simple presence/value check in response_inspector.

    Oracle:
        max-age >= hsts_min_max_age_seconds  -> no additional finding
        max-age < hsts_min_max_age_seconds   -> FAIL finding with actual value

Sub-test 3 -- Cross-endpoint consistency check
    Samples up to endpoint_sample_size additional endpoints (beyond the
    reference), sends a GET to each, and compares their security header
    presence set against the reference.  Missing or extra headers on any
    endpoint produce a FAIL finding documenting the inconsistency.

    Oracle:
        All sampled endpoints have same header presence set  -> no finding
        Any endpoint differs from reference                  -> FAIL finding
--------------------------------------------------------------------------

Endpoint selection strategy:
    The test selects GET endpoints from the AttackSurface.  GET is preferred
    because it is the safest read-only method and is universally supported.
    If no GET endpoints are available, the test returns SKIP.
    Parametric paths (containing '{') are de-prioritised but not excluded;
    a 404 from a parametric path does not invalidate the header check because
    the Gateway still injects security headers on 4xx responses.

EvidenceStore policy:
    Every request (including 401 responses) is logged via _log_transaction().
    Requests on endpoints that produce FAIL findings are additionally stored
    via store.add_fail_evidence() so the evidence.json contains the raw HTTP
    transaction for each reported violation.  Requests on endpoints that pass
    all checks are logged only (not stored in EvidenceStore).
"""

from __future__ import annotations

import re
from typing import ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import (
    EndpointRecord,
    EvidenceRecord,
    Finding,
    TestResult,
    TestStatus,
    TestStrategy,
)
from src.tests.base import BaseTest
from src.tests.helpers.path_resolver import resolve_path_with_seed
from src.tests.helpers.response_inspector import (
    SECURITY_HEADER_DEFINITIONS,
    find_invalid_security_headers,
    find_leaky_headers,
    find_missing_security_headers,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Regex that extracts the numeric max-age value from an HSTS header.
# The HSTS header value is a semicolon-separated directive list, e.g.:
#   "max-age=31536000; includeSubDomains"
# The capture group extracts the integer that follows 'max-age='.
_HSTS_MAX_AGE_PATTERN: re.Pattern[str] = re.compile(
    r"max-age\s*=\s*(\d+)",
    re.IGNORECASE,
)

# Header name used for HSTS checks (normalized lowercase per RFC 9110).
_HSTS_HEADER_NAME: str = "strict-transport-security"

# The includeSubDomains directive recommended by ASVS V3.4.1.
_HSTS_INCLUDE_SUBDOMAINS_DIRECTIVE: str = "includesubdomains"

# HTTP method preferred for header sampling probes.
_PREFERRED_METHOD: str = "GET"

# CWE and OWASP references for security header findings.
_REFERENCES_SECURITY_HEADERS: list[str] = [
    "OWASP ASVS v5.0.0 V3.4",
    "OWASP API8:2023 Security Misconfiguration",
    "Mozilla Observatory Security Headers Best Practices",
    "RFC 9110",
]
_REFERENCES_HSTS: list[str] = [
    "OWASP ASVS v5.0.0 V3.4.1",
    "RFC 6797 Section 6.1",
    "NIST SP 800-52 Rev. 2",
]
_REFERENCES_LEAKY: list[str] = [
    "OWASP ASVS v5.0.0 V13.4.6",
    "OWASP API8:2023 Security Misconfiguration",
    "CWE-200",
]
_REFERENCES_CONSISTENCY: list[str] = [
    "OWASP ASVS v5.0.0 V3.4",
    "OWASP API8:2023 Security Misconfiguration",
]


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------


class Test62SecurityHeadersAudit(BaseTest):
    """
    Test 6.2 -- Security Header Configuration Audit (WHITE_BOX, P3).

    Verifies that the Gateway injects the required HTTP security headers
    on every outbound response, and that no leaky server-identification
    headers are present.  Implements a three-part audit:
        1. Reference endpoint full header checklist.
        2. HSTS max-age numeric threshold validation.
        3. Cross-endpoint consistency sampling.
    """

    # ------------------------------------------------------------------
    # BaseTest class-level contract
    # ------------------------------------------------------------------

    test_id: ClassVar[str] = "6.2"
    test_name: ClassVar[str] = "Security Headers Configured Appropriately"
    priority: ClassVar[int] = 3
    domain: ClassVar[int] = 6
    strategy: ClassVar[TestStrategy] = TestStrategy.WHITE_BOX
    depends_on: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = [
        "hardening",
        "headers",
        "OWASP-API8",
        "ASVS-V3.4",
        "hsts",
        "csp",
    ]
    cwe_id: ClassVar[str] = "CWE-16"

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
        Execute the Security Header Configuration Audit.

        Workflow:
            1. Guard: AttackSurface must be present.
            2. Select reference endpoint (first usable GET from surface).
            3. Sub-test 1: audit full header checklist on reference endpoint.
            4. Sub-test 2: validate HSTS max-age numeric threshold.
            5. Sub-test 3: cross-endpoint consistency on sampled endpoints.
            6. Aggregate findings and return TestResult.

        Args:
            target:  Frozen TargetContext carrying AttackSurface and test params.
            context: Mutable TestContext (not written by this test).
            client:  SecurityClient for all HTTP requests.
            store:   EvidenceStore for persisting FAIL transaction evidence.

        Returns:
            TestResult with status PASS, FAIL, SKIP, or ERROR.
        """
        try:
            # ------------------------------------------------------------------
            # Guard: AttackSurface required
            # ------------------------------------------------------------------
            guard = self._requires_attack_surface(target)
            if guard is not None:
                return guard

            assert target.attack_surface is not None  # narrowing after guard

            # ------------------------------------------------------------------
            # Endpoint selection
            # ------------------------------------------------------------------
            all_get_endpoints = target.attack_surface.get_endpoints_by_method(_PREFERRED_METHOD)

            if not all_get_endpoints:
                return self._make_skip(
                    reason=(
                        "No GET endpoints found in the AttackSurface. "
                        "The security header audit requires at least one GET endpoint "
                        "to sample. Verify the OpenAPI specification includes GET operations."
                    )
                )

            reference_endpoint = all_get_endpoints[0]
            sample_size = target.tests_config.test_6_2.endpoint_sample_size

            # Build the consistency sample: up to sample_size additional endpoints
            # beyond the reference (index 0).  If sample_size == 0, include all.
            if sample_size == 0:
                consistency_endpoints: list[EndpointRecord] = all_get_endpoints[1:]
            else:
                consistency_endpoints = all_get_endpoints[1 : sample_size + 1]

            log.info(
                "test_6_2_endpoint_selection",
                reference=reference_endpoint.path,
                consistency_sample_count=len(consistency_endpoints),
                total_get_endpoints=len(all_get_endpoints),
            )

            # ------------------------------------------------------------------
            # Accumulated findings across all sub-tests
            # ------------------------------------------------------------------
            findings: list[Finding] = []

            # ------------------------------------------------------------------
            # Sub-test 1 + 2: reference endpoint audit.
            # _audit_reference_endpoint returns both findings and the reference
            # header presence set computed from the same response, avoiding a
            # second identical GET to the reference endpoint.
            # ------------------------------------------------------------------
            reference_findings, reference_header_presence = self._audit_reference_endpoint(
                endpoint=reference_endpoint,
                target=target,
                client=client,
                store=store,
            )
            findings.extend(reference_findings)

            # ------------------------------------------------------------------
            # Sub-test 3: cross-endpoint consistency check
            # ------------------------------------------------------------------
            for endpoint in consistency_endpoints:
                consistency_findings = self._check_endpoint_consistency(
                    endpoint=endpoint,
                    reference_presence=reference_header_presence,
                    target=target,
                    client=client,
                    store=store,
                )
                findings.extend(consistency_findings)

            # ------------------------------------------------------------------
            # Final TestResult
            # ------------------------------------------------------------------
            if findings:
                return TestResult(
                    test_id=self.test_id,
                    status=TestStatus.FAIL,
                    message=(
                        f"Security header audit found {len(findings)} violation(s) "
                        f"across {1 + len(consistency_endpoints)} endpoint(s). "
                        "See findings for details."
                    ),
                    findings=findings,
                    transaction_log=list(self._transaction_log),
                    **self._metadata_kwargs(),
                )

            return TestResult(
                test_id=self.test_id,
                status=TestStatus.PASS,
                message=(
                    f"All required security headers present and valid on "
                    f"{1 + len(consistency_endpoints)} sampled endpoint(s). "
                    "No leaky server-identification headers detected."
                ),
                findings=[],
                transaction_log=list(self._transaction_log),
                **self._metadata_kwargs(),
            )

        except Exception as exc:  # noqa: BLE001
            return self._make_error(exc)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _audit_reference_endpoint(
        self,
        endpoint: EndpointRecord,
        target: TargetContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> tuple[list[Finding], frozenset[str]]:
        """
        Execute sub-tests 1 and 2 against the reference endpoint.

        Sends a single GET request (no Authorization header) and runs the
        full header checklist plus the HSTS max-age numeric threshold check.
        Also computes the reference header presence set from the same response
        headers so that the caller can use it for the cross-endpoint consistency
        check (sub-test 3) without issuing a second identical GET.

        Args:
            endpoint: The reference EndpointRecord to probe.
            target:   TargetContext for base_url, path_seed, and test config.
            client:   SecurityClient for the HTTP request.
            store:    EvidenceStore for persisting FAIL evidence records.

        Returns:
            Tuple of (findings, reference_presence) where:
                findings:           List of Finding objects; empty if all pass.
                reference_presence: frozenset of lowercase security header names
                                    present in the response, for consistency check.
        """
        resolved_path = resolve_path_with_seed(endpoint.path, target.path_seed)
        response, record = client.request(
            method=_PREFERRED_METHOD,
            path=resolved_path,
            test_id=self.test_id,
        )

        findings: list[Finding] = []
        headers = dict(response.headers)
        is_fail = False

        # Sub-test 1a -- missing required security headers
        missing = find_missing_security_headers(headers)
        if missing:
            is_fail = True
            findings.append(
                Finding(
                    title="Required Security Headers Missing",
                    detail=(
                        f"Endpoint {endpoint.method} {endpoint.path} is missing the "
                        f"following required security headers: {', '.join(missing)}. "
                        "These headers must be injected by the Gateway on every response "
                        "to provide defence-in-depth against client-side attacks "
                        "(OWASP ASVS v5.0.0 V3.4)."
                    ),
                    references=_REFERENCES_SECURITY_HEADERS,
                    evidence_ref=record.record_id,
                )
            )
            log.warning(
                "test_6_2_missing_headers",
                endpoint=endpoint.path,
                missing=missing,
            )

        # Sub-test 1b -- present but invalid security headers
        invalid = find_invalid_security_headers(headers)
        if invalid:
            is_fail = True
            findings.append(
                Finding(
                    title="Security Headers Present but Misconfigured",
                    detail=(
                        f"Endpoint {endpoint.method} {endpoint.path} has the following "
                        f"security headers present but with non-compliant values: "
                        f"{', '.join(invalid)}. "
                        "Common causes: HSTS max-age below minimum, X-Frame-Options "
                        "using the deprecated ALLOW-FROM value, or CSP containing "
                        "'default-src *' which nullifies the policy."
                    ),
                    references=_REFERENCES_SECURITY_HEADERS,
                    evidence_ref=record.record_id,
                )
            )
            log.warning(
                "test_6_2_invalid_headers",
                endpoint=endpoint.path,
                invalid=invalid,
            )

        # Sub-test 1c -- leaky server-identification headers
        leaky = find_leaky_headers(headers)
        if leaky:
            is_fail = True
            findings.append(
                Finding(
                    title="Server Identification Headers Disclose Implementation Details",
                    detail=(
                        f"Endpoint {endpoint.method} {endpoint.path} includes the "
                        f"following headers that disclose server implementation details: "
                        f"{', '.join(leaky)}. "
                        "The 'X-Powered-By' header must be removed entirely. "
                        "The 'Server' header must not carry a version string "
                        "(e.g. 'nginx/1.18.0' is leaky; 'nginx' is acceptable). "
                        "These headers enable fingerprinting and CVE targeting "
                        "(OWASP ASVS v5.0.0 V13.4.6)."
                    ),
                    references=_REFERENCES_LEAKY,
                    evidence_ref=record.record_id,
                )
            )
            log.warning(
                "test_6_2_leaky_headers",
                endpoint=endpoint.path,
                leaky=leaky,
            )

        # Sub-test 2 -- HSTS max-age numeric threshold
        hsts_finding = self._check_hsts_max_age(
            headers=headers,
            endpoint=endpoint,
            record=record,
            hsts_min_max_age_seconds=target.tests_config.test_6_2.hsts_min_max_age_seconds,
        )
        if hsts_finding is not None:
            is_fail = True
            findings.append(hsts_finding)

        # Log the transaction; store evidence only if this endpoint failed.
        if is_fail:
            store.add_fail_evidence(record)
            self._log_transaction(record, oracle_state="FAIL", is_fail=True)
        else:
            self._log_transaction(record, oracle_state="PASS")

        # Build reference presence set from the headers already in memory.
        # This avoids issuing a second identical GET for the consistency check.
        normalized: dict[str, str] = {k.lower(): v for k, v in headers.items()}
        reference_presence = frozenset(
            name for name in SECURITY_HEADER_DEFINITIONS if name in normalized
        )

        return findings, reference_presence

    def _check_hsts_max_age(
        self,
        headers: dict[str, str],
        endpoint: EndpointRecord,
        record: EvidenceRecord,
        hsts_min_max_age_seconds: int,
    ) -> Finding | None:
        """
        Validate the numeric max-age value in the HSTS header.

        Parses the integer following 'max-age=' in the Strict-Transport-Security
        header and compares it against the configured minimum.  Also checks for
        the 'includeSubDomains' directive as a best-practice warning embedded
        in the finding detail (not a separate FAIL).

        Args:
            headers:                 Normalized response headers dict.
            endpoint:                EndpointRecord being audited (for finding detail).
            record:                  EvidenceRecord for evidence_ref linkage.
            hsts_min_max_age_seconds: Minimum acceptable max-age from test config.

        Returns:
            A Finding if the HSTS max-age is present but below the minimum.
            None if the header is absent (already caught by sub-test 1a),
            not parseable (already caught by sub-test 1b), or valid.
        """
        normalized_headers: dict[str, str] = {k.lower(): v for k, v in headers.items()}
        hsts_value = normalized_headers.get(_HSTS_HEADER_NAME, "")

        if not hsts_value:
            # Absence is already reported by find_missing_security_headers.
            return None

        match = _HSTS_MAX_AGE_PATTERN.search(hsts_value)
        if match is None:
            # Malformed value is caught by find_invalid_security_headers.
            return None

        actual_max_age = int(match.group(1))

        if actual_max_age < hsts_min_max_age_seconds:
            include_subdomains_present = _HSTS_INCLUDE_SUBDOMAINS_DIRECTIVE in hsts_value.lower()
            subdomain_note = (
                ""
                if include_subdomains_present
                else " The 'includeSubDomains' directive is also absent (best practice)."
            )
            log.warning(
                "test_6_2_hsts_max_age_below_minimum",
                endpoint=endpoint.path,
                actual_max_age=actual_max_age,
                required_minimum=hsts_min_max_age_seconds,
            )
            return Finding(
                title="HSTS max-age Below Required Minimum",
                detail=(
                    f"Endpoint {endpoint.method} {endpoint.path} returns "
                    f"Strict-Transport-Security with max-age={actual_max_age}, "
                    f"which is below the required minimum of "
                    f"{hsts_min_max_age_seconds} seconds (1 year per ASVS V3.4.1). "
                    "A short max-age reduces the window during which browsers enforce "
                    f"HTTPS-only behaviour, weakening the HSTS guarantee.{subdomain_note}"
                ),
                references=_REFERENCES_HSTS,
                evidence_ref=record.record_id,
            )

        # max-age is valid; optionally log a debug note about includeSubDomains.
        include_subdomains_present = _HSTS_INCLUDE_SUBDOMAINS_DIRECTIVE in hsts_value.lower()
        if not include_subdomains_present:
            log.debug(
                "test_6_2_hsts_include_subdomains_absent",
                endpoint=endpoint.path,
                note=(
                    "The 'includeSubDomains' directive is absent from HSTS. "
                    "This is a best-practice recommendation, not a FAIL."
                ),
            )

        return None

    def _check_endpoint_consistency(
        self,
        endpoint: EndpointRecord,
        reference_presence: frozenset[str],
        target: TargetContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> list[Finding]:
        """
        Compare a sampled endpoint's security header presence against the reference.

        Sends a GET to the endpoint and checks whether the set of present required
        security headers matches the reference set.  Any discrepancy (a header
        present on the reference but absent here, or vice-versa) is a FAIL finding.

        Args:
            endpoint:           EndpointRecord to probe.
            reference_presence: frozenset of header names present on the reference,
                                computed by _audit_reference_endpoint from the same
                                response used for sub-tests 1 and 2.
            target:             TargetContext for base_url, path_seed.
            client:             SecurityClient for the HTTP request.
            store:              EvidenceStore for FAIL evidence persistence.

        Returns:
            List of Finding objects.  Empty if the endpoint is consistent.
        """
        resolved_path = resolve_path_with_seed(endpoint.path, target.path_seed)
        response, record = client.request(
            method=_PREFERRED_METHOD,
            path=resolved_path,
            test_id=self.test_id,
        )

        normalized: dict[str, str] = {k.lower(): v for k, v in response.headers.items()}
        endpoint_presence = frozenset(
            name for name in SECURITY_HEADER_DEFINITIONS if name in normalized
        )

        missing_vs_reference = sorted(reference_presence - endpoint_presence)
        extra_vs_reference = sorted(endpoint_presence - reference_presence)

        if not missing_vs_reference and not extra_vs_reference:
            self._log_transaction(record, oracle_state="CONSISTENT")
            return []

        # Inconsistency detected.
        store.add_fail_evidence(record)
        self._log_transaction(record, oracle_state="INCONSISTENT", is_fail=True)

        detail_parts: list[str] = [
            f"Endpoint {endpoint.method} {endpoint.path} has an inconsistent "
            "security header set compared to the reference endpoint."
        ]
        if missing_vs_reference:
            detail_parts.append(
                f"Headers present on reference but absent here: {', '.join(missing_vs_reference)}."
            )
        if extra_vs_reference:
            detail_parts.append(
                f"Headers absent on reference but present here: {', '.join(extra_vs_reference)}."
            )
        detail_parts.append(
            "Inconsistent security headers indicate selective or incomplete "
            "Gateway policy application.  All endpoints must receive the same "
            "security header set regardless of authentication state or path."
        )

        log.warning(
            "test_6_2_consistency_mismatch",
            endpoint=endpoint.path,
            missing_vs_reference=missing_vs_reference,
            extra_vs_reference=extra_vs_reference,
        )

        return [
            Finding(
                title="Security Header Inconsistency Across Endpoints",
                detail=" ".join(detail_parts),
                references=_REFERENCES_CONSISTENCY,
                evidence_ref=record.record_id,
            )
        ]
