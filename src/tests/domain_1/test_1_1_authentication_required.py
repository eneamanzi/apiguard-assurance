"""
src/tests/domain_1/test_1_1_authentication_required.py

Test 1.1 -- Only Authenticated Requests Access Protected Resources.

Guarantee (3_TOP_metodologia.md, Section 1.1):
    Every endpoint that exposes sensitive data or privileged operations must
    reject requests that carry no credentials before reaching the business
    logic. The enforcement must produce HTTP 401 Unauthorized or 403 Forbidden
    immediately on missing or structurally invalid tokens.

Methodology (3_TOP_metodologia.md, Section 1.1):
    - Unauthenticated access: GET every protected endpoint with no
      Authorization header.
    - Empty and malformed token: send structurally broken token values on a
      confirmed ENFORCED endpoint.
    - Path normalization: test variant paths on a confirmed ENFORCED endpoint
      to detect Gateway normalisation bypass.

Strategy: BLACK_BOX -- zero credentials, anonymous attacker simulation.
Priority: P0 -- authentication enforcement is the foundational Gateway guarantee.
          A failure here invalidates the premise of every subsequent test.

Oracle design -- three-outcome classification
---------------------------------------------
A response to an unauthenticated request falls into exactly one of three
semantic categories:

    ENFORCED  (401, 403)
        The API verified the absence of credentials and correctly blocked
        the request. Positive evidence that the auth layer is active.

    BYPASS  (2xx)
        The API returned data or completed an operation without requiring
        credentials. This is the vulnerability we are searching for and
        the ONLY category that produces a Finding.

    INCONCLUSIVE  (3xx, 4xx other than 401/403, 5xx, transport errors)
        The response neither confirms enforcement nor demonstrates bypass.
        Sub-categories:
            INCONCLUSIVE_PARAMETRIC   -- 404/405/410 on a parametric path:
                expected behaviour when the placeholder resource ID does not
                exist on the server. Not a finding.
            INCONCLUSIVE_NOT_FOUND    -- 404/405/410 on a non-parametric path:
                the endpoint exists in the spec but the server does not find it.
                Possible spec/server configuration drift. Logged as WARNING.
            INCONCLUSIVE_REDIRECT     -- 3xx: server issued a redirect.
                Ambiguous (could be login redirect = enforced). No finding.
            INCONCLUSIVE_SERVER_ERROR -- 5xx: server crashed. No auth finding.
            TRANSPORT_ERROR           -- connection-level failure. No finding.

Tier segregation
----------------
All protected endpoints are partitioned into two tiers:

    Tier A -- non-parametric paths (no {param} templates).
        The server can resolve the resource handler without an actual resource
        ID. Auth enforcement is visible: the server will perform the auth check
        and return 401/403, or return 2xx (bypass). INCONCLUSIVE_NOT_FOUND on
        Tier A is anomalous and is logged separately for analyst review.

    Tier B -- parametric paths (contain {param} templates).
        The server performs resource-resolution before the auth check in many
        REST frameworks. A 404 response is the normal, expected outcome when
        a placeholder ID is used. These are classified INCONCLUSIVE_PARAMETRIC
        and do not generate findings. A 2xx on a parametric path IS still a
        bypass finding: the server returned data for a resource that a
        placeholder ID resolved to.

Coverage reporting
------------------
The TestResult message includes a full breakdown of outcome counts across all
probed endpoints. This makes the assessment scope and its inherent limitations
transparent in the report -- a prerequisite for academic rigour.

Cap behaviour (config.tests.domain_1.max_endpoints_cap)
--------------------------------------------------------
By default (cap = 0) the test probes ALL protected endpoints declared in the
OpenAPI spec. A positive cap limits the probe to the first N endpoints in the
list returned by AttackSurface.get_authenticated_endpoints(). When a cap is
applied, the message explicitly notes this trade-off so that the operator can
assess whether the reduced coverage is acceptable for their context.

DAG role
--------
test_id = "1.1", depends_on = [].
This test is the prerequisite for tests 1.2, 1.3, 1.4, 2.1, 2.2, 2.3, 2.4,
2.5, 3.1, 5.1, 5.2, 6.1, 6.3, 7.1, 7.3, 7.4. Its PASS confirms the auth
layer exists and it is safe to proceed with authenticated grey-box testing.
With fail_fast=true, a FAIL or ERROR here halts the entire pipeline.

Audit trail integration
-----------------------
Every HTTP transaction performed during execute() is recorded via
self._log_transaction(record, oracle_state=..., is_fail=...). The oracle_state
values used in this test are:

    Main probe loop:
        ENFORCED                 -- 401/403, auth correctly applied
        AUTH_BYPASS              -- 2xx without credentials (FAIL)
        INCONCLUSIVE_REDIRECT    -- 3xx, ambiguous outcome
        INCONCLUSIVE_PARAMETRIC  -- 404/405/410 on parametric path, expected
        INCONCLUSIVE_NOT_FOUND   -- 404/405/410 on non-parametric path, anomalous
        INCONCLUSIVE_SERVER_ERROR -- 5xx, server-side crash

    Malformed token sub-check:
        MALFORMED_TOKEN_BYPASS   -- 2xx returned for structurally invalid token (FAIL)
        MALFORMED_TOKEN_REJECTED -- 401/403 returned for invalid token, correct

    Path normalization sub-check:
        NORMALIZATION_BYPASS     -- 2xx on a path variant without auth (FAIL)
        NORMALIZATION_ACCEPTABLE -- 401/403/404/405, acceptable outcome
"""

from __future__ import annotations

import re
from typing import ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import EndpointRecord, Finding, TestResult, TestStatus, TestStrategy
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Oracle outcome labels
# Each constant is a key in the counters dict aggregated for coverage reporting.
# ---------------------------------------------------------------------------

_OUTCOME_ENFORCED: str = "enforced"
_OUTCOME_BYPASS: str = "bypass"
_OUTCOME_INCONCLUSIVE_PARAMETRIC: str = "inconclusive_parametric"
_OUTCOME_INCONCLUSIVE_NOT_FOUND: str = "inconclusive_not_found"
_OUTCOME_INCONCLUSIVE_REDIRECT: str = "inconclusive_redirect"
_OUTCOME_INCONCLUSIVE_SERVER_ERROR: str = "inconclusive_server_error"
_OUTCOME_TRANSPORT_ERROR: str = "transport_error"

# ---------------------------------------------------------------------------
# Oracle HTTP status code sets
# ---------------------------------------------------------------------------

# Positive evidence that auth enforcement exists for the probed endpoint.
_ENFORCED_STATUS_CODES: frozenset[int] = frozenset({401, 403})

# Positive evidence that the endpoint served data without requiring auth.
# Only 2xx responses constitute a bypass -- the server completed the request.
# 3xx redirects are classified as INCONCLUSIVE_REDIRECT (see below).
_BYPASS_STATUS_CODES: frozenset[int] = frozenset(range(200, 300))

# Redirect responses: ambiguous. The redirect target could be a login page
# (enforcement) or a data resource (bypass). Since SecurityClient disables
# redirect following, we cannot determine which. Classified as INCONCLUSIVE.
_REDIRECT_STATUS_CODES: frozenset[int] = frozenset({301, 302, 303, 307, 308})

# Resource-absent responses: the server acknowledged the request but could not
# find the resource. Auth may or may not have been checked first.
_RESOURCE_ABSENT_STATUS_CODES: frozenset[int] = frozenset({404, 405, 410})

# ---------------------------------------------------------------------------
# Placeholder value for OpenAPI path template parameters.
# The value "1" is chosen because it is a valid integer ID for most resources.
# A non-existent resource will produce 404 (classified as INCONCLUSIVE),
# which is the expected and documented behaviour for Tier B endpoints.
# ---------------------------------------------------------------------------

_PATH_PARAM_PLACEHOLDER: str = "1"

# ---------------------------------------------------------------------------
# Malformed Authorization header values for sub-check 2.
# Each tuple: (header_value, human_readable_label)
# ---------------------------------------------------------------------------

_MALFORMED_TOKENS: tuple[tuple[str, str], ...] = (
    ("Bearer", "Bearer scheme with empty token value"),
    ("Bearer null", "literal string 'null' as token"),
    ("Bearer undefined", "literal string 'undefined' as token"),
    ("no-scheme-apiguard-probe", "raw string without Bearer prefix"),
    ("Bearer " + "X" * 8, "token body structurally too short for any real format"),
)

# ---------------------------------------------------------------------------
# Path normalization variant generators for sub-check 3.
# Applied to the first Tier A endpoint confirmed as ENFORCED.
# ---------------------------------------------------------------------------

# Acceptable outcomes for normalization variants: the Gateway either
# enforces auth on the variant (401/403) or rejects the path entirely (404/405).
# Any 2xx response is a bypass finding.
_NORMALIZATION_ACCEPTABLE_CODES: frozenset[int] = frozenset({401, 403, 404, 405, 410})


# ---------------------------------------------------------------------------
# Test implementation
# ---------------------------------------------------------------------------


class Test_1_1_AuthenticationRequired(BaseTest):  # noqa: N801
    """
    Verify that all documented protected endpoints enforce authentication.

    Probes every protected endpoint in the OpenAPI spec (subject to the
    configurable cap at config.tests.domain_1.max_endpoints_cap) with
    a GET request carrying no Authorization header. Classifies each response
    using the three-outcome oracle (ENFORCED / BYPASS / INCONCLUSIVE) and
    reports a Finding only for BYPASS outcomes.

    Additionally runs two sub-checks on the first confirmed ENFORCED Tier A
    endpoint:
        - Malformed token values (should all produce 401).
        - Path normalization variants (trailing slash, uppercase, double slash).

    Every HTTP transaction -- including ENFORCED and INCONCLUSIVE outcomes --
    is recorded in the per-test audit trail via self._log_transaction() so
    that the HTML report can display the full coverage scope.
    """

    test_id: ClassVar[str] = "1.1"
    priority: ClassVar[int] = 0
    strategy: ClassVar[TestStrategy] = TestStrategy.BLACK_BOX
    depends_on: ClassVar[list[str]] = []
    test_name: ClassVar[str] = "Only Authenticated Requests Access Protected Resources"
    domain: ClassVar[int] = 1
    tags: ClassVar[list[str]] = [
        "authentication",
        "OWASP-API2:2023",
        "NIST-SP-800-63B-4-S4.3.1",
        "OWASP-ASVS-V6.3",
        "CIS-API-Gateway-Controls-2.1",
    ]
    cwe_id: ClassVar[str] = "CWE-306"

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Execute authentication enforcement verification across all protected endpoints.

        Returns PASS if no bypass is detected and at least one endpoint confirmed
        enforcement. Returns FAIL with one Finding per bypass detected (main probe,
        malformed token sub-check, normalization sub-check). Returns SKIP if the
        spec declares no protected endpoints. Returns ERROR on unexpected exception.
        """
        try:
            skip = self._requires_attack_surface(target)
            if skip is not None:
                return skip

            assert target.attack_surface is not None
            surface = target.attack_surface

            protected = surface.get_authenticated_endpoints()
            if not protected:
                return self._make_skip(
                    reason=(
                        "No endpoints with security requirements found in the OpenAPI spec. "
                        "Either the API declares no security schemes, or all endpoints are "
                        "marked as publicly accessible. Cannot verify authentication enforcement."
                    )
                )

            # Apply configurable cap. Default 0 = test all endpoints.
            cap = target.tests_config.test_1_1.max_endpoints_cap
            candidates: list[EndpointRecord] = protected if cap == 0 else protected[:cap]

            log.info(
                "test_1_1_starting",
                total_protected=len(protected),
                total_to_probe=len(candidates),
                cap_applied=cap > 0,
                cap_value=cap,
            )

            # ------------------------------------------------------------------
            # Phase A -- Main probe loop across all candidate endpoints
            # ------------------------------------------------------------------

            counters: dict[str, int] = {
                _OUTCOME_ENFORCED: 0,
                _OUTCOME_BYPASS: 0,
                _OUTCOME_INCONCLUSIVE_PARAMETRIC: 0,
                _OUTCOME_INCONCLUSIVE_NOT_FOUND: 0,
                _OUTCOME_INCONCLUSIVE_REDIRECT: 0,
                _OUTCOME_INCONCLUSIVE_SERVER_ERROR: 0,
                _OUTCOME_TRANSPORT_ERROR: 0,
            }
            findings: list[Finding] = []

            # Tracks the first non-parametric endpoint confirmed as ENFORCED.
            # Used as the anchor for sub-checks B and C. We pick the first
            # rather than a random one for reproducibility across runs.
            enforced_tier_a_anchor: EndpointRecord | None = None

            for endpoint in candidates:
                is_parametric = "{" in endpoint.path

                outcome, finding = self._probe_unauthenticated(
                    endpoint=endpoint,
                    is_parametric=is_parametric,
                    client=client,
                    store=store,
                )
                counters[outcome] += 1

                if finding is not None:
                    findings.append(finding)

                # Capture the first Tier A endpoint confirmed as ENFORCED.
                if (
                    outcome == _OUTCOME_ENFORCED
                    and not is_parametric
                    and enforced_tier_a_anchor is None
                ):
                    enforced_tier_a_anchor = endpoint
                    log.debug(
                        "test_1_1_enforced_anchor_selected",
                        path=endpoint.path,
                        method=endpoint.method,
                    )

            # ------------------------------------------------------------------
            # Phase B -- Malformed token sub-check (requires ENFORCED anchor)
            # The anchor guarantees we probe a reachable, protected endpoint.
            # Testing malformed tokens on a 404-returning endpoint would produce
            # uninformative results (the 404 may precede the auth check).
            # ------------------------------------------------------------------

            if enforced_tier_a_anchor is not None:
                malformed_findings = self._check_malformed_tokens(
                    anchor=enforced_tier_a_anchor,
                    client=client,
                    store=store,
                )
                findings.extend(malformed_findings)
                counters[_OUTCOME_BYPASS] += len(malformed_findings)
            else:
                log.info(
                    "test_1_1_malformed_token_subcheck_skipped",
                    reason=(
                        "No Tier A (non-parametric) endpoint returned ENFORCED. "
                        "Cannot anchor the malformed-token sub-check to a reachable "
                        "protected endpoint. Sub-check omitted."
                    ),
                )

            # ------------------------------------------------------------------
            # Phase C -- Path normalization sub-check (same anchor as Phase B)
            # ------------------------------------------------------------------

            if enforced_tier_a_anchor is not None:
                normalization_findings = self._check_path_normalization(
                    anchor=enforced_tier_a_anchor,
                    client=client,
                    store=store,
                )
                findings.extend(normalization_findings)
                counters[_OUTCOME_BYPASS] += len(normalization_findings)

            # ------------------------------------------------------------------
            # Phase D -- Build result
            # ------------------------------------------------------------------

            coverage_summary = _build_coverage_summary(
                total_protected=len(protected),
                total_tested=len(candidates),
                cap_applied=cap > 0,
                counters=counters,
            )

            if findings:
                # Include the accumulated transaction_log explicitly because
                # this FAIL path uses a direct TestResult() constructor rather
                # than the _make_fail() helper (which supports only a single
                # Finding). Passing transaction_log=list(self._transaction_log)
                # ensures the audit trail is preserved in the HTML report.
                return TestResult(
                    test_id=self.test_id,
                    status=TestStatus.FAIL,
                    message=(
                        f"Authentication enforcement violated on {len(findings)} check(s). "
                        f"{coverage_summary}"
                    ),
                    findings=findings,
                    transaction_log=list(self._transaction_log),
                    **self._metadata_kwargs(),
                )

            # No bypass detected. Distinguish between confirmed enforcement and
            # zero evidence (all INCONCLUSIVE). Both return PASS but with
            # different messages so analysts can assess confidence level.
            if counters[_OUTCOME_ENFORCED] == 0:
                return self._make_pass(
                    message=(
                        "No authentication bypass detected, but no positive enforcement "
                        "evidence was obtained (all responses were INCONCLUSIVE). "
                        "This occurs when all probed endpoints return 404 before "
                        "reaching the auth check. Manual verification recommended. "
                        f"{coverage_summary}"
                    )
                )

            return self._make_pass(
                message=(
                    "Authentication enforcement correctly applied on all probed endpoints. "
                    "No unauthenticated access was possible. "
                    f"{coverage_summary}"
                )
            )

        except Exception as exc:
            return self._make_error(exc)

    # ------------------------------------------------------------------
    # Sub-check A -- Single unauthenticated probe (called in the main loop)
    # ------------------------------------------------------------------

    def _probe_unauthenticated(
        self,
        endpoint: EndpointRecord,
        is_parametric: bool,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> tuple[str, Finding | None]:
        """
        Send one GET request without credentials and classify the response.

        Uses GET unconditionally regardless of the endpoint's declared HTTP
        method. Rationale: GET is the read operation with the lowest chance
        of server-side side effects. A server that performs auth enforcement
        before processing the request will return 401/403 for GET just as it
        would for POST/DELETE. A non-GET endpoint may return 405 (Method Not
        Allowed), which is correctly classified as INCONCLUSIVE_NOT_FOUND and
        does not generate a false positive.

        Every completed HTTP transaction is recorded in the audit trail via
        self._log_transaction(). Transport errors are counted as
        TRANSPORT_ERROR and are not logged (no record was produced).

        Args:
            endpoint:      The EndpointRecord to probe.
            is_parametric: True if the endpoint path contains {param} templates.
            client:        SecurityClient for HTTP requests.
            store:         EvidenceStore for FAIL evidence.

        Returns:
            Tuple of (outcome_label, Finding | None).
            Finding is non-None only for BYPASS outcomes.
        """
        path = _resolve_path(endpoint.path)

        try:
            response, record = client.request(
                method="GET",
                path=path,
                test_id=self.test_id,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "test_1_1_transport_error",
                path=path,
                exc_type=type(exc).__name__,
                detail=str(exc),
            )
            return _OUTCOME_TRANSPORT_ERROR, None

        status = response.status_code

        # --- ENFORCED: auth was verified before responding ---
        if status in _ENFORCED_STATUS_CODES:
            log.debug(
                "test_1_1_probe_enforced",
                path=path,
                status_code=status,
                is_parametric=is_parametric,
            )
            self._log_transaction(record, oracle_state="ENFORCED")
            return _OUTCOME_ENFORCED, None

        # --- BYPASS: server returned data without requiring auth ---
        if status in _BYPASS_STATUS_CODES:
            log.warning(
                "test_1_1_probe_bypass_detected",
                path=path,
                status_code=status,
                is_parametric=is_parametric,
            )
            store.add_fail_evidence(record)
            self._log_transaction(record, oracle_state="AUTH_BYPASS", is_fail=True)
            finding = Finding(
                title="Protected endpoint accessible without authentication",
                detail=(
                    f"GET {path} returned HTTP {status} with no Authorization header. "
                    f"The endpoint is declared with security requirements in the OpenAPI "
                    f"spec (path: '{endpoint.path}', method: {endpoint.method}) "
                    f"but returned a successful response without requiring credentials. "
                    f"Expected: HTTP 401 Unauthorized or 403 Forbidden."
                ),
                references=[
                    self.cwe_id,
                    "OWASP-API2:2023",
                    "NIST-SP-800-63B-4-S4.3.1",
                    "OWASP-ASVS-V6.3",
                ],
                evidence_ref=record.record_id,
            )
            return _OUTCOME_BYPASS, finding

        # --- INCONCLUSIVE: redirect, resource absent, or server error ---

        if status in _REDIRECT_STATUS_CODES:
            log.debug(
                "test_1_1_probe_redirect",
                path=path,
                status_code=status,
                detail=(
                    "Server issued a redirect. Cannot determine whether the "
                    "redirect target enforces auth without following it. "
                    "Classified as INCONCLUSIVE_REDIRECT."
                ),
            )
            self._log_transaction(record, oracle_state="INCONCLUSIVE_REDIRECT")
            return _OUTCOME_INCONCLUSIVE_REDIRECT, None

        if status in _RESOURCE_ABSENT_STATUS_CODES:
            if is_parametric:
                # Expected: the placeholder ID "1" does not correspond to any
                # real resource on the server.
                log.debug(
                    "test_1_1_probe_inconclusive_parametric",
                    path=path,
                    status_code=status,
                )
                self._log_transaction(record, oracle_state="INCONCLUSIVE_PARAMETRIC")
                return _OUTCOME_INCONCLUSIVE_PARAMETRIC, None
            else:
                # Anomalous: a non-parametric endpoint exists in the spec but
                # the server cannot find it. Possible spec/server drift.
                log.warning(
                    "test_1_1_probe_tier_a_not_found",
                    path=path,
                    status_code=status,
                    detail=(
                        "A non-parametric endpoint declared in the OpenAPI spec "
                        "returned 404/405/410 without authentication. "
                        "This may indicate configuration drift between the spec "
                        "and the deployed server. No auth finding generated."
                    ),
                )
                self._log_transaction(record, oracle_state="INCONCLUSIVE_NOT_FOUND")
                return _OUTCOME_INCONCLUSIVE_NOT_FOUND, None

        if status >= 500:  # noqa: PLR2004
            log.debug(
                "test_1_1_probe_server_error",
                path=path,
                status_code=status,
            )
            self._log_transaction(record, oracle_state="INCONCLUSIVE_SERVER_ERROR")
            return _OUTCOME_INCONCLUSIVE_SERVER_ERROR, None

        # Catch-all for any other status (429 Too Many Requests, etc.).
        log.debug(
            "test_1_1_probe_unclassified_status",
            path=path,
            status_code=status,
        )
        self._log_transaction(record, oracle_state="INCONCLUSIVE_NOT_FOUND")
        return _OUTCOME_INCONCLUSIVE_NOT_FOUND, None

    # ------------------------------------------------------------------
    # Sub-check B -- Malformed Authorization header values
    # ------------------------------------------------------------------

    def _check_malformed_tokens(
        self,
        anchor: EndpointRecord,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> list[Finding]:
        """
        Send structurally invalid Authorization header values to the anchor endpoint.

        Tests whether the server accepts tokens that are syntactically malformed
        -- i.e., tokens that no legitimate client would ever send. A secure server
        must reject all of these with 401/403, identical to the missing-header case.

        The anchor endpoint is guaranteed to have returned ENFORCED for a no-auth
        request, so we know the endpoint is reachable and the auth layer is active.
        This eliminates the ambiguity that would arise from testing malformed tokens
        on an endpoint that already returned 404.

        All transactions (both BYPASS and correctly rejected) are recorded in the
        audit trail with their respective oracle states.

        Args:
            anchor: First Tier A endpoint confirmed as ENFORCED.
            client: SecurityClient for HTTP requests.
            store:  EvidenceStore for FAIL evidence.

        Returns:
            List of Findings for any malformed token that produced a BYPASS response.
        """
        findings: list[Finding] = []
        path = _resolve_path(anchor.path)

        for token_value, token_label in _MALFORMED_TOKENS:
            try:
                response, record = client.request(
                    method="GET",
                    path=path,
                    test_id=self.test_id,
                    headers={"Authorization": token_value},
                )
            except Exception as exc:  # noqa: BLE001
                log.debug(
                    "test_1_1_malformed_token_transport_error",
                    path=path,
                    token_label=token_label,
                    exc_type=type(exc).__name__,
                    detail=str(exc),
                )
                continue

            if response.status_code in _BYPASS_STATUS_CODES:
                log.warning(
                    "test_1_1_malformed_token_bypass",
                    path=path,
                    token_label=token_label,
                    status_code=response.status_code,
                )
                store.add_fail_evidence(record)
                self._log_transaction(
                    record,
                    oracle_state="MALFORMED_TOKEN_BYPASS",
                    is_fail=True,
                )
                findings.append(
                    Finding(
                        title="Protected endpoint accepts malformed Authorization token",
                        detail=(
                            f"GET {path} with 'Authorization: {token_value}' "
                            f"({token_label}) returned HTTP {response.status_code}. "
                            f"A syntactically malformed token must be rejected with "
                            f"401 Unauthorized, identical to the missing-header case. "
                            f"The server is not performing structural validation on "
                            f"the Authorization header value before processing the request."
                        ),
                        references=[
                            self.cwe_id,
                            "OWASP-API2:2023",
                            "RFC-9110-S11.6.2",
                            "OWASP-ASVS-V6.3",
                        ],
                        evidence_ref=record.record_id,
                    )
                )
            else:
                # 401/403: server correctly rejected the malformed token.
                self._log_transaction(record, oracle_state="MALFORMED_TOKEN_REJECTED")

        return findings

    # ------------------------------------------------------------------
    # Sub-check C -- Path normalization variants
    # ------------------------------------------------------------------

    def _check_path_normalization(
        self,
        anchor: EndpointRecord,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> list[Finding]:
        """
        Test path normalization variants of the anchor endpoint without credentials.

        A secure Gateway normalises request paths before applying security policies.
        If a variant path bypasses authentication (returns 2xx), it means the
        Gateway is matching security policies against the raw request path rather
        than the normalized form.

        Acceptable responses for variants:
            401/403 -- auth enforced on the variant (correct)
            404/405 -- path rejected after normalization (correct)
            2xx     -- bypass finding (incorrect)

        The 404 on a normalization variant is explicitly acceptable: it means the
        Gateway normalised the path and found no matching route, which is the
        correct behaviour for a deny-by-default Gateway.

        All transactions are recorded in the audit trail regardless of outcome.

        Args:
            anchor: First Tier A endpoint confirmed as ENFORCED.
            client: SecurityClient for HTTP requests.
            store:  EvidenceStore for FAIL evidence.

        Returns:
            List of Findings for any variant path that produced a BYPASS response.
        """
        findings: list[Finding] = []
        base_path = _resolve_path(anchor.path)
        path_without_leading_slash = base_path.lstrip("/")

        variants: list[tuple[str, str]] = [
            (base_path.rstrip("/") + "/", "trailing slash appended"),
            ("/" + path_without_leading_slash.upper(), "path converted to uppercase"),
            ("/" + "/" + path_without_leading_slash, "double leading slash"),
        ]

        for variant_path, variant_label in variants:
            # Skip degenerate cases where the variant is identical to the base.
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
                    "test_1_1_normalization_transport_error",
                    variant_path=variant_path,
                    variant_label=variant_label,
                    exc_type=type(exc).__name__,
                    detail=str(exc),
                )
                continue

            status = response.status_code

            if status in _NORMALIZATION_ACCEPTABLE_CODES:
                log.debug(
                    "test_1_1_normalization_acceptable",
                    variant_path=variant_path,
                    variant_label=variant_label,
                    status_code=status,
                )
                self._log_transaction(record, oracle_state="NORMALIZATION_ACCEPTABLE")
                continue

            if status in _BYPASS_STATUS_CODES:
                log.warning(
                    "test_1_1_normalization_bypass",
                    base_path=base_path,
                    variant_path=variant_path,
                    variant_label=variant_label,
                    status_code=status,
                )
                store.add_fail_evidence(record)
                self._log_transaction(
                    record,
                    oracle_state="NORMALIZATION_BYPASS",
                    is_fail=True,
                )
                findings.append(
                    Finding(
                        title="Path normalisation bypass: protected endpoint accessible",
                        detail=(
                            f"GET {variant_path} ({variant_label}) returned HTTP {status} "
                            f"with no Authorization header. "
                            f"The canonical path '{base_path}' correctly returned "
                            f"401/403 when probed without credentials, but this "
                            f"normalisation variant bypasses the security policy. "
                            f"The Gateway is applying auth policies against the raw "
                            f"request path before normalisation."
                        ),
                        references=[
                            self.cwe_id,
                            "OWASP-ASVS-V6.3",
                            "NIST-SP-800-204-S4.1",
                            "CWE-284",
                        ],
                        evidence_ref=record.record_id,
                    )
                )
            else:
                # Any other status (e.g. 429, 5xx): neither bypass nor clean deny.
                # Record without a specific oracle label -- treated as inconclusive.
                self._log_transaction(record, oracle_state="NORMALIZATION_ACCEPTABLE")

        return findings


# ---------------------------------------------------------------------------
# Module-level helpers (pure functions, no HTTP, no state)
# ---------------------------------------------------------------------------


def _resolve_path(path: str) -> str:
    """
    Replace all OpenAPI path template parameters with the placeholder value.

    Converts '/api/v1/repos/{owner}/{repo}/issues/{index}' to
    '/api/v1/repos/1/1/issues/1', producing a syntactically valid URL
    that is safe to send as an HTTP request.

    The replacement is done via regex to handle all {param} patterns,
    including those with constraints like '{id:[0-9]+}' (FastAPI style),
    though the regex is intentionally kept simple for portability.

    Args:
        path: OpenAPI path string, possibly containing {param} segments.

    Returns:
        Path with all template parameters replaced by _PATH_PARAM_PLACEHOLDER.
    """
    return re.sub(r"\{[^}]+\}", _PATH_PARAM_PLACEHOLDER, path)


def _build_coverage_summary(
    total_protected: int,
    total_tested: int,
    cap_applied: bool,
    counters: dict[str, int],
) -> str:
    """
    Build a human-readable coverage summary for inclusion in the TestResult message.

    The summary reports the assessment scope (endpoints tested vs total) and
    the full distribution of oracle outcomes. This data is visible in the HTML
    report and constitutes the methodological transparency required for academic
    validity: the reader can assess whether the coverage is sufficient for the
    findings to be considered authoritative.

    Args:
        total_protected: Total protected endpoints declared in the OpenAPI spec.
        total_tested:    Endpoints actually probed (may differ from total if cap applied).
        cap_applied:     True if a non-zero cap was applied.
        counters:        Dict of outcome label -> count, as populated by the probe loop.

    Returns:
        Multi-sentence human-readable summary string.
    """
    cap_note = (
        " (coverage cap applied -- see config.tests.domain_1.max_endpoints_cap)"
        if cap_applied
        else ""
    )
    scope_line = f"Scope: {total_tested}/{total_protected} protected endpoints probed{cap_note}."

    enforced = counters[_OUTCOME_ENFORCED]
    bypass = counters[_OUTCOME_BYPASS]
    inconclusive_parametric = counters[_OUTCOME_INCONCLUSIVE_PARAMETRIC]
    inconclusive_not_found = counters[_OUTCOME_INCONCLUSIVE_NOT_FOUND]
    inconclusive_redirect = counters[_OUTCOME_INCONCLUSIVE_REDIRECT]
    inconclusive_server_error = counters[_OUTCOME_INCONCLUSIVE_SERVER_ERROR]
    transport_error = counters[_OUTCOME_TRANSPORT_ERROR]

    outcomes_line = (
        f"Outcomes: {enforced} enforced (auth confirmed), "
        f"{bypass} bypass (auth absent), "
        f"{inconclusive_parametric} inconclusive-parametric (placeholder ID returned 404), "
        f"{inconclusive_not_found} inconclusive-not-found (Tier A endpoint absent on server), "
        f"{inconclusive_redirect} redirect, "
        f"{inconclusive_server_error} server-error, "
        f"{transport_error} transport-error."
    )

    return f"{scope_line} {outcomes_line}"
