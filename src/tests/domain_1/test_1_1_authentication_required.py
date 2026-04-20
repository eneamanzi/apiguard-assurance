"""
src/tests/domain_1/test_1_1_authentication_required.py

Test 1.1 -- Only Authenticated Requests Access Protected Resources.

Guarantee (Implementazione.md, Dominio 0):
    Every endpoint that exposes sensitive data or privileged operations must
    reject requests that carry no credentials before reaching the business
    logic. The enforcement must produce HTTP 401 Unauthorized or 403 Forbidden
    immediately on missing or structurally invalid tokens.

Methodology (3_TOP_metodologia.md, Section 1.1):
    - Unauthenticated access: probe every protected endpoint using its
      declared HTTP method (never hardcoded GET) with no Authorization header.
    - Empty and malformed token: send structurally broken token values on a
      confirmed ENFORCED endpoint.
    - Path normalization: test variant paths on a confirmed ENFORCED endpoint
      to detect Gateway normalisation bypass.

Strategy: BLACK_BOX -- zero credentials, anonymous attacker simulation.
Priority: P0 -- authentication enforcement is the foundational Gateway guarantee.
          A failure here invalidates the premise of every subsequent test.

Method-safety matrix for unauthenticated probes
-------------------------------------------------
A critical source of false positives is probing a protected POST endpoint by
sending a GET. The server returns 200 (public GET resource exists) and the tool
incorrectly reports an auth bypass. This test always uses endpoint.method.

To prevent side effects on a potentially misconfigured server while preserving
the ability to trigger auth enforcement, the following safety matrix is applied:

    READ  (GET, HEAD, OPTIONS):
        Send the request normally. No body required. These methods are
        idempotent and read-only; no server-side state is mutated even if
        the auth check erroneously passes.

    WRITE (POST, PUT, PATCH):
        Send with an empty JSON body (json={}). The empty body reliably
        triggers the auth layer (returning 401/403) before body validation
        (400/422) or resource creation. This prevents spurious data from
        being written if the endpoint is misconfigured and lacks auth
        enforcement.

    DELETE parametric (path contains {param}, e.g. /users/{id}):
        Resolve all path template parameters with the safe placeholder
        "apiguard-probe" and send the request unauthenticated. The
        string is deliberately chosen to be an unlikely resource ID in
        any real database, bounding the risk of accidental deletion to
        a near-zero probability.

    DELETE non-parametric (global destructive endpoint, e.g. /delete-all):
        DO NOT send the request. Issuing an unauthenticated DELETE to a
        non-parametric path risks catastrophic, irreversible data loss if
        the auth check erroneously passes at the infrastructure layer.
        The endpoint is classified as INCONCLUSIVE_UNPROBED_DESTRUCTIVE
        and requires manual verification outside the automated tool.

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

    INCONCLUSIVE  (3xx, 4xx other than 401/403, 5xx, transport errors,
                   unprobed destructive DELETE):
        The response neither confirms enforcement nor demonstrates bypass.
        Sub-categories:
            INCONCLUSIVE_PARAMETRIC              -- 404/405/410 on parametric path.
            INCONCLUSIVE_NOT_FOUND               -- 404/405/410 on non-parametric path.
            INCONCLUSIVE_REDIRECT                -- 3xx redirect.
            INCONCLUSIVE_SERVER_ERROR            -- 5xx crash.
            INCONCLUSIVE_RATELIMITED             -- 429 rate-limited.
            INCONCLUSIVE_UNPROBED_DESTRUCTIVE    -- non-parametric DELETE not sent.
            TRANSPORT_ERROR                      -- connection-level failure.

Tier segregation
----------------
All protected endpoints are partitioned into two tiers:

    Tier A -- non-parametric paths (no {param} templates).
        Auth enforcement is directly observable. INCONCLUSIVE_NOT_FOUND on
        Tier A is anomalous and logged separately.

    Tier B -- parametric paths (contain {param} templates).
        Resource-resolution may precede auth. 404 on a placeholder ID is
        expected and classified as INCONCLUSIVE_PARAMETRIC.

Coverage reporting
------------------
The TestResult message includes a full breakdown of outcome counts.
The INCONCLUSIVE_UNPROBED_DESTRUCTIVE count is included so operators
can identify endpoints requiring manual follow-up.

Cap behaviour (config.tests.domain_1.max_endpoints_cap)
--------------------------------------------------------
Default (cap = 0): probe ALL protected endpoints. Positive cap: first N only.

DAG role
--------
test_id = "1.1", depends_on = [].
"""

from __future__ import annotations

from typing import Any, ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import EndpointRecord, Finding, TestResult, TestStatus, TestStrategy
from src.tests.base import BaseTest
from src.tests.helpers.path_resolver import (
    PATH_PARAM_FALLBACK_DEFAULT,
    PATH_PARAM_FALLBACK_SAFE_DELETE,
    resolve_path_with_seed,
)

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
_OUTCOME_INCONCLUSIVE_RATELIMITED: str = "inconclusive_ratelimited"
_OUTCOME_TRANSPORT_ERROR: str = "transport_error"
_OUTCOME_INCONCLUSIVE_UNPROBED_DESTRUCTIVE: str = "inconclusive_unprobed_destructive"

# ---------------------------------------------------------------------------
# Oracle HTTP status code sets
# ---------------------------------------------------------------------------

# Positive evidence that auth enforcement exists for the probed endpoint.
_ENFORCED_STATUS_CODES: frozenset[int] = frozenset({401, 403})

# Positive evidence that the endpoint served data without requiring auth.
# Only 2xx responses constitute a bypass -- the server completed the request.
_BYPASS_STATUS_CODES: frozenset[int] = frozenset(range(200, 300))

# Redirect responses: ambiguous. Cannot determine whether the redirect target
# enforces auth without following it (SecurityClient disables redirect following).
_REDIRECT_STATUS_CODES: frozenset[int] = frozenset({301, 302, 303, 307, 308})

# Resource-absent responses: the server acknowledged the request but could not
# find the resource. Auth may or may not have been checked first.
_RESOURCE_ABSENT_STATUS_CODES: frozenset[int] = frozenset({404, 405, 410})

# ---------------------------------------------------------------------------
# Method safety matrix -- classify methods by probing behaviour
# ---------------------------------------------------------------------------

# READ methods: idempotent, no body, send as-is.
_READ_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

# WRITE methods: require a body to avoid premature 400/422 before auth check.
# Sending json={} ensures the auth layer fires before body validation.
_WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH"})

# ---------------------------------------------------------------------------
# Path parameter placeholders
# ---------------------------------------------------------------------------

# Default placeholder for path template parameters in non-DELETE probes.
# Imported from src.tests.helpers.path_resolver to keep the definition in one place.
# Aliased here as a module-level name so the rest of this file can reference it
# without the fully-qualified import chain everywhere.
_PATH_PARAM_PLACEHOLDER: str = PATH_PARAM_FALLBACK_DEFAULT

# Safe placeholder for parametric DELETE probes.
# Aliased from the shared constant for the same reason.
_PATH_PARAM_PLACEHOLDER_SAFE_DELETE: str = PATH_PARAM_FALLBACK_SAFE_DELETE

# ---------------------------------------------------------------------------
# Malformed Authorization header values for sub-check B.
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
# Path normalization variant acceptable codes for sub-check C.
# ---------------------------------------------------------------------------

# Acceptable outcomes for normalization variants: auth enforced on variant
# (401/403) or path entirely rejected (404/405). Any 2xx response is a bypass.
_NORMALIZATION_ACCEPTABLE_CODES: frozenset[int] = frozenset({401, 403, 404, 405, 410})


# ---------------------------------------------------------------------------
# Test implementation
# ---------------------------------------------------------------------------


class Test_1_1_AuthenticationRequired(BaseTest):  # noqa: N801
    """
    Verify that all documented protected endpoints enforce authentication.

    Probes every protected endpoint in the OpenAPI spec (subject to the
    configurable cap at config.tests.domain_1.max_endpoints_cap) using the
    endpoint's declared HTTP method with no Authorization header. The method-
    safety matrix (see module docstring) determines the exact request shape.

    Additionally runs three sub-checks on the first confirmed ENFORCED Tier A
    endpoint:
        B.  Malformed token values (should all produce 401).
        B.5 Authorization header case variations (RFC 9110 case-insensitivity).
        C.  Path normalization variants (trailing slash, uppercase, double slash).

    Every HTTP transaction is recorded in the per-test audit trail via
    self._log_transaction() so that the HTML report displays full coverage scope.
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

            if target.attack_surface is None:
                return self._make_skip(reason="AttackSurface is not available.")

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

            # Apply configurable cap. Default 0 = probe all protected endpoints.
            cap = target.tests_config.test_1_1.max_endpoints_cap
            candidates: list[EndpointRecord] = protected if cap == 0 else protected[:cap]

            log.info(
                "test_1_1_starting",
                total_protected=len(protected),
                total_to_probe=len(candidates),
                cap_applied=cap > 0,
                cap_value=cap,
                path_seed_param_count=len(target.path_seed),
            )

            # Extract the path seed once from the frozen TargetContext so that
            # every probe in this execution receives the same consistent dict.
            # dict() produces a plain mutable copy; the frozen TargetContext
            # field is not affected.
            seed: dict[str, str] = dict(target.path_seed)

            # ------------------------------------------------------------------
            # Phase A -- Main probe loop across all candidate endpoints
            # ------------------------------------------------------------------

            # All counter keys must be initialised here so that _build_coverage_summary
            # can access them unconditionally. Adding a new outcome constant requires
            # adding it here AND in _build_coverage_summary.
            counters: dict[str, int] = {
                _OUTCOME_ENFORCED: 0,
                _OUTCOME_BYPASS: 0,
                _OUTCOME_INCONCLUSIVE_PARAMETRIC: 0,
                _OUTCOME_INCONCLUSIVE_NOT_FOUND: 0,
                _OUTCOME_INCONCLUSIVE_REDIRECT: 0,
                _OUTCOME_INCONCLUSIVE_SERVER_ERROR: 0,
                _OUTCOME_INCONCLUSIVE_RATELIMITED: 0,
                _OUTCOME_TRANSPORT_ERROR: 0,
                _OUTCOME_INCONCLUSIVE_UNPROBED_DESTRUCTIVE: 0,
            }
            findings: list[Finding] = []

            # Tracks the first non-parametric endpoint confirmed as ENFORCED.
            # Used as the anchor for sub-checks B and C. The anchor is chosen
            # to be non-parametric (Tier A) so that sub-check paths are
            # unambiguous (no placeholder substitution needed). By construction,
            # the anchor can never be a non-parametric DELETE (those return
            # UNPROBED_DESTRUCTIVE, not ENFORCED).
            enforced_tier_a_anchor: EndpointRecord | None = None

            for endpoint in candidates:
                is_parametric = "{" in endpoint.path

                outcome, finding = self._probe_unauthenticated(
                    endpoint=endpoint,
                    is_parametric=is_parametric,
                    seed=seed,
                    client=client,
                    store=store,
                )
                counters[outcome] += 1

                if finding is not None:
                    findings.append(finding)

                # Capture the first non-parametric endpoint confirmed as ENFORCED.
                # Non-parametric DELETEs return UNPROBED_DESTRUCTIVE and are
                # therefore excluded from anchor candidacy automatically.
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
            # ------------------------------------------------------------------

            if enforced_tier_a_anchor is not None:
                malformed_findings = self._check_malformed_tokens(
                    anchor=enforced_tier_a_anchor,
                    seed=seed,
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
            # Phase B.5 -- Authorization header case variation sub-check
            # ------------------------------------------------------------------

            if enforced_tier_a_anchor is not None:
                header_case_findings = self._check_header_case_variations(
                    anchor=enforced_tier_a_anchor,
                    seed=seed,
                    client=client,
                    store=store,
                )
                findings.extend(header_case_findings)
                counters[_OUTCOME_BYPASS] += len(header_case_findings)

            # ------------------------------------------------------------------
            # Phase C -- Path normalization sub-check
            # ------------------------------------------------------------------

            if enforced_tier_a_anchor is not None:
                normalization_findings = self._check_path_normalization(
                    anchor=enforced_tier_a_anchor,
                    seed=seed,
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
    # Method-safety matrix helper
    # ------------------------------------------------------------------

    @staticmethod
    def _prepare_probe(
        method: str,
        raw_path: str,
        is_parametric: bool,
        seed: dict[str, str],
    ) -> tuple[str, dict[str, Any]] | None:
        """
        Apply the method-safety matrix and return (resolved_path, extra_request_kwargs).

        This is the single authoritative implementation of the safety matrix.
        All probe methods (main loop and sub-checks) MUST call this helper
        instead of constructing request parameters inline, ensuring consistent
        behaviour across the entire test.

        The resolved_path has all {param} template segments replaced with an
        appropriate placeholder depending on the method and parametricity.

        The extra_request_kwargs dict contains keyword arguments to be unpacked
        directly into SecurityClient.request() (e.g. {"json": {}} for WRITE
        methods). It is empty for READ and DELETE probes.

        Args:
            method:        HTTP method uppercase (as stored on EndpointRecord).
            raw_path:      OpenAPI path template, possibly containing {param} segments.
            is_parametric: True if raw_path contains at least one {param} template.

        Returns:
            Tuple (resolved_path, extra_kwargs) if the probe SHOULD be sent.
            None if the probe MUST NOT be sent (non-parametric global DELETE).
        """
        extra_kwargs: dict[str, Any] = {}

        if method in _READ_METHODS:
            # Idempotent methods: resolve with seed, fallback to default placeholder.
            resolved_path = resolve_path_with_seed(
                raw_path, seed=seed, fallback=_PATH_PARAM_PLACEHOLDER
            )

        elif method in _WRITE_METHODS:
            # State-mutating methods: include an empty JSON body so that the
            # auth layer fires before body validation. Without a body, some
            # frameworks reject the request with 400/415 before checking auth,
            # making the response ambiguous (enforcement or malformed request?).
            resolved_path = resolve_path_with_seed(
                raw_path, seed=seed, fallback=_PATH_PARAM_PLACEHOLDER
            )
            extra_kwargs["json"] = {}

        elif method == "DELETE":
            if is_parametric:
                # Targeted DELETE: prefer seed values (real IDs are unlikely to
                # match real records when probed without credentials). Fall back
                # to the safe placeholder to bound the risk of accidental deletion.
                resolved_path = resolve_path_with_seed(
                    raw_path, seed=seed, fallback=_PATH_PARAM_PLACEHOLDER_SAFE_DELETE
                )
            else:
                # Global (non-parametric) DELETE: never send without auth.
                # The risk of irreversible data loss if auth erroneously passes
                # outweighs the value of the probe. Return None to signal that
                # the caller must classify this endpoint as UNPROBED_DESTRUCTIVE.
                return None

        else:
            # Unknown or non-standard HTTP method (e.g., TRACE, CONNECT):
            # apply READ semantics as a conservative safe default.
            log.warning(
                "test_1_1_unknown_method_defaulting_to_read_semantics",
                method=method,
                raw_path=raw_path,
            )
            resolved_path = resolve_path_with_seed(
                raw_path, seed=seed, fallback=_PATH_PARAM_PLACEHOLDER
            )

        return resolved_path, extra_kwargs

    # ------------------------------------------------------------------
    # Phase A -- Single unauthenticated probe (called in the main loop)
    # ------------------------------------------------------------------

    def _probe_unauthenticated(
        self,
        endpoint: EndpointRecord,
        is_parametric: bool,
        seed: dict[str, str],
        client: SecurityClient,
        store: EvidenceStore,
    ) -> tuple[str, Finding | None]:
        """
        Send one unauthenticated request using the endpoint's declared method.

        The method-safety matrix (_prepare_probe) determines the exact request
        shape: whether a JSON body is included, which placeholder is used, and
        whether the probe is sent at all (non-parametric DELETE is skipped).

        Every completed HTTP transaction is recorded in the audit trail via
        self._log_transaction(). Non-parametric DELETEs are logged as a
        structured WARNING with no HTTP transaction, since no request is sent.
        Transport errors are counted as TRANSPORT_ERROR with no transaction log
        entry (no EvidenceRecord was produced).

        Args:
            endpoint:      The EndpointRecord to probe.
            is_parametric: True if the endpoint path contains {param} templates.
            client:        SecurityClient for HTTP requests.
            store:         EvidenceStore for FAIL evidence.

        Returns:
            Tuple of (outcome_label, Finding | None).
            Finding is non-None only for BYPASS outcomes.
        """
        method: str = endpoint.method  # already uppercase per EndpointRecord field_validator

        # Determine the exact request parameters via the safety matrix.
        probe_result = Test_1_1_AuthenticationRequired._prepare_probe(
            method=method,
            raw_path=endpoint.path,
            is_parametric=is_parametric,
            seed=seed,
        )

        if probe_result is None:
            # Non-parametric DELETE: skip this probe entirely for safety.
            log.warning(
                "test_1_1_probe_skipped_non_parametric_delete",
                path=endpoint.path,
                method=method,
                detail=(
                    "Non-parametric DELETE endpoints are not probed without "
                    "authentication. A successful unauthenticated response could "
                    "indicate catastrophic global data deletion. Manual verification "
                    "is required. Classified as INCONCLUSIVE_UNPROBED_DESTRUCTIVE."
                ),
            )
            return _OUTCOME_INCONCLUSIVE_UNPROBED_DESTRUCTIVE, None

        resolved_path, extra_kwargs = probe_result

        try:
            response, record = client.request(
                method=method,
                path=resolved_path,
                test_id=self.test_id,
                **extra_kwargs,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "test_1_1_transport_error",
                path=resolved_path,
                method=method,
                exc_type=type(exc).__name__,
                detail=str(exc),
            )
            return _OUTCOME_TRANSPORT_ERROR, None

        status = response.status_code

        # --- ENFORCED: auth was verified before responding ---
        if status in _ENFORCED_STATUS_CODES:
            log.debug(
                "test_1_1_probe_enforced",
                path=resolved_path,
                method=method,
                status_code=status,
                is_parametric=is_parametric,
            )
            self._log_transaction(record, oracle_state="ENFORCED")
            return _OUTCOME_ENFORCED, None

        # --- BYPASS: server returned data without requiring auth ---
        if status in _BYPASS_STATUS_CODES:
            log.warning(
                "test_1_1_probe_bypass_detected",
                path=resolved_path,
                method=method,
                status_code=status,
                is_parametric=is_parametric,
            )
            store.add_fail_evidence(record)
            self._log_transaction(record, oracle_state="AUTH_BYPASS", is_fail=True)
            finding = Finding(
                title="Protected endpoint accessible without authentication",
                detail=(
                    f"{method} {resolved_path} returned HTTP {status} "
                    f"with no Authorization header. "
                    f"The endpoint is declared with security requirements in the OpenAPI "
                    f"spec (path: '{endpoint.path}', method: {method}) "
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

        # --- INCONCLUSIVE: redirect, resource absent, server error, or rate-limited ---

        if status in _REDIRECT_STATUS_CODES:
            log.debug(
                "test_1_1_probe_redirect",
                path=resolved_path,
                method=method,
                status_code=status,
                detail=(
                    "Server issued a redirect. Cannot determine whether the redirect "
                    "target enforces auth without following it. "
                    "Classified as INCONCLUSIVE_REDIRECT."
                ),
            )
            self._log_transaction(record, oracle_state="INCONCLUSIVE_REDIRECT")
            return _OUTCOME_INCONCLUSIVE_REDIRECT, None

        if status in _RESOURCE_ABSENT_STATUS_CODES:
            if is_parametric:
                log.debug(
                    "test_1_1_probe_inconclusive_parametric",
                    path=resolved_path,
                    method=method,
                    status_code=status,
                )
                self._log_transaction(record, oracle_state="INCONCLUSIVE_PARAMETRIC")
                return _OUTCOME_INCONCLUSIVE_PARAMETRIC, None
            else:
                log.warning(
                    "test_1_1_probe_tier_a_not_found",
                    path=resolved_path,
                    method=method,
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

        if status == 429:  # noqa: PLR2004
            log.debug(
                "test_1_1_probe_ratelimited",
                path=resolved_path,
                method=method,
                status_code=status,
                detail=(
                    "The probe endpoint returned 429 Too Many Requests. "
                    "The auth check outcome is inconclusive. "
                    "Test 4.1 covers rate limiting specifically."
                ),
            )
            self._log_transaction(record, oracle_state="INCONCLUSIVE_RATELIMITED")
            return _OUTCOME_INCONCLUSIVE_RATELIMITED, None

        if status >= 500:  # noqa: PLR2004
            log.debug(
                "test_1_1_probe_server_error",
                path=resolved_path,
                method=method,
                status_code=status,
            )
            self._log_transaction(record, oracle_state="INCONCLUSIVE_SERVER_ERROR")
            return _OUTCOME_INCONCLUSIVE_SERVER_ERROR, None

        log.debug(
            "test_1_1_probe_unclassified_status",
            path=resolved_path,
            method=method,
            status_code=status,
        )
        self._log_transaction(record, oracle_state="INCONCLUSIVE_NOT_FOUND")
        return _OUTCOME_INCONCLUSIVE_NOT_FOUND, None

    # ------------------------------------------------------------------
    # Phase B -- Malformed Authorization header values
    # ------------------------------------------------------------------

    def _check_malformed_tokens(
        self,
        anchor: EndpointRecord,
        seed: dict[str, str],
        client: SecurityClient,
        store: EvidenceStore,
    ) -> list[Finding]:
        """
        Send structurally invalid Authorization header values to the anchor endpoint.

        The anchor is guaranteed to be non-parametric and to have returned ENFORCED
        for a no-auth request, so the auth layer is confirmed reachable. The same
        HTTP method and safety matrix body (json={} for WRITE methods) are used
        as in the main probe loop to avoid method-mismatch false positives.

        All transactions (BYPASS and correctly rejected) are recorded in the
        audit trail with their respective oracle states.

        Args:
            anchor: First Tier A endpoint confirmed as ENFORCED. Its method
                    attribute determines the request method and body for this
                    sub-check.
            client: SecurityClient for HTTP requests.
            store:  EvidenceStore for FAIL evidence.

        Returns:
            List of Findings for any malformed token that produced a BYPASS response.
        """
        findings: list[Finding] = []
        method: str = anchor.method

        # Anchor is guaranteed non-parametric (Tier A selection), so
        # resolve_path_with_seed is a no-op here. Passing seed is correct for
        # API consistency and future cases where the anchor selection logic changes.
        path: str = resolve_path_with_seed(anchor.path, seed=seed, fallback=_PATH_PARAM_PLACEHOLDER)

        # Derive the body extra_kwargs from the anchor's method. The anchor can
        # never be a non-parametric DELETE (those return UNPROBED_DESTRUCTIVE
        # and are excluded from anchor candidacy), so this expression is always
        # well-defined without a None check.
        base_kwargs: dict[str, Any] = {"json": {}} if method in _WRITE_METHODS else {}

        for token_value, token_label in _MALFORMED_TOKENS:
            try:
                response, record = client.request(
                    method=method,
                    path=path,
                    test_id=self.test_id,
                    headers={"Authorization": token_value},
                    **base_kwargs,
                )
            except Exception as exc:  # noqa: BLE001
                log.debug(
                    "test_1_1_malformed_token_transport_error",
                    path=path,
                    method=method,
                    token_label=token_label,
                    exc_type=type(exc).__name__,
                    detail=str(exc),
                )
                continue

            if response.status_code in _BYPASS_STATUS_CODES:
                log.warning(
                    "test_1_1_malformed_token_bypass",
                    path=path,
                    method=method,
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
                            f"{method} {path} with "
                            f"'Authorization: {token_value}' "
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
                self._log_transaction(record, oracle_state="MALFORMED_TOKEN_REJECTED")

        return findings

    # ------------------------------------------------------------------
    # Phase B.5 -- Authorization header case variations
    # ------------------------------------------------------------------

    def _check_header_case_variations(
        self,
        anchor: EndpointRecord,
        seed: dict[str, str],
        client: SecurityClient,
        store: EvidenceStore,
    ) -> list[Finding]:
        """
        Send the anchor endpoint requests with non-canonical Authorization header casing.

        RFC 9110 Section 5.1 specifies that HTTP header names are case-insensitive.
        A conforming Gateway must apply auth enforcement regardless of the casing
        used for the Authorization header name. Uses the anchor's declared method
        and body (json={} for WRITE) to avoid method-mismatch false positives.

        Args:
            anchor: First Tier A endpoint confirmed as ENFORCED.
            client: SecurityClient for HTTP requests.
            store:  EvidenceStore for FAIL evidence.

        Returns:
            List of Findings for any casing variant that produced a BYPASS response.
        """
        findings: list[Finding] = []
        method: str = anchor.method
        path: str = resolve_path_with_seed(anchor.path, seed=seed, fallback=_PATH_PARAM_PLACEHOLDER)
        base_kwargs: dict[str, Any] = {"json": {}} if method in _WRITE_METHODS else {}

        header_variants: tuple[tuple[str, str], ...] = (
            ("authorization", "all-lowercase header name"),
            ("AUTHORIZATION", "all-uppercase header name"),
            ("AuThOrIzAtIoN", "mixed-case header name"),
        )

        for header_name, variant_label in header_variants:
            try:
                response, record = client.request(
                    method=method,
                    path=path,
                    test_id=self.test_id,
                    headers={header_name: "Bearer apiguard-case-probe"},
                    **base_kwargs,
                )
            except Exception as exc:  # noqa: BLE001
                log.debug(
                    "test_1_1_header_case_transport_error",
                    path=path,
                    method=method,
                    header_name=header_name,
                    exc_type=type(exc).__name__,
                    detail=str(exc),
                )
                continue

            if response.status_code in _BYPASS_STATUS_CODES:
                log.warning(
                    "test_1_1_header_case_bypass",
                    path=path,
                    method=method,
                    header_name=header_name,
                    status_code=response.status_code,
                )
                store.add_fail_evidence(record)
                self._log_transaction(
                    record,
                    oracle_state="HEADER_CASE_BYPASS",
                    is_fail=True,
                )
                findings.append(
                    Finding(
                        title="Auth enforcement bypassed via non-canonical header casing",
                        detail=(
                            f"{method} {path} with header "
                            f"'{header_name}: Bearer apiguard-case-probe' "
                            f"({variant_label}) returned HTTP {response.status_code}. "
                            f"RFC 9110 requires HTTP header names to be treated as "
                            f"case-insensitive. The Gateway appears to perform auth "
                            f"enforcement only on the canonical 'Authorization' casing, "
                            f"allowing an attacker to bypass the auth layer by sending "
                            f"credentials in a non-standard casing."
                        ),
                        references=[
                            self.cwe_id,
                            "OWASP-API2:2023",
                            "RFC-9110-S5.1",
                            "OWASP-ASVS-V6.3",
                        ],
                        evidence_ref=record.record_id,
                    )
                )
            else:
                log.debug(
                    "test_1_1_header_case_enforced",
                    path=path,
                    method=method,
                    header_name=header_name,
                    status_code=response.status_code,
                )
                self._log_transaction(record, oracle_state="HEADER_CASE_ENFORCED")

        return findings

    # ------------------------------------------------------------------
    # Phase C -- Path normalization variants
    # ------------------------------------------------------------------

    def _check_path_normalization(
        self,
        anchor: EndpointRecord,
        seed: dict[str, str],
        client: SecurityClient,
        store: EvidenceStore,
    ) -> list[Finding]:
        """
        Test path normalization variants of the anchor endpoint without credentials.

        A secure Gateway normalises request paths before applying security policies.
        If a variant path bypasses authentication (returns 2xx), it means the
        Gateway is matching security policies against the raw request path rather
        than the normalized form. Uses the anchor's declared method and body
        (json={} for WRITE) to avoid method-mismatch false positives.

        Acceptable responses for variants:
            401/403 -- auth enforced on the variant (correct).
            404/405 -- path rejected after normalization (correct).
            2xx     -- bypass finding (incorrect).

        Args:
            anchor: First Tier A endpoint confirmed as ENFORCED.
            client: SecurityClient for HTTP requests.
            store:  EvidenceStore for FAIL evidence.

        Returns:
            List of Findings for any variant path that produced a BYPASS response.
        """
        findings: list[Finding] = []
        method: str = anchor.method
        base_path: str = resolve_path_with_seed(
            anchor.path, seed=seed, fallback=_PATH_PARAM_PLACEHOLDER
        )
        path_without_leading_slash = base_path.lstrip("/")
        base_kwargs: dict[str, Any] = {"json": {}} if method in _WRITE_METHODS else {}

        variants: list[tuple[str, str]] = [
            (base_path.rstrip("/") + "/", "trailing slash appended"),
            ("/" + path_without_leading_slash.upper(), "path converted to uppercase"),
            ("/" + "/" + path_without_leading_slash, "double leading slash"),
        ]

        for variant_path, variant_label in variants:
            if variant_path == base_path:
                continue

            try:
                response, record = client.request(
                    method=method,
                    path=variant_path,
                    test_id=self.test_id,
                    **base_kwargs,
                )
            except Exception as exc:  # noqa: BLE001
                log.debug(
                    "test_1_1_normalization_transport_error",
                    variant_path=variant_path,
                    method=method,
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
                    method=method,
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
                    method=method,
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
                            f"{method} {variant_path} ({variant_label}) "
                            f"returned HTTP {status} with no Authorization header. "
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
                self._log_transaction(record, oracle_state="NORMALIZATION_ACCEPTABLE")

        return findings


# ---------------------------------------------------------------------------
# Module-level helpers (pure functions, no HTTP, no state)
# ---------------------------------------------------------------------------


def _build_coverage_summary(
    total_protected: int,
    total_tested: int,
    cap_applied: bool,
    counters: dict[str, int],
) -> str:
    """
    Build a human-readable coverage summary for inclusion in the TestResult message.

    Reports the assessment scope (endpoints tested vs total) and the full
    distribution of oracle outcomes, including the UNPROBED_DESTRUCTIVE count
    so operators can identify endpoints requiring manual follow-up.

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
    inconclusive_ratelimited = counters[_OUTCOME_INCONCLUSIVE_RATELIMITED]
    transport_error = counters[_OUTCOME_TRANSPORT_ERROR]
    unprobed_destructive = counters[_OUTCOME_INCONCLUSIVE_UNPROBED_DESTRUCTIVE]

    outcomes_line = (
        f"Outcomes: {enforced} enforced (auth confirmed), "
        f"{bypass} bypass (auth absent), "
        f"{inconclusive_parametric} inconclusive-parametric (placeholder ID returned 404), "
        f"{inconclusive_not_found} inconclusive-not-found (Tier A endpoint absent on server), "
        f"{inconclusive_redirect} redirect, "
        f"{inconclusive_server_error} server-error, "
        f"{inconclusive_ratelimited} rate-limited (429, auth outcome indeterminate), "
        f"{unprobed_destructive} inconclusive-unprobed-destructive "
        f"(non-parametric DELETE not probed for safety -- manual verification required), "
        f"{transport_error} transport-error."
    )

    return f"{scope_line} {outcomes_line}"
