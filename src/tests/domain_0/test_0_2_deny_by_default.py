"""
src/tests/domain_0/test_0_2_deny_by_default.py

Test 0.2 -- Gateway Deny-by-Default on Unregistered Paths.

Guarantee (Implementazione.md, Dominio 0):
    The Gateway blocks any request whose path does not match exactly a
    registered route, returning 404 or 403 without forwarding to a backend
    or revealing internal topology information.

Methodology (3_TOP_metodologia.md, Section 0.2):
    - Unregistered path rejection: probe guaranteed-nonexistent paths and
      verify the Gateway returns 404/403 without leaking internal topology.
    - Default backend fallback detection: check response headers for
      backend-identifying information (application server names) on
      unregistered paths.
    - Path normalization consistency: probe URL-encoded, double-slash,
      trailing-slash, and uppercase variants of a DOCUMENTED authenticated
      path. A variant returning HTTP 200 without credentials is a bypass
      vulnerability; 401/403/404 on all variants is the correct behaviour.

Strategy: BLACK_BOX -- zero credentials required.
    All three sub-checks send unauthenticated requests. The path-normalization
    sub-check relies on the canonical path enforcing authentication (401/403
    without credentials), which is verified empirically via a baseline probe
    before testing variants. No token is needed: the baseline probe itself is
    the unauthenticated request that establishes the oracle.

Priority: P0 -- deny-by-default is a fundamental Gateway security guarantee.

Sub-check design:
-----------------
Sub-check 1 -- Guaranteed-nonexistent path rejection + backend header detection.
    Sends GET to paths guaranteed to not exist on any well-configured Gateway.
    Each response is checked for two independent failure modes:
        a) Status code NOT in {403, 404, 410}: Gateway forwarded the request
           instead of blocking it (deny-by-default violated).
        b) 'Server' response header identifies an application server (not a
           Gateway): the request reached the backend before being rejected.

Sub-check 2 -- Path normalization on an authenticated endpoint.
    1. Selects a documented non-parametric path with requires_auth=True from
       the AttackSurface. Falls back to any non-parametric path if none with
       requires_auth is found.
    2. Probes the canonical path without credentials (baseline probe). If the
       response is 401/403, the oracle is valid: variants returning 200 are
       authentication bypasses. If 200 (public endpoint), the normalization
       sub-check is skipped with an InfoNote -- variants of a public path
       returning 200 are expected, not a bypass.
    3. Probes four structural variants: trailing slash, double slash (after
       the first path separator -- API-agnostic), uppercase, URL-encoded
       last segment.

EvidenceStore policy:
    FAIL transactions: store.add_fail_evidence(record) called at call site,
    then _log_transaction(is_fail=True). Never inside a helper method.
    Transport errors: logged via structlog only. No EvidenceRecord is
    available when SecurityClientError occurs (the record is created only
    after a successful HTTP exchange), so _log_transaction() cannot be called.
    PASS/neutral transactions: _log_transaction() only; no store write.
"""

from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, ClassVar

import structlog

if TYPE_CHECKING:
    # httpx is imported only for static type checking.
    # Test modules must never import httpx at runtime (SecurityClient is the
    # single HTTP entry point); TYPE_CHECKING guards ensure the import is
    # a zero-runtime-cost annotation aid only.
    import httpx

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
from src.core.models import (
    AttackSurface,
    EvidenceRecord,
    Finding,
    InfoNote,
    TestResult,
    TestStatus,
    TestStrategy,
)
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants -- probe paths
# ---------------------------------------------------------------------------

# Paths guaranteed not to exist on any well-configured Gateway.
# Chosen to be syntactically valid but semantically meaningless, with enough
# uniqueness to avoid accidental collision with real application routes.
_GUARANTEED_NONEXISTENT_PATHS: list[str] = [
    "/nonexistent-apiguard-probe-xyz-123",
    "/api/nonexistent-apiguard-probe-abc-456",
    "/apiguard-shadow-probe-789",
    "/api/v99/nonexistent-probe",
]

# ---------------------------------------------------------------------------
# Constants -- response classification
# ---------------------------------------------------------------------------

# Status codes that indicate the Gateway correctly denied the request.
# 410 Gone is also acceptable: it signals deliberate decommissioning.
_DENY_STATUS_CODES: frozenset[int] = frozenset({403, 404, 410})

# Status codes that confirm authentication is actively enforced at the
# canonical path. Used to validate the baseline before variant testing.
_AUTH_ENFORCED_CODES: frozenset[int] = frozenset({401, 403})

# 'Server' header values that identify an API Gateway rather than a backend
# application server. Checked case-insensitively as substring matches.
#
# THIS CONSTANT IS THE FALLBACK DEFAULT ONLY.
# At runtime, Test 0.2 reads the operator-configured list from:
#     target.tests_config.test_0_2.gateway_server_identifiers
# which is populated from config.yaml -> tests.domain_0.test_0_2.
# The test NEVER reads _GATEWAY_SERVER_VALUES_DEFAULT directly.
# It is kept here only for documentation symmetry with domain_0.py.
_GATEWAY_SERVER_VALUES_DEFAULT: frozenset[str] = frozenset(
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
# Constants -- oracle state labels for TransactionSummary.oracle_state
# ---------------------------------------------------------------------------

_STATE_CORRECTLY_DENIED: str = "CORRECTLY_DENIED"
_STATE_GATEWAY_BYPASS: str = "GATEWAY_BYPASS"
_STATE_BACKEND_LEAKED: str = "BACKEND_LEAKED"
_STATE_BASELINE_AUTH_ENFORCED: str = "BASELINE_AUTH_ENFORCED"
_STATE_BASELINE_PUBLIC: str = "BASELINE_PUBLIC"
_STATE_BASELINE_UNEXPECTED: str = "BASELINE_UNEXPECTED"
_STATE_AUTH_BYPASS_VIA_NORMALIZATION: str = "AUTH_BYPASS_VIA_NORMALIZATION"
_STATE_AUTH_ENFORCED_ON_VARIANT: str = "AUTH_ENFORCED_ON_VARIANT"
_STATE_VARIANT_REJECTED: str = "VARIANT_REJECTED"
# Note: there is intentionally no _STATE_TRANSPORT_ERROR constant here.
# _safe_get() cannot call _log_transaction() when a SecurityClientError occurs
# because no EvidenceRecord is available (the record is only created after a
# successful HTTP exchange). Transport failures are logged via structlog only.

# ---------------------------------------------------------------------------
# Constants -- standard references
# ---------------------------------------------------------------------------

_REFERENCES: list[str] = [
    "CWE-284",
    "NIST-SP-800-204-S4.1",
    "OWASP-ASVS-v5.0.0-V4.1.1",
    "CIS-Benchmark-API-GW-Controls-2.3",
]


# ---------------------------------------------------------------------------
# Test implementation
# ---------------------------------------------------------------------------


class Test02DenyByDefault(BaseTest):
    """
    Verify that the Gateway enforces deny-by-default for unregistered paths.

    Executes two independent sub-checks:

    Sub-check 1 -- Unregistered path rejection + backend header detection.
        Probes guaranteed-nonexistent paths (paths that cannot exist on any
        well-configured Gateway). Each probe must return 403/404/410.
        Additionally, the 'Server' response header is inspected on every
        response: a value identifying an application server (not a Gateway)
        indicates that the request reached the backend before being rejected,
        which is a deny-by-default violation regardless of the status code.

    Sub-check 2 -- Path normalization consistency.
        Selects a documented non-parametric authenticated path, verifies via
        a baseline probe that it enforces auth (401/403 without credentials),
        then probes four structural variants. A variant returning HTTP 200
        is an authentication bypass via path normalization.
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

        Returns:
            TestResult(PASS)  if all probes produce correct deny responses
                              and no normalization variant bypasses auth.
            TestResult(FAIL)  if any unregistered path is not denied, any
                              backend Server header leaks on a denied path,
                              or any path variant bypasses authentication.
                              One Finding is produced per distinct violation.
            TestResult(SKIP)  if the AttackSurface is unavailable in TargetContext.
            TestResult(ERROR) on unexpected exception.
        """
        try:
            skip = self._requires_attack_surface(target)
            if skip is not None:
                return skip

            assert target.attack_surface is not None  # noqa: S101 -- type narrowing only

            # Read the operator-configured Gateway Server identifiers once,
            # convert to frozenset for O(1) membership tests in the probe loop.
            gateway_ids: frozenset[str] = frozenset(
                target.tests_config.test_0_2.gateway_server_identifiers
            )

            findings: list[Finding] = []
            notes: list[InfoNote] = []

            # Sub-check 1: probe guaranteed-nonexistent paths.
            findings.extend(
                self._check_nonexistent_paths(
                    client=client,
                    store=store,
                    gateway_ids=gateway_ids,
                )
            )

            # Sub-check 2: path normalization consistency.
            norm_findings, norm_notes = self._check_path_normalization(
                surface=target.attack_surface,
                client=client,
                store=store,
            )
            findings.extend(norm_findings)
            notes.extend(norm_notes)

            if findings:
                return TestResult(
                    test_id=self.test_id,
                    status=TestStatus.FAIL,
                    message=(
                        f"Deny-by-default policy violated: {len(findings)} "
                        f"violation(s) detected (unregistered path not denied, "
                        f"backend header leaked, or path normalization bypass)."
                    ),
                    findings=findings,
                    notes=notes,
                    transaction_log=list(self._transaction_log),
                    **self._metadata_kwargs(),
                )

            return self._make_pass(
                message=(
                    "Deny-by-default correctly enforced. "
                    "All unregistered paths returned 403/404 without backend header leakage. "
                    "All path normalization variants triggered authentication enforcement "
                    "or were correctly rejected."
                ),
                notes=notes if notes else None,
            )

        except Exception as exc:  # noqa: BLE001
            return self._make_error(exc)

    # ------------------------------------------------------------------
    # Sub-check 1: unregistered path rejection
    # ------------------------------------------------------------------

    def _check_nonexistent_paths(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        gateway_ids: frozenset[str],
    ) -> list[Finding]:
        """
        Probe guaranteed-nonexistent paths and flag non-deny responses.

        Two independent failure modes are checked per probe:
            a) Status code outside {403, 404, 410}: Gateway forwarded the
               request to the backend instead of blocking it.
            b) 'Server' header identifies an application server: the request
               reached the backend before being rejected, even if status is 404.

        Both checks run for every probe. When either or both fail, a SINGLE
        store.add_fail_evidence(record) and a SINGLE _log_transaction() are
        issued -- never more than once per record. This is required by the
        EvidenceStore contract documented in SecurityClient.request(): calling
        add_fail_evidence twice on the same record creates duplicate entries
        in evidence.json and corrupts the transaction log.

        A single probe can therefore produce two Findings (one per failure mode)
        that share one EvidenceRecord. The oracle_state logged reflects the most
        severe mode: GATEWAY_BYPASS (wrong status) dominates BACKEND_LEAKED
        (Server header only), because a bypass implies backend involvement and
        the header check is a secondary confirmation.

        Args:
            client:      Centralized HTTP client (SecurityClient).
            store:       EvidenceStore -- add_fail_evidence called at most once per record.
            gateway_ids: Frozenset of lowercase Gateway Server header substrings,
                         populated from target.tests_config.test_0_2.gateway_server_identifiers.

        Returns:
            List of Finding, one per violation type detected across all probes.
        """
        findings: list[Finding] = []

        for path in _GUARANTEED_NONEXISTENT_PATHS:
            response, record = self._safe_get(client, path)
            if response is None or record is None:
                # Transport error already logged by _safe_get via structlog.
                # No EvidenceRecord available: skip without finding.
                continue

            probe_findings: list[Finding] = []

            # Failure mode (a): status code not in the expected deny set.
            if response.status_code not in _DENY_STATUS_CODES:
                probe_findings.append(
                    Finding(
                        title="Unregistered path not denied by Gateway",
                        detail=(
                            f"GET {path} returned HTTP {response.status_code} "
                            f"instead of the expected 403 or 404. "
                            f"The Gateway is not enforcing deny-by-default: the request "
                            f"appears to have been forwarded to the backend rather than "
                            f"intercepted and blocked at the perimeter. "
                            f"Every path not explicitly registered in the Gateway routing "
                            f"table must be rejected before reaching upstream services."
                        ),
                        references=_REFERENCES,
                        evidence_ref=record.record_id,
                    )
                )

            # Failure mode (b): Server header reveals backend identity.
            # Checked independently of failure mode (a) -- both can co-occur.
            backend_finding = _detect_backend_server_header(
                path=path,
                record=record,
                gateway_ids=gateway_ids,
            )
            if backend_finding is not None:
                probe_findings.append(backend_finding)

            if probe_findings:
                # Single store write + single log entry for this record,
                # regardless of how many failure modes were detected.
                store.add_fail_evidence(record)
                oracle_state = (
                    _STATE_GATEWAY_BYPASS
                    if response.status_code not in _DENY_STATUS_CODES
                    else _STATE_BACKEND_LEAKED
                )
                self._log_transaction(record, oracle_state=oracle_state, is_fail=True)
                findings.extend(probe_findings)
            else:
                # Status in deny set and no backend header leak: fully compliant.
                self._log_transaction(record, oracle_state=_STATE_CORRECTLY_DENIED)

        return findings

    # ------------------------------------------------------------------
    # Sub-check 2: path normalization consistency
    # ------------------------------------------------------------------

    def _check_path_normalization(
        self,
        surface: AttackSurface,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> tuple[list[Finding], list[InfoNote]]:
        """
        Test path normalization consistency on a documented authenticated endpoint.

        Workflow:
            1. Select a non-parametric path from the AttackSurface, preferring
               paths with requires_auth=True.
            2. Probe the canonical path without credentials (baseline probe).
               - 401/403: auth enforced -> oracle valid -> proceed to variants.
               - 200: public path -> skip with InfoNote to avoid false positives.
               - Other: inconclusive -> skip with InfoNote.
            3. Probe structural variants of the canonical path and flag 200 responses.

        Args:
            surface: AttackSurface from TargetContext.attack_surface.
            client:  Centralized HTTP client.
            store:   EvidenceStore for FAIL transactions.

        Returns:
            Tuple (findings, notes). findings is empty if no bypass is detected
            or if the sub-check was skipped. notes carries InfoNote entries
            explaining any skip or coverage gap.
        """
        findings: list[Finding] = []
        notes: list[InfoNote] = []

        sample_path = _select_authenticated_sample_path(surface)

        if sample_path is None:
            notes.append(
                InfoNote(
                    title="Path Normalization Sub-check Skipped: No Suitable Path",
                    detail=(
                        "No non-parametric path was found in the AttackSurface for "
                        "normalization testing. All documented endpoints contain path "
                        "template parameters (e.g. {owner}, {repo}). The sub-check "
                        "requires a path with a static URL to generate meaningful variants. "
                        "This is a coverage gap, not a security failure."
                    ),
                    references=_REFERENCES,
                )
            )
            log.debug("normalization_no_sample_path", reason="all_documented_paths_parametric")
            return findings, notes

        log.debug("normalization_sample_path_selected", path=sample_path)

        # Baseline probe: verify the canonical path enforces auth at runtime.
        baseline_response, baseline_record = self._safe_get(client, sample_path)

        if baseline_response is None or baseline_record is None:
            notes.append(
                InfoNote(
                    title="Path Normalization Sub-check Skipped: Baseline Probe Failed",
                    detail=(
                        f"GET {sample_path} (baseline probe) failed at the transport layer. "
                        f"The authentication oracle for variant testing cannot be established "
                        f"without a valid baseline response."
                    ),
                    references=_REFERENCES,
                )
            )
            return findings, notes

        baseline_status = baseline_response.status_code

        if baseline_status in _AUTH_ENFORCED_CODES:
            # Oracle confirmed: canonical path enforces authentication.
            # Any variant returning 200 is an unambiguous bypass.
            self._log_transaction(baseline_record, oracle_state=_STATE_BASELINE_AUTH_ENFORCED)
            log.debug(
                "normalization_baseline_auth_enforced",
                path=sample_path,
                status=baseline_status,
            )
            findings.extend(
                self._probe_normalization_variants(
                    canonical_path=sample_path,
                    client=client,
                    store=store,
                )
            )

        elif baseline_status == 200:
            # Public endpoint selected: variants returning 200 are not bypasses.
            self._log_transaction(baseline_record, oracle_state=_STATE_BASELINE_PUBLIC)
            notes.append(
                InfoNote(
                    title="Path Normalization Sub-check Not Applicable: Public Endpoint",
                    detail=(
                        f"The selected path '{sample_path}' returned HTTP 200 without "
                        f"credentials (public endpoint). Normalization bypass testing is "
                        f"only meaningful on authenticated endpoints: a variant of a public "
                        f"path returning 200 is expected behaviour, not a bypass. "
                        f"If authenticated non-parametric endpoints exist, verify that "
                        f"'requires_auth' is correctly declared in the OpenAPI specification."
                    ),
                    references=_REFERENCES,
                )
            )

        else:
            # Unexpected baseline status (404, 500, etc.): oracle inconclusive.
            self._log_transaction(baseline_record, oracle_state=_STATE_BASELINE_UNEXPECTED)
            notes.append(
                InfoNote(
                    title="Path Normalization Sub-check Skipped: Unexpected Baseline Status",
                    detail=(
                        f"GET {sample_path} returned HTTP {baseline_status} without credentials. "
                        f"Neither an auth-enforcement signal (401/403) nor a public-path signal "
                        f"(200). The oracle for variant testing cannot be established. "
                        f"This may indicate a misconfigured route or a path requiring a "
                        f"specific request body. Manual normalization verification recommended."
                    ),
                    references=_REFERENCES,
                )
            )

        return findings, notes

    def _probe_normalization_variants(
        self,
        canonical_path: str,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> list[Finding]:
        """
        Probe structural variants of canonical_path and flag HTTP 200 responses.

        Called only after the baseline probe confirmed 401/403 on the canonical
        path, establishing that a 200 on any variant is an authentication bypass.

        Oracle per variant:
            200            -> FAIL: authentication bypassed via normalization.
            401/403        -> PASS: auth enforced on the variant too.
            404 or other   -> PASS: variant correctly rejected by the Gateway.

        Args:
            canonical_path: Documented path confirmed to enforce auth (401/403).
            client:         Centralized HTTP client.
            store:          EvidenceStore for FAIL transactions.

        Returns:
            List of Finding, one per bypass detected.
        """
        findings: list[Finding] = []
        variants = _build_path_variants(canonical_path)

        for variant_label, variant_path in variants:
            if variant_path == canonical_path:
                # Transformation produced no change (e.g. encoding a plain-ASCII
                # segment yields the same string). Skip to avoid redundant probes.
                continue

            log.debug(
                "normalization_variant_probe",
                variant=variant_label,
                path=variant_path,
            )

            response, record = self._safe_get(client, variant_path)
            if response is None or record is None:
                continue

            if response.status_code == 200:
                store.add_fail_evidence(record)
                self._log_transaction(
                    record,
                    oracle_state=_STATE_AUTH_BYPASS_VIA_NORMALIZATION,
                    is_fail=True,
                )
                findings.append(
                    Finding(
                        title="Authentication bypass via path normalization variant",
                        detail=(
                            f"GET {variant_path} ({variant_label}) returned HTTP 200 "
                            f"without an Authorization header. "
                            f"The canonical path '{canonical_path}' enforces authentication "
                            f"(baseline probe returned {_AUTH_ENFORCED_CODES!r}), but this "
                            f"structural variant bypasses the auth check. "
                            f"The Gateway is not normalizing paths before policy application, "
                            f"or the normalized form resolves to an unprotected handler."
                        ),
                        references=_REFERENCES + ["OWASP-API2:2023"],
                        evidence_ref=record.record_id,
                    )
                )
                log.warning(
                    "normalization_bypass_detected",
                    variant=variant_label,
                    path=variant_path,
                )

            elif response.status_code in _AUTH_ENFORCED_CODES:
                self._log_transaction(record, oracle_state=_STATE_AUTH_ENFORCED_ON_VARIANT)
            else:
                self._log_transaction(record, oracle_state=_STATE_VARIANT_REJECTED)

        return findings

    # ------------------------------------------------------------------
    # Transport helper
    # ------------------------------------------------------------------

    def _safe_get(
        self,
        client: SecurityClient,
        path: str,
    ) -> tuple[httpx.Response | None, EvidenceRecord | None]:
        """
        Issue an unauthenticated GET and handle transport errors uniformly.

        On success, returns (httpx.Response, EvidenceRecord). On SecurityClientError,
        logs the transport error via structlog and returns (None, None).
        The caller checks for None before reading response attributes.

        httpx is imported under TYPE_CHECKING only (never at runtime): test
        modules must not import httpx directly per project rules. The annotation
        is evaluated lazily due to 'from __future__ import annotations' and
        therefore carries zero runtime cost.

        Centralising error handling here ensures that every GET probe in this
        test -- nonexistent-path probes and normalization probes alike -- applies
        the same error discipline without repetitive try/except blocks at each
        call site.

        Args:
            client: Centralized HTTP client.
            path:   URL path to probe (relative to target base URL).

        Returns:
            (httpx.Response, EvidenceRecord) on success.
            (None, None) on transport failure.
        """
        try:
            response, record = client.request(method="GET", path=path, test_id=self.test_id)
            return response, record
        except SecurityClientError as exc:
            log.debug(
                "deny_by_default_transport_error",
                path=path,
                exc_type=type(exc).__name__,
                detail=str(exc),
            )
            return None, None


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _detect_backend_server_header(
    path: str,
    record: EvidenceRecord,
    gateway_ids: frozenset[str],
) -> Finding | None:
    """
    Inspect the 'Server' response header for application server identity.

    A 'Server' header that does NOT contain any substring from gateway_ids
    suggests the response was generated by the backend application, not the
    Gateway. Even when the status code is 404, a backend-generated response
    means the request bypassed Gateway-layer deny-by-default enforcement.

    Responsibility boundary:
        This function constructs the Finding but does NOT call
        store.add_fail_evidence(). That call is the exclusive responsibility
        of the call site (_check_nonexistent_paths) to maintain a single,
        auditable evidence-writing pattern.

    Args:
        path:        The probed URL path (for the Finding detail message).
        record:      EvidenceRecord with response_headers and response_status_code.
        gateway_ids: Frozenset of lowercase substrings identifying known Gateways.
                     Populated from target.tests_config.test_0_2.gateway_server_identifiers
                     and passed down by _check_nonexistent_paths. Using a parameter
                     (not a module constant) makes this function API-agnostic:
                     the operator can add HAProxy, Tyk, APISIX, etc. in config.yaml
                     without touching the test code.

    Returns:
        Finding if a non-Gateway Server header is detected, else None.
    """
    raw_server = record.response_headers.get("server", "")
    server_lower = raw_server.lower()

    # An absent Server header does not identify the backend: no finding.
    if not server_lower:
        return None

    # A known Gateway identifier in the Server header: no finding.
    if any(gw_id in server_lower for gw_id in gateway_ids):
        return None

    return Finding(
        title="Backend application server identified in response to unregistered path",
        detail=(
            f"GET {path} returned HTTP {record.response_status_code} "
            f"with 'Server: {raw_server}'. "
            f"This value does not contain any known API Gateway identifier "
            f"(configured: {sorted(gateway_ids)}). "
            f"The response was generated by the backend application, indicating that "
            f"the request bypassed the Gateway's deny-by-default policy and reached "
            f"the upstream service before being rejected. "
            f"Expected: the Gateway intercepts all unregistered paths at the perimeter "
            f"and returns 403/404 under its own Server identifier. "
            f"If this is a false positive, add the observed Server substring to "
            f"'tests.domain_0.test_0_2.gateway_server_identifiers' in config.yaml."
        ),
        references=_REFERENCES + ["CWE-209"],
        evidence_ref=record.record_id,
    )


def _select_authenticated_sample_path(surface: AttackSurface) -> str | None:
    """
    Select the best non-parametric path for normalization baseline testing.

    Prioritises paths with requires_auth=True, because an authenticated path
    provides a clear oracle: if the canonical path returns 401/403 without
    credentials, any variant returning 200 is an unambiguous bypass.

    Priority order:
        1. Non-parametric GET path with requires_auth=True.
        2. Non-parametric path (any method) with requires_auth=True.
        3. Non-parametric GET path (any auth requirement).
        4. Any non-parametric path.

    Returns None only if every documented endpoint contains path template
    parameters (e.g. {owner}, {repo}), making static URL construction
    impossible in Black Box mode.

    Args:
        surface: AttackSurface with the full endpoint inventory.

    Returns:
        Path string, or None if no suitable path exists.
    """
    candidates = [ep for ep in surface.endpoints if "{" not in ep.path and len(ep.path) > 1]

    if not candidates:
        return None

    # Priority 1: authenticated GET.
    for ep in candidates:
        if ep.requires_auth and ep.method == "GET":
            return ep.path

    # Priority 2: authenticated, any method.
    for ep in candidates:
        if ep.requires_auth:
            return ep.path

    # Priority 3: GET, any auth.
    for ep in candidates:
        if ep.method == "GET":
            return ep.path

    # Priority 4: anything non-parametric.
    return candidates[0].path


def _build_path_variants(canonical_path: str) -> list[tuple[str, str]]:
    """
    Generate structural variants of a canonical URL path.

    Each variant targets a specific class of normalization mismatch between
    the Gateway routing layer and the backend HTTP stack:

        Trailing slash:
            Tests whether '/foo' and '/foo/' are treated as the same route
            under the same security policy. Some stacks collapse trailing
            slashes; others treat them as distinct paths.

        Double slash (API-agnostic):
            Inserts an extra slash after the FIRST path separator, producing
            '/first-segment//rest'. Does NOT assume any specific prefix (e.g.
            '/api/') -- the insertion point is always after the first segment.
            Example: '/api/v1/repos' -> '/api//v1/repos'.
            Tests whether double slashes are collapsed before route lookup.

        Uppercase:
            Tests case-sensitivity mismatch. Linux-based Gateways are case-
            sensitive; Windows IIS backends are case-insensitive. A Gateway
            that denies '/API/USERS' but routes '/api/users' to an unprotected
            handler exposes a bypass.

        URL-encoded last segment:
            Percent-encodes the last path segment. Tests whether the Gateway
            decodes percent-encoding before route matching. If '/api/v1/%75sers'
            is not decoded to '/api/v1/users' before the policy lookup, the
            encoded form may bypass authentication.

    Args:
        canonical_path: Documented API path, must start with '/'.

    Returns:
        List of (label, variant_path) tuples. The caller must skip duplicates
        of canonical_path (e.g. when encoding produces no change for ASCII
        segments). Order matches the enumeration in the methodology.
    """
    variants: list[tuple[str, str]] = []

    # Variant 1: trailing slash.
    variants.append(("trailing slash", canonical_path.rstrip("/") + "/"))

    # Variant 2: double slash -- API-agnostic insertion after the first segment.
    # Strip the leading '/' and find the first separator between segments.
    stripped = canonical_path.lstrip("/")
    first_sep = stripped.find("/")
    if first_sep >= 0:
        # Path has at least two segments: '/seg1/seg2/...'
        # Insert double slash between first and second segment.
        # Example: '/api/v1/repos' -> '/api//v1/repos'
        first_segment = stripped[:first_sep]
        remainder = stripped[first_sep:]  # starts with '/', e.g. '/seg2/...'
        double_slash_path = "/" + first_segment + "/" + remainder
    else:
        # Single-segment path (e.g. '/repos'): prepend an extra leading slash.
        # '//repos' is distinct from '/repos' and from the trailing-slash variant.
        double_slash_path = "/" + canonical_path

    variants.append(("double slash", double_slash_path))

    # Variant 3: uppercase.
    variants.append(("uppercase", canonical_path.upper()))

    # Variant 4: URL-encoded last segment.
    # Split on the last '/' to isolate the final segment.
    parts = canonical_path.rstrip("/").rsplit("/", 1)
    if len(parts) == 2 and parts[1]:
        encoded_segment = urllib.parse.quote(parts[1], safe="")
        encoded_path = parts[0] + "/" + encoded_segment
        variants.append(("url-encoded last segment", encoded_path))

    return variants
