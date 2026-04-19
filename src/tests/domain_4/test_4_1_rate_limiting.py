"""
src/tests/domain_4/test_4_1_rate_limiting.py

Test 4.1 -- Rate Limiting: Resource Exhaustion Prevention.

Guarantee (3_TOP_metodologia.md, Section 4.1):
    The Gateway applies rate limiting to prevent automated abuse (DoS,
    brute-force, scraping). Exceeding the configured limit produces
    HTTP 429 Too Many Requests with a Retry-After or X-RateLimit-Reset
    header. The counter must be bound to the real TCP source IP, not to
    a spoofable HTTP header such as X-Forwarded-For.

Strategy: BLACK_BOX -- zero credentials required. Rate limiting is a
    perimeter control enforced by the Gateway before any authentication.
    A 401 response still consumes a request slot and increments the
    counter in correctly configured gateways (Kong rate-limiting plugin).

Priority: P0 -- rate limiting prevents resource exhaustion. Its absence
    enables unbounded brute-force, scraping, and DoS.

Sub-tests (executed in this fixed order):
--------------------------------------------------------------------------
Sub-test 1 -- Spoofing Resistance (runs first)
    Probes the endpoint sending a different random X-Forwarded-For value
    on every request. A Gateway that uses this header as the rate-limit
    key would never accumulate a counter for any single IP, and 429
    would never arrive despite sending max_requests requests.

    Oracle:
        429 received within max_requests  -> PASS  (Gateway uses real TCP IP)
        No 429 within max_requests        -> FAIL  Finding: spoofing vulnerability

    Why first: if the Gateway IS robust (uses real IP), this sub-test
    will deplete part of the rate-limit budget. Sub-test 2 (enforcement)
    then reaches 429 quickly on the same counter -- still a valid PASS.
    If the Gateway is NOT robust (uses X-Forwarded-For), sub-test 1
    finds no 429 AND sub-test 2 will also find no 429 because the gateway
    cannot distinguish individual IPs at all. The two findings are
    consistent and reinforce each other.

Sub-test 2 -- Enforcement (runs second)
    Probes the same endpoint with no X-Forwarded-For manipulation. Uses
    the same per-test request budget (max_requests). If sub-test 1
    partially depleted the counter, 429 may arrive faster here -- that
    is still a valid PASS (rate limiting exists and is functional).

    Oracle:
        429 received within max_requests  -> PASS
        No 429 within max_requests        -> FAIL  Finding: rate limiting absent

Sub-test 3 -- Retry-After header (derived, not independent)
    Triggered automatically by the first 429 observed in either sub-test
    1 or sub-test 2. Inspects the response headers for Retry-After or
    X-RateLimit-Reset. Their absence is a non-blocking additional Finding
    (the gateway enforces rate limiting but provides no backoff guidance).

    Oracle:
        Retry-After OR X-RateLimit-Reset present  -> no additional Finding
        Both absent after a 429                   -> additional Finding added
--------------------------------------------------------------------------

Probe endpoint selection (API-agnostic):
    The test selects ONE endpoint from the AttackSurface for all probes,
    using this priority order:
        1. First non-parametric GET endpoint (no {param} templates).
        2. First non-parametric endpoint with any method.
        3. First endpoint of any kind.
    If the AttackSurface is empty, the test returns SKIP.

    Rationale: a non-parametric path avoids 404/405 noise caused by
    placeholder resource IDs and produces clean 401/200 responses that
    consistently increment the rate-limit counter on every request.

EvidenceStore policy:
    FAIL transactions: stored via store.add_fail_evidence() + _log_transaction(is_fail=True).
    All probe requests (including 200/401 probe hits): logged via
    _log_transaction() only (no EvidenceStore entry -- high volume, low signal).
    First 429 response: always stored via store.add_fail_evidence() as
    pinned evidence (even on PASS), because it is the observable proof
    that rate limiting triggered. This is an intentional deviation from
    the "FAIL only" rule -- a pinned 429 response is the most important
    artifact of this test regardless of outcome.
"""

from __future__ import annotations

import secrets
import time
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

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# HTTP status code that signals rate limiting was enforced.
_HTTP_RATE_LIMITED: int = 429

# Headers that carry rate-limit backoff guidance (checked case-insensitively).
_RETRY_GUIDANCE_HEADERS: frozenset[str] = frozenset(
    {
        "retry-after",
        "x-ratelimit-reset",
        "x-rate-limit-reset",
        "ratelimit-reset",
    }
)

# Oracle state labels used in TransactionSummary for analyst triage.
_STATE_RATE_LIMIT_HIT: str = "RATE_LIMIT_HIT"
_STATE_PROBE_HIT: str = "PROBE_HIT"
_STATE_TRANSPORT_ERROR: str = "TRANSPORT_ERROR"

# References cited in every Finding produced by this test.
_REFERENCES: list[str] = [
    "OWASP-API4:2023",
    "OWASP-ASVS-v5.0.0-V2.4.1",
    "NIST-SP-800-204-Section-4.5",
    "CWE-400",
]


class Test41RateLimiting(BaseTest):
    """
    Test 4.1 -- Rate Limiting: Resource Exhaustion Prevention.

    Verifies that the API Gateway applies rate limiting on the probe
    endpoint, that the counter is bound to the real TCP source IP
    (not spoofable via X-Forwarded-For), and that a 429 response
    carries Retry-After or X-RateLimit-Reset guidance.
    """

    # ------------------------------------------------------------------
    # BaseTest class-level contract
    # ------------------------------------------------------------------

    test_id: ClassVar[str] = "4.1"
    test_name: ClassVar[str] = "Rate Limiting -- Resource Exhaustion Prevention"
    domain: ClassVar[int] = 4
    priority: ClassVar[int] = 0
    strategy: ClassVar[TestStrategy] = TestStrategy.BLACK_BOX
    depends_on: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = [
        "availability",
        "rate-limiting",
        "dos-prevention",
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
        Run all three rate-limiting sub-tests against the selected probe endpoint.

        Execution order: spoofing resistance -> enforcement -> Retry-After check.
        All sub-tests share a single probe endpoint chosen from the AttackSurface.

        Returns:
            TestResult with status PASS, FAIL, SKIP, or ERROR.
        """
        try:
            skip_guard = self._requires_attack_surface(target)
            if skip_guard is not None:
                return skip_guard

            probe_endpoint = self._select_probe_endpoint(target)
            if probe_endpoint is None:
                return self._make_skip(
                    reason=(
                        "AttackSurface contains no usable endpoints. "
                        "Cannot select a probe path for rate-limit verification."
                    )
                )

            probe_path: str = probe_endpoint.path
            probe_method: str = probe_endpoint.method
            cfg = target.tests_config.test_4_1

            log.info(
                "test_4_1_starting",
                probe_path=probe_path,
                probe_method=probe_method,
                max_requests=cfg.max_requests,
                request_interval_ms=cfg.request_interval_ms,
            )

            findings: list[Finding] = []

            # Sub-test 1: Spoofing Resistance
            spoofing_finding, first_429_record = self._run_spoofing_resistance(
                target=target,
                client=client,
                store=store,
                path=probe_path,
                method=probe_method,
            )
            if spoofing_finding is not None:
                findings.append(spoofing_finding)

            # Sub-test 2: Enforcement
            enforcement_finding, enforcement_429_record = self._run_enforcement(
                target=target,
                client=client,
                store=store,
                path=probe_path,
                method=probe_method,
            )
            if enforcement_finding is not None:
                findings.append(enforcement_finding)

            # Sub-test 3: Retry-After header (derived from first observed 429)
            canonical_429: EvidenceRecord | None = first_429_record or enforcement_429_record
            retry_after_finding = self._check_retry_after_header(
                canonical_429_response_headers=(
                    canonical_429.response_headers if canonical_429 is not None else {}
                ),
                probe_path=probe_path,
            )
            if retry_after_finding is not None:
                findings.append(retry_after_finding)

            # Build result
            if findings:
                return TestResult(
                    test_id=self.test_id,
                    status=TestStatus.FAIL,
                    message=(
                        f"Rate limiting check on {probe_method} {probe_path} "
                        f"produced {len(findings)} finding(s). "
                        f"See findings for details."
                    ),
                    findings=findings,
                    transaction_log=list(self._transaction_log),
                    **self._metadata_kwargs(),
                )

            return self._make_pass(
                message=(
                    f"Rate limiting enforced on {probe_method} {probe_path}: "
                    f"HTTP 429 received within probe budget, counter bound to real "
                    f"source IP, Retry-After guidance present."
                )
            )

        except Exception as exc:  # noqa: BLE001
            log.exception("test_4_1_unexpected_error", error=str(exc))
            return self._make_error(exc)

    # ------------------------------------------------------------------
    # Sub-test 1: Spoofing Resistance
    # ------------------------------------------------------------------

    def _run_spoofing_resistance(
        self,
        target: TargetContext,
        client: SecurityClient,
        store: EvidenceStore,
        path: str,
        method: str,
    ) -> tuple[Finding | None, EvidenceRecord | None]:
        """
        Sub-test 1: Probe with a different random X-Forwarded-For on every request.

        If the Gateway uses this header as the rate-limit key, the counter
        resets on every request and 429 never arrives -- a Finding is generated.
        If the Gateway uses the real TCP IP, the counter accumulates normally
        and 429 arrives as expected -- no Finding.

        Args:
            target:  Frozen TargetContext providing tests_config.test_4_1.
            client:  SecurityClient for sending HTTP requests.
            store:   EvidenceStore for pinning the first 429.
            path:    Probe endpoint path.
            method:  Probe endpoint HTTP method.

        Returns:
            Tuple of (Finding | None, EvidenceRecord | None).
            Finding is non-None only when 429 was NOT received (vulnerability).
            The EvidenceRecord is non-None when 429 WAS received (pinned proof).
        """
        cfg = target.tests_config.test_4_1
        log.info(
            "test_4_1_spoofing_resistance_started",
            max_requests=cfg.max_requests,
        )

        for request_index in range(1, cfg.max_requests + 1):
            # Generate a fresh random IPv4 string for every request.
            spoofed_ip = self._random_ipv4()
            extra_headers = {"X-Forwarded-For": spoofed_ip}

            try:
                _response, record = client.request(
                    method=method,
                    path=path,
                    test_id=self.test_id,
                    headers=extra_headers,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "test_4_1_spoofing_transport_error",
                    request_index=request_index,
                    error=str(exc),
                )
                continue

            if record.response_status_code == _HTTP_RATE_LIMITED:
                # Gateway uses real IP -- spoofing did not prevent enforcement.
                # Pin this 429 as evidence even on PASS (it proves rate limiting works).
                store.add_fail_evidence(record)
                self._log_transaction(
                    record,
                    oracle_state=_STATE_RATE_LIMIT_HIT,
                    is_fail=True,
                )
                log.info(
                    "test_4_1_spoofing_resistance_pass",
                    request_index=request_index,
                    spoofed_ip=spoofed_ip,
                )
                return None, record

            self._log_transaction(record, oracle_state=_STATE_PROBE_HIT)

            if request_index < cfg.max_requests:
                time.sleep(cfg.request_interval_seconds)

        # No 429 arrived despite max_requests with random X-Forwarded-For values.
        log.warning(
            "test_4_1_spoofing_resistance_fail",
            max_requests=cfg.max_requests,
        )
        finding = Finding(
            title="Rate Limit Counter Bound to X-Forwarded-For (Spoofing Vulnerability)",
            detail=(
                f"Sent {cfg.max_requests} requests to {method} {path}, each carrying "
                f"a distinct random X-Forwarded-For value. No HTTP 429 was received. "
                f"The Gateway appears to use the X-Forwarded-For header as the "
                f"rate-limit key instead of the real TCP source IP. An attacker can "
                f"rotate this header on every request to bypass rate limiting entirely."
            ),
            references=_REFERENCES,
            evidence_ref=None,
        )
        return finding, None

    # ------------------------------------------------------------------
    # Sub-test 2: Enforcement
    # ------------------------------------------------------------------

    def _run_enforcement(
        self,
        target: TargetContext,
        client: SecurityClient,
        store: EvidenceStore,
        path: str,
        method: str,
    ) -> tuple[Finding | None, EvidenceRecord | None]:
        """
        Sub-test 2: Probe without X-Forwarded-For manipulation.

        Sends requests using the real source IP as seen by the Gateway.
        Expects HTTP 429 to arrive within the configured budget.

        Note on counter state: if sub-test 1 already caused a 429 (spoofing-
        resistant gateway), the counter may be partially or fully depleted
        at the start of this sub-test. A 429 arriving quickly here is still
        a valid PASS for enforcement: rate limiting is present and functional.

        Args:
            target:  Frozen TargetContext providing tests_config.test_4_1.
            client:  SecurityClient for sending HTTP requests.
            store:   EvidenceStore for pinning the first 429.
            path:    Probe endpoint path.
            method:  Probe endpoint HTTP method.

        Returns:
            Tuple of (Finding | None, EvidenceRecord | None).
            Finding is non-None only when 429 was NOT received.
            The EvidenceRecord is non-None when 429 WAS received (pinned proof).
        """
        cfg = target.tests_config.test_4_1
        log.info(
            "test_4_1_enforcement_started",
            max_requests=cfg.max_requests,
        )

        for request_index in range(1, cfg.max_requests + 1):
            try:
                _response, record = client.request(
                    method=method,
                    path=path,
                    test_id=self.test_id,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "test_4_1_enforcement_transport_error",
                    request_index=request_index,
                    error=str(exc),
                )
                continue

            if record.response_status_code == _HTTP_RATE_LIMITED:
                store.add_fail_evidence(record)
                self._log_transaction(
                    record,
                    oracle_state=_STATE_RATE_LIMIT_HIT,
                    is_fail=True,
                )
                log.info(
                    "test_4_1_enforcement_pass",
                    request_index=request_index,
                )
                return None, record

            self._log_transaction(record, oracle_state=_STATE_PROBE_HIT)

            if request_index < cfg.max_requests:
                time.sleep(cfg.request_interval_seconds)

        log.warning(
            "test_4_1_enforcement_fail",
            max_requests=cfg.max_requests,
        )
        finding = Finding(
            title="Rate Limiting Not Enforced",
            detail=(
                f"Sent {cfg.max_requests} requests to {method} {path} at "
                f"{cfg.request_interval_ms}ms intervals without receiving "
                f"HTTP 429 Too Many Requests. Rate limiting appears absent or "
                f"configured with a threshold above the probe budget. "
                f"Without rate limiting, the endpoint is exposed to unbounded "
                f"brute-force, credential stuffing, and DoS via resource exhaustion."
            ),
            references=_REFERENCES,
            evidence_ref=None,
        )
        return finding, None

    # ------------------------------------------------------------------
    # Sub-test 3: Retry-After header check (derived)
    # ------------------------------------------------------------------

    def _check_retry_after_header(
        self,
        canonical_429_response_headers: dict[str, str],
        probe_path: str,
    ) -> Finding | None:
        """
        Sub-test 3: Verify that a 429 response carries backoff guidance.

        Inspects the response headers of the first observed 429 for the
        presence of Retry-After, X-RateLimit-Reset, or equivalent headers.
        Their absence is an additional (non-blocking) Finding: rate limiting
        IS present but clients have no way to know when to retry.

        Args:
            canonical_429_response_headers: Headers dict from the first 429
                EvidenceRecord. Empty dict if no 429 was observed (in which
                case this check is trivially skipped -- no 429 means no
                headers to inspect).
            probe_path: Path of the probe endpoint, used only in the Finding detail.

        Returns:
            Finding if guidance headers are absent on a received 429, else None.
        """
        if not canonical_429_response_headers:
            # No 429 was observed by either sub-test: this check has no data
            # to work with. Skip silently -- the enforcement FAIL finding
            # already captures the absence of rate limiting.
            log.debug("test_4_1_retry_after_skipped_no_429_observed")
            return None

        lowercase_headers = {k.lower() for k in canonical_429_response_headers}
        guidance_found = bool(lowercase_headers & _RETRY_GUIDANCE_HEADERS)

        if guidance_found:
            matched = lowercase_headers & _RETRY_GUIDANCE_HEADERS
            log.info("test_4_1_retry_after_present", matched_headers=list(matched))
            return None

        log.warning(
            "test_4_1_retry_after_missing",
            present_headers=list(lowercase_headers),
        )
        return Finding(
            title="429 Response Missing Retry-After / X-RateLimit-Reset Header",
            detail=(
                f"HTTP 429 was received for {probe_path} but the response carried "
                f"neither Retry-After nor X-RateLimit-Reset (or equivalent). "
                f"Clients cannot determine when the rate-limit window resets and "
                f"must resort to arbitrary backoff, increasing retry pressure. "
                f"Present response headers: "
                f"{sorted(lowercase_headers) or ['(none)']}"
            ),
            references=[
                "OWASP-ASVS-v5.0.0-V2.4.1",
                "RFC-9110-Section-15.5.30",
            ],
            evidence_ref=None,
        )

    # ------------------------------------------------------------------
    # Probe endpoint selection
    # ------------------------------------------------------------------

    def _select_probe_endpoint(
        self,
        target: TargetContext,
    ) -> EndpointRecord | None:
        """
        Select the best endpoint to use as the rate-limit probe target.

        Priority order:
            1. First non-parametric GET endpoint (cleanest signal).
            2. First non-parametric endpoint with any method.
            3. First endpoint of any kind.
            None if the AttackSurface is empty.

        Non-parametric paths (no {param} templates) avoid the 404/405
        noise that parametric paths produce when a placeholder resource
        ID is used, and produce consistent 401/200 responses that
        reliably increment the rate-limit counter.

        Args:
            target: Frozen TargetContext with a populated AttackSurface.

        Returns:
            The selected EndpointRecord, or None if the surface is empty.
        """
        surface = target.attack_surface
        if surface is None:
            return None
        all_endpoints = surface.endpoints

        if not all_endpoints:
            return None

        non_parametric = [ep for ep in all_endpoints if "{" not in ep.path]

        # Priority 1: non-parametric GET
        for ep in non_parametric:
            if ep.method == "GET":
                log.debug(
                    "test_4_1_probe_selected",
                    path=ep.path,
                    method=ep.method,
                    reason="non_parametric_get",
                )
                return ep

        # Priority 2: non-parametric, any method
        if non_parametric:
            ep = non_parametric[0]
            log.debug(
                "test_4_1_probe_selected",
                path=ep.path,
                method=ep.method,
                reason="non_parametric_any_method",
            )
            return ep

        # Priority 3: fallback to first endpoint of any kind
        ep = all_endpoints[0]
        log.debug(
            "test_4_1_probe_selected",
            path=ep.path,
            method=ep.method,
            reason="fallback_first_endpoint",
        )
        return ep

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _random_ipv4() -> str:
        """
        Generate a cryptographically random dotted-decimal IPv4 string.

        Uses secrets.randbelow() (CSPRNG) to produce each octet.
        The first octet is constrained to 1-254 to avoid reserved ranges
        (0.x.x.x broadcast prefix, 255.x.x.x limited broadcast).

        Returns:
            A string in the form "A.B.C.D" with A in [1, 254] and B,C,D in [0, 255].
        """
        a = secrets.randbelow(254) + 1  # [1, 254]
        b = secrets.randbelow(256)  # [0, 255]
        c = secrets.randbelow(256)
        d = secrets.randbelow(256)
        return f"{a}.{b}.{c}.{d}"
