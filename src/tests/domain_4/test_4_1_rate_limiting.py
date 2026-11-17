"""
src/tests/domain_4/test_4_1_rate_limiting.py

Test 4.1: guarantee "the gateway limits the request rate" (OWASP API4:2023).

A burst of GETs to a documented endpoint looks for a rate limit's refusal (a
`429`, or the status the gateway states for a limit that may apply); then the
same burst with a random client address per request, in every header that may
carry one, checks the limit is keyed to the real connection (its oracle:
info.oracle, generated on the test page).

The gateway's limits, when the adapter reads them (`Need.GATEWAY`, optional,
src/tests/helpers/route_limits.py), decide when a burst is enough: it goes on
until it provably exceeded every limit that may apply within one of its windows
(_exceeded), at most `max_burst` requests, and stops at the first refusal. A
burst every answer of which refused it (`401`, `403`) may have been refused
before the limit counted it (Kong and APISIX run authentication, ACL and IP
restriction before their rate limits): it is sent again with user_a's
credential.

BLACK_BOX, effect `STRESSES_TARGET` (it runs after every other test, rule 7).

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import math
import secrets
import time
from typing import Annotated

import structlog
from pydantic import BaseModel, ConfigDict, Field

from src.core.assessment_test import category_of
from src.core.auth_placement import RequestAuthParts
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
from src.core.gateway.base import CONCEPT_RATE_LIMITS, CONCEPT_ROUTES
from src.core.gateway.concepts import RateLimit
from src.core.models import (
    Confidence,
    EvidenceRecord,
    Finding,
    InfoNote,
    Outcome,
    Reference,
    ResponseCategory,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.test_metadata import DecisiveAnswer, Effect, Need, OracleCase, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.auth import optional_role_parts
from src.tests.helpers.path_resolver import resolve_path_with_seed
from src.tests.helpers.route_limits import RouteLimits, limits_for_request

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB_LIMIT: str = "limit_enforced"
_SUB_SPOOF: str = "ip_spoofing_resisted"

# The headers that carry a client address, all set to the same random address
# on each spoofed request: X-Forwarded-For (de facto standard), X-Real-IP
# (nginx's realip module), X-Client-IP and True-Client-IP (CDNs), and Forwarded
# (RFC 7239, as "for=<address>").
_SPOOF_HEADERS: tuple[str, ...] = (
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Client-IP",
    "True-Client-IP",
)
_FORWARDED_HEADER: str = "Forwarded"

_BURST_METHOD: str = "GET"
_TOO_MANY_REQUESTS: int = 429
# What some limits answer over the limit (APISIX's default), and an unavailable backend too.
_SERVICE_UNAVAILABLE: int = 503
# Answers that may come from a refusal that runs before the limit counts the request.
_REFUSED: frozenset[ResponseCategory] = frozenset(
    {ResponseCategory.UNAUTHENTICATED, ResponseCategory.FORBIDDEN}
)
# A run of requests shorter than a fixed window touches at most two windows,
# and each further window length it lasts adds one (Kong's windows are
# calendar periods, APISIX's start at the first request counted).
_BOUNDARY_WINDOWS: int = 2
# How many answers that say nothing, in a row, end a burst (a single one does not).
_SPOIL_SAMPLE: int = 3

_NO_LIMIT_RISK: str = (
    " Without a rate limit a loop can exhaust the backend's resources or brute-force a "
    "credential (OWASP API4:2023, ASVS v5.0.0-2.4.1). Configure a rate-limiting plugin on the "
    "gateway."
)

_ORACLE: tuple[OracleCase, ...] = (
    OracleCase(
        sub_test=_SUB_LIMIT,
        when="the burst meets a `429`, or, after answers with another status, the status the "
        "gateway states for a limit that may apply (APISIX's default `503`)",
        outcome=Outcome.ENFORCED,
        detail="RATE_LIMITED",
    ),
    OracleCase(
        sub_test=_SUB_LIMIT,
        when="no refusal, and the burst exceeded every limit read for the routes that may serve "
        "the path within one of its windows, each counted on a counter every node shares: the "
        "limit is configured and not enforced",
        outcome=Outcome.VIOLATION,
        detail="NO_RATE_LIMIT",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_LIMIT,
        when="no refusal within `max_burst`, and no limit read or a route that may serve the path "
        "without one (no limit of fewer than half the burst per window as long as the burst; a "
        "higher one is not seen); or every limit read exceeded, one counted per node",
        outcome=Outcome.VIOLATION,
        detail="NO_RATE_LIMIT",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_LIMIT,
        when="no refusal within `max_burst`, and a limit that may apply was not provably "
        "exceeded: its count above the cap, a window too short for the burst's pace, or not a "
        "count per window",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="LIMIT_NOT_REACHED",
    ),
    OracleCase(
        sub_test=_SUB_LIMIT,
        when="three `503` in a row after answers that said something: a limit refusing with "
        "`503` that the gateway does not state, or a backend going down",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="LIMIT_OR_UNAVAILABLE",
    ),
    OracleCase(
        sub_test=_SUB_LIMIT,
        when="every answer refused the burst (`401`, `403`), perhaps before the limit counted "
        "it, and no user_a account to send it again",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="NO_CREDENTIAL_TO_RETRY",
    ),
    OracleCase(
        sub_test=_SUB_LIMIT,
        when="the burst sent again with user_a's credential is refused all the same",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="REFUSED_BEFORE_LIMIT",
    ),
    OracleCase(
        sub_test=_SUB_SPOOF,
        when="the burst with a random client address per request meets the refusal the plain "
        "burst met",
        outcome=Outcome.ENFORCED,
        detail="SPOOF_RESISTED",
    ),
    OracleCase(
        sub_test=_SUB_SPOOF,
        when="it is never refused, and a plain request right after it is: the limit counts "
        "the address a header claims",
        outcome=Outcome.VIOLATION,
        detail="IP_SPOOF_BYPASS",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_SPOOF,
        when="it is never refused, and neither is a plain request right after it (the limit's "
        "window may have ended during the burst)",
        outcome=Outcome.VIOLATION,
        detail="IP_SPOOF_BYPASS",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_SPOOF,
        when="the plain burst found no limit (`NO_RATE_LIMIT`)",
        outcome=Outcome.NOT_APPLICABLE,
        detail="NO_LIMIT_TO_BYPASS",
    ),
    OracleCase(
        sub_test=_SUB_SPOOF,
        when="the plain burst could not tell whether a limit applies (`limit_enforced` not "
        "verifiable)",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="NO_LIMIT_SEEN",
    ),
)


class Test41Params(BaseModel):
    """Parameters of test 4.1."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_burst: Annotated[int, Field(ge=2)] = Field(
        default=150,
        description=(
            "The largest burst the test sends: the burst when the gateway's limits cannot be read, "
            "and the cap of the one sized from them. The burst stops at the first 429."
        ),
    )
    probe_path: str = Field(
        default="",
        description=(
            "The documented path to flood; empty derives the shortest documented GET. A read "
            "path, so the flood changes nothing."
        ),
    )


class _Burst(BaseModel):
    """What one burst produced."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    sent: int
    # Requests answered (they reached the gateway, which counted them), and the
    # time from the first request to the last answer.
    answered: int
    seconds: float
    # The answer that refused the burst as a limit does, if any.
    limited: EvidenceRecord | None
    last: EvidenceRecord | None
    # Why the burst ended on answers that say nothing (_uninformative), if it did.
    failing: str | None = None
    # Every answer refused the request (_REFUSED).
    refused_only: bool = False


class Test41RateLimiting(BaseTest[Test41Params]):
    """Test 4.1 -- whether the gateway enforces a rate limit and resists IP spoofing."""

    info = TestInfo(
        id="4.1",
        name="Rate Limiting",
        priority=0,
        strategy=TestStrategy.BLACK_BOX,
        cwe="CWE-770",
        references=(
            # ASVS v5.0.0 2.4.1 (read 2026-11-16): anti-automation controls
            # against excessive calls to application functions.
            Reference(standard=Standard.OWASP_API_TOP10, id="API4:2023"),
            Reference(standard=Standard.ASVS, id="v5.0.0-2.4.1"),
            Reference(standard=Standard.NIST_SP, id="800-204", section="4.5"),
        ),
        tags=("resource-consumption", "rate-limiting"),
        optional_needs=(Need.GATEWAY, Need.USER_ACCOUNT),
        effect=Effect.STRESSES_TARGET,
        sub_tests=(_SUB_LIMIT, _SUB_SPOOF),
        decisive_answers=(
            DecisiveAnswer(
                category=ResponseCategory.RATE_LIMITED,
                reason="a `429` is the rate limit this test looks for: the burst stops at it.",
            ),
        ),
        oracle=_ORACLE,
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Flood a documented endpoint, then flood it again spoofing the client address.

        Args:
            target:  The run's target (surface, gateway, path seed).
            context: The run's context (user_a's credential, for a refused burst).
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._requires_attack_surface(...), self._skip(...),
            or self._error(exc).
        """
        try:
            missing = self._requires_attack_surface(target)
            if missing is not None:
                return missing
            path = self._probe_path(target)
            if path is None:
                return self._skip("No documented GET endpoint to probe for a rate limit.")
            cap = self.params(target).max_burst
            routes = self._limits(target, store, path)
            flood = _Flood(client, path, cap, routes)
            plain, credential = self._plain_burst(target, context, flood)
            if plain is None:
                self._record(_SUB_SPOOF, Outcome.NOT_VERIFIABLE, "NO_LIMIT_SEEN")
                return self._finish(message=f"Burst on {path} refused without a credential.")
            notes, no_limit = self._judge_limit(store, flood, plain)
            self._judge_spoofing(store, flood, plain, credential, no_limit=no_limit)
            return self._finish(notes=notes, message=f"Burst of {plain.sent} requests on {path}.")
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_4_1_unexpected_error", error=str(exc))
            return self._error(exc)

    def _probe_path(self, target: TargetContext) -> str | None:
        """The path to flood: the configured one, or the shortest documented GET, public first."""
        cfg = self.params(target)
        if cfg.probe_path:
            return cfg.probe_path
        surface = target.attack_surface
        if surface is None:
            return None
        gets = [e for e in surface.endpoints if e.method.upper() == _BURST_METHOD]
        if not gets:
            return None
        shortest = min(gets, key=lambda e: (e.requires_auth, len(e.path), e.path))
        return resolve_path_with_seed(shortest.path, target.path_seed)

    def _limits(
        self, target: TargetContext, store: EvidenceStore, path: str
    ) -> tuple[RouteLimits[RateLimit], ...] | None:
        """The routes that may serve the probe with their limits (None: unknown); evidence."""
        gateway = target.gateway
        if gateway is None:
            return None
        limits = gateway.rate_limits()
        self._record_gateway_concept(target, store, CONCEPT_RATE_LIMITS, limits)
        self._record_gateway_concept(target, store, CONCEPT_ROUTES, gateway.routes())
        return limits_for_request(gateway, limits, target.endpoint_base_url(), path, _BURST_METHOD)

    def _plain_burst(
        self, target: TargetContext, context: TestContext, flood: _Flood
    ) -> tuple[_Burst | None, RequestAuthParts | None]:
        """
        The plain burst, sent again with user_a's credential when every answer refused it.

        Returns:
            The burst to judge and the credential it carried; (None, None) when
            it was refused and no credential could be had (recorded here).
        """
        plain = self._burst(flood, spoof=False, limited_by=None, credential=None)
        if plain.limited is not None or plain.failing is not None or not plain.refused_only:
            return plain, None
        if plain.last is not None:
            self._step(plain.last)
        credential = optional_role_parts(target, context, ROLE_USER_A)
        if credential is None:
            self._record(_SUB_LIMIT, Outcome.NOT_VERIFIABLE, "NO_CREDENTIAL_TO_RETRY")
            return None, None
        return self._burst(flood, spoof=False, limited_by=None, credential=credential), credential

    def _burst(
        self,
        flood: _Flood,
        *,
        spoof: bool,
        limited_by: int | None,
        credential: RequestAuthParts | None,
    ) -> _Burst:
        """
        Send GETs until a refusal, enough to exceed every known limit, a failing run, or the cap.

        Args:
            flood:      The path, the cap and the limits that may apply.
            spoof:      A random client address on every request (_spoofed_headers).
            limited_by: The status that counts as the limit (the plain burst's
                        refusal); None for the plain burst (_Flood.refuses).
            credential: user_a's request parts, or None.

        Returns:
            The burst's result.
        """
        sub_test = _SUB_SPOOF if spoof else _SUB_LIMIT
        last: EvidenceRecord | None = None
        answered = 0
        failing_in_a_row = 0
        statuses: set[int] = set()
        refused_only = True
        informative_before = False
        sent = 0
        started = time.monotonic()
        for sent in range(1, flood.cap + 1):
            record = _send(flood.client, flood.path, credential, spoof=spoof)
            last = record
            seconds = time.monotonic() - started
            status = record.response_status_code
            if status is not None:
                answered += 1
                is_limit = (
                    status == limited_by
                    if limited_by is not None
                    else flood.refuses(status, statuses)
                )
                if is_limit:
                    return _Burst(
                        sent=sent, answered=answered, seconds=seconds, limited=record, last=record
                    )
                statuses.add(status)
            failing = self._uninformative(record, sub_test)
            if failing is None:
                failing_in_a_row = 0
                informative_before = True
                refused_only = refused_only and category_of(record) in _REFUSED
            else:
                failing_in_a_row += 1
                if failing_in_a_row >= _SPOIL_SAMPLE:
                    maybe_limit = (
                        limited_by is None and informative_before and status == _SERVICE_UNAVAILABLE
                    )
                    return _Burst(
                        sent=sent,
                        answered=answered,
                        seconds=seconds,
                        limited=None,
                        last=record,
                        failing="LIMIT_OR_UNAVAILABLE" if maybe_limit else failing,
                    )
            if flood.enough(answered, seconds):
                break
        return _Burst(
            sent=sent,
            answered=answered,
            seconds=time.monotonic() - started,
            limited=None,
            last=last,
            refused_only=refused_only and informative_before,
        )

    def _judge_limit(
        self, store: EvidenceStore, flood: _Flood, plain: _Burst
    ) -> tuple[list[InfoNote], bool]:
        """
        Judge whether the plain burst met a rate limit (info.oracle, `limit_enforced`).

        Returns:
            A note naming the limits not provably exceeded, when there are some;
            and whether the burst found no limit (NO_RATE_LIMIT).
        """
        if plain.limited is not None:
            self._judge(plain.limited, store, _SUB_LIMIT, Outcome.ENFORCED, "RATE_LIMITED")
            return [], False
        if plain.failing is not None:
            self._record(_SUB_LIMIT, Outcome.NOT_VERIFIABLE, plain.failing)
            return [], False
        if plain.refused_only:
            self._record(_SUB_LIMIT, Outcome.NOT_VERIFIABLE, "REFUSED_BEFORE_LIMIT")
            return [], False
        path = flood.path
        burst = (
            f"{plain.answered} requests to {path} in a burst of {plain.seconds:.1f} s all "
            "answered without a refusal"
        )
        routes = flood.routes
        unlimited = None if routes is None else [r for r in routes if not r.limits]
        if routes is None or unlimited:
            stated = (
                f" The gateway states no rate limit for route {unlimited[0].route.name}, which "
                "may serve this path."
                if unlimited
                else ""
            )
            finding = Finding(
                title=f"No rate limit on {path}",
                detail=(
                    f"{burst}.{stated} No limit of {(plain.answered - 1) // 2} requests or fewer "
                    f"per window of {plain.seconds:.1f} s or longer applies (a burst may straddle "
                    "two windows); a higher limit would not be seen by this burst (raise "
                    "max_burst to look further)." + _NO_LIMIT_RISK
                ),
                confidence=Confidence.FIRM,
            )
            self._violation(store, _SUB_LIMIT, "NO_RATE_LIMIT", finding, plain.last)
            return [], True
        limits = _distinct_limits(routes)
        unproven = [
            limit for limit in limits if not _exceeded(limit, plain.answered, plain.seconds)
        ]
        if unproven:
            self._record(_SUB_LIMIT, Outcome.NOT_VERIFIABLE, "LIMIT_NOT_REACHED")
            note = InfoNote(
                title="Rate limit not reached",
                detail=(
                    f"{burst}, and the burst did not provably go past every limit the "
                    f"gateway states for the routes that may serve it: "
                    f"{'; '.join(_describe(limit) for limit in unproven)}. A limit above "
                    "max_burst, one whose window is too short for the burst's pace, or one "
                    "not counted per window, cannot be judged by this burst."
                ),
            )
            return [note], False
        shared = all(limit.shared_counter is True for limit in limits)
        finding = Finding(
            title=f"Rate limit not enforced on {path}",
            detail=(
                f"{burst}, although the gateway states "
                f"{'; '.join(_describe(limit) for limit in limits)} for the routes that may serve "
                "it, and the burst went past each within one of its windows: the limit is "
                "configured and not enforced"
                + (
                    "."
                    if shared
                    else (
                        ", unless the gateway runs several nodes that each count their own "
                        "requests and the burst was spread over them."
                    )
                )
                + _NO_LIMIT_RISK
            ),
            confidence=Confidence.CERTAIN if shared else Confidence.FIRM,
        )
        self._violation(store, _SUB_LIMIT, "NO_RATE_LIMIT", finding, plain.last)
        return [], True

    def _judge_spoofing(
        self,
        store: EvidenceStore,
        flood: _Flood,
        plain: _Burst,
        credential: RequestAuthParts | None,
        *,
        no_limit: bool,
    ) -> None:
        """Judge the IP-spoofing bypass (info.oracle, `ip_spoofing_resisted`)."""
        if plain.limited is None:
            if no_limit:
                self._record(_SUB_SPOOF, Outcome.NOT_APPLICABLE, "NO_LIMIT_TO_BYPASS")
            else:
                self._record(_SUB_SPOOF, Outcome.NOT_VERIFIABLE, "NO_LIMIT_SEEN")
            return
        refusal = plain.limited.response_status_code
        spoofed = self._burst(flood, spoof=True, limited_by=refusal, credential=credential)
        if spoofed.failing is not None:
            self._record(_SUB_SPOOF, Outcome.NOT_VERIFIABLE, spoofed.failing)
            return
        if spoofed.limited is not None:
            self._judge(spoofed.limited, store, _SUB_SPOOF, Outcome.ENFORCED, "SPOOF_RESISTED")
            return
        control = _send(flood.client, flood.path, credential, spoof=False)
        self._step(control)
        still_limited = control.response_status_code == refusal
        finding = Finding(
            title=f"Rate limit bypassed by spoofing the client address on {flood.path}",
            detail=(
                f"A plain burst to {flood.path} was refused ({refusal}) after {plain.sent} "
                f"requests, but the same burst with a random client address on every request, "
                f"in {', '.join((*_SPOOF_HEADERS, _FORWARDED_HEADER))}, sent {spoofed.sent} "
                "without a refusal"
                + (
                    f", and a plain request right after it was refused ({refusal}) again: the "
                    "limit counts the address a header claims"
                    if still_limited
                    else (
                        f"; a plain request right after it was not refused "
                        f"({control.response_status_code}), so the limit's window may have "
                        "ended during the spoofed burst"
                    )
                )
                + " (which header is not told apart). An attacker rotates it and floods freely "
                "(OWASP API4:2023). Key the limit to the real connection, or trust these headers "
                "only from known proxies."
            ),
            confidence=Confidence.CERTAIN if still_limited else Confidence.FIRM,
        )
        self._violation(store, _SUB_SPOOF, "IP_SPOOF_BYPASS", finding, spoofed.last)

    def _violation(
        self,
        store: EvidenceStore,
        sub_test: str,
        detail: str,
        finding: Finding,
        record: EvidenceRecord | None,
    ) -> None:
        """Record a VIOLATION, pointing it to the burst's last request when there is one."""
        if record is not None:
            self._judge(record, store, sub_test, Outcome.VIOLATION, detail, finding)
        else:
            self._record(sub_test, Outcome.VIOLATION, detail, finding)


class _Flood:
    """The burst's target, cap and the limits that may apply, with the rules they give."""

    def __init__(
        self,
        client: SecurityClient,
        path: str,
        cap: int,
        routes: tuple[RouteLimits[RateLimit], ...] | None,
    ) -> None:
        """
        Args:
            client: The run's HTTP client.
            path:   The path to flood.
            cap:    The largest burst (max_burst).
            routes: The routes that may serve the path with their limits, or None.
        """
        self.client = client
        self.path = path
        self.cap = cap
        self.routes = routes
        limits = [] if routes is None else _distinct_limits(routes)
        self._refusals = frozenset(
            limit.refusal_status
            for limit in limits
            if limit.refusal_status is not None and limit.refusal_status != _TOO_MANY_REQUESTS
        )
        countable = (
            routes is not None
            and all(entry.limits for entry in routes)
            and all(limit.windows for limit in limits)
        )
        self._limits = limits if countable else []

    def refuses(self, status: int, earlier: set[int]) -> bool:
        """
        Whether an answer of the plain burst is a limit's refusal.

        A `429`, or a status a limit that may apply states, once the burst had
        answers with another status (the limit lets the first requests through).
        """
        if status == _TOO_MANY_REQUESTS:
            return True
        return status in self._refusals and bool(earlier - {status})

    def enough(self, answered: int, seconds: float) -> bool:
        """Whether the burst exceeded every limit that may apply (False when they are not known)."""
        return bool(self._limits) and all(
            _exceeded(limit, answered, seconds) for limit in self._limits
        )


def _distinct_limits(routes: tuple[RouteLimits[RateLimit], ...]) -> list[RateLimit]:
    """Every limit of the routes once (a global one applies to each of them)."""
    distinct: dict[str, RateLimit] = {}
    for entry in routes:
        for limit in entry.limits:
            distinct.setdefault(limit.source, limit)
    return list(distinct.values())


def _exceeded(limit: RateLimit, answered: int, seconds: float) -> bool:
    """
    Whether a burst put more than one window's count in a single window.

    A burst of `seconds` touches at most floor(seconds / window) +
    _BOUNDARY_WINDOWS windows; more requests than the count times that number
    put more than the count in one of them.
    """
    return any(
        answered > window.requests * (math.floor(seconds / window.seconds) + _BOUNDARY_WINDOWS)
        for window in limit.windows
    )


def _describe(limit: RateLimit) -> str:
    """A limit in words, for a finding or a note."""
    if not limit.windows:
        return f"{limit.source} (not a count per window)"
    counts = " or ".join(f"{window.requests} per {window.seconds:g} s" for window in limit.windows)
    return f"{limit.source} ({counts})"


def _spoofed_headers() -> dict[str, str]:
    """Every client-address header set to one random address (_SPOOF_HEADERS)."""
    address = _random_ip()
    headers = dict.fromkeys(_SPOOF_HEADERS, address)
    headers[_FORWARDED_HEADER] = f"for={address}"
    return headers


def _random_ip() -> str:
    """A random IPv4 address for the spoofing probe."""
    return ".".join(str(secrets.randbelow(254) + 1) for _ in range(4))


def _send(
    client: SecurityClient,
    path: str,
    credential: RequestAuthParts | None,
    *,
    spoof: bool,
) -> EvidenceRecord:
    """One GET, with user_a's credential and spoofed addresses when given; its record."""
    parts = credential or RequestAuthParts()
    headers = {**parts.headers, **(_spoofed_headers() if spoof else {})}
    try:
        _response, record = client.request(
            _BURST_METHOD,
            path,
            test_id="4.1",
            headers=headers or None,
            params=dict(parts.params) or None,
        )
    except SecurityClientError as exc:
        if exc.record is None:
            raise
        return exc.record
    return record
