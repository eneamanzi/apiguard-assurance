"""
src/tests/domain_4/test_4_1_rate_limiting.py

Test 4.1: guarantee "the gateway limits the request rate" (OWASP API4:2023).

A gateway must stop a flood: past a limit it answers `429 Too Many Requests`.
The test sends a burst to a documented endpoint and looks for the 429, then
repeats the burst with a different, spoofed client address on every request to
check the limit is keyed to the real connection, not to a header an attacker
controls.

    limit_enforced        a burst reaches a 429 -> ENFORCED; none within the
                          budget -> VIOLATION/NO_RATE_LIMIT;
    ip_spoofing_resisted  the same burst with a random client address per
                          request, in every header that carries one
                          (_SPOOF_HEADERS), still reaches a 429 -> ENFORCED; it floods
                          freely while the plain burst was limited ->
                          VIOLATION/IP_SPOOF_BYPASS.

The gateway's own limits, when the adapter can read them (`Need.GATEWAY`,
optional: `rate_limits()`, requests per window of seconds), size the burst and
sharpen the verdict. A limit counts only when it may apply to the probe: the
limits on every request, on the backend and on the route, for every route that
may serve the path (src/tests/helpers/route_limits.py). The burst may straddle
the boundary of a fixed window, so it must send more than twice a window's
count to put more than the count in one window (_BOUNDARY_WINDOWS); the budget
is that, for the largest of the limits that may apply, capped by `max_burst`.
After a burst without a 429:

    no limit read, or a route that may serve the path has none
        -> VIOLATION/NO_RATE_LIMIT, FIRM: "no limit at or below this many
           requests", a higher limit, or one the adapter does not read, would
           not be seen;
    every limit that may apply was exceeded within one of its windows (by the
    burst's measured duration)
        -> VIOLATION/NO_RATE_LIMIT, CERTAIN when every one is counted on a
           counter shared by all the gateway's nodes, else FIRM: a per-node
           counter is not exceeded when the burst is spread over several nodes;
    a limit that may apply was not provably exceeded (above the cap, a window
    too short for the burst's pace, or a limit not counted per window)
        -> NOT_VERIFIABLE/LIMIT_NOT_REACHED.

The burst stops at the first 429, so a working limit is not flooded past its
threshold.

BLACK_BOX (no credential: an anonymous flood), effect `STRESSES_TARGET` (it runs
after every other test, rule 7).

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
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
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
from src.core.test_metadata import DecisiveAnswer, Effect, Need, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.path_resolver import resolve_path_with_seed
from src.tests.helpers.route_limits import RouteLimits, limits_for_request

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB_LIMIT: str = "limit_enforced"
_SUB_SPOOF: str = "ip_spoofing_resisted"

# The headers an attacker spoofs to pretend to be many clients, all set to the
# same random address on each request; the gateway must key its limit to the
# real TCP connection, not to these values. X-Forwarded-For (the de facto
# standard), Forwarded (RFC 7239, as "for=<address>"), X-Real-IP (nginx's
# realip module, which Kong and APISIX build on), X-Client-IP and
# True-Client-IP (set by CDNs): one burst covers them all (# only X-Forwarded-For was sent).
_SPOOF_HEADERS: tuple[str, ...] = (
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Client-IP",
    "True-Client-IP",
)
_FORWARDED_HEADER: str = "Forwarded"

# The method of the burst's requests.
_BURST_METHOD: str = "GET"

# A run of requests shorter than one window touches at most two fixed windows,
# and each further window length it lasts adds one: more than this many times a
# window's count puts more than the count in one window, wherever the window
# boundaries fall (Kong's are calendar periods, APISIX's start at the first
# request counted).
_BOUNDARY_WINDOWS: int = 2


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


class Test41RateLimiting(BaseTest[Test41Params]):
    """
    Test 4.1 -- whether the gateway enforces a rate limit and resists IP spoofing.

    The oracle of each sub-test is in the module docstring and on the test page.
    """

    info = TestInfo(
        id="4.1",
        name="Rate Limiting",
        priority=0,
        strategy=TestStrategy.BLACK_BOX,
        cwe="CWE-770",
        references=(
            # Read on the ASVS v5.0.0 source 2026-10-23: 2.4.1 (anti-automation /
            # rate limiting against resource-consumption abuse).
            Reference(standard=Standard.OWASP_API_TOP10, id="API4:2023"),
            Reference(standard=Standard.ASVS, id="v5.0.0-2.4.1"),
            Reference(standard=Standard.NIST_SP, id="800-204", section="4.5"),
        ),
        tags=("resource-consumption", "rate-limiting"),
        optional_needs=(Need.GATEWAY,),
        effect=Effect.STRESSES_TARGET,
        sub_tests=(_SUB_LIMIT, _SUB_SPOOF),
        decisive_answers=(
            DecisiveAnswer(
                category=ResponseCategory.RATE_LIMITED,
                reason="a `429` is the rate limit this test looks for: the burst stops at it.",
            ),
        ),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Flood a documented endpoint, then flood it again spoofing the client IP.

        Args:
            target:  The run's target (surface, gateway, path seed).
            context: Unused.
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._requires_attack_surface(...), self._skip(...),
            or self._error(exc).
        """
        del context
        try:
            missing = self._requires_attack_surface(target)
            if missing is not None:
                return missing
            path = self._probe_path(target)
            if path is None:
                return self._skip("No documented GET endpoint to probe for a rate limit.")
            budget, routes = self._budget(target, store, path)
            plain = self._burst(client, path, budget, spoof=False)
            notes = self._judge_limit(store, path, plain, routes)
            self._judge_spoofing(client, store, path, budget, plain)
            return self._finish(notes=notes, message=f"Burst budget {budget} on {path}.")
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_4_1_unexpected_error", error=str(exc))
            return self._error(exc)

    def _probe_path(self, target: TargetContext) -> str | None:
        """The path to flood: the configured one, or the shortest documented GET."""
        cfg = self.params(target)
        if cfg.probe_path:
            return cfg.probe_path
        surface = target.attack_surface
        if surface is None:
            return None
        gets = [e for e in surface.endpoints if e.method.upper() == "GET"]
        if not gets:
            return None
        shortest = min(gets, key=lambda e: (len(e.path), e.path))
        return resolve_path_with_seed(shortest.path, target.path_seed)

    def _budget(
        self, target: TargetContext, store: EvidenceStore, path: str
    ) -> tuple[int, tuple[RouteLimits[RateLimit], ...] | None]:
        """
        The burst size, and the limits that may apply to the probe.

        The concepts read are kept as evidence. The size is the cap unless
        every route that may serve the path has limits counted per window:
        then enough to exceed the largest of them in one window
        (_needed_requests), within the cap.

        Args:
            target: The run's target (gateway, base URL, parameters).
            store:  The test's evidence store.
            path:   The path to flood.

        Returns:
            The budget, and the routes that may serve the path with their
            limits (None when nothing is known of them).
        """
        cap = self.params(target).max_burst
        gateway = target.gateway
        if gateway is None:
            return cap, None
        limits = gateway.rate_limits()
        self._record_gateway_concept(target, store, CONCEPT_RATE_LIMITS, limits)
        self._record_gateway_concept(target, store, CONCEPT_ROUTES, gateway.routes())
        routes = limits_for_request(
            gateway, limits, target.endpoint_base_url(), path, _BURST_METHOD
        )
        needed = _needed_requests(routes)
        return (cap if needed is None else min(cap, needed)), routes

    def _burst(
        self,
        client: SecurityClient,
        path: str,
        budget: int,
        *,
        spoof: bool,
    ) -> _BurstResult:
        """
        Send up to `budget` GETs, stopping at the first 429.

        Args:
            client: The run's HTTP client.
            path:   The path to flood.
            budget: The largest number of requests to send.
            spoof:  Send a random client address on every request (_spoofed_headers),
                    for the spoofing sub-test.

        Returns:
            The burst's result: how many requests, whether a 429 was seen (and
            its record), and whether the upstream was failing.
        """
        last: EvidenceRecord | None = None
        failing_in_a_row = 0
        served_before = False
        answered = 0
        started = time.monotonic()
        for sent in range(1, budget + 1):
            headers = _spoofed_headers() if spoof else None
            record = _send(client, path, headers)
            if record is None:
                continue
            last = record
            answered += 1
            category = category_of(record)
            if category == ResponseCategory.RATE_LIMITED:
                return _BurstResult(
                    sent=sent,
                    answered=answered,
                    seconds=time.monotonic() - started,
                    limited_record=record,
                    last_record=last,
                    upstream_failing=False,
                )
            failing = self._uninformative(record, _SUB_SPOOF if spoof else _SUB_LIMIT)
            if failing is not None:
                failing_in_a_row += 1
            else:
                failing_in_a_row = 0
                served_before = served_before or category == ResponseCategory.SERVED
            if failing_in_a_row >= _SPOIL_SAMPLE:
                # The endpoint keeps failing: flooding it further says nothing
                # (a run of failures, not a single one). After
                # answers that were served, a run of 503 may be a limit that
                # rejects with 503 instead of 429.
                return _BurstResult(
                    sent=sent,
                    answered=answered,
                    seconds=time.monotonic() - started,
                    limited_record=None,
                    last_record=last,
                    upstream_failing=True,
                    failing_reason=failing,
                    maybe_limit=served_before
                    and record.response_status_code == _SERVICE_UNAVAILABLE,
                )
        return _BurstResult(
            sent=budget,
            answered=answered,
            seconds=time.monotonic() - started,
            limited_record=None,
            last_record=last,
            upstream_failing=False,
        )

    def _judge_limit(
        self,
        store: EvidenceStore,
        path: str,
        plain: _BurstResult,
        routes: tuple[RouteLimits[RateLimit], ...] | None,
    ) -> list[InfoNote]:
        """
        Judge whether the plain burst met a rate limit (module docstring: the cases).

        Args:
            store:  The test's evidence store.
            path:   The path flooded.
            plain:  The plain burst's result.
            routes: The routes that may serve the path with their limits, or None.

        Returns:
            A note naming the limits not provably exceeded, when there are some.
        """
        if plain.upstream_failing:
            detail = "LIMIT_OR_UNAVAILABLE" if plain.maybe_limit else plain.failing_reason
            self._record(_SUB_LIMIT, Outcome.NOT_VERIFIABLE, detail)
            return []
        if plain.limited_record is not None:
            self._judge(plain.limited_record, store, _SUB_LIMIT, Outcome.ENFORCED, "RATE_LIMITED")
            return []
        burst = (
            f"{plain.answered} requests to {path} in a burst of {plain.seconds:.1f} s all "
            "answered without a 429 Too Many Requests"
        )
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
                    f"{burst}.{stated} No limit applies at or below that rate; a higher limit "
                    "would not be seen by this burst (raise max_burst to look further)."
                    + _NO_LIMIT_RISK
                ),
                confidence=Confidence.FIRM,
            )
            self._violation(store, _SUB_LIMIT, "NO_RATE_LIMIT", finding, plain.last_record)
            return []
        limits = _distinct_limits(routes)
        unproven = [
            limit for limit in limits if not _exceeded(limit, plain.answered, plain.seconds)
        ]
        if unproven:
            self._record(_SUB_LIMIT, Outcome.NOT_VERIFIABLE, "LIMIT_NOT_REACHED")
            return [
                InfoNote(
                    title="Rate limit not reached",
                    detail=(
                        f"{burst}, and the burst did not provably go past every limit the "
                        f"gateway states for the routes that may serve it: "
                        f"{'; '.join(_describe(limit) for limit in unproven)}. A limit above "
                        "max_burst, one whose window is too short for the burst's pace, or one "
                        "not counted per window, cannot be judged by this burst."
                    ),
                )
            ]
        shared = all(limit.shared_counter is True for limit in limits)
        stated = "; ".join(_describe(limit) for limit in limits)
        finding = Finding(
            title=f"Rate limit not enforced on {path}",
            detail=(
                f"{burst}, although the gateway states {stated} for the routes that may serve "
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
        self._violation(store, _SUB_LIMIT, "NO_RATE_LIMIT", finding, plain.last_record)
        return []

    def _judge_spoofing(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        path: str,
        budget: int,
        plain: _BurstResult,
    ) -> None:
        """Judge the IP-spoofing bypass, only when there was a limit to bypass."""
        if plain.limited_record is None:
            self._record(_SUB_SPOOF, Outcome.NOT_APPLICABLE, "NO_LIMIT_TO_BYPASS")
            return
        spoofed = self._burst(client, path, budget, spoof=True)
        if spoofed.upstream_failing:
            self._record(_SUB_SPOOF, Outcome.NOT_VERIFIABLE, spoofed.failing_reason)
            return
        if spoofed.limited_record is not None:
            self._judge(
                spoofed.limited_record, store, _SUB_SPOOF, Outcome.ENFORCED, "SPOOF_RESISTED"
            )
            return
        finding = Finding(
            title=f"Rate limit bypassed by spoofing the client address on {path}",
            detail=(
                f"A plain burst to {path} met a 429 after {plain.sent} requests, but the same "
                f"burst with a random client address on every request, in "
                f"{', '.join((*_SPOOF_HEADERS, _FORWARDED_HEADER))}, sent {budget} without a "
                "429. The gateway keys its rate limit to a client-controlled header (which of "
                "these is not told apart), so an attacker rotates it and floods freely (OWASP "
                "API4:2023). Key the limit to the real connection, or trust these headers only "
                "from known proxies."
            ),
            confidence=Confidence.CERTAIN,
        )
        self._violation(store, _SUB_SPOOF, "IP_SPOOF_BYPASS", finding, spoofed.last_record)

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


# The risk a finding of this sub-test names.
_NO_LIMIT_RISK: str = (
    " Without a rate limit a loop can exhaust the backend's resources or brute-force a "
    "credential (OWASP API4:2023, ASVS v5.0.0-2.4.1). Configure a rate-limiting plugin on the "
    "gateway."
)

# How many failing answers in a row end the burst (a single transient 5xx does
# not stop it).
_SPOIL_SAMPLE: int = 3
# 503 Service Unavailable: what some gateways' rate limiters answer over the
# limit (instead of 429), and what an unavailable backend answers too.
_SERVICE_UNAVAILABLE: int = 503


class _BurstResult(BaseModel):
    """What one burst produced."""

    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    sent: int
    # Requests that got an answer (they reached the gateway, which counted
    # them), and the time from the first request to the last answer.
    answered: int
    seconds: float
    limited_record: EvidenceRecord | None
    last_record: EvidenceRecord | None
    upstream_failing: bool
    # The failing run is 503s after served answers: possibly a limit rejecting
    # with 503 (some gateways' default) rather than an unavailable backend.
    maybe_limit: bool = False
    # Why the last answer of a failing run says nothing (_uninformative).
    failing_reason: str = ResponseCategory.UPSTREAM_UNAVAILABLE.value


def _needed_requests(routes: tuple[RouteLimits[RateLimit], ...] | None) -> int | None:
    """
    Requests enough to exceed, in one window, every limit that may apply.

    For each limit, the smallest of its windows' counts times _BOUNDARY_WINDOWS,
    plus one (a burst shorter than that window); the largest over the limits.
    None when nothing is known of the limits, a route that may serve the path
    has none, or a limit is not counted per window: the budget is then the cap.
    """
    if routes is None or any(not entry.limits for entry in routes):
        return None
    limits = _distinct_limits(routes)
    if any(not limit.windows for limit in limits):
        return None
    return max(
        min(window.requests for window in limit.windows) * _BOUNDARY_WINDOWS + 1 for limit in limits
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
    client: SecurityClient, path: str, headers: dict[str, str] | None
) -> EvidenceRecord | None:
    """One GET; its record, or None on a transport failure."""
    try:
        _response, record = client.request("GET", path, test_id="4.1", headers=headers)
    except SecurityClientError as exc:
        return exc.record
    return record
