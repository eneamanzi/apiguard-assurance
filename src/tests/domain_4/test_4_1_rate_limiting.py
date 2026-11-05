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

The budget (how many requests the burst sends before giving up) is the gateway's
own configured limit plus a margin, when the adapter can read it (`Need.GATEWAY`,
optional), and otherwise the `max_burst` cap. On the two supported gateways the
limit is stated as a number (Kong's `rate-limiting.minute`, APISIX's
`limit-count.count`, checked on their schemas 2026-11-03) and the configuration
scan collects strings only, so in practice the budget is the cap. A burst that
meets no 429 therefore proves "no limit at or below this many requests", not "no
limit": the finding is FIRM and says so, and CERTAIN only when a configured limit
was read and the budget went past it. A limit read above the cap cannot be
reached and gives NOT_VERIFIABLE/LIMIT_ABOVE_BUDGET. The burst stops at the
first 429, so a working limit is not flooded past its threshold.

BLACK_BOX (no credential: an anonymous flood), effect `STRESSES_TARGET` (it runs
after every other test, rule 7).

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import secrets
from typing import Annotated

import structlog
from pydantic import BaseModel, ConfigDict, Field

from src.core.assessment_test import category_of
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
from src.core.gateway.base import BaseGatewayAdapter
from src.core.gateway.concepts import ConceptStatus
from src.core.models import (
    Confidence,
    EvidenceRecord,
    Finding,
    Outcome,
    Reference,
    ResponseCategory,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.path_resolver import resolve_path_with_seed

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

# Added to a limit read from the gateway, so the burst crosses the threshold.
_BUDGET_MARGIN: int = 5

# A config value is treated as a rate limit when its location names a
# rate-limiting plugin; the smallest positive integer among those is the limit.
_RATE_LIMIT_MARKERS: tuple[str, ...] = ("rate-limit", "rate_limit", "ratelimit")


class Test41Params(BaseModel):
    """Parameters of test 4.1."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_burst: Annotated[int, Field(ge=2)] = Field(
        default=150,
        description=(
            "The largest burst the test sends before concluding there is no rate limit, when the "
            "gateway's configured limit cannot be read. The burst stops at the first 429."
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
            budget, limit = self._budget(target)
            plain = self._burst(client, path, budget, spoof=False)
            self._judge_limit(store, path, plain, budget, limit)
            self._judge_spoofing(client, store, path, budget, plain)
            return self._finish(message=f"Burst budget {budget} on {path}.")
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

    def _budget(self, target: TargetContext) -> tuple[int, int | None]:
        """The burst size (the configured limit plus a margin, or the cap) and the limit read."""
        cap = self.params(target).max_burst
        gateway = target.gateway
        limit = _configured_limit(gateway) if gateway is not None else None
        if limit is None:
            return cap, None
        return min(cap, limit + _BUDGET_MARGIN), limit

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
            spoof:  Send a random client address on every request (_spoofed_headers).

        Returns:
            The burst's result: how many requests, whether a 429 was seen (and
            its record), and whether the upstream was failing.
        """
        last: EvidenceRecord | None = None
        failing_in_a_row = 0
        served_before = False
        for sent in range(1, budget + 1):
            headers = _spoofed_headers() if spoof else None
            record = _send(client, path, headers)
            if record is None:
                continue
            last = record
            category = category_of(record)
            if category == ResponseCategory.RATE_LIMITED:
                return _BurstResult(
                    sent=sent, limited_record=record, last_record=last, upstream_failing=False
                )
            if category in _SPOILING:
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
                    limited_record=None,
                    last_record=last,
                    upstream_failing=True,
                    maybe_limit=served_before
                    and record.response_status_code == _SERVICE_UNAVAILABLE,
                )
        return _BurstResult(
            sent=budget, limited_record=None, last_record=last, upstream_failing=False
        )

    def _judge_limit(
        self,
        store: EvidenceStore,
        path: str,
        plain: _BurstResult,
        budget: int,
        limit: int | None,
    ) -> None:
        """Judge whether the plain burst met a rate limit (module docstring: the confidence)."""
        if plain.upstream_failing:
            detail = "LIMIT_OR_UNAVAILABLE" if plain.maybe_limit else "UPSTREAM_UNAVAILABLE"
            self._record(_SUB_LIMIT, Outcome.NOT_VERIFIABLE, detail)
            return
        if plain.limited_record is not None:
            self._judge(plain.limited_record, store, _SUB_LIMIT, Outcome.ENFORCED, "RATE_LIMITED")
            return
        if limit is not None and budget <= limit:
            # A configured limit the capped burst cannot reach: its silence says
            # nothing about whether the limit is enforced.
            self._record(_SUB_LIMIT, Outcome.NOT_VERIFIABLE, "LIMIT_ABOVE_BUDGET")
            return
        configured = limit is not None
        finding = Finding(
            title=f"No rate limit on {path}",
            detail=(
                f"{budget} requests to {path} in a burst all answered without a 429 Too Many "
                "Requests"
                + (
                    f", although the gateway states a limit of {limit}: the limit is configured "
                    "and not enforced."
                    if configured
                    else ". No limit applies at or below that rate; a higher limit would not be "
                    "seen by this burst (raise max_burst to look further)."
                )
                + " Without a rate limit a loop can exhaust the backend's resources or "
                "brute-force a credential (OWASP API4:2023, ASVS v5.0.0-2.4.1). Configure a "
                "rate-limiting plugin on the gateway."
            ),
            confidence=Confidence.CERTAIN if configured else Confidence.FIRM,
        )
        self._violation(store, _SUB_LIMIT, "NO_RATE_LIMIT", finding, plain.last_record)

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
            self._record(_SUB_SPOOF, Outcome.NOT_VERIFIABLE, "UPSTREAM_UNAVAILABLE")
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


# Categories that mean the endpoint is failing, not rate-limiting.
_SPOILING: frozenset[ResponseCategory] = frozenset(
    {
        ResponseCategory.UPSTREAM_UNAVAILABLE,
        ResponseCategory.SERVER_ERROR,
        ResponseCategory.NO_RESPONSE,
    }
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
    limited_record: EvidenceRecord | None
    last_record: EvidenceRecord | None
    upstream_failing: bool
    # The failing run is 503s after served answers: possibly a limit rejecting
    # with 503 (some gateways' default) rather than an unavailable backend.
    maybe_limit: bool = False


def _configured_limit(gateway: BaseGatewayAdapter) -> int | None:
    """The smallest positive integer value of a rate-limiting plugin, or None."""
    answer = gateway.config_values()
    if answer.status != ConceptStatus.READ:
        return None
    limits: list[int] = []
    for item in answer.items:
        if not item.enabled:
            continue
        location = item.location.lower()
        if not any(marker in location for marker in _RATE_LIMIT_MARKERS):
            continue
        value = item.value.get_secret_value().strip()
        if value.isdigit() and int(value) > 0:
            limits.append(int(value))
    return min(limits) if limits else None


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
