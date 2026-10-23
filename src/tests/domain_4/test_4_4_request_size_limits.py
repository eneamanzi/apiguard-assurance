"""
src/tests/domain_4/test_4_4_request_size_limits.py

Test 4.4: guarantee "the gateway limits the request body size" (new,
docs/project/test-review/group-g.md). OWASP API4:2023.

A gateway should reject an oversized request body with `413 Request Entity Too
Large` before it is routed or processed; without a limit, a large body ties up
memory and bandwidth and can exhaust the backend. The test sends a documented
write endpoint an oversized body, unauthenticated, and expects a 413: the
gateway rejects it by size before the backend's own authentication, so no
credential is needed and nothing is created.

    oversized_body_rejected  a body above the limit answers 413 -> ENFORCED;
                             anything else means the gateway forwarded it ->
                             VIOLATION/NO_SIZE_LIMIT.

The size sent is the gateway's configured body-size limit plus a margin, read
through the adapter when available (`Need.GATEWAY`, optional), else a configured
size. BLACK_BOX, effect `STRESSES_TARGET`.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

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

_SUB: str = "oversized_body_rejected"

# HTTP status for an oversized body (RFC 9110: Content Too Large).
_PAYLOAD_TOO_LARGE: int = 413

# Write methods whose body a size limit applies to.
_WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH"})

# Added to a limit read from the gateway so the body crosses it.
_SIZE_MARGIN_BYTES: int = 1024

# A config value is a body-size limit when its location names such a plugin.
_SIZE_LIMIT_MARKERS: tuple[str, ...] = (
    "request-size",
    "request_size",
    "body-size",
    "body_size",
    "size-limit",
    "size_limit",
)

# Categories that say the endpoint is failing, not enforcing a size limit.
_SPOILING: frozenset[ResponseCategory] = frozenset(
    {
        ResponseCategory.UPSTREAM_UNAVAILABLE,
        ResponseCategory.SERVER_ERROR,
        ResponseCategory.NO_RESPONSE,
    }
)


class Test44Params(BaseModel):
    """Parameters of test 4.4."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    body_size_bytes: Annotated[int, Field(ge=1024)] = Field(
        default=2_000_000,
        description=(
            "The size of the body sent when the gateway's configured limit cannot be read. A "
            "body above a sane API limit (default 2 MB); a gateway that accepts it has no small "
            "body-size limit."
        ),
    )
    probe_path: str = Field(
        default="",
        description=(
            "The documented write path to probe; empty derives the shortest documented write."
        ),
    )


class Test44RequestSizeLimits(BaseTest[Test44Params]):
    """
    Test 4.4 -- whether the gateway rejects an oversized request body.

    The oracle is in the module docstring and on the test page.
    """

    info = TestInfo(
        id="4.4",
        name="Request Size Limits",
        priority=1,
        strategy=TestStrategy.BLACK_BOX,
        cwe="CWE-400",
        references=(
            Reference(standard=Standard.OWASP_API_TOP10, id="API4:2023"),
            Reference(standard=Standard.ASVS, id="v5.0.0-2.4.1"),
            Reference(standard=Standard.RFC, id="9110", section="15.5.14"),
        ),
        tags=("resource-consumption", "size-limit"),
        optional_needs=(Need.GATEWAY,),
        effect=Effect.STRESSES_TARGET,
        sub_tests=(_SUB,),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Send a documented write endpoint an oversized body and judge the answer.

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
                return self._skip("No documented write endpoint to probe for a size limit.")
            size, from_gateway = self._size(target)
            record = _send_oversized(client, path, size)
            self._judge_oversized(record, store, path, size, from_gateway)
            return self._finish()
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_4_4_unexpected_error", error=str(exc))
            return self._error(exc)

    def _probe_path(self, target: TargetContext) -> str | None:
        """The write path to probe: the configured one, or the shortest documented write."""
        cfg = self.params(target)
        if cfg.probe_path:
            return cfg.probe_path
        surface = target.attack_surface
        if surface is None:
            return None
        writes = [e for e in surface.endpoints if e.method.upper() in _WRITE_METHODS]
        if not writes:
            return None
        shortest = min(writes, key=lambda e: (len(e.path), e.path, e.method))
        return resolve_path_with_seed(shortest.path, target.path_seed)

    def _size(self, target: TargetContext) -> tuple[int, bool]:
        """The body size to send, and whether it came from the gateway's config."""
        gateway = target.gateway
        if gateway is not None:
            limit = _configured_limit(gateway)
            if limit is not None:
                return limit + _SIZE_MARGIN_BYTES, True
        return self.params(target).body_size_bytes, False

    def _judge_oversized(
        self,
        record: EvidenceRecord | None,
        store: EvidenceStore,
        path: str,
        size: int,
        from_gateway: bool,
    ) -> None:
        """Judge the answer to the oversized body."""
        if record is None:
            self._record(_SUB, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return
        status = record.response_status_code
        if status == _PAYLOAD_TOO_LARGE:
            self._judge(record, store, _SUB, Outcome.ENFORCED, "SIZE_LIMIT_ENFORCED")
            return
        if category_of(record) in _SPOILING:
            self._judge(record, store, _SUB, Outcome.NOT_VERIFIABLE, "UPSTREAM_UNAVAILABLE")
            return
        # The gateway forwarded the oversized body (it answered something other
        # than 413): there is no size limit at this size.
        confidence = Confidence.CERTAIN if from_gateway else Confidence.FIRM
        basis = (
            "the gateway's own configured limit plus a margin"
            if from_gateway
            else f"{size} bytes (no configured limit was readable)"
        )
        self._judge(
            record,
            store,
            _SUB,
            Outcome.VIOLATION,
            "NO_SIZE_LIMIT",
            Finding(
                title=f"Oversized body not rejected: {path}",
                detail=(
                    f"A body of {size} bytes sent to {path} answered HTTP {status}, not 413: the "
                    f"gateway forwarded it ({basis}). Without a body-size limit a large body ties "
                    "up memory and bandwidth and can exhaust the backend (OWASP API4:2023). "
                    "Configure a request-size limit on the gateway."
                ),
                confidence=confidence,
            ),
        )


def _configured_limit(gateway: BaseGatewayAdapter) -> int | None:
    """The smallest positive integer value of a body-size-limit plugin, or None."""
    answer = gateway.config_values()
    if answer.status != ConceptStatus.READ:
        return None
    limits: list[int] = []
    for item in answer.items:
        location = item.location.lower()
        if not any(marker in location for marker in _SIZE_LIMIT_MARKERS):
            continue
        value = item.value.get_secret_value().strip()
        if value.isdigit() and int(value) > 0:
            limits.append(int(value))
    return min(limits) if limits else None


def _send_oversized(client: SecurityClient, path: str, size: int) -> EvidenceRecord | None:
    """Send an unauthenticated write with an oversized JSON body; its record or None."""
    body = {"data": "A" * size}
    try:
        _response, record = client.request("POST", path, test_id="4.4", json=body)
    except SecurityClientError as exc:
        return exc.record
    return record
