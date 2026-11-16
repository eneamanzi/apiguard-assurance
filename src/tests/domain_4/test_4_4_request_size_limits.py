"""
src/tests/domain_4/test_4_4_request_size_limits.py

Test 4.4: guarantee "the gateway limits the request body size" (new). OWASP API4:2023.

A gateway should reject an oversized request body with `413 Request Entity Too
Large` before it is routed or processed; without a limit, a large body ties up
memory and bandwidth and can exhaust the backend. The test sends a documented
write endpoint an oversized body, unauthenticated, and expects a 413: the
gateway rejects it by size before the backend's own authentication, so no
credential is needed and nothing is created.

    oversized_body_rejected  a body above the limit answers 413 -> ENFORCED;
                             anything else means the gateway forwarded it ->
                             VIOLATION/NO_SIZE_LIMIT.

A 401 or 403 does not say who refused: the application, after the gateway
forwarded the body, or the gateway itself, before its size check (Kong runs
key-auth before request-size-limiting). The same body is then sent once more
with user_a's credential, when the configuration provides it (owner decision
2026-11-04), and its answer is judged as above. When that is
refused too, a forged credential (a random value placed as the run's credential
is) tells who refused: the same status as the forged one means user_a's
credential did not get past the first refuser,
NOT_VERIFIABLE/REFUSED_BEFORE_SIZE_CHECK; a different one means it did, so the
body went past it without a 413 (Forgejo: forged 401, user_a 403 for a token
scope). Without a credential the first refusal is
NOT_VERIFIABLE/NO_CREDENTIAL_TO_RETRY. The body ({"data": "AAA..."})
holds no field a real write expects, so an application refuses it rather than
creating anything.

The size sent is a configured size (`body_size_bytes`), unless the gateway's
own limits can be read (`Need.GATEWAY`, optional: `body_size_limits()`, in
bytes) and every route that may serve the path has one: then the largest limit
that may apply to the probe (the limits on every request, on the backend and on
the route, src/tests/helpers/route_limits.py) plus a margin, so the body is
above whichever the gateway applies. A body above every such limit and not
refused is a limit configured and not enforced (CERTAIN); a body of the
configured size not refused says only that no limit applies at that size
(FIRM). BLACK_BOX, effect `STRESSES_TARGET`.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

from typing import Annotated

import structlog
from pydantic import BaseModel, ConfigDict, Field

from src.core.assessment_test import category_of
from src.core.auth_placement import RequestAuthParts
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError, SecurityClientError
from src.core.gateway.base import CONCEPT_BODY_SIZE_LIMITS, CONCEPT_ROUTES
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
from src.core.references import random_sibling_path, random_token
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.auth import acquire_tokens, auth_parts, credential_parts
from src.tests.helpers.route_limits import limits_for_request

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB: str = "oversized_body_rejected"

# HTTP status for an oversized body (RFC 9110: Content Too Large).
_PAYLOAD_TOO_LARGE: int = 413

# Write methods whose body a size limit applies to.
_WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH"})
# The method of the probe (_send_oversized).
_PROBE_METHOD: str = "POST"

# Added to a limit read from the gateway so the body crosses it.
_SIZE_MARGIN_BYTES: int = 1024

# Answers that do not say who refused (the application or the gateway before
# its size check): the probe is retried with a credential.
_REFUSED: frozenset[ResponseCategory] = frozenset(
    {ResponseCategory.UNAUTHENTICATED, ResponseCategory.FORBIDDEN}
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
        optional_needs=(Need.GATEWAY, Need.USER_ACCOUNT),
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
            context: The run's context (user_a's credential, for the retry).
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
                return self._skip("No documented write endpoint to probe for a size limit.")
            size, basis, certain = self._size(target, store, path)
            record = _send_oversized(client, path, size)
            if record is not None and category_of(record) in _REFUSED:
                self._step(record)
                user_a = self._user_a(target, context, client)
                if user_a is None:
                    self._judge(
                        record, store, _SUB, Outcome.NOT_VERIFIABLE, "NO_CREDENTIAL_TO_RETRY"
                    )
                    return self._finish()
                record = _send_oversized(client, path, size, user_a)
                if record is not None and category_of(record) in _REFUSED:
                    forged = _send_oversized(
                        client, path, size, credential_parts(target, random_token())
                    )
                    if forged is not None:
                        self._step(forged)
                    if forged is None or forged.response_status_code == record.response_status_code:
                        self._judge(
                            record,
                            store,
                            _SUB,
                            Outcome.NOT_VERIFIABLE,
                            "REFUSED_BEFORE_SIZE_CHECK",
                        )
                        return self._finish()
            self._judge_oversized(record, store, path, size, basis, certain)
            return self._finish()
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_4_4_unexpected_error", error=str(exc))
            return self._error(exc)

    def _user_a(
        self, target: TargetContext, context: TestContext, client: SecurityClient
    ) -> RequestAuthParts | None:
        """
        user_a's request parts, for the retry after a 401 or 403.

        Args:
            target:  The run's target (credentials, placement).
            context: The run's context (the role's credential).
            client:  The run's HTTP client (the login goes through it).

        Returns:
            The parts, or None when the role is not configured or its login did
            not work (logged).
        """
        if not target.credentials.has_user_a():
            return None
        try:
            acquire_tokens(target, context, client, required_roles=frozenset({ROLE_USER_A}))
            return auth_parts(target, context, ROLE_USER_A)
        except (AuthenticationSetupError, SecurityClientError) as exc:
            log.warning("test_4_4_no_credential", error=str(exc))
            return None

    def _probe_path(self, target: TargetContext) -> str | None:
        """
        The write path to probe: the configured one, or the shortest documented write.

        A write that requires authentication is preferred: the probe is sent
        unauthenticated, so the gateway's size check (a 413) comes first and the
        backend then refuses with 401, never creating anything. A public write is
        used only when no authenticated one exists, and then a body under the
        limit could be processed: the oversized body is still rejected by a size
        limit, but the absence of one on a public write is a creation risk noted
        on the page.
        """
        cfg = self.params(target)
        if cfg.probe_path:
            return cfg.probe_path
        surface = target.attack_surface
        if surface is None:
            return None
        writes = [e for e in surface.endpoints if e.method.upper() in _WRITE_METHODS]
        if not writes:
            return None
        shortest = min(writes, key=lambda e: (not e.requires_auth, len(e.path), e.path, e.method))
        # Parameters get a random sibling, never the operator's resource from the
        # seed: the gateway applies its size limit to the route before anything
        # looks the object up, so a path that exists adds nothing and risks the
        # oversized body reaching a real object.
        if "{" in shortest.path:
            return random_sibling_path(shortest.path, shortest.parameters)
        return shortest.path

    def _size(
        self, target: TargetContext, store: EvidenceStore, path: str
    ) -> tuple[int, str, bool]:
        """
        The body size to send, what it rests on, and whether it is above a limit read.

        The concepts read are kept as evidence. The size is above every limit
        that may apply when each route that may serve the path has one with a
        size; otherwise it is `body_size_bytes`.

        Args:
            target: The run's target (gateway, base URL, parameters).
            store:  The test's evidence store.
            path:   The path to probe.

        Returns:
            The size in bytes, the basis a finding states, and True when the
            size is above every limit read for the routes that may serve the path.
        """
        default = self.params(target).body_size_bytes
        gateway = target.gateway
        if gateway is None:
            return default, f"{default} bytes (no gateway configured to read a limit from)", False
        limits = gateway.body_size_limits()
        self._record_gateway_concept(target, store, CONCEPT_BODY_SIZE_LIMITS, limits)
        self._record_gateway_concept(target, store, CONCEPT_ROUTES, gateway.routes())
        routes = limits_for_request(
            gateway, limits, target.endpoint_base_url(), path, _PROBE_METHOD
        )
        if routes is None:
            return default, f"{default} bytes (no configured limit was readable)", False
        unlimited = [entry.route.name for entry in routes if not entry.limits]
        if unlimited:
            return (
                default,
                (
                    f"{default} bytes; the gateway states no body-size limit for route "
                    f"{unlimited[0]}, which may serve this path"
                ),
                False,
            )
        stated = {limit.source: limit for entry in routes for limit in entry.limits}
        sizes = [limit.max_bytes for limit in stated.values() if limit.max_bytes is not None]
        if len(sizes) < len(stated):
            return (
                default,
                f"{default} bytes; a limit the gateway states applies to part of the traffic only",
                False,
            )
        described = "; ".join(
            f"{limit.source} ({limit.max_bytes} bytes)" for limit in stated.values()
        )
        return (
            max(sizes) + _SIZE_MARGIN_BYTES,
            (
                "above every body-size limit the gateway states for the routes that may serve "
                f"it: {described}"
            ),
            True,
        )

    def _judge_oversized(
        self,
        record: EvidenceRecord | None,
        store: EvidenceStore,
        path: str,
        size: int,
        basis: str,
        certain: bool,
    ) -> None:
        """Judge the answer to the oversized body (`_size`: the basis and the confidence)."""
        if record is None:
            self._record(_SUB, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return
        status = record.response_status_code
        if status == _PAYLOAD_TOO_LARGE:
            self._judge(record, store, _SUB, Outcome.ENFORCED, "SIZE_LIMIT_ENFORCED")
            return
        # An answer that says nothing about the size limit: a 429 among them,
        # the body refused for the rate before anything weighed it (until
        # 2026-11-16 it was read as a forwarded body, a false NO_SIZE_LIMIT).
        uninformative = self._uninformative(record, _SUB)
        if uninformative is not None:
            self._judge(record, store, _SUB, Outcome.NOT_VERIFIABLE, uninformative)
            return
        # The gateway forwarded the oversized body (it answered something other
        # than 413): there is no size limit at this size.
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
                    f"gateway forwarded it ({basis})"
                    + (": the limit is configured and not enforced. " if certain else ". ")
                    + "Without a body-size limit a large body ties up memory and bandwidth and can "
                    "exhaust the backend (OWASP API4:2023). Configure a request-size limit on the "
                    "gateway."
                ),
                confidence=Confidence.CERTAIN if certain else Confidence.FIRM,
            ),
        )


def _send_oversized(
    client: SecurityClient, path: str, size: int, credential: RequestAuthParts | None = None
) -> EvidenceRecord | None:
    """Send a write with an oversized JSON body, with a credential if given; its record or None."""
    body = {"data": "A" * size}
    parts = credential or RequestAuthParts()
    try:
        _response, record = client.request(
            "POST",
            path,
            test_id="4.4",
            headers=dict(parts.headers) or None,
            params=dict(parts.params) or None,
            json=body,
        )
    except SecurityClientError as exc:
        return exc.record
    return record
