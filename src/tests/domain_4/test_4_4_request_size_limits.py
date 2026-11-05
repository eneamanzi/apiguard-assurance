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
from src.core.auth_placement import RequestAuthParts
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError, SecurityClientError
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
from src.core.references import random_sibling_path, random_token
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.auth import acquire_tokens, auth_parts, credential_parts

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

# Answers that do not say who refused (the application or the gateway before
# its size check): the probe is retried with a credential.
_REFUSED: frozenset[ResponseCategory] = frozenset(
    {ResponseCategory.UNAUTHENTICATED, ResponseCategory.FORBIDDEN}
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
            size, from_gateway = self._size(target)
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
            self._judge_oversized(record, store, path, size, from_gateway)
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
        if not item.enabled:
            continue
        location = item.location.lower()
        if not any(marker in location for marker in _SIZE_LIMIT_MARKERS):
            continue
        value = item.value.get_secret_value().strip()
        if value.isdigit() and int(value) > 0:
            limits.append(int(value))
    return min(limits) if limits else None


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
