"""
src/tests/domain_4/test_4_4_request_size_limits.py

Test 4.4: guarantee "the gateway limits the request body size" (new). OWASP API4:2023.

The test sends a documented write, with its documented method, an oversized
body and expects `413` (its oracle: info.oracle, generated on its page). The body
({"data": "AAA..."}) holds no field a real write expects, so nothing is created.

A `401` or `403` does not say who refused: the application after the gateway
forwarded the body, or the gateway before its size check (Kong runs key-auth
before request-size-limiting). The body is then sent with user_a's credential,
and if refused again with a forged one: the same status means user_a's did not
get past the first refuser.

The same body is then sent in chunks (Transfer-Encoding: chunked, no
Content-Length): a gateway that weighs only the declared length lets it through.

The size is `body_size_bytes`, unless the gateway's limits can be read
(body_size_limits(), src/tests/helpers/route_limits.py) for every route that may
serve the probe: then the largest of them plus a margin, so the body is above
whichever the gateway applies. BLACK_BOX, effect `STRESSES_TARGET`.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import json
from typing import Annotated, NamedTuple

import structlog
from pydantic import BaseModel, ConfigDict, Field

from src.core.assessment_test import category_of
from src.core.auth_placement import RequestAuthParts
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
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
from src.core.test_metadata import Effect, Need, OracleCase, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.auth import credential_parts, optional_role_parts
from src.tests.helpers.route_limits import limits_for_request

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB: str = "oversized_body_rejected"
# The same body sent in chunks, without a Content-Length: a gateway that weighs
# only the declared length lets it through.
_SUB_CHUNKED: str = "chunked_body_rejected"
# The size of each chunk of the chunked body.
_CHUNK_BYTES: int = 65536
_JSON_CONTENT_TYPE: str = "application/json"

# HTTP status for an oversized body (RFC 9110: Content Too Large).
_PAYLOAD_TOO_LARGE: int = 413

# Write methods whose body a size limit applies to.
_WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH"})
# The method of a probe path given in the configuration (probe_path).
_CONFIGURED_METHOD: str = "POST"

# Added to a limit read from the gateway so the body crosses it.
_SIZE_MARGIN_BYTES: int = 1024

# Answers that do not say who refused (the application or the gateway before
# its size check): the probe is retried with a credential.
_REFUSED: frozenset[ResponseCategory] = frozenset(
    {ResponseCategory.UNAUTHENTICATED, ResponseCategory.FORBIDDEN}
)


class _Probe(NamedTuple):
    """What is sent: the write, the size of its body, and whether in chunks."""

    method: str
    path: str
    size: int
    chunked: bool

    @property
    def label(self) -> str:
        """The probe as a finding names it: "POST /path", "(chunked)" when it is."""
        return f"{self.method} {self.path}" + (" (chunked)" if self.chunked else "")


def _cases(sub_test: str, body: str) -> tuple[OracleCase, ...]:
    """The oracle of one sub-test: the same cases for the body sent whole or in chunks."""
    return (
        OracleCase(
            sub_test=sub_test,
            when=f"{body} answers `413`",
            outcome=Outcome.ENFORCED,
            detail="SIZE_LIMIT_ENFORCED",
        ),
        OracleCase(
            sub_test=sub_test,
            when=f"{body}, above every limit read for the routes that may serve the path, is not "
            "rejected: the limit is configured and not enforced",
            outcome=Outcome.VIOLATION,
            detail="NO_SIZE_LIMIT",
            confidence=Confidence.CERTAIN,
        ),
        OracleCase(
            sub_test=sub_test,
            when=f"no limit read for every route that may serve the path, and {body} of "
            "`body_size_bytes` is not rejected (a larger limit may exist)",
            outcome=Outcome.VIOLATION,
            detail="NO_SIZE_LIMIT",
            confidence=Confidence.FIRM,
        ),
        OracleCase(
            sub_test=sub_test,
            when=f"{body} is refused (`401`, `403`) without a credential, and no user_a account "
            "to retry",
            outcome=Outcome.NOT_VERIFIABLE,
            detail="NO_CREDENTIAL_TO_RETRY",
        ),
        OracleCase(
            sub_test=sub_test,
            when=f"{body} is refused with user_a's credential too, with the status a forged "
            "credential gets: the credential did not get past the first refuser",
            outcome=Outcome.NOT_VERIFIABLE,
            detail="REFUSED_BEFORE_SIZE_CHECK",
        ),
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
            "The documented write path to probe, sent as a POST; empty derives the shortest "
            "documented write, sent with its documented method."
        ),
    )


class Test44RequestSizeLimits(BaseTest[Test44Params]):
    """
    Test 4.4 -- whether the gateway rejects an oversized request body.
    """

    info = TestInfo(
        id="4.4",
        name="Request Size Limits",
        priority=1,
        strategy=TestStrategy.BLACK_BOX,
        cwe="CWE-400",
        references=(
            # API4:2023, How To Prevent: "Define and enforce a maximum size of data
            # on all incoming parameters and payloads". ASVS v5.0.0-2.4.1 was cited
            # until 2026-11-16: it is about excessive calls (test 4.1), and ASVS
            # 5.0.0 has no requirement on the size of a request body.
            Reference(standard=Standard.OWASP_API_TOP10, id="API4:2023"),
            Reference(standard=Standard.RFC, id="9110", section="15.5.14"),
        ),
        tags=("resource-consumption", "size-limit"),
        optional_needs=(Need.GATEWAY, Need.USER_ACCOUNT),
        effect=Effect.STRESSES_TARGET,
        sub_tests=(_SUB, _SUB_CHUNKED),
        oracle=(*_cases(_SUB, "the body"), *_cases(_SUB_CHUNKED, "the chunked body")),
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
            probe = self._probe(target)
            if probe is None:
                return self._skip("No documented write endpoint to probe for a size limit.")
            method, path = probe
            size, basis, certain = self._size(target, store, method, path)
            for sub_test, chunked in ((_SUB, False), (_SUB_CHUNKED, True)):
                sent = _Probe(method, path, size, chunked)
                self._probe_body(target, context, client, store, sub_test, sent, basis, certain)
            return self._finish()
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_4_4_unexpected_error", error=str(exc))
            return self._error(exc)

    def _probe_body(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
        sub_test: str,
        probe: _Probe,
        basis: str,
        certain: bool,
    ) -> None:
        """
        Send the oversized body, retry after a refusal with user_a's credential, judge it.

        Args:
            target:   The run's target (credential placement).
            context:  The run's context (user_a's credential).
            client:   The run's HTTP client.
            store:    The test's evidence store.
            sub_test: The sub-test judged.
            probe:    What is sent (method, path, size, chunked or not).
            basis:    What the size rests on, for a finding (_size).
            certain:  Whether the size is above every limit read (_size).
        """
        record = _send_oversized(client, probe)
        if record is not None and category_of(record) in _REFUSED:
            self._step(record)
            user_a = optional_role_parts(target, context, ROLE_USER_A)
            if user_a is None:
                self._judge(
                    record, store, sub_test, Outcome.NOT_VERIFIABLE, "NO_CREDENTIAL_TO_RETRY"
                )
                return
            record = _send_oversized(client, probe, user_a)
            if record is not None and category_of(record) in _REFUSED:
                forged = _send_oversized(client, probe, credential_parts(target, random_token()))
                if forged is not None:
                    self._step(forged)
                if forged is None or forged.response_status_code == record.response_status_code:
                    self._judge(
                        record, store, sub_test, Outcome.NOT_VERIFIABLE, "REFUSED_BEFORE_SIZE_CHECK"
                    )
                    return
        self._judge_oversized(record, store, sub_test, probe, basis, certain)

    def _probe(self, target: TargetContext) -> tuple[str, str] | None:
        """
        The write to probe, method and path: the configured path, or the shortest documented write.

        The documented method is sent (until 2026-11-16 always POST: on an
        operation documented only as PUT a gateway may refuse a POST before its
        size check, Kong's "no Route matched", read as a forwarded body).

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
            return _CONFIGURED_METHOD, cfg.probe_path
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
        method = shortest.method.upper()
        if "{" in shortest.path:
            return method, random_sibling_path(shortest.path, shortest.parameters)
        return method, shortest.path

    def _size(
        self, target: TargetContext, store: EvidenceStore, method: str, path: str
    ) -> tuple[int, str, bool]:
        """
        The body size to send, what it rests on, and whether it is above a limit read.

        The concepts read are kept as evidence. The size is above every limit
        that may apply when each route that may serve the path has one with a
        size; otherwise it is `body_size_bytes`.

        Args:
            target: The run's target (gateway, base URL, parameters).
            store:  The test's evidence store.
            method: The method of the probe.
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
        routes = limits_for_request(gateway, limits, target.endpoint_base_url(), path, method)
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
        sub_test: str,
        probe: _Probe,
        basis: str,
        certain: bool,
    ) -> None:
        """Judge the answer to the oversized body (`_size`: the basis and the confidence)."""
        if record is None:
            self._record(sub_test, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return
        status = record.response_status_code
        if status == _PAYLOAD_TOO_LARGE:
            self._judge(record, store, sub_test, Outcome.ENFORCED, "SIZE_LIMIT_ENFORCED")
            return
        # An answer that says nothing about the size limit: a 429 among them,
        # the body refused for the rate before anything weighed it (until
        # 2026-11-16 it was read as a forwarded body, a false NO_SIZE_LIMIT).
        uninformative = self._uninformative(record, _SUB)
        if uninformative is not None:
            self._judge(record, store, sub_test, Outcome.NOT_VERIFIABLE, uninformative)
            return
        # The gateway forwarded the oversized body (it answered something other
        # than 413): there is no size limit at this size.
        self._judge(
            record,
            store,
            sub_test,
            Outcome.VIOLATION,
            "NO_SIZE_LIMIT",
            Finding(
                title=f"Oversized body not rejected: {probe.label}",
                detail=(
                    f"A body of {probe.size} bytes sent to {probe.label} answered HTTP {status}, "
                    f"not 413: the gateway forwarded it ({basis})"
                    + (": the limit is configured and not enforced. " if certain else ". ")
                    + "Without a body-size limit a large body ties up memory and bandwidth and can "
                    "exhaust the backend (OWASP API4:2023). Configure a request-size limit on the "
                    "gateway."
                ),
                confidence=Confidence.CERTAIN if certain else Confidence.FIRM,
            ),
        )


def _send_oversized(
    client: SecurityClient, probe: _Probe, credential: RequestAuthParts | None = None
) -> EvidenceRecord | None:
    """
    Send the write with an oversized JSON body, whole or in chunks; its record or None.

    A chunked body goes as a tuple of chunks (SecurityClient sends it with
    Transfer-Encoding: chunked and no Content-Length).
    """
    body = json.dumps({"data": "A" * probe.size}).encode()
    parts = credential or RequestAuthParts()
    headers = {**dict(parts.headers), "Content-Type": _JSON_CONTENT_TYPE}
    content: bytes | tuple[bytes, ...] = body
    if probe.chunked:
        content = tuple(
            body[start : start + _CHUNK_BYTES] for start in range(0, len(body), _CHUNK_BYTES)
        )
    try:
        _response, record = client.request(
            probe.method,
            probe.path,
            test_id="4.4",
            headers=headers,
            params=dict(parts.params) or None,
            content=content,
        )
    except SecurityClientError as exc:
        return exc.record
    return record
