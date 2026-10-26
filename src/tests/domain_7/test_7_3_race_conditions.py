"""
src/tests/domain_7/test_7_3_race_conditions.py

Test 7.3: guarantee "a once-only operation is safe under concurrency" (CWE-362,
TOCTOU race conditions).

An operation that must take effect at most once (redeem a single-use coupon,
submit one order, apply a referral, withdraw a balance) must serialize
concurrent attempts: a check-then-act that is not atomic lets several
simultaneous requests all pass the check and all act (a TOCTOU race), so the
one-only effect happens several times. The test fires N identical requests at
the configured operation at the same instant (native threads) and counts how
many succeeded.

    concurrent_requests_safe  at most `max_successful` of the N concurrent
                              requests succeed (2xx) -> ENFORCED; more than that
                              -> VIOLATION / RACE_DOUBLE_EFFECT; none succeed ->
                              NOT_VERIFIABLE / OPERATION_FAILED (the operation
                              did not run, so concurrency says nothing).

Configure `race_operation` only for an operation whose success must be bounded
(by default: once). A plain create that legitimately makes N objects from N
requests is not a race and must not be configured here.

GREY_BOX (the operation usually needs a credential), effect STRESSES_TARGET (a
concurrent burst; runs after the other tests, rule 7) and it changes data on the
target (announce it on a shared target).

Dependency rule: imports from stdlib, structlog, pydantic and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Annotated

import structlog
from pydantic import BaseModel, ConfigDict, Field

from src.core.assessment_test import NEEDED_TO_RUN, REFERS_TO_RESOURCE
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError, SecurityClientError
from src.core.models import (
    Confidence,
    EvidenceRecord,
    Finding,
    Outcome,
    Reference,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.templating import render
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.auth import acquire_tokens, auth_parts
from src.tests.helpers.resources import create_resource

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB: str = "concurrent_requests_safe"

# A successful effect of the operation: a 2xx.
_SUCCESS_STATUS: frozenset[int] = frozenset({200, 201, 202, 204})

_RACE: str = "RACE_DOUBLE_EFFECT"
_OPERATION_FAILED: str = "OPERATION_FAILED"


class Test73RaceOperation(BaseModel):
    """A once-only operation to fire concurrently (config, no default)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(
        min_length=1,
        description="Path of the once-only operation. May hold a resource's values as {name}.",
    )
    method: str = Field(default="POST", description="HTTP method of the operation (default POST).")
    body: dict[str, object] | None = Field(
        default=None, description="JSON body sent on every concurrent request (optional)."
    )
    role: str = Field(
        default="user_a",
        min_length=1,
        description="Role whose credential performs the operation (default user_a).",
    )
    resource: str | None = Field(
        default=None,
        min_length=1,
        json_schema_extra=REFERS_TO_RESOURCE,
        description=(
            "Optional prepared resource (resources: in config.yaml) created once before the "
            "burst; its values fill the path, and it is removed at teardown."
        ),
    )


class Test73Params(BaseModel):
    """Parameters of test 7.3."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    race_operation: Test73RaceOperation | None = Field(
        default=None,
        json_schema_extra=NEEDED_TO_RUN,
        examples=[
            {
                "path": "/workshop/api/shop/apply_coupon",
                "method": "POST",
                "body": {"coupon_code": "TRAC075"},
                "role": "user_a",
                "resource": "cart",
            }
        ],
        description=(
            "The once-only operation to probe for a race condition. No default: unset, the "
            "engine records the test as SKIP before it runs."
        ),
    )
    concurrency: Annotated[int, Field(ge=2, le=50)] = Field(
        default=15,
        description="How many identical requests are fired at the same instant.",
    )
    max_successful: Annotated[int, Field(ge=1)] = Field(
        default=1,
        description=(
            "The largest number of concurrent requests that may succeed without a race. 1 for a "
            "strictly once-only operation (the default); raise it for a bounded quota."
        ),
    )


class Test73RaceConditions(BaseTest[Test73Params]):
    """
    Test 7.3 -- whether a once-only operation serializes concurrent attempts.

    The oracle is in the module docstring and on the test page.
    """

    info = TestInfo(
        id="7.3",
        name="Race Conditions in Critical Operations",
        priority=1,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-362",
        references=(
            # Verified on the ASVS v5.0.0 source 2026-10-23: 15.4.2 (Safe
            # Concurrency) -- a check and the action depending on it must be a
            # single atomic operation to prevent TOCTOU race conditions.
            Reference(standard=Standard.ASVS, id="v5.0.0-15.4.2"),
        ),
        tags=("business-logic", "concurrency"),
        needs=(Need.USER_ACCOUNT,),
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
        Fire N concurrent identical requests and judge how many took effect.

        Args:
            target:  The run's target (surface, resources, path seed).
            context: Carries the acquired tokens.
            client:  The run's HTTP client (httpx is thread-safe for requests).
            store:   The test's evidence store.

        Returns:
            self._finish(), self._skip(...), or self._error(exc).
        """
        try:
            cfg = self.params(target)
            op = cfg.race_operation
            if op is None:  # NEEDED_TO_RUN; the engine normally SKIPs first.
                return self._skip("No race_operation configured for test 7.3.")
            try:
                acquire_tokens(target, context, client, required_roles=frozenset({op.role}))
            except (AuthenticationSetupError, SecurityClientError) as exc:
                return self._error(exc)
            parts = auth_parts(target, context, op.role)
            values = self._resource_values(target, context, client, op)
            path = str(render(op.path, values))
            records = self._fire(
                client, op, path, dict(parts.headers), dict(parts.params), cfg.concurrency
            )
            self._judge_race(store, op, path, records, cfg.concurrency, cfg.max_successful)
            return self._finish(message=f"{cfg.concurrency} concurrent {op.method} {path}.")
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_7_3_unexpected_error", error=str(exc))
            return self._error(exc)

    def _resource_values(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        op: Test73RaceOperation,
    ) -> dict[str, str]:
        """Create the operation's prepared resource (if any) and return its values."""
        if op.resource is None:
            return {}
        prepared = create_resource(target, context, client, op.resource, op.role, self.info.id)
        return dict(prepared.values)

    def _fire(
        self,
        client: SecurityClient,
        op: Test73RaceOperation,
        path: str,
        headers: dict[str, str],
        params: dict[str, str],
        concurrency: int,
    ) -> list[EvidenceRecord]:
        """
        Send `concurrency` identical requests at once and collect their records.

        The requests run in threads so they reach the server together; the
        records are judged afterwards on the main thread (the evidence store and
        the tally are not touched from the workers).
        """

        def one() -> EvidenceRecord | None:
            try:
                _response, record = client.request(
                    op.method.upper(),
                    path,
                    test_id=self.info.id,
                    headers=headers or None,
                    params=params or None,
                    json=op.body,
                )
            except SecurityClientError as exc:
                return exc.record
            return record

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            results = list(pool.map(lambda _: one(), range(concurrency)))
        return [record for record in results if record is not None]

    def _judge_race(
        self,
        store: EvidenceStore,
        op: Test73RaceOperation,
        path: str,
        records: list[EvidenceRecord],
        concurrency: int,
        max_successful: int,
    ) -> None:
        """Judge the burst: count successes against the allowed maximum."""
        successes = [r for r in records if r.response_status_code in _SUCCESS_STATUS]
        self._log_others(records, successes)
        if not successes:
            self._record(_SUB, Outcome.NOT_VERIFIABLE, _OPERATION_FAILED)
            return
        if len(successes) <= max_successful:
            self._judge(successes[0], store, _SUB, Outcome.ENFORCED, "CONCURRENCY_SERIALIZED")
            return
        finding = Finding(
            title=f"Race condition: {op.method} {path} took effect {len(successes)} times",
            detail=(
                f"{concurrency} identical requests to {op.method} {path} were fired at the same "
                f"instant; {len(successes)} succeeded, above the allowed maximum of "
                f"{max_successful}. A once-only operation that is not serialized lets concurrent "
                "requests all pass the check and all act (a TOCTOU race, CWE-362, ASVS "
                "v5.0.0-15.4.2), so the effect (a coupon, an order, a withdrawal) happens several "
                "times. Make the check-then-act atomic (a database transaction, a unique "
                "constraint, or a lock)."
            ),
            confidence=Confidence.CERTAIN,
        )
        self._judge(successes[0], store, _SUB, Outcome.VIOLATION, _RACE, finding)
        log.info("test_7_3_race_detected", path=path, successes=len(successes), fired=concurrency)

    def _log_others(self, records: list[EvidenceRecord], successes: list[EvidenceRecord]) -> None:
        """Log the non-successful concurrent requests as preparation steps (not judged)."""
        success_ids = {id(r) for r in successes}
        for record in records:
            if id(record) not in success_ids:
                self._step(record)
