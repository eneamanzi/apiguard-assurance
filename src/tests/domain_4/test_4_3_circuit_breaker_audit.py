"""
src/tests/domain_4/test_4_3_circuit_breaker_audit.py

Test 4.3: guarantee "the system degrades gracefully with a circuit breaker"
. OWASP API4:2023.

A circuit breaker stops a failing downstream from cascading: it opens after N
failures and answers at once instead of waiting for a timeout on every request.
Not every gateway has a dedicated breaker; a passive health check (a backend is
taken out of rotation after repeated failures) is the equivalent control, and
is accepted as a compensating one.

A health check counts only when it can *detect* a failing backend: passive
thresholds above zero, or an active probe on healthy targets (an interval above
zero).  Both gateways answer with their defaults filled in, so a backend with no
health check at all still comes back with a full `active` record whose intervals
are zero: reading "the record exists" as "a check is configured" would turn
every such backend into a pass.  Re-enabling an excluded backend is a separate
property (`HealthCheck.recovers_automatically`, an active probe on unhealthy
targets): it is not required for the control to exist, and the note says when it
is missing.

The test reads two gateway concepts through the adapter and judges the single
sub-test `degradation_configured`:

    a circuit breaker is enabled                  ENFORCED/CIRCUIT_BREAKER
    else a health check that detects failures     ENFORCED/HEALTH_CHECK (a note:
                                                    a compensating control, and
                                                    whether it recovers)
    neither, and both concepts were answered      VIOLATION/NO_CIRCUIT_BREAKER
    neither, but one concept was not accessible   NOT_VERIFIABLE/GATEWAY_READ_FAILED
    neither concept readable                      SKIP

The NOT_VERIFIABLE case is the honest answer to a half-read admin plane: with
the breakers unread, "the gateway has no breaker" is not a fact.  A concept the
gateway does not have at all (NOT_SUPPORTED) is different: there the absence is
a fact and the violation stands.

WHITE_BOX (the gateway Admin API), READ_ONLY. Rebuilt on the new base from the
test on `main`, keeping the passive-health-check-as-breaker reasoning.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base.
"""

from __future__ import annotations

from typing import Any

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.gateway.base import CONCEPT_CIRCUIT_BREAKERS, CONCEPT_HEALTH_CHECKS
from src.core.gateway.concepts import (
    CircuitBreaker,
    ConceptRead,
    ConceptStatus,
    HealthCheck,
)
from src.core.models import (
    Confidence,
    Finding,
    InfoNote,
    Outcome,
    Reference,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB: str = "degradation_configured"

_DETAIL_BREAKER: str = "CIRCUIT_BREAKER"
_DETAIL_HEALTH_CHECK: str = "HEALTH_CHECK"
_DETAIL_NONE: str = "NO_CIRCUIT_BREAKER"
_DETAIL_NOT_READ: str = "GATEWAY_READ_FAILED"

_REFERENCES: tuple[Reference, ...] = (
    # Read on the ASVS v5.0.0 source 2026-10-23: 16.5.2 (an automated recovery
    # mechanism for an overloaded or failing component).
    Reference(standard=Standard.OWASP_API_TOP10, id="API4:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-16.5.2"),
    Reference(standard=Standard.NIST_SP, id="800-204", section="4.5.1"),
)


class Test43CircuitBreakerAudit(BaseTest):
    """
    Test 4.3 -- whether the gateway degrades gracefully (a breaker or a passive
    health check).

    The oracle is in the module docstring and on the test page.
    """

    info = TestInfo(
        id="4.3",
        name="Circuit Breaker Audit",
        priority=1,
        strategy=TestStrategy.WHITE_BOX,
        cwe="CWE-400",
        references=_REFERENCES,
        tags=("resource-consumption", "circuit-breaker", "resilience"),
        needs=(Need.GATEWAY,),
        effect=Effect.READ_ONLY,
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
        Read the circuit breakers and health checks and judge graceful degradation.

        Args:
            target:  The run's target (gateway adapter).
            context: Unused.
            client:  Unused (the audit reads the gateway, sends no request).
            store:   The test's evidence store.

        Returns:
            self._finish(), self._skip(...), or self._error(exc).
        """
        del context, client
        try:
            gateway = target.gateway
            assert gateway is not None  # noqa: S101 -- Need.GATEWAY, checked by the engine
            breakers = gateway.circuit_breakers()
            ref_cb = self._record_gateway_concept(target, store, CONCEPT_CIRCUIT_BREAKERS, breakers)
            checks = gateway.health_checks()
            ref_hc = self._record_gateway_concept(target, store, CONCEPT_HEALTH_CHECKS, checks)

            enabled = (
                [b for b in breakers.items if b.enabled]
                if breakers.status == ConceptStatus.READ
                else []
            )
            if enabled:
                self._record(_SUB, Outcome.ENFORCED, _DETAIL_BREAKER)
                return self._finish(notes=[_breaker_note(enabled, ref_cb)])

            detecting = _detecting_backends(checks) if checks.status == ConceptStatus.READ else []
            if detecting:
                self._record(_SUB, Outcome.ENFORCED, _DETAIL_HEALTH_CHECK)
                return self._finish(notes=[_health_check_note(detecting, ref_hc)])

            if breakers.status != ConceptStatus.READ and checks.status != ConceptStatus.READ:
                return self._skip(
                    reason=(
                        "Neither circuit breakers nor health checks could be read from the "
                        f"gateway (circuit breakers: {_why(breakers)}; health checks: "
                        f"{_why(checks)}). Evidence: {ref_cb}, {ref_hc}."
                    )
                )

            unread = [
                name
                for name, answer in (
                    (CONCEPT_CIRCUIT_BREAKERS, breakers),
                    (CONCEPT_HEALTH_CHECKS, checks),
                )
                if answer.status == ConceptStatus.NOT_ACCESSIBLE
            ]
            if unread:
                self._record(_SUB, Outcome.NOT_VERIFIABLE, _DETAIL_NOT_READ)
                return self._finish(
                    notes=[_not_read_note(unread, breakers, checks, ref_cb, ref_hc)]
                )

            self._record(
                _SUB,
                Outcome.VIOLATION,
                _DETAIL_NONE,
                Finding(
                    title="No circuit breaker or health check on the gateway",
                    detail=(
                        "The gateway has no circuit breaker, and no health check that detects a "
                        "failing backend (the passive thresholds are zero and no active probe "
                        "runs on healthy targets): when a backend fails, every request waits for "
                        "its timeout, the thread pool fills and one failing dependency cascades "
                        "to the whole gateway (OWASP API4:2023, ASVS v5.0.0-16.5.2). Configure a "
                        "circuit breaker, or a passive health check with a failure threshold "
                        "above zero, so a failing backend is taken out of rotation."
                    ),
                    confidence=Confidence.CERTAIN,
                    evidence_ref=ref_cb,
                ),
            )
            return self._finish()
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_4_3_unexpected_error", error=str(exc))
            return self._error(exc)


def _detecting_backends(checks: ConceptRead[HealthCheck]) -> list[HealthCheck]:
    """
    The backends whose health check can detect a failing backend.

    Detection is what graceful degradation needs: a failing backend must be
    noticed and taken out of rotation. Recovery (an active probe on unhealthy
    targets) is reported separately, by the note.
    """
    return [item for item in checks.items if _detects_failures(item)]


def _detects_failures(item: HealthCheck) -> bool:
    """Whether this backend's health check notices that the backend is failing."""
    return _passive_configured(item) or _actively_probed(item)


def _passive_configured(item: HealthCheck) -> bool:
    """A passive health check with at least one non-zero failure threshold."""
    passive = item.passive
    if passive is None:
        return False
    thresholds = (passive.http_failures, passive.tcp_failures, passive.timeouts)
    return any(value for value in thresholds if value)


def _actively_probed(item: HealthCheck) -> bool:
    """
    An active health check that actually probes the healthy targets.

    Both gateways answer with their defaults filled in, so the `active` record
    exists even where nothing is configured; an interval of zero means the
    target is never probed (concepts.ActiveCheck), so the record's presence
    proves nothing by itself.
    """
    active = item.active
    if active is None:
        return False
    interval = active.healthy_interval_seconds
    return interval is not None and interval > 0


def _why(answer: ConceptRead[Any]) -> str:
    """The adapter's reason for an answer that is not READ."""
    return (answer.reason or str(answer.status)).rstrip(". ")


def _breaker_note(enabled: list[CircuitBreaker], ref: str) -> InfoNote:
    """The note naming the circuit breakers found."""
    names = ", ".join(f"{b.name} (threshold {b.failure_threshold})" for b in enabled)
    return InfoNote(
        title="Circuit breaker configured",
        detail=f"The gateway has an enabled circuit breaker: {names}. Evidence: {ref}.",
    )


def _health_check_note(detecting: list[HealthCheck], ref: str) -> InfoNote:
    """The note stating a health check is the gateway's compensating control."""
    names = ", ".join(sorted(item.name for item in detecting))
    detail = (
        "No circuit breaker is enabled on the gateway, but a health check notices a failing "
        f"backend and takes it out of rotation ({names}): the equivalent graceful degradation. "
    )
    no_recovery = sorted(item.name for item in detecting if not item.recovers_automatically)
    if no_recovery:
        detail += (
            "Only an active probe on unhealthy targets re-enables an excluded target, and these "
            f"backends have none ({', '.join(no_recovery)}): once excluded they stay excluded "
            "until someone intervenes. "
        )
    return InfoNote(
        title="Compensating control: a health check stands in for a circuit breaker",
        detail=f"{detail}Evidence: {ref}.",
    )


def _not_read_note(
    unread: list[str],
    breakers: ConceptRead[CircuitBreaker],
    checks: ConceptRead[HealthCheck],
    ref_cb: str,
    ref_hc: str,
) -> InfoNote:
    """The note of a verdict that could not be reached: part of the admin plane was unread."""
    return InfoNote(
        title="Graceful degradation not verifiable: the gateway was read only in part",
        detail=(
            f"Nothing was found in what could be read, but {' and '.join(unread)} could not be "
            "read from the gateway, so the absence of a control is not established: circuit "
            f"breakers: {_why(breakers)}; health checks: {_why(checks)}. Re-run with an admin "
            f"credential that can read both, or check them by hand. Evidence: {ref_cb}, {ref_hc}."
        ),
    )
