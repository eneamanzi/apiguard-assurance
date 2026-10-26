"""
src/tests/domain_4/test_4_3_circuit_breaker_audit.py

Test 4.3: guarantee "the system degrades gracefully with a circuit breaker"
(docs/project/test-review/group-g.md). OWASP API4:2023.

A circuit breaker stops a failing downstream from cascading: it opens after N
failures and answers at once instead of waiting for a timeout on every request.
Not every gateway has a dedicated breaker; a passive health check (a backend is
taken out of rotation after repeated failures) is the equivalent control, and
is accepted as a compensating one.

The test reads two gateway concepts through the adapter and judges the single
sub-test `degradation_configured`:

    a circuit breaker is enabled                 ENFORCED/CIRCUIT_BREAKER
    else a passive or active health check is set  ENFORCED/HEALTH_CHECK (a note:
      (Kong's equivalent of a breaker)            a compensating control)
    neither                                       VIOLATION/NO_CIRCUIT_BREAKER
    neither concept readable                      SKIP

WHITE_BOX (the gateway Admin API), READ_ONLY. Rebuilt on the new base from the
test on `main`, keeping the passive-health-check-as-breaker reasoning.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base.
"""

from __future__ import annotations

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.gateway.base import CONCEPT_CIRCUIT_BREAKERS, CONCEPT_HEALTH_CHECKS
from src.core.gateway.concepts import CircuitBreaker, ConceptStatus, HealthCheck
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
                self._record(_SUB, Outcome.ENFORCED, "CIRCUIT_BREAKER")
                return self._finish(notes=[_breaker_note(enabled, ref_cb)])

            protected = _with_health_check(checks) if checks.status == ConceptStatus.READ else []
            if protected:
                self._record(_SUB, Outcome.ENFORCED, "HEALTH_CHECK")
                return self._finish(notes=[_health_check_note(protected, ref_hc)])

            if breakers.status != ConceptStatus.READ and checks.status != ConceptStatus.READ:
                return self._skip(
                    reason=(
                        "Neither circuit breakers nor health checks could be read from the "
                        f"gateway ({breakers.reason or 'not supported'}). Evidence: {ref_cb}, "
                        f"{ref_hc}."
                    )
                )
            self._record(
                _SUB,
                Outcome.VIOLATION,
                "NO_CIRCUIT_BREAKER",
                Finding(
                    title="No circuit breaker or health check on the gateway",
                    detail=(
                        "The gateway has no circuit breaker and no passive or active health "
                        "check: when a backend fails, every request waits for its timeout, the "
                        "thread pool fills and one failing dependency cascades to the whole "
                        "gateway (OWASP API4:2023, ASVS v5.0.0-16.5.2). Configure a circuit "
                        "breaker, or at least a passive health check that takes a failing backend "
                        "out of rotation."
                    ),
                    confidence=Confidence.CERTAIN,
                    evidence_ref=ref_cb,
                ),
            )
            return self._finish()
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_4_3_unexpected_error", error=str(exc))
            return self._error(exc)


def _with_health_check(checks: object) -> list[HealthCheck]:
    """The backends with a configured passive or active health check."""
    items: tuple[HealthCheck, ...] = getattr(checks, "items", ())
    protected: list[HealthCheck] = []
    for item in items:
        if _passive_configured(item) or item.active is not None:
            protected.append(item)
    return protected


def _passive_configured(item: HealthCheck) -> bool:
    """A passive health check with at least one non-zero failure threshold."""
    passive = item.passive
    if passive is None:
        return False
    thresholds = (passive.http_failures, passive.tcp_failures, passive.timeouts)
    return any(value for value in thresholds if value)


def _breaker_note(enabled: list[CircuitBreaker], ref: str) -> InfoNote:
    """The note naming the circuit breakers found."""
    names = ", ".join(f"{b.name} (threshold {b.failure_threshold})" for b in enabled)
    return InfoNote(
        title="Circuit breaker configured",
        detail=f"The gateway has an enabled circuit breaker: {names}. Evidence: {ref}.",
    )


def _health_check_note(protected: list[HealthCheck], ref: str) -> InfoNote:
    """The note stating a health check is the gateway's compensating control."""
    names = ", ".join(sorted(item.name for item in protected))
    return InfoNote(
        title="Compensating control: a health check stands in for a circuit breaker",
        detail=(
            "The gateway has no dedicated circuit breaker, but a passive or active health check "
            f"takes a failing backend out of rotation ({names}): the equivalent graceful "
            f"degradation (Kong has no breaker plugin, this is its mechanism). Evidence: {ref}."
        ),
    )
