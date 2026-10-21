"""
src/tests/domain_4/test_4_2_timeout_config_audit.py

Test 4.2 -- Timeout Configuration Audit: Prevention of Resource Lock.

Guarantee (docs/06-knowledge/04-guarantees.md, Section 4.2):
    Every I/O operation (DB query, outbound HTTP call) must have a configured
    timeout. Without timeouts, a single blocked thread occupies a slot in the
    connection pool indefinitely; accumulated blocked threads exhaust the pool
    and prevent the server from accepting new requests.

    This test audits the gateway's timeouts towards its backends (connect,
    read, write) against the oracle bounds of the methodology:

        connect_timeout  <=  5 000 ms  (NIST SP 800-204A Section 4.3: <= 5 s)
        read_timeout     <= 30 000 ms  (NIST SP 800-204A Section 4.3: <= 30 s)
        write_timeout    <= 30 000 ms

Strategy: WHITE_BOX -- Configuration Audit through the gateway adapter.
Priority: P1 -- a missing timeout on any upstream service is a resource-lock
    vulnerability that cascades into full pool exhaustion (CWE-400).

Pilot of the test review (docs/project/test-review.md, phase 0c piece 1): the
oracle is the v0.1.0 one, moved onto the computed result; its review (e.g.
whether a timeout the gateway does not state is a violation, Q-29) is phase 1.

Sub-tests: connect_timeout, read_timeout, write_timeout. For each backend (or
route that overrides its backend's timeouts) and each timeout:

    value in (0, maximum]    -> ENFORCED/WITHIN_LIMIT
    value > maximum          -> VIOLATION/ABOVE_LIMIT
    value == 0               -> VIOLATION/NOT_CONFIGURED
    value not stated (None)  -> VIOLATION/NOT_STATED

Gateway access:
    The test reads the neutral concept "backend timeouts" through the gateway
    adapter (target.gateway.backend_timeouts(), src/core/gateway/concepts.py),
    in seconds; the oracle thresholds stay in milliseconds (configuration) and
    the values are converted. A concept not supported or not accessible gives
    SKIP with the reason (BaseTest._skip_for_concept); no backend gives SKIP.

EvidenceStore policy:
    No HTTP request is made to the target API. The concept read is stored as
    an artifact (BaseTest._record_gateway_concept) and every Finding points to
    it through evidence_ref.
"""  # noqa: N999

from __future__ import annotations

from typing import Annotated

import structlog
from pydantic import BaseModel, Field

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.gateway.base import CONCEPT_BACKEND_TIMEOUTS
from src.core.gateway.concepts import BackendTimeout, ConceptScope, ConceptStatus
from src.core.models import Finding, Outcome, TestResult, TestStrategy
from src.core.test_metadata import Need, TestInfo
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Parameters: tests.domain_4.test_4_2 in config.yaml
# ---------------------------------------------------------------------------

# Oracle thresholds from methodology section 4.2 (NIST SP 800-204A Section 4.3).
# Thresholds in milliseconds; test 4.2 converts the backend timeouts the adapter
# reads (seconds).
TEST_42_MAX_CONNECT_TIMEOUT_MS_DEFAULT: int = 5_000

TEST_42_MAX_READ_TIMEOUT_MS_DEFAULT: int = 30_000

TEST_42_MAX_WRITE_TIMEOUT_MS_DEFAULT: int = 30_000


class Test42Params(BaseModel):
    """
    Tuning parameters for Test 4.2 (Timeout Configuration Audit).

    Oracle thresholds are taken directly from the methodology (section 4.2,
    NIST SP 800-204A Section 4.3):
        connect_timeout  <= 5 000 ms  (5 s)
        read_timeout     <= 30 000 ms (30 s)
        write_timeout    <= 30 000 ms (30 s)

    Thresholds in milliseconds; the backend timeouts the adapter reads are in
    seconds and test 4.2 converts them.
    Adjust these only when the target gateway is intentionally configured
    with different timeouts and the deviation is accepted as a documented risk.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    max_connect_timeout_ms: Annotated[int, Field(ge=1)] = Field(
        default=TEST_42_MAX_CONNECT_TIMEOUT_MS_DEFAULT,
        description=(
            "Maximum acceptable backend connect timeout of a gateway service, in milliseconds. "
            "Methodology oracle: connect_timeout <= 5 000 ms (NIST SP 800-204A Section 4.3). "
            "Services with a higher value will produce a FAIL finding."
        ),
    )
    max_read_timeout_ms: Annotated[int, Field(ge=1)] = Field(
        default=TEST_42_MAX_READ_TIMEOUT_MS_DEFAULT,
        description=(
            "Maximum acceptable backend read timeout of a gateway service, in milliseconds. "
            "Methodology oracle: read_timeout <= 30 000 ms (NIST SP 800-204A Section 4.3). "
            "Services with a higher value will produce a FAIL finding."
        ),
    )
    max_write_timeout_ms: Annotated[int, Field(ge=1)] = Field(
        default=TEST_42_MAX_WRITE_TIMEOUT_MS_DEFAULT,
        description=(
            "Maximum acceptable backend write (send) timeout of a gateway service, "
            "in milliseconds. "
            "Methodology oracle: write_timeout <= 30 000 ms. "
            "Services with a higher value will produce a FAIL finding."
        ),
    )


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# The three timeouts: the sub-test (named as the gateways commonly name the
# timeout, also the word of the findings) and the concept's field (seconds).
_TIMEOUT_LABELS: tuple[tuple[str, str], ...] = (
    ("connect_timeout", "connect_seconds"),
    ("read_timeout", "read_seconds"),
    ("write_timeout", "send_seconds"),
)
_MS_PER_SECOND: int = 1000

# A timeout of zero means "not configured". Kong defaults all three to
# 60 000 ms, so a zero should not appear, but it gets a clear finding rather
# than a confusing comparison.
_TIMEOUT_UNCONFIGURED: int = 0

# Details of the judgements (the oracle table above).
_WITHIN_LIMIT: str = "WITHIN_LIMIT"
_ABOVE_LIMIT: str = "ABOVE_LIMIT"
_NOT_CONFIGURED: str = "NOT_CONFIGURED"
_NOT_STATED: str = "NOT_STATED"

# Word for the object a timeout applies to, in the findings.
_SCOPE_WORDS: dict[ConceptScope, str] = {
    ConceptScope.BACKEND: "service",
    ConceptScope.ROUTE: "route",
    ConceptScope.GLOBAL: "gateway",
}

# OWASP/NIST references cited in every Finding produced by this test.
_REFERENCES: tuple[str, ...] = (
    "OWASP-API4:2023",
    "CWE-400",
    "NIST-SP-800-204A-Section-4.3",
    "OWASP-ASVS-v5.0.0-V16.5.2",
)


class Test42TimeoutConfigAudit(BaseTest[Test42Params]):
    """
    Test 4.2 -- Timeout Configuration Audit: Prevention of Resource Lock.

    Judges the connect, read and write timeouts of every backend the gateway
    states, one sub-test per timeout. A WHITE_BOX configuration audit: no
    HTTP request is made to the target API; the evidence is the concept read.
    """

    info = TestInfo(
        id="4.2",
        name="Timeout Configuration Audit -- Prevention of Resource Lock",
        priority=1,
        strategy=TestStrategy.WHITE_BOX,
        cwe="CWE-400",
        tags=(
            "availability",
            "timeout",
            "resource-lock",
            "white-box",
            "OWASP-API4",
        ),
        needs=(Need.GATEWAY,),
        sub_tests=tuple(label for label, _ in _TIMEOUT_LABELS),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Audit the timeouts towards the backends through the gateway adapter.

        Execution flow:
            1. A gateway adapter is configured (Need.GATEWAY: the engine skips
               the test otherwise).
            2. Read the concept "backend timeouts" and store it as evidence.
            3. Not supported or not accessible: SKIP with the reason.
            4. No backend: SKIP (nothing to audit).
            5. Judge connect, read and write timeouts of each item against the
               configured thresholds; the result is computed (_finish).

        Returns:
            TestResult: computed from the judgements, SKIP, or ERROR.
        """
        try:
            gateway = target.gateway
            assert gateway is not None  # noqa: S101 -- Need.GATEWAY, checked by the engine

            cfg = self.params(target)

            log.info(
                "test_4_2_starting",
                gateway_adapter=gateway.adapter_name,
                max_connect_timeout_ms=cfg.max_connect_timeout_ms,
                max_read_timeout_ms=cfg.max_read_timeout_ms,
                max_write_timeout_ms=cfg.max_write_timeout_ms,
            )

            answer = gateway.backend_timeouts()
            evidence_ref = self._record_gateway_concept(
                target, store, CONCEPT_BACKEND_TIMEOUTS, answer
            )
            if answer.status != ConceptStatus.READ:
                return self._skip_for_concept(CONCEPT_BACKEND_TIMEOUTS, answer, evidence_ref)

            if not answer.items:
                return self._skip(
                    reason=(
                        "No backend registered on the gateway: there is nothing to audit "
                        "for timeout configuration. Verify that the gateway has at least "
                        f"one backend before running this test. Evidence: {evidence_ref}."
                    )
                )

            log.info("test_4_2_backends_retrieved", backend_count=len(answer.items))
            self._judge_timeouts(answer.items, cfg, evidence_ref)
            return self._finish(
                message=f"{len(answer.items)} backend(s) or route(s) read from the gateway."
            )

        except Exception as exc:  # noqa: BLE001
            log.exception("test_4_2_unexpected_error", error=str(exc))
            return self._error(exc)

    # ------------------------------------------------------------------
    # Timeout judgement
    # ------------------------------------------------------------------

    def _judge_timeouts(
        self,
        items: tuple[BackendTimeout, ...],
        cfg: Test42Params,
        evidence_ref: str,
    ) -> None:
        """
        Judge the three timeouts of every item of the concept.

        Args:
            items:        The backend timeouts read from the gateway.
            cfg:          Test42Params carrying the oracle thresholds.
            evidence_ref: Evidence record of the concept read.
        """
        thresholds: dict[str, int] = {
            "connect_timeout": cfg.max_connect_timeout_ms,
            "read_timeout": cfg.max_read_timeout_ms,
            "write_timeout": cfg.max_write_timeout_ms,
        }
        for item in items:
            subject = f"{_SCOPE_WORDS[item.scope]} '{item.name}'"
            for label, concept_field in _TIMEOUT_LABELS:
                seconds: float | None = getattr(item, concept_field)
                value_ms = None if seconds is None else round(seconds * _MS_PER_SECOND)
                detail, finding = self._judge_single_timeout(
                    subject=subject,
                    label=label,
                    value_ms=value_ms,
                    max_value_ms=thresholds[label],
                    evidence_ref=evidence_ref,
                )
                outcome = Outcome.ENFORCED if finding is None else Outcome.VIOLATION
                self._record(label, outcome, detail, finding)
                log.debug(
                    "test_4_2_timeout_judged",
                    subject=subject,
                    field=label,
                    value_ms=value_ms,
                    oracle_max_ms=thresholds[label],
                    outcome=outcome,
                    detail=detail,
                )

    def _judge_single_timeout(
        self,
        subject: str,
        label: str,
        value_ms: int | None,
        max_value_ms: int,
        evidence_ref: str,
    ) -> tuple[str, Finding | None]:
        """
        Judge one timeout of one backend or route.

        Three conditions are a violation: the timeout is not stated (None), it
        is 0 ("not configured"), it exceeds max_value_ms.

        Args:
            subject:      "service '<name>'" or "route '<name>'", for the messages.
            label:        Timeout name (the sub-test, e.g. 'connect_timeout').
            value_ms:     The timeout in milliseconds, or None if not stated.
            max_value_ms: Maximum acceptable value in milliseconds.
            evidence_ref: Evidence record of the concept read.

        Returns:
            (detail, finding): the finding is None when the timeout is compliant.
        """
        if value_ms is None:
            return _NOT_STATED, Finding(
                title=f"Timeout Field Absent: {label} on {subject}",
                detail=(
                    f"The gateway does not state '{label}' for {subject}. Expected a "
                    f"timeout value. Without it, timeout enforcement for this backend is "
                    f"unknown and cannot be audited (the gateway's default applies)."
                ),
                references=list(_REFERENCES),
                evidence_ref=evidence_ref,
            )

        if value_ms == _TIMEOUT_UNCONFIGURED:
            return _NOT_CONFIGURED, Finding(
                title=f"Timeout Not Configured: {label} == 0 on {subject}",
                detail=(
                    f"{subject.capitalize()} has {label} = 0, which indicates the timeout is "
                    f"not configured. An unconfigured timeout on a backend means a single slow "
                    f"or unresponsive dependency can block a connection-pool thread "
                    f"indefinitely, leading to pool exhaustion and denial of service. "
                    f"Oracle: {label} must be > 0 and <= {max_value_ms} ms "
                    f"(NIST SP 800-204A Section 4.3)."
                ),
                references=list(_REFERENCES),
                evidence_ref=evidence_ref,
            )

        if value_ms > max_value_ms:
            return _ABOVE_LIMIT, Finding(
                title=(f"Timeout Exceeds Oracle Threshold: {label} = {value_ms} ms on {subject}"),
                detail=(
                    f"{subject.capitalize()} has {label} = {value_ms} ms, "
                    f"which exceeds the oracle threshold of {max_value_ms} ms "
                    f"({max_value_ms / 1000:.0f} s) from NIST SP 800-204A Section 4.3. "
                    f"A {label} of {value_ms / 1000:.1f} s means the Gateway will wait "
                    f"up to {value_ms / 1000:.1f} s before aborting the upstream connection. "
                    f"Under load ({100} concurrent requests blocked for {value_ms / 1000:.0f} s "
                    f"each), the connection pool saturates and the Gateway stops accepting new "
                    f"requests entirely, producing a self-inflicted denial of service. "
                    f"Recommended action: reduce {label} to <= {max_value_ms} ms in the "
                    f"gateway configuration."
                ),
                references=list(_REFERENCES),
                evidence_ref=evidence_ref,
            )

        return _WITHIN_LIMIT, None
