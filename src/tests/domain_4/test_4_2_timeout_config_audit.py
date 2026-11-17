"""
src/tests/domain_4/test_4_2_timeout_config_audit.py

Test 4.2: guarantee "the gateway bounds how long it waits for a backend"
(OWASP API4:2023, NIST SP 800-204A section 4.3).

A WHITE_BOX audit of the connect, read and write timeouts of every backend the
gateway states (and of every route that overrides them), through the concept
`backend_timeouts()` (seconds), against the methodology's thresholds
(milliseconds, configuration; no standard sets a value). A timeout the
configuration does not set is judged at the gateway's default, when the adapter
states it (`defaulted`). One sub-test per timeout; the oracle: info.oracle,
generated on the test page. No request is sent to the API: every finding points
to the concept read.
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
from src.core.models import (
    Confidence,
    Finding,
    Outcome,
    Reference,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.test_metadata import Effect, Need, OracleCase, TestInfo
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Parameters: tests.domain_4.test_4_2 in config.yaml
# ---------------------------------------------------------------------------

# Oracle thresholds from methodology section 4.2 (no standard sets a value).
# Thresholds in milliseconds; test 4.2 converts the backend timeouts the adapter
# reads (seconds).
TEST_42_MAX_CONNECT_TIMEOUT_MS_DEFAULT: int = 5_000

TEST_42_MAX_READ_TIMEOUT_MS_DEFAULT: int = 30_000

TEST_42_MAX_WRITE_TIMEOUT_MS_DEFAULT: int = 30_000


class Test42Params(BaseModel):
    """Parameters of test 4.2: the methodology's thresholds, in milliseconds."""

    model_config = {"frozen": True, "extra": "forbid"}

    max_connect_timeout_ms: Annotated[int, Field(ge=1)] = Field(
        default=TEST_42_MAX_CONNECT_TIMEOUT_MS_DEFAULT,
        description=(
            "Maximum acceptable backend connect timeout of a gateway service, in milliseconds. "
            "Methodology oracle: connect_timeout <= 5 000 ms (no standard sets a value). "
            "Services with a higher value will produce a FAIL finding."
        ),
    )
    max_read_timeout_ms: Annotated[int, Field(ge=1)] = Field(
        default=TEST_42_MAX_READ_TIMEOUT_MS_DEFAULT,
        description=(
            "Maximum acceptable backend read timeout of a gateway service, in milliseconds. "
            "Methodology oracle: read_timeout <= 30 000 ms (no standard sets a value). "
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

# A timeout of 0: the gateway sets no bound (the concept's meaning).
_NO_BOUND: int = 0

_WITHIN_LIMIT: str = "WITHIN_LIMIT"
_ABOVE_LIMIT: str = "ABOVE_LIMIT"
_UNBOUNDED: str = "UNBOUNDED"
_NOT_STATED: str = "NOT_STATED"

# Word for the object a timeout applies to, in the findings.
_SCOPE_WORDS: dict[ConceptScope, str] = {
    ConceptScope.BACKEND: "service",
    ConceptScope.ROUTE: "route",
    ConceptScope.GLOBAL: "gateway",
}

# Every finding of 4.2 is a value read from the gateway configuration: the
# observed fact itself.
_CONFIDENCE: Confidence = Confidence.CERTAIN

# The standards of the guarantee, declared in info and cited by every finding
# (the primary CWE is info.cwe).
_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API4:2023"),
    Reference(standard=Standard.NIST_SP, id="800-204A", section="4.3"),
    # ASVS v5.0.0 13.2.6 (read 2026-11-16): connections to separate services
    # follow their documented configuration, connection timeouts among it.
    # 16.5.2 (operate securely when external access fails) was cited until then:
    # it is about circuit breakers and degradation (test 4.3).
    Reference(standard=Standard.ASVS, id="v5.0.0-13.2.6"),
)


def _cases(sub_test: str) -> tuple[OracleCase, ...]:
    """The oracle of one timeout, the same for the three."""
    return (
        OracleCase(
            sub_test=sub_test,
            when=f"the {sub_test} of a backend or route is within its threshold",
            outcome=Outcome.ENFORCED,
            detail=_WITHIN_LIMIT,
        ),
        OracleCase(
            sub_test=sub_test,
            when="it is set above its threshold",
            outcome=Outcome.VIOLATION,
            detail=_ABOVE_LIMIT,
            confidence=Confidence.CERTAIN,
        ),
        OracleCase(
            sub_test=sub_test,
            when="it is not set, and the gateway's default, which its adapter states, is above "
            "the threshold",
            outcome=Outcome.VIOLATION,
            detail=_ABOVE_LIMIT,
            confidence=Confidence.FIRM,
        ),
        OracleCase(
            sub_test=sub_test,
            when="it is `0`: the gateway sets no bound",
            outcome=Outcome.VIOLATION,
            detail=_UNBOUNDED,
            confidence=Confidence.CERTAIN,
        ),
        OracleCase(
            sub_test=sub_test,
            when="it is neither set nor stated as the gateway's default",
            outcome=Outcome.NOT_VERIFIABLE,
            detail=_NOT_STATED,
        ),
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
        references=_REFERENCES,
        tags=(
            "availability",
            "timeout",
            "resource-lock",
            "white-box",
        ),
        needs=(Need.GATEWAY,),
        effect=Effect.READ_ONLY,
        sub_tests=tuple(label for label, _ in _TIMEOUT_LABELS),
        oracle=tuple(case for label, _ in _TIMEOUT_LABELS for case in _cases(label)),
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

        The concept read is kept as evidence; not supported or not accessible
        gives the shared answer (_unread_concept), no backend a SKIP.

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
                return self._unread_concept(CONCEPT_BACKEND_TIMEOUTS, answer, evidence_ref)

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
                if value_ms is None:
                    # Neither set nor stated as the gateway's default: unknown (rule 1).
                    self._record(label, Outcome.NOT_VERIFIABLE, _NOT_STATED)
                    continue
                detail, finding = self._judge_single_timeout(
                    subject=subject,
                    label=label,
                    value=(value_ms, concept_field in item.defaulted),
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
        value: tuple[int, bool],
        max_value_ms: int,
        evidence_ref: str,
    ) -> tuple[str, Finding | None]:
        """
        Judge one timeout of one backend or route.

        Two conditions are a violation: the timeout is 0 (no bound), or it
        exceeds max_value_ms.

        Args:
            subject:      "service '<name>'" or "route '<name>'", for the messages.
            label:        Timeout name (the sub-test, e.g. 'connect_timeout').
            value:        The timeout in milliseconds, and whether it is the
                          gateway's default (the configuration sets none).
            max_value_ms: Maximum acceptable value in milliseconds.
            evidence_ref: Evidence record of the concept read.

        Returns:
            (detail, finding): the finding is None when the timeout is compliant.
        """
        value_ms, is_default = value
        if value_ms == _NO_BOUND:
            return _UNBOUNDED, Finding(
                title=f"No timeout: {label} unbounded on {subject}",
                detail=(
                    f"{subject.capitalize()} has {label} = 0: the gateway sets no bound, so a "
                    f"single slow or unresponsive backend can hold a gateway worker "
                    f"indefinitely, leading to pool exhaustion and denial of service. "
                    f"Oracle: {label} must be > 0 and <= {max_value_ms} ms (the methodology's "
                    f"bound; NIST SP 800-204A asks for timeouts, SM-DR9)."
                ),
                evidence_ref=evidence_ref,
                confidence=_CONFIDENCE,
            )

        if value_ms > max_value_ms:
            origin = (
                " (not set in the configuration: the gateway's own default, as its adapter "
                "states it; the Admin API does not report it)"
                if is_default
                else ""
            )
            return _ABOVE_LIMIT, Finding(
                title=(f"Timeout Exceeds Oracle Threshold: {label} = {value_ms} ms on {subject}"),
                detail=(
                    f"{subject.capitalize()} has {label} = {value_ms} ms{origin}, "
                    f"which exceeds the oracle threshold of {max_value_ms} ms "
                    f"({max_value_ms / 1000:.0f} s), the methodology's bound. "
                    f"A {label} of {value_ms / 1000:.1f} s means the Gateway will wait "
                    f"up to {value_ms / 1000:.1f} s before aborting the upstream connection, "
                    f"holding a worker for that long on every request to a slow backend: under "
                    f"load the pool can saturate and the Gateway stop accepting new requests. "
                    f"Recommended action: reduce {label} to <= {max_value_ms} ms in the "
                    f"gateway configuration."
                ),
                evidence_ref=evidence_ref,
                # FIRM for a default: stated by the adapter, not read from the gateway.
                confidence=Confidence.FIRM if is_default else _CONFIDENCE,
            )

        return _WITHIN_LIMIT, None
