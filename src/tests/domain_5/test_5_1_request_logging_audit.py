"""
src/tests/domain_5/test_5_1_request_logging_audit.py

Test 5.1: guarantee "every request is logged with its metadata"
. NIST SP 800-92, OWASP ASVS v5.0.0-16.3.3 and 16.4.3,
NIST SP 800-53 Rev.5 AU-2.

The methodology states the limit plainly: "without access to the logs this
guarantee cannot be checked empirically from outside." So the test audits the
one thing it can see from outside, the gateway's configuration: is a
plugin enabled that ships the request logs to a separate system (ASVS
v5.0.0-16.4.3)? Which plugins do that is the gateway adapter's knowledge (the
log-shipping concept): this test names no gateway (audit D235-2, owner decision
2026-11-04). What it cannot see is the gateway's own access log: it is not in
the Admin API, so the test never claims that requests are not logged, only that
no plugin ships them (audit D235-1). The log-content checks (the required fields,
the redaction of secrets, the real source IP, log-injection resistance) need
read access to the logs, which the tool does not have on any target, so they
are permanently out of reach: stated as a note, never faked as a pass.

    request_logging_configured  a plugin the adapter reports as shipping the
                               request logs is enabled on the gateway ->
                               ENFORCED/LOGS_SHIPPED; none ->
                               VIOLATION/LOGS_NOT_SHIPPED (FIRM: a collector
                               on the gateway's host is invisible here).

WHITE_BOX (the gateway Admin API), READ_ONLY.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base.
"""

from __future__ import annotations

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.gateway.base import CONCEPT_CONFIG_VALUES, CONCEPT_LOG_SHIPPING
from src.core.gateway.concepts import ConceptStatus
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

_SUB: str = "request_logging_configured"


# What the tool cannot check from outside, permanently.
_CONTENT_CHECKS_NOTE: InfoNote = InfoNote(
    title="Log-content checks need log access (not done)",
    detail=(
        "This test audits only that a plugin shipping the request logs is enabled on the "
        "gateway. The methodology's log-content checks (the required fields, redaction of "
        "secrets, the real source IP, log-injection resistance) need read access to the logs, "
        "which the tool does not have from outside. They are outside this test for good, so "
        "check them by hand on the log stream: a gateway that logs unredacted tokens still "
        "passes here."
    ),
)

_REFERENCES: tuple[Reference, ...] = (
    # Read on the ASVS v5.0.0 source 2026-10-28: 16.3.3 (the security events of
    # the documentation are logged, bypass attempts included) and 16.4.3 (the
    # logs reach a logically separate system for analysis and alerting), which
    # is what a gateway logging plugin does. 16.2.1 (each log entry carries
    # the metadata needed to investigate: time, source, who, what, outcome).
    Reference(standard=Standard.ASVS, id="v5.0.0-16.3.3"),
    Reference(standard=Standard.ASVS, id="v5.0.0-16.4.3"),
    Reference(standard=Standard.NIST_SP, id="800-92"),
    Reference(standard=Standard.NIST_SP, id="800-53r5", section="3.3"),
)


class Test51RequestLoggingAudit(BaseTest):
    """
    Test 5.1 -- whether the gateway is configured to log requests.

    The oracle is in the module docstring and on the test page.
    """

    info = TestInfo(
        id="5.1",
        name="Request Logging Audit",
        priority=1,
        strategy=TestStrategy.WHITE_BOX,
        cwe="CWE-778",
        references=_REFERENCES,
        tags=("logging", "auditing"),
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
        Read the gateway configuration and judge whether a logging plugin is on.

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
            answer = gateway.config_values()
            evidence_ref = self._record_gateway_concept(
                target, store, CONCEPT_CONFIG_VALUES, answer
            )
            if answer.status != ConceptStatus.READ:
                return self._unread_concept(CONCEPT_CONFIG_VALUES, answer, evidence_ref)
            if not answer.items:
                # The read succeeded and returned nothing: a gateway with no
                # service and no plugin, or a reader that found no value where
                # there are some (the shape of the Kong defect fixed on
                # 2026-10-28). Saying "no logging plugin" on that basis would
                # accuse the target of a gap this run never looked for.
                self._record(_SUB, Outcome.NOT_VERIFIABLE, "NO_CONFIG_VALUE")
                return self._finish(
                    notes=[
                        InfoNote(
                            title="The gateway configuration read was empty",
                            detail=(
                                "The gateway answered its configuration endpoints with no value "
                                "at all, so this run cannot say whether requests are logged. "
                                f"Evidence: {evidence_ref}."
                            ),
                        )
                    ]
                )
            shipping = gateway.log_shipping()
            evidence_ref = self._record_gateway_concept(
                target, store, CONCEPT_LOG_SHIPPING, shipping
            )
            if shipping.status != ConceptStatus.READ:
                return self._unread_concept(CONCEPT_LOG_SHIPPING, shipping, evidence_ref)
            # A disabled plugin ships nothing.
            plugins = sorted({f"{s.plugin} ({s.source})" for s in shipping.items if s.enabled})
            if plugins:
                self._record(_SUB, Outcome.ENFORCED, "LOGS_SHIPPED")
                return self._finish(
                    notes=[
                        InfoNote(
                            title="Log-shipping plugin configured",
                            detail=(
                                f"The gateway ships its request logs with: {', '.join(plugins)}."
                            ),
                        ),
                        _CONTENT_CHECKS_NOTE,
                    ]
                )
            self._record(
                _SUB,
                Outcome.VIOLATION,
                "LOGS_NOT_SHIPPED",
                Finding(
                    title="No gateway plugin ships the request logs to a separate system",
                    detail=(
                        "The gateway's configuration has no plugin enabled that sends request "
                        "logs to another system (as the gateway adapter recognises them). The "
                        "gateway may still write "
                        "its own access log, which the Admin API does not show; kept on the "
                        "gateway's host, it is lost or altered with that host, while ASVS "
                        "v5.0.0-16.4.3 asks that logs reach a logically separate system for "
                        "analysis and alerting (also NIST SP 800-92, NIST SP 800-53 Rev.5 AU-2). "
                        "Enable a plugin that ships structured logs to the log store, or confirm "
                        "that a collector on the gateway's host already ships its access log."
                    ),
                    confidence=Confidence.FIRM,
                    evidence_ref=evidence_ref,
                ),
            )
            return self._finish(notes=[_CONTENT_CHECKS_NOTE])
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_5_1_unexpected_error", error=str(exc))
            return self._error(exc)
