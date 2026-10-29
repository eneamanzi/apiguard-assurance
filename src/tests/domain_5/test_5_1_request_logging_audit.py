"""
src/tests/domain_5/test_5_1_request_logging_audit.py

Test 5.1: guarantee "every request is logged with its metadata"
. NIST SP 800-92, OWASP ASVS v5.0.0-16.3.3 and 16.4.3,
NIST SP 800-53 Rev.5 AU-2.

The methodology states the limit plainly: "without access to the logs this
guarantee cannot be checked empirically from outside." So the test audits the
one thing it can see from outside, the gateway's configuration: is a
request-logging plugin enabled? The log-content checks (the required fields,
the redaction of secrets, the real source IP, log-injection resistance) need
read access to the logs, which the tool does not have on any target, so they
are permanently out of reach: stated as a note, never faked as a pass.

    request_logging_configured  a known logging plugin (Kong http-log/file-log/
                               syslog/..., APISIX http-logger/syslog/...) is
                               enabled on the gateway -> ENFORCED; none ->
                               VIOLATION/NO_REQUEST_LOGGING.

WHITE_BOX (the gateway Admin API), READ_ONLY.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base.
"""

from __future__ import annotations

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.gateway.base import CONCEPT_CONFIG_VALUES
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

# Fragments of the names of request-logging plugins (Kong and APISIX), matched
# case-insensitively in a config value's location ("plugin <name> (id ...)").
_LOGGING_PLUGIN_MARKERS: tuple[str, ...] = (
    "http-log",
    "file-log",
    "tcp-log",
    "udp-log",
    "syslog",
    "-logger",  # APISIX: http-logger, tcp-logger, kafka-logger, ...
    "loggly",
    "datadog",
    "splunk",
    "kafka-log",
)

# What the tool cannot check from outside, permanently.
_CONTENT_CHECKS_NOTE: InfoNote = InfoNote(
    title="Log-content checks need log access (not done)",
    detail=(
        "This test audits only that a request-logging plugin is enabled on the gateway. The "
        "methodology's log-content checks (the required fields, redaction of secrets, the real "
        "source IP, log-injection resistance) need read access to the logs, which the tool does "
        "not have from outside. They are outside this test for good, so check them by hand on "
        "the log stream: a gateway that logs unredacted tokens still passes here."
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
                return self._skip(
                    reason=(
                        f"The gateway configuration could not be read "
                        f"({answer.reason or 'not supported'}). Evidence: {evidence_ref}."
                    )
                )
            plugins = sorted(
                {
                    item.location
                    for item in answer.items
                    if any(marker in item.location.lower() for marker in _LOGGING_PLUGIN_MARKERS)
                }
            )
            if plugins:
                self._record(_SUB, Outcome.ENFORCED, "LOGGING_CONFIGURED")
                return self._finish(
                    notes=[
                        InfoNote(
                            title="Request-logging plugin configured",
                            detail=f"The gateway has a logging plugin: {', '.join(plugins)}.",
                        ),
                        _CONTENT_CHECKS_NOTE,
                    ]
                )
            self._record(
                _SUB,
                Outcome.VIOLATION,
                "NO_REQUEST_LOGGING",
                Finding(
                    title="No request-logging plugin on the gateway",
                    detail=(
                        "The gateway has no request-logging plugin enabled (Kong http-log, "
                        "file-log, syslog, ...; APISIX http-logger, syslog, ...), so requests are "
                        "not logged at the gateway: a security incident or a brute-force attempt "
                        "leaves no trail for investigation (NIST SP 800-92, ASVS "
                        "v5.0.0-16.3.3 and 16.4.3, NIST SP 800-53 Rev.5 AU-2). "
                        "Enable a logging plugin that ships structured logs to the log store."
                    ),
                    confidence=Confidence.CERTAIN,
                    evidence_ref=evidence_ref,
                ),
            )
            return self._finish(notes=[_CONTENT_CHECKS_NOTE])
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_5_1_unexpected_error", error=str(exc))
            return self._error(exc)
