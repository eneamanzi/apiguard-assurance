"""
src/tests/domain_5/test_5_2_security_alerting_audit.py

Test 5.2: guarantee "anomalous security events trigger real-time alerts"
. NIST SP 800-61 Rev.3 section 3.2 (CSF outcome
DE.AE-06: alerts reach the staff and the tools that respond).

Alerting lives in the SIEM or the notification channel, not in the gateway, and
the methodology says it is "only partly checkable from outside": its tests
(a brute-force alert, deduplication, a threshold) all need read access to the
alert rules and a webhook receiver to observe the alert. The tool has neither
from outside, so the test cannot judge the guarantee and returns SKIP with that
reason, rather than a hollow pass. The behavioural alert checks are a deferred
follow-up (they share the out-of-band listener of tests 7.2 and 7.4).

    anomalous_event_alerted  SKIP: no alert-rule or alert-channel access.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base.
"""

from __future__ import annotations

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import InfoNote, Reference, Standard, TestResult, TestStrategy
from src.core.test_metadata import Effect, TestInfo
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB: str = "anomalous_event_alerted"

_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API8:2023"),
    Reference(standard=Standard.NIST_SP, id="800-61r3", section="3.2"),
)


class Test52SecurityAlertingAudit(BaseTest):
    """
    Test 5.2 -- whether anomalous security events raise alerts.

    Not verifiable from outside (alerting is the SIEM's): the test SKIPs with
    the reason. The oracle and the deferred behavioural checks are on the page.
    """

    info = TestInfo(
        id="5.2",
        name="Security Alerting Audit",
        priority=2,
        strategy=TestStrategy.WHITE_BOX,
        cwe="CWE-778",
        references=_REFERENCES,
        tags=("alerting", "monitoring"),
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
        Return SKIP: alerting cannot be verified from outside.

        Args:
            target:  Unused.
            context: Unused.
            client:  Unused.
            store:   Unused.

        Returns:
            self._skip(reason) with a note on the deferred behavioural checks.
        """
        del target, context, client, store
        return self._skip(
            reason=(
                "Real-time security alerting cannot be verified from outside: the alert rules "
                "live in the SIEM or the notification channel, which the tool cannot read, and "
                "observing an alert needs a webhook receiver. No alert-rule or alert-channel "
                "access is configured."
            ),
            notes=[
                InfoNote(
                    title="Behavioural alert checks are outside this test",
                    detail=(
                        "The methodology's checks (a brute-force alert within seconds, alert "
                        "deduplication, a configured threshold) need an alert receiver the tool "
                        "can observe. No such receiver exists and none is planned, so this gap is "
                        "permanent: verify the alerting rules by hand on the gateway or the SIEM."
                    ),
                )
            ],
        )
