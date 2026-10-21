"""
src/external_tests/_template_ext_test.py

TEMPLATE -- Copy this file and rename it to implement a new ExternalToolTest.

Naming convention (non-optional -- enables automatic discovery by ExternalTestRegistry):
    src/external_tests/ext_test_<tool>_<description>.py

Steps to add a new ExternalToolTest:
    1. Copy this file to src/external_tests/ext_test_<tool>_<description>.py.
    2. Replace TemplateExtTest with your test class name.
    3. Fill in the declaration ``info = TestInfo(...)`` (src/core/test_metadata.py):
       an ID "ext.X.Y.tool", ``tool`` set to the tool's key in external_tools,
       and its sub-tests (at least one).
    4. Implement _build_connector(), _invoke_connector(), and _evaluate().
    A duplicate ID or an invalid declaration stops the run with a message
    naming the test (src/core/test_discovery.py).

Timeout access pattern:
    Read timeout from target.external_tools.<tool>.timeout_seconds.
    This is the canonical source; do NOT read it from the test's parameters.

    Example:
        timeout_seconds = target.external_tools.testssl.timeout_seconds
        timeout_seconds = target.external_tools.nuclei.timeout_seconds
        timeout_seconds = target.external_tools.ffuf.timeout_seconds

raw_output contract (ConnectorRawOutput):
    The connector's run() method must populate raw_output with all four REQUIRED
    keys documented in ConnectorRawOutput (src/connectors/base.py):
        command, command_json, results, all_count.
    Connectors are dumb pipes -- pass ALL findings in results; the oracle in
    _evaluate() records the outcome each result means (src/core/assessment_test.py).
    Use self._build_reproducible_commands() in the connector to produce
    command and command_json without reimplementing path normalisation.

Dependency rule:
    Imports from: stdlib, structlog, src.connectors, src.external_tests.base,
                  src.core.context, src.core.models, src.core.evidence.
    Must never import from: tests/, config/loader.py, discovery/, report/,
                             engine.py.
"""

from __future__ import annotations

import structlog

from src.connectors.base import BaseConnector, ConnectorResult

# from src.connectors.<toolname> import <ToolnameConnector>
from src.core.context import TargetContext
from src.core.models import Finding, InfoNote, Outcome, TestStrategy
from src.core.models.results import TestResult
from src.core.test_metadata import TestInfo
from src.external_tests.base import ExternalToolTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_REFERENCES: tuple[str, ...] = (
    "OWASP-API-Security-Top-10-2023",
    # Add relevant NIST, CWE, OWASP ASVS references here.
)


# ---------------------------------------------------------------------------
# TemplateExtTest -- rename this class
# ---------------------------------------------------------------------------


class TemplateExtTest(ExternalToolTest):
    """
    External test for <Garanzia X.Y> -- <brief description>.

    <One paragraph describing what this test verifies, which section of the
    methodology it implements, and how it relates to any native test with the
    same domain number.>

    Oracle:
        <The table: which tool result is VIOLATION, ENFORCED, NOT_VERIFIABLE or
        NOT_APPLICABLE, with the detail of each; the status is computed.>

    DAG placement:
        depends_on = [], requires_pass = [] -- no prerequisites (the usual case).
        depends_on = ["X.Y"] -- uses data that test X.Y produces (TestContext
            shared data); SKIP unless X.Y ends PASS or FAIL.
        requires_pass = ["X.Y"] -- meaningful only if test X.Y holds; SKIP
            unless X.Y ends PASS. Rules: src/core/dag.py.
    """

    # The declaration: one TestInfo, checked when the module is imported.
    # id: "ext.X.Y.tool" (X = domain, Y = sequence, tool = lowercase tool name),
    #     e.g. "ext.0.1.nuclei", "ext.1.5.testssl"; the domain is taken from it.
    # tool: the tool's key in external_tools (testssl, sslyze, nuclei); an
    #     unknown key makes is_tool_enabled() exclude the test from the run.
    # depends_on / requires_pass: see "DAG placement" above; omitted when empty.
    info = TestInfo(
        id="ext.0.9.template",
        name="Template External Test Name",
        priority=2,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-200",
        tags=("template", "external"),
        tool="template",
        sub_tests=("tool_scan",),
    )

    # ------------------------------------------------------------------
    # ExternalToolTest ABC implementation
    # ------------------------------------------------------------------

    def _build_connector(self) -> BaseConnector:
        """
        Instantiate and return the connector for this tool.

        This method must perform ONLY object construction -- zero I/O, zero
        subprocess calls, zero network access.  The ExternalTestRegistry
        calls this method during Phase R4 to check tool availability once
        per tool group before injecting the shared connector instance.

        Returns:
            BaseConnector: A newly constructed connector instance.
        """
        # Replace with the actual connector class.
        # return ToolnameConnector()
        raise NotImplementedError("Replace with the actual connector class.")

    def _invoke_connector(
        self,
        connector: BaseConnector,
        target: TargetContext,
        target_url: str,
    ) -> ConnectorResult:
        """
        Call connector.run() with tool-specific parameters.

        Reads timeout_seconds from target.external_tools.<tool>.timeout_seconds.

        Args:
            connector:   Connector instance (injected by registry or freshly built).
            target:      Frozen TargetContext.
            target_url:  URL returned by target.endpoint_base_url().

        Returns:
            ConnectorResult: Parsed tool output.
        """
        # Read timeout from external_tools, not from the test's parameters.
        # Replace "testssl" with the actual tool name (nuclei, ffuf, ...).
        # timeout_seconds is guaranteed non-None here because Phase 1 validation
        # rejects enabled=True with timeout_seconds=None (ConfigurationError).
        timeout_seconds: int = target.external_tools.testssl.timeout_seconds  # type: ignore[assignment]

        log.info(
            "template_ext_test_invoke_connector",
            target_url=target_url,
            timeout_seconds=timeout_seconds,
        )

        return connector.run(
            target_url=target_url,
            timeout_seconds=timeout_seconds,
        )

    def _evaluate(
        self,
        result: ConnectorResult,
        artifact_ref: str,
    ) -> TestResult:
        """
        Apply the oracle to ConnectorResult: record the outcome of each result.

        For each tool result, self._record(sub_test, outcome, detail, finding);
        then return self._finish(), which computes the status as for a native
        test and copies the declaration (test_name, domain, priority, strategy,
        tags, cwe_id, source, tool_name) into the result. Never build
        TestResult(...) directly.

        The thresholds below are an example only: how each tool's results map
        to the four outcomes is decided per tool (docs/project/test-review.md,
        phase 0c piece 10).

        Args:
            result:       ConnectorResult from _invoke_connector().
            artifact_ref: EvidenceStore record ID from store.pin_artifact():
                          the evidence_ref of every finding.

        Returns:
            TestResult: self._finish() (ERROR is handled by _run()).
        """
        notes: list[InfoNote] = []
        violations = 0

        for item in result.raw_output.get("results", []):
            severity = str(item.get("severity", "")).upper()

            if severity in {"HIGH", "CRITICAL"}:
                violations += 1
                self._record(
                    "tool_scan",
                    Outcome.VIOLATION,
                    "TOOL_FINDING_ABOVE_THRESHOLD",
                    finding=Finding(
                        title=f"[{severity}] {item.get('id', 'unknown')}",
                        detail=str(item.get("finding", "")),
                        references=list(_REFERENCES),
                        evidence_ref=artifact_ref,
                    ),
                )

            elif severity in {"MEDIUM", "WARN"}:
                # Below the threshold: an InfoNote (a blue card in the HTML
                # report), not a judgement.
                notes.append(
                    InfoNote(
                        title=f"[{severity}] Observation: {item.get('id', 'unknown')}",
                        detail=str(item.get("finding", "")),
                        references=list(_REFERENCES),
                    )
                )

        if violations == 0:
            # The scan ran and found nothing above the threshold: verified.
            self._record("tool_scan", Outcome.ENFORCED, "NO_FINDING_ABOVE_THRESHOLD")

        return self._finish(
            notes=notes,
            message=f"{result.raw_output.get('all_count', 0)} tool result(s), raw output "
            f"'{artifact_ref}'.",
        )
