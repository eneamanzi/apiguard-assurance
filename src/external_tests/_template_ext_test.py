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
from src.core.models import (
    Confidence,
    Finding,
    InfoNote,
    Outcome,
    Reference,
    Standard,
    TestStrategy,
)
from src.core.models.results import TestResult
from src.core.test_metadata import Effect, TestInfo
from src.external_tests.base import ExternalToolTest, ToolRun

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# The standards of the guarantee, each written as its standard writes it
# (src/core/models/standards.py); declared in info and cited by the findings.
# The primary CWE is info.cwe: do not repeat it here.
_REFERENCES: tuple[Reference, ...] = (Reference(standard=Standard.OWASP_API_TOP10, id="API8:2023"),)

# The oracle: the identifier of each tool check the test uses -> the outcome and
# detail it means (the table of the test page). Example identifiers.
_ORACLE: dict[str, tuple[Outcome, str]] = {
    "example-weak-protocol": (Outcome.VIOLATION, "WEAK_PROTOCOL_OFFERED"),
    "example-protocol-ok": (Outcome.ENFORCED, "PROTOCOL_OK"),
}

# Tool checks that report a problem of the tool itself, not of the target.
_TOOL_PROBLEMS: frozenset[str] = frozenset({"example-engine-problem"})


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
    #     e.g. "ext.0.1.ffuf", "ext.1.5.testssl"; the domain is taken from it.
    # tool: the tool's key in external_tools (testssl, nuclei, ffuf, schemathesis); an
    #     unknown key makes is_tool_enabled() exclude the test from the run.
    # depends_on / requires_pass: see "DAG placement" above; omitted when empty.
    info = TestInfo(
        id="ext.0.9.template",
        name="Template External Test Name",
        priority=2,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-200",
        references=_REFERENCES,
        # Topics, lowercase words joined by hyphens; standards go in references.
        tags=("template", "external"),
        tool="template",
        sub_tests=("tool_scan",),
        # What the tool does to the target: a scanner sending many requests is
        # usually STRESSES_TARGET.
        effect=Effect.STRESSES_TARGET,
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
        run: ToolRun,
    ) -> TestResult:
        """
        Apply the oracle to ConnectorResult: record the outcome of each result.

        For each tool result, self._record(sub_test, outcome, detail, finding);
        then return self._finish(), which computes the status as for a native
        test and copies the declaration (test_name, domain, priority, strategy,
        tags, cwe_id, source, tool_name) into the result. Never build
        TestResult(...) directly.

        The oracle is the tool's check, not its severity (rule 11): each check
        identifier the test uses is mapped to an outcome in _ORACLE; a check the
        test does not map is not judged; a result outside the target goes to a
        note; the tool's own problems are NOT_VERIFIABLE.
        A test that verifies a tool result with a request of its own uses
        run.client and judges the response with self._judge().

        Args:
            result: ConnectorResult from _invoke_connector().
            run:    The target, context, client and store of the run, and the
                    tool output's record ID (run.artifact_ref, the evidence_ref
                    of a finding resting on the output alone).

        Returns:
            TestResult: self._finish() (ERROR is handled by _run()).
        """
        notes: list[InfoNote] = []
        target_url = run.target.endpoint_base_url()
        for item in result.raw_output.get("results", []):
            check = str(item.get("id", ""))
            where = str(item.get("url", target_url))
            if not where.startswith(target_url):
                notes.append(
                    InfoNote(
                        title=f"Result outside the target: {check}",
                        detail=f"{where}: not judged (only the target counts).",
                    )
                )
                continue
            if check in _TOOL_PROBLEMS:
                self._record("tool_scan", Outcome.NOT_VERIFIABLE, "TOOL_COULD_NOT_CHECK")
                continue
            mapped = _ORACLE.get(check)
            if mapped is None:
                continue
            outcome, detail = mapped
            finding = None
            if outcome == Outcome.VIOLATION:
                finding = Finding(
                    title=f"{check}: {item.get('finding', '')}",
                    detail=str(item.get("finding", "")),
                    evidence_ref=run.artifact_ref,
                    # The level is a column of the test's oracle table; FIRM here
                    # only as an example.
                    confidence=Confidence.FIRM,
                )
            self._record("tool_scan", outcome, detail, finding)

        return self._finish(
            notes=notes,
            message=f"{result.raw_output.get('all_count', 0)} tool result(s), raw output "
            f"'{run.artifact_ref}'.",
        )
