"""
src/external_tests/_template_ext_test.py

TEMPLATE -- Copy this file and rename it to implement a new ExternalToolTest.

Naming convention (non-optional -- enables automatic discovery by ExternalTestRegistry):
    src/external_tests/ext_test_<tool>_<description>.py

Steps to add a new ExternalToolTest:
    1. Copy this file to src/external_tests/ext_test_<tool>_<description>.py.
    2. Replace TemplateExtTest with your test class name.
    3. Fill in all ClassVar declarations (all eight are mandatory per LLM_rules.md).
    4. Implement _build_connector(), _invoke_connector(), and _evaluate().
    5. Verify test_id uniqueness: grep for your chosen test_id across all test files.

Timeout access pattern (Proposal C):
    Read timeout from target.external_tools.<tool>.timeout_seconds.
    This is the canonical source; do NOT read from tests_config domain fields.

    Example:
        timeout_seconds = target.external_tools.testssl.timeout_seconds
        timeout_seconds = target.external_tools.nuclei.timeout_seconds
        timeout_seconds = target.external_tools.ffuf.timeout_seconds

raw_output contract (ConnectorRawOutput):
    The connector's run() method must populate raw_output with all four REQUIRED
    keys documented in ConnectorRawOutput (src/connectors/base.py):
        command, command_json, results, all_count.
    Connectors are dumb pipes -- pass ALL findings in results; the oracle in
    _evaluate() partitions them into FAIL / note / ignore buckets.
    Use self._build_reproducible_commands() in the connector to produce
    command and command_json without reimplementing path normalisation.

Dependency rule:
    Imports from: stdlib, structlog, src.connectors, src.external_tests.base,
                  src.core.context, src.core.models, src.core.evidence.
    Must never import from: tests/, config/loader.py, discovery/, report/,
                             engine.py.
"""

from __future__ import annotations

from typing import ClassVar

import structlog

from src.connectors.base import BaseConnector, ConnectorResult

# from src.connectors.<toolname> import <ToolnameConnector>
from src.core.context import TargetContext
from src.core.models import Finding, InfoNote, TestStrategy
from src.core.models.results import TestResult
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
        <Describe the PASS/FAIL criteria here.>

    DAG placement:
        depends_on = [] -- no prerequisites; runs in Phase A.
        OR
        depends_on = ["1.1"] -- requires native Test 1.1 to have run first.
    """

    # --- Mandatory ClassVar declarations (LLM_rules.md §3.3) ---
    # Verify test_id uniqueness before committing: grep -r "test_id" src/tests/ src/external_tests/
    test_id: ClassVar[str] = "ext.X.Y"
    test_name: ClassVar[str] = "Template External Test Name"
    priority: ClassVar[int] = 2  # 0-3 (P0-P3)
    domain: ClassVar[int] = 0  # methodology domain number
    strategy: ClassVar[TestStrategy] = TestStrategy.GREY_BOX
    depends_on: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = ["template", "external"]
    cwe_id: ClassVar[str] = "CWE-000"

    # tool_name must match a field name in ExternalToolsConfig (testssl/nuclei/ffuf).
    # A typo here triggers a WARNING in is_tool_enabled() (Proposal E) and
    # causes this test to be excluded from the run.
    tool_name: ClassVar[str] = "template-tool"  # replace with "testssl", "nuclei", or "ffuf"

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

        Reads timeout_seconds from target.external_tools.<tool>.timeout_seconds
        (Proposal C canonical pattern).

        Args:
            connector:   Connector instance (injected by registry or freshly built).
            target:      Frozen TargetContext.
            target_url:  URL returned by target.effective_endpoint_base_url().

        Returns:
            ConnectorResult: Parsed tool output.
        """
        # Proposal C canonical pattern: always read from external_tools.
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
        Apply the oracle to ConnectorResult and produce a TestResult.

        ALWAYS use self._make_pass() / self._make_fail() / self._make_skip()
        to construct the return value.  Building TestResult(...) directly will
        produce a result missing all metadata fields (test_name, domain,
        priority, strategy, tags, cwe_id, source, tool_name) because those
        fields are populated exclusively by _metadata_kwargs() inside the
        _make_*() helpers.  Pydantic will not raise -- it will silently use
        the default="" values, producing empty cells in the HTML report.

        Args:
            result:       ConnectorResult from _invoke_connector().
            artifact_ref: EvidenceStore record ID from store.pin_artifact().
                          Include in every Finding.evidence_ref for traceability.

        Returns:
            TestResult: PASS, FAIL, or SKIP (never ERROR -- that is handled by _run()).
        """
        findings: list[Finding] = []
        notes: list[InfoNote] = []

        for item in result.raw_output.get("results", []):
            severity = str(item.get("severity", "")).upper()

            if severity in {"HIGH", "CRITICAL"}:
                # FAIL path: build a Finding for each violation.
                findings.append(
                    Finding(
                        title=f"[{severity}] {item.get('id', 'unknown')}",
                        detail=str(item.get("finding", "")),
                        references=list(_REFERENCES),
                        evidence_ref=artifact_ref,
                    )
                )

            elif severity in {"MEDIUM", "WARN"}:
                # PASS-with-note path: surface below-threshold items as InfoNote.
                # InfoNote objects appear as blue cards in the HTML report and do
                # NOT affect the test status or finding count.
                notes.append(
                    InfoNote(
                        title=f"[{severity}] Observation: {item.get('id', 'unknown')}",
                        detail=str(item.get("finding", "")),
                        references=list(_REFERENCES),
                    )
                )

        if findings:
            return self._make_fail(
                message=(
                    f"{len(findings)} finding(s) triggered FAIL oracle. "
                    f"See evidence artifact '{artifact_ref}' for raw output."
                ),
                findings=findings,
            )

        return self._make_pass(
            message=(
                f"No FAIL-grade findings in {result.raw_output.get('all_count', 0)} total result(s)."  # noqa: E501
                + (f" {len(notes)} informational note(s) below FAIL threshold." if notes else "")
            ),
            notes=notes,
        )
