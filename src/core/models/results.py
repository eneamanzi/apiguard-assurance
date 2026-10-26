"""
src/core/models/results.py

Test result models for the APIGuard Assurance tool.

Contains the complete result hierarchy produced by test executions and
accumulated by the engine over a pipeline run.

    Finding        -- Unit of technical evidence produced by a FAIL result.
    InfoNote       -- Informational annotation for PASS results (non-violation context).
    SubTestResult  -- Counters and status of one declared sub-test.
    TestResult     -- Complete outcome of a single BaseTest.execute() call.
    ResultSet      -- Ordered collection of all TestResult objects for a pipeline run.

The status rule lives here, next to the models it constrains
(docs/project/test-review.md, topic 3): status_from_counts() gives a
sub-test's status from its counters, combine_sub_tests() gives the test's
status and coverage from its sub-tests. A test records outcomes; it never
chooses PASS, FAIL or INCONCLUSIVE.

Dependency rule: this module imports only from pydantic, the stdlib, and
sibling modules within src.core.models. It must never import from any other
src/ package.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from src.core.models.enums import Confidence, Coverage, ExitCode, NotRunReason, TestStatus
from src.core.models.http import TransactionSummary
from src.core.models.standards import Reference, duplicate_references

# ---------------------------------------------------------------------------
# Finding — unit of technical evidence
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """
    A single unit of technical evidence produced when a test detects a
    violation of a security guarantee.

    Deliberately free of severity judgment. The tool provides objective
    technical evidence; severity assessment is delegated to the analyst
    or external risk-scoring systems.

    One TestResult(status=FAIL) must contain at least one Finding.
    One TestResult may contain multiple Findings for distinct violations.
    """

    title: str = Field(description="Short description of the violation.")
    detail: str = Field(description="Technical description, specific enough to reproduce.")
    references: list[Reference] = Field(
        default_factory=list,
        description="The standards the violation breaks (src/core/models/standards.py).",
    )
    evidence_ref: str | None = Field(
        default=None,
        description="`record_id` of the proof in `evidence.json`.",
    )
    confidence: Confidence = Field(
        description=(
            "How sure the tool is that the violation is real: `CERTAIN` (the observed fact, or "
            "proven by a positive control), `FIRM` (resting on one stated assumption), "
            "`TENTATIVE` (a heuristic or an indirect sign). Not a severity."
        )
    )
    supporting_refs: list[str] = Field(
        default_factory=list,
        description=(
            "`record_id`s of the reference responses the verdict rests on (calibration probes, "
            "positive controls: `ref_NNN` in `evidence.json`)."
        ),
    )

    @field_validator("title", "detail")
    @classmethod
    def must_not_be_empty(cls, value: str) -> str:
        """Reject empty strings for mandatory narrative fields."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("Field must not be empty or whitespace-only.")
        return stripped

    @field_validator("references")
    @classmethod
    def references_unique(cls, value: list[Reference]) -> list[Reference]:
        """Reject a standard cited more than once."""
        duplicates = duplicate_references(value)
        if duplicates:
            raise ValueError(f"references cited more than once: {duplicates}")
        return value


# ---------------------------------------------------------------------------
# InfoNote — informational annotation for PASS results
# ---------------------------------------------------------------------------


class InfoNote(BaseModel):
    """
    A non-security-finding annotation attached to a PASS TestResult.

    InfoNote is semantically distinct from Finding:

        Finding  -- evidence of a security guarantee VIOLATION.
                    Attached only to FAIL results. Counted in totals.
                    Rendered in red in the HTML report.

        InfoNote -- informational annotation documenting architectural context,
                    compensating controls, or observability gaps on a PASS result.
                    Does NOT represent a violation. NOT counted in finding totals.
                    Does NOT affect the test status or exit code.
                    Rendered in blue in the HTML report.

    Design rationale (docs/04-architecture/02-data-model.md, "Results"):
        The model_validator on TestResult enforces that a PASS result must have
        zero Findings. This is correct: a PASS with findings would be a
        contradiction in terms. However, some tests need to surface contextual
        information alongside a PASS — for example, Test 4.3 Level 2, which
        PASSES via a compensating control and needs to explain the architectural
        difference between a passive healthcheck and a true circuit breaker.

        InfoNote solves this without relaxing the model_validator invariant.
        It is a separate field (TestResult.notes) that the validator does not
        constrain, and the HTML report renders it in a visually distinct blue
        card to make the semantic difference immediately clear to the analyst.

    Usage:
        notes: list[InfoNote] = [
            InfoNote(
                title="Compensating Control: Upstream Passive HC",
                detail="...",
                references=[Reference(standard=Standard.ASVS, id="v5.0.0-16.5.2")],
            )
        ]
        return TestResult(status=TestStatus.PASS, findings=[], notes=notes, ...)
    """

    title: str = Field(
        description=(
            "What the analyst should know (e.g. a compensating control, a skipped sub-check)."
        )
    )
    detail: str = Field(description="The context, in full.")
    references: list[Reference] = Field(
        default_factory=list,
        description="The standards the note relates to.",
    )

    @field_validator("title", "detail")
    @classmethod
    def must_not_be_empty(cls, value: str) -> str:
        """Reject empty strings for mandatory narrative fields."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("Field must not be empty or whitespace-only.")
        return stripped

    @field_validator("references")
    @classmethod
    def references_unique(cls, value: list[Reference]) -> list[Reference]:
        """Reject a standard cited more than once."""
        duplicates = duplicate_references(value)
        if duplicates:
            raise ValueError(f"references cited more than once: {duplicates}")
        return value


# ---------------------------------------------------------------------------
# SubTestResult — counters and status of one sub-test, and the status rule
# ---------------------------------------------------------------------------

# The statuses a finished sub-test or test can have, computed from counters.
_COMPUTED_STATUSES: frozenset[TestStatus] = frozenset(
    {TestStatus.PASS, TestStatus.FAIL, TestStatus.INCONCLUSIVE, TestStatus.SKIP}
)


def status_from_counts(violations: int, enforced: int, not_verifiable: int) -> TestStatus:
    """
    The status of a finished sub-test, from its counters.

    The first rule that holds decides: a violation gives FAIL; otherwise a
    verified case gives PASS; otherwise a case that could not be verified gives
    INCONCLUSIVE; otherwise (only not applicable cases, or none) SKIP.

    Args:
        violations:     Cases judged VIOLATION.
        enforced:       Cases judged ENFORCED.
        not_verifiable: Cases judged NOT_VERIFIABLE.

    Returns:
        FAIL, PASS, INCONCLUSIVE or SKIP.
    """
    if violations > 0:
        return TestStatus.FAIL
    if enforced > 0:
        return TestStatus.PASS
    if not_verifiable > 0:
        return TestStatus.INCONCLUSIVE
    return TestStatus.SKIP


class SubTestResult(BaseModel):
    """
    The counters and status of one sub-test a test declares.

    Built with from_counts(), which computes the status and the coverage, so
    that the counters and the status can never disagree. Every sub-test the
    test declares has one, even when nothing was judged in it (SKIP).
    """

    model_config = {"frozen": True}

    name: str = Field(description="The sub-test's name, as the test declares it.")
    status: TestStatus = Field(
        description="`PASS`, `FAIL`, `INCONCLUSIVE` or `SKIP`, computed from the counters."
    )
    coverage: Coverage | None = Field(
        default=None,
        description="For a PASS: `complete`, or `partial` when cases were not verifiable.",
    )
    violations: int = Field(ge=0, description="Cases judged `VIOLATION`.")
    enforced: int = Field(ge=0, description="Cases judged `ENFORCED`.")
    not_verifiable: int = Field(ge=0, description="Cases judged `NOT_VERIFIABLE`.")
    not_applicable: int = Field(ge=0, description="Cases judged `NOT_APPLICABLE`.")
    not_verifiable_reasons: dict[str, int] = Field(
        default_factory=dict,
        description="Why cases were not verifiable: each detail and how many times.",
    )

    @classmethod
    def from_counts(
        cls,
        name: str,
        *,
        violations: int,
        enforced: int,
        not_applicable: int,
        not_verifiable_reasons: dict[str, int],
    ) -> SubTestResult:
        """
        Build a sub-test's result, computing its status and coverage.

        Args:
            name:                   The sub-test's declared name.
            violations:             Cases judged VIOLATION.
            enforced:               Cases judged ENFORCED.
            not_applicable:         Cases judged NOT_APPLICABLE.
            not_verifiable_reasons: The details of the NOT_VERIFIABLE cases
                                    and their counts.

        Returns:
            The SubTestResult.
        """
        not_verifiable = sum(not_verifiable_reasons.values())
        status = status_from_counts(violations, enforced, not_verifiable)
        coverage = None
        if status == TestStatus.PASS:
            coverage = Coverage.PARTIAL if not_verifiable else Coverage.COMPLETE
        return cls(
            name=name,
            status=status,
            coverage=coverage,
            violations=violations,
            enforced=enforced,
            not_verifiable=not_verifiable,
            not_applicable=not_applicable,
            not_verifiable_reasons=dict(not_verifiable_reasons),
        )

    @model_validator(mode="after")
    def counters_and_status_agree(self) -> SubTestResult:
        """Reject a status, coverage or reason count that the counters contradict."""
        expected = status_from_counts(self.violations, self.enforced, self.not_verifiable)
        if self.status != expected:
            raise ValueError(
                f"sub-test {self.name!r}: status {self.status} contradicts its counters "
                f"(expected {expected})"
            )
        if sum(self.not_verifiable_reasons.values()) != self.not_verifiable:
            raise ValueError(
                f"sub-test {self.name!r}: the reasons count "
                f"{sum(self.not_verifiable_reasons.values())} cases, not_verifiable is "
                f"{self.not_verifiable}"
            )
        if (self.coverage is not None) != (self.status == TestStatus.PASS):
            raise ValueError(f"sub-test {self.name!r}: coverage is set only for a PASS")
        return self


def combine_sub_tests(sub_tests: list[SubTestResult]) -> tuple[TestStatus, Coverage | None]:
    """
    The status and coverage of a finished test, from its sub-tests.

    A sub-test FAIL gives FAIL; otherwise a sub-test PASS gives PASS, partial
    when another sub-test is INCONCLUSIVE or a PASS sub-test is partial;
    otherwise a sub-test INCONCLUSIVE gives INCONCLUSIVE; otherwise SKIP
    (nothing the test applies to).

    Args:
        sub_tests: Every declared sub-test's result.

    Returns:
        (status, coverage); coverage is None unless the status is PASS.
    """
    statuses = {sub.status for sub in sub_tests}
    if TestStatus.FAIL in statuses:
        return TestStatus.FAIL, None
    if TestStatus.PASS in statuses:
        partial = TestStatus.INCONCLUSIVE in statuses or any(
            sub.coverage == Coverage.PARTIAL for sub in sub_tests
        )
        return TestStatus.PASS, Coverage.PARTIAL if partial else Coverage.COMPLETE
    if TestStatus.INCONCLUSIVE in statuses:
        return TestStatus.INCONCLUSIVE, None
    return TestStatus.SKIP, None


# ---------------------------------------------------------------------------
# TestResult — complete outcome of one test execution
# ---------------------------------------------------------------------------


class TestResult(BaseModel):
    """
    Complete outcome of a single BaseTest.execute() call.

    TestResult is the only object BaseTest.execute() may return.
    Raw exceptions are caught internally and converted to status=ERROR.

    Transaction log (full audit trail):
        transaction_log holds every TransactionSummary accumulated by the
        test via BaseTest._judge() and _step() during execute(). It is embedded
        in the HTML report as a collapsible table inside the expanded row panel.

        NO CAP is applied. The ultra-lightweight TransactionSummary design
        (~160 bytes, no body content) makes a cap architecturally unnecessary:
        - 2000 entries (worst case, Test 4.1) = 320 KB of JSON in HTML
        - Full assessment (2885 entries estimated) = 461 KB
        Both values are safe for browser rendering and Python RAM.

        Body content is absent by design. Reproducibility of FAIL payloads
        is guaranteed by EvidenceStore / evidence.json (full EvidenceRecord).
        The transaction_log provides COVERAGE proof, not payload detail.
    """

    __test__ = False

    test_id: str = Field(
        description="Unique test identifier matching BaseTest.test_id, e.g. '1.2'."
    )
    status: TestStatus = Field(description="Outcome of the test execution.")
    message: str = Field(description="One-line summary of the test outcome.")
    findings: list[Finding] = Field(
        default_factory=list,
        description="Technical evidence units. Non-empty only for FAIL (mandatory).",
    )
    notes: list[InfoNote] = Field(
        default_factory=list,
        description=(
            "Informational annotations for PASS results. "
            "Semantically distinct from findings: notes document architectural context, "
            "compensating controls, or observability gaps without representing a "
            "security violation. Rendered in blue in the HTML report. "
            "NOT counted in finding totals. NOT constrained by the PASS/FAIL validator."
        ),
    )
    skip_reason: str | None = Field(
        default=None,
        description="Why the test was skipped. Populated only for status=SKIP.",
    )
    coverage: Coverage | None = Field(
        default=None,
        description=(
            "For a PASS: `complete` when every applicable case was verified, `partial` when "
            "some could not be (a sub-test `INCONCLUSIVE`, or not verifiable cases)."
        ),
    )
    sub_tests: list[SubTestResult] = Field(
        default_factory=list,
        description=(
            "One entry per sub-test the test declares, with its counters and status; empty "
            "when the test stopped before judging (SKIP before the start, ERROR)."
        ),
    )
    duration_ms: float | None = Field(
        default=None,
        description="Wall-clock execution time in milliseconds, set by the engine.",
    )

    # --- Full audit trail (new in v1.1) ---
    transaction_log: list[TransactionSummary] = Field(
        default_factory=list,
        description=(
            "Complete ordered audit trail of ALL HTTP transactions performed "
            "during this test execution, including successful ones. "
            "Populated by BaseTest._judge() and _step(), no cap applied. "
            "Embedded in the HTML report as a collapsible table. "
            "NOT serialized to evidence.json (which stores only EvidenceRecord)."
        ),
    )

    # --- Test metadata ---
    # Copied from the test's declaration (info, TestInfo) when the result is
    # built (src/core/assessment_test.py). Allows builder.py to produce a
    # complete report without importing from tests/ (unidirectional
    # dependency rule).
    test_name: str = Field(
        default="",
        description="Human-readable test name, from the test's declaration (info.name).",
    )
    domain: int = Field(
        default=-1,
        description="Test domain (0-7); -1 if metadata not populated.",
    )
    priority: int = Field(
        default=0,
        description="Test priority (0=P0 critical, 1=P1, 2=P2, 3=P3 low).",
    )
    strategy: str = Field(
        default="",
        description="Test strategy: 'BLACK_BOX', 'GREY_BOX', or 'WHITE_BOX'.",
    )
    effect: str = Field(
        default="",
        description="The test's declared effect: 'READ_ONLY', 'CHANGES_DATA' or 'STRESSES_TARGET'.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Topic labels from the test's declaration (e.g. `availability`).",
    )
    references: list[Reference] = Field(
        default_factory=list,
        description="The standards of the guarantee, from the test's declaration.",
    )
    cwe_id: str = Field(
        default="",
        description=(
            "Primary CWE identifier addressed by the test (e.g. `CWE-287`); empty when the "
            "test declares none because no catalogue entry describes its weakness."
        ),
    )

    # --- External tool identifier ---
    # Populated exclusively for source='external' results, from the test's
    # declaration (info.tool: "testssl", "sslyze", "nuclei") so the HTML report can display
    # it in the dedicated "Tool" column of the External Tool Tests sub-table
    # without requiring any import from external_tests/ in builder.py.
    # Empty string for all source='native' results.
    tool_name: str = Field(
        default="",
        description=(
            "Name of the external binary used by this test. "
            "Non-empty only for source='external' results. "
            "Taken from the test's declaration (info.tool, e.g. 'testssl', "
            "'sslyze', 'nuclei'). "
            "Rendered in the 'Tool' column of the External Tool Tests sub-table."
        ),
    )

    # --- Result origin (ADR-001 §8.5 — promoted to architectural primitive) ---
    # Populated by TestRegistry ("native") or ExternalTestRegistry ("external").
    # Drives the Domain-Centric Split in report/builder.py: the builder partitions
    # each domain's results into two distinct blocks — native controls and external
    # scanner analysis — based exclusively on this field.
    # The engine never writes this field; it arrives pre-valorised inside the
    # TestResult returned by execute().
    source: Literal["native", "external"] = Field(
        default="native",
        description=(
            "Origin of the TestResult. 'native' = produced by a Python BaseTest "
            "running via SecurityClient. 'external' = produced by an ExternalToolTest "
            "wrapping a binary (ffuf, testssl.sh, nuclei). "
            "Used by report/builder.py to partition results per domain."
        ),
    )

    # --- Raw external tool output (ADR-001 §8.5) ---
    # Populated exclusively by ExternalToolTest._run() via model_copy() after
    # _evaluate() returns. Contains ConnectorResult.raw_output dict.
    # Embedded in the HTML report for the Tool Output modal without needing
    # evidence.json as a separate file. Always None for source='native' results.
    tool_artifact: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Raw output dict from the external tool (ConnectorResult.raw_output). "
            "Populated only for source='external' results by ExternalToolTest._run(). "
            "Embedded in the self-contained HTML report for the Tool Output modal. "
            "None for all source='native' results."
        ),
    )

    # --- Artifact cross-reference fields (populated alongside tool_artifact) ---
    # These two fields carry the label and record_id produced by
    # EvidenceStore.pin_artifact() so that the HTML report's Tool Output modal
    # can reconstruct the exact filename used by _persist_tool_artifact() on
    # disk (outputs/tools/<label_safe>_output.json) for the browser download,
    # and can embed the record_id in the download envelope for cross-referencing
    # with evidence.json.
    #
    # Without these fields, the JS in the template would have to re-derive the
    # label from testId.  Storing the actual label used by pin_artifact() keeps
    # the disk file and the download envelope in lock-step.
    #
    # Both fields are None for source='native' results and for external results
    # where pin_artifact() was never called (e.g. SKIP, ERROR before Step 4).
    tool_artifact_label: str | None = Field(
        default=None,
        description=(
            "Label passed to EvidenceStore.pin_artifact() when the tool artifact "
            "was stored. Format: '{test_id}_{tool_name_safe}', e.g. 'ext.0.1_nuclei'. "
            "The HTML report uses this to reconstruct the disk filename "
            "('<label_safe>_output.json') for the browser download button, ensuring "
            "the downloaded file has the same name as the on-disk artifact. "
            "None for source='native' results and for external results that SKIPped "
            "before the artifact pinning step."
        ),
    )
    tool_artifact_record_id: str | None = Field(
        default=None,
        description=(
            "Record ID returned by EvidenceStore.pin_artifact() for this artifact. "
            "Embedded in the JSON download envelope so the downloaded file can be "
            "cross-referenced with the corresponding record in evidence.json. "
            "None for source='native' results and for external results that SKIPped "
            "before the artifact pinning step."
        ),
    )

    @model_validator(mode="after")
    def validate_status_finding_consistency(self) -> TestResult:
        """
        Enforce the invariants between status, findings, coverage and sub-tests.

        FAIL         -> findings must be non-empty (evidence is mandatory).
        PASS         -> findings must be empty; coverage must be set.
        INCONCLUSIVE -> findings must be empty (nothing was proven violated).
        SKIP         -> findings empty, skip_reason must be present.
        ERROR        -> findings may be empty or non-empty.
        coverage is set only for a PASS. When sub-tests are present and the
        status is computed (not ERROR), the status and coverage must be those
        combine_sub_tests() gives. notes (list[InfoNote]) are never
        constrained.
        """
        if self.status == TestStatus.FAIL and not self.findings:
            raise ValueError(
                "A TestResult with status=FAIL must contain at least one Finding. "
                "A FAIL without evidence is not a valid assessment outcome."
            )
        if self.status in (TestStatus.PASS, TestStatus.INCONCLUSIVE) and self.findings:
            raise ValueError(
                f"A TestResult with status={self.status} must have an empty findings list. "
                f"Found {len(self.findings)} finding(s): a violation makes it FAIL."
            )
        if self.status == TestStatus.SKIP and not self.skip_reason:
            raise ValueError(
                "A TestResult with status=SKIP must provide a skip_reason. "
                "SKIP without explanation is indistinguishable from a silent failure."
            )
        if (self.coverage is not None) != (self.status == TestStatus.PASS):
            raise ValueError("coverage is set for a PASS, and only for a PASS.")
        if self.sub_tests and self.status in _COMPUTED_STATUSES:
            expected = combine_sub_tests(self.sub_tests)
            if (self.status, self.coverage) != expected:
                raise ValueError(
                    f"status {self.status} / coverage {self.coverage} contradict the sub-tests "
                    f"(expected {expected[0]} / {expected[1]})."
                )
        return self


# ---------------------------------------------------------------------------
# NotRunEntry — a test of the tool that the run did not execute
# ---------------------------------------------------------------------------


class NotRunEntry(BaseModel):
    """
    A test of the tool that was not executed in this run, and why.

    Built by the registries (filters) and by the engine (fail-fast). With the
    TestResults of the run, it accounts for every test of the tool: executed
    + not run = all tests.
    """

    model_config = {"frozen": True}

    test_id: str = Field(description="The test's ID.")
    test_name: str = Field(description="The test's name.")
    source: Literal["native", "external"] = Field(description="`native` or `external`.")
    reason: NotRunReason = Field(
        description=(
            "`priority` (above `min_priority`), `strategy` (not in `strategies`), "
            "`not_in_test_ids` (`test_ids` set and not listing it), `tool_disabled` "
            "(external tool or master switch off), `fail_fast` (the run stopped earlier)."
        )
    )
    detail: str = Field(
        description=(
            "The values that excluded it, e.g. `priority P2 is above execution.min_priority "
            "(P1)`, `external_tools.enabled is false`, `execution.fail_fast: the run "
            "stopped after 0.1 returned FAIL`."
        )
    )


# ---------------------------------------------------------------------------
# ResultSet — ordered collection of all TestResult for one pipeline run
# ---------------------------------------------------------------------------


class ResultSet(BaseModel):
    """
    Ordered collection of all TestResult objects produced during a pipeline run.

    Primary input to report/builder.py and source of truth for exit code
    calculation. Built incrementally by the engine during Phase 5.
    """

    results: list[TestResult] = Field(
        default_factory=list,
        description="All TestResult objects produced during Phase 5, in scheduling order.",
    )
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp when ResultSet was instantiated (start of Phase 5).",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="UTC timestamp when Phase 5 finished; None while still in progress.",
    )
    not_run: list[NotRunEntry] = Field(
        default_factory=list,
        description=(
            "Tests of the tool not executed in this run, with the reason "
            "(filters from Phase 4, fail-fast from Phase 5), sorted by test_id."
        ),
    )

    def add_result(self, result: TestResult) -> None:
        """Append a TestResult to the collection."""
        self.results.append(result)

    def compute_exit_code(self) -> ExitCode:
        """
        Compute the process exit code from the current ResultSet state.

        Priority: FAIL (1) > ERROR or INCONCLUSIVE (3) > CLEAN (0): an
        INCONCLUSIVE test, like an ERROR, is a verification that did not
        complete. Exit code 10 (infrastructure error) is handled upstream by
        the engine.
        """
        if any(r.status == TestStatus.FAIL for r in self.results):
            return ExitCode.FAIL
        if any(r.status in (TestStatus.ERROR, TestStatus.INCONCLUSIVE) for r in self.results):
            return ExitCode.ERROR
        return ExitCode.CLEAN

    @property
    def total_count(self) -> int:
        """Total number of test results."""
        return len(self.results)

    @property
    def pass_count(self) -> int:
        """Number of PASS results."""
        return sum(1 for r in self.results if r.status == TestStatus.PASS)

    @property
    def fail_count(self) -> int:
        """Number of FAIL results."""
        return sum(1 for r in self.results if r.status == TestStatus.FAIL)

    @property
    def skip_count(self) -> int:
        """Number of SKIP results."""
        return sum(1 for r in self.results if r.status == TestStatus.SKIP)

    @property
    def error_count(self) -> int:
        """Number of ERROR results."""
        return sum(1 for r in self.results if r.status == TestStatus.ERROR)

    @property
    def inconclusive_count(self) -> int:
        """Number of INCONCLUSIVE results."""
        return sum(1 for r in self.results if r.status == TestStatus.INCONCLUSIVE)

    @property
    def total_finding_count(self) -> int:
        """Total Finding objects across all FAIL results."""
        return sum(len(r.findings) for r in self.results)

    @property
    def total_transaction_count(self) -> int:
        """
        Total TransactionSummary entries across all TestResult objects.

        Represents the complete number of HTTP requests sent to the target
        during the assessment. Used in the HTML report executive summary
        stat card 'HTTP Requests Sent'.
        """
        return sum(len(r.transaction_log) for r in self.results)

    @property
    def duration_seconds(self) -> float | None:
        """Total assessment duration in seconds. None if not yet completed."""
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()
