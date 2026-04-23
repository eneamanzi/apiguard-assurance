"""
src/core/models/results.py

Test result models for the APIGuard Assurance tool.

Contains the complete result hierarchy produced by test executions and
accumulated by the engine over a pipeline run.

    Finding     -- Unit of technical evidence produced by a FAIL result.
    InfoNote    -- Informational annotation for PASS results (non-violation context).
    TestResult  -- Complete outcome of a single BaseTest.execute() call.
    ResultSet   -- Ordered collection of all TestResult objects for a pipeline run.

Dependency rule: this module imports only from pydantic, the stdlib, and
sibling modules within src.core.models. It must never import from any other
src/ package.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field, field_validator, model_validator

from src.core.models.enums import TestStatus
from src.core.models.http import TransactionSummary

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

    title: str = Field(description="Short description of the violated guarantee.")
    detail: str = Field(
        description="Technical description, specific enough to reproduce the finding."
    )
    references: list[str] = Field(
        default_factory=list,
        description="Standard references: 'CWE-287', 'OWASP-API2:2023', 'RFC-8725'.",
    )
    evidence_ref: str | None = Field(
        default=None,
        description="record_id of the EvidenceRecord in EvidenceStore proving this finding.",
    )

    @field_validator("title", "detail")
    @classmethod
    def must_not_be_empty(cls, value: str) -> str:
        """Reject empty strings for mandatory narrative fields."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("Field must not be empty or whitespace-only.")
        return stripped


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

    Design rationale (Implementazione.md, Section 4.6):
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
                references=["OWASP-ASVS-v5.0.0-V16.5.2"],
            )
        ]
        return TestResult(status=TestStatus.PASS, findings=[], notes=notes, ...)
    """

    title: str = Field(description="Short description of the informational context.")
    detail: str = Field(description="Technical detail, specific enough for an analyst to act on.")
    references: list[str] = Field(
        default_factory=list,
        description="Standard references: 'OWASP-ASVS-v5.0.0-V16.5.2', 'CWE-400'.",
    )

    @field_validator("title", "detail")
    @classmethod
    def must_not_be_empty(cls, value: str) -> str:
        """Reject empty strings for mandatory narrative fields."""
        stripped = value.strip()
        if not stripped:
            raise ValueError("Field must not be empty or whitespace-only.")
        return stripped


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
        test via BaseTest._log_transaction() during execute(). It is embedded
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
            "Populated by BaseTest._log_transaction() — no cap applied. "
            "Embedded in the HTML report as a collapsible table. "
            "NOT serialized to evidence.json (which stores only EvidenceRecord)."
        ),
    )

    # --- Test metadata ---
    # Copied from BaseTest ClassVar at result-construction time via
    # _metadata_kwargs(). Allows builder.py to produce a complete report
    # without importing from tests/ (unidirectional dependency rule).
    test_name: str = Field(default="")
    domain: int = Field(default=-1)
    priority: int = Field(default=0)
    strategy: str = Field(default="")
    tags: list[str] = Field(default_factory=list)
    cwe_id: str = Field(default="")

    @model_validator(mode="after")
    def validate_status_finding_consistency(self) -> TestResult:
        """
        Enforce the invariant between status and findings list.

        FAIL  -> findings must be non-empty (evidence is mandatory).
        PASS  -> findings must be empty (no violation detected).
                 notes (list[InfoNote]) are NOT constrained: a PASS result
                 may carry informational annotations documenting compensating
                 controls or architectural gaps without these representing
                 security violations.
        SKIP  -> findings empty, skip_reason must be present.
        ERROR -> findings may be empty or non-empty.
        """
        if self.status == TestStatus.FAIL and not self.findings:
            raise ValueError(
                "A TestResult with status=FAIL must contain at least one Finding. "
                "A FAIL without evidence is not a valid assessment outcome."
            )
        if self.status == TestStatus.PASS and self.findings:
            raise ValueError(
                f"A TestResult with status=PASS must have an empty findings list. "
                f"Found {len(self.findings)} finding(s). Use status=FAIL instead."
            )
        if self.status == TestStatus.SKIP and not self.skip_reason:
            raise ValueError(
                "A TestResult with status=SKIP must provide a skip_reason. "
                "SKIP without explanation is indistinguishable from a silent failure."
            )
        return self


# ---------------------------------------------------------------------------
# ResultSet — ordered collection of all TestResult for one pipeline run
# ---------------------------------------------------------------------------


class ResultSet(BaseModel):
    """
    Ordered collection of all TestResult objects produced during a pipeline run.

    Primary input to report/builder.py and source of truth for exit code
    calculation. Built incrementally by the engine during Phase 5.
    """

    results: list[TestResult] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = Field(default=None)

    def add_result(self, result: TestResult) -> None:
        """Append a TestResult to the collection."""
        self.results.append(result)

    def compute_exit_code(self) -> int:
        """
        Compute the process exit code from the current ResultSet state.

        Priority: FAIL (1) > ERROR (2) > CLEAN (0).
        Exit code 10 (infrastructure error) is handled upstream by the engine.
        """
        if any(r.status == TestStatus.FAIL for r in self.results):
            return 1
        if any(r.status == TestStatus.ERROR for r in self.results):
            return 2
        return 0

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
