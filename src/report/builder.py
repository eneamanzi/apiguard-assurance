"""
src/report/builder.py

Report data aggregator: transforms a completed ResultSet into a structured
ReportData object ready for Jinja2 template rendering.

This module is responsible exclusively for aggregation and computation.
It does not perform any I/O, does not read files, and does not produce
any output. Its single public function build_report_data() transforms
input data into a structured, pre-computed report model.

Separation of concerns:
    builder.py  -- aggregation and computation (this module)
    renderer.py -- Jinja2 template rendering and file I/O

Previously, this module contained two stub functions (_parse_domain_from_test_id
and _parse_priority_from_test_id) that inferred metadata from the test_id string
format. This was a workaround for the fact that TestResult did not carry the full
metadata from the BaseTest ClassVar declarations. Now that TestResult includes
test_name, domain, priority, strategy, tags, and cwe_id as proper fields (populated
by BaseTest helper methods at construction time), this module simply reads them
directly from each TestResult — no inference, no workarounds, no dependency on
the tests/ package needed.

Dependency rule:
    This module imports from stdlib, pydantic, structlog,
    src.core.models, and src.config.schema only.
    It must never import from engine.py, tests/, discovery/, or renderer.py.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

import structlog
from pydantic import BaseModel, Field

from src.config.schema import ToolConfig
from src.core.models import Finding, ResultSet, TestStatus, TransactionSummary

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DOMAIN_NAMES: dict[int, str] = {
    0: "API Discovery and Inventory Management",
    1: "Identity and Authentication",
    2: "Authorization and Access Control",
    3: "Data Integrity",
    4: "Availability and Resilience",
    5: "Visibility and Auditing",
    6: "Configuration and Hardening",
    7: "Business Logic and Sensitive Flows",
}

PRIORITY_LABELS: dict[int, str] = {
    0: "P0 — Critical",
    1: "P1 — High",
    2: "P2 — Medium",
    3: "P3 — Low",
}


# ---------------------------------------------------------------------------
# Report data models
# ---------------------------------------------------------------------------


class TestResultRow(BaseModel):
    """
    Flattened representation of a single TestResult for template rendering.

    Flattening avoids complex nested attribute access inside the Jinja2
    template, which has no type safety and where attribute errors manifest
    as silent empty strings rather than exceptions. Pre-computing all
    display values here keeps the template logic minimal.

    All fields are directly sourced from TestResult, which now carries the
    full BaseTest metadata (test_name, domain, priority, strategy, tags,
    cwe_id) populated at result-construction time.
    """

    model_config = {"frozen": True}

    test_id: str = Field(description="Test identifier, e.g. '1.2'.")
    test_name: str = Field(description="Human-readable test name.")
    domain: int = Field(description="Domain number (0-7).")
    domain_name: str = Field(description="Human-readable domain name.")
    priority: int = Field(description="Priority level (0-3).")
    priority_label: str = Field(description="Human-readable priority label.")
    strategy: str = Field(description="Strategy value string.")
    status: str = Field(description="Status value string (PASS/FAIL/SKIP/ERROR).")
    message: str = Field(description="One-line outcome summary.")
    skip_reason: str | None = Field(
        default=None,
        description="Skip reason, populated only for SKIP results.",
    )
    duration_ms: float | None = Field(
        default=None,
        description="Execution time in milliseconds.",
    )
    finding_count: int = Field(
        default=0,
        description="Number of Finding objects in this result.",
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="Finding objects, non-empty only for FAIL results.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Tags from the BaseTest class declaration.",
    )
    cwe_id: str = Field(
        default="",
        description="Primary CWE identifier from the BaseTest class declaration.",
    )
    transaction_log: list[TransactionSummary] = Field(
        default_factory=list,
        description=(
            "Complete ordered audit trail of all HTTP transactions performed during "
            "this test execution. Sourced from TestResult.transaction_log. "
            "Embedded in REPORT_DATA JSON for lazy rendering via the HTML audit trail "
            "section. Body content is absent by design — only metadata fields."
        ),
    )


class DomainSummary(BaseModel):
    """
    Aggregated statistics and test rows for a single methodology domain.

    One DomainSummary per domain (0-7) is included in ReportData.domains.
    Domains with no active tests are excluded from the list entirely.
    """

    model_config = {"frozen": True}

    domain: int = Field(description="Domain number (0-7).")
    domain_name: str = Field(description="Human-readable domain name.")
    rows: list[TestResultRow] = Field(
        description="Ordered list of test result rows for this domain.",
    )
    pass_count: Annotated[int, Field(ge=0)] = Field(default=0)
    fail_count: Annotated[int, Field(ge=0)] = Field(default=0)
    skip_count: Annotated[int, Field(ge=0)] = Field(default=0)
    error_count: Annotated[int, Field(ge=0)] = Field(default=0)
    total_finding_count: Annotated[int, Field(ge=0)] = Field(default=0)

    @property
    def total_count(self) -> int:
        """Total number of tests in this domain."""
        return len(self.rows)

    @property
    def has_failures(self) -> bool:
        """True if any test in this domain returned FAIL."""
        return self.fail_count > 0


class ExecutiveSummary(BaseModel):
    """
    High-level statistics for the report header and executive overview section.
    """

    model_config = {"frozen": True}

    total_tests: Annotated[int, Field(ge=0)] = Field(
        description="Total number of tests that were executed (PASS + FAIL + ERROR). "
        "Does not include SKIP."
    )
    pass_count: Annotated[int, Field(ge=0)] = Field(default=0)
    fail_count: Annotated[int, Field(ge=0)] = Field(default=0)
    skip_count: Annotated[int, Field(ge=0)] = Field(default=0)
    error_count: Annotated[int, Field(ge=0)] = Field(default=0)
    total_finding_count: Annotated[int, Field(ge=0)] = Field(
        description="Total number of Finding objects across all FAIL results.",
        default=0,
    )
    exit_code: int = Field(description="Process exit code computed from the ResultSet.")
    exit_code_label: str = Field(description="Human-readable label for the exit code.")
    pass_rate_pct: float = Field(
        description="Percentage of executed tests (excluding SKIP) that passed. "
        "Range: 0.0 to 100.0.",
        default=0.0,
    )
    assessment_duration_seconds: float | None = Field(
        default=None,
        description="Total wall-clock duration of the assessment in seconds.",
    )


class ReportData(BaseModel):
    """
    Complete, pre-computed data structure for the HTML report template.

    This model is the single input to renderer.py. The Jinja2 template
    accesses fields on this object directly, with no further computation.
    All display-ready values are computed here, not in the template.
    """

    model_config = {"frozen": True}

    run_id: str = Field(description="Unique run identifier from the engine.")
    generated_at_utc: str = Field(description="ISO 8601 UTC timestamp of report generation.")
    target_base_url: str = Field(description="Base URL of the assessed API.")
    spec_title: str = Field(description="OpenAPI spec title from the AttackSurface.")
    spec_version: str = Field(description="OpenAPI spec version from the AttackSurface.")
    min_priority_label: str = Field(
        description="Human-readable label for the configured min_priority."
    )
    strategies_label: str = Field(description="Comma-separated list of enabled strategy names.")
    executive_summary: ExecutiveSummary = Field(
        description="High-level statistics for the report header."
    )
    domains: list[DomainSummary] = Field(
        description="Per-domain breakdown, ordered by domain number. "
        "Domains with no active tests are excluded."
    )
    all_rows: list[TestResultRow] = Field(
        description="Flat list of all TestResultRow objects, ordered by test_id. "
        "Used for the full results table in the report appendix."
    )


# ---------------------------------------------------------------------------
# Exit code label mapping
# ---------------------------------------------------------------------------

_EXIT_CODE_LABELS: dict[int, str] = {
    0: "CLEAN — No violations detected",
    1: "FAIL — At least one security guarantee violated",
    2: "ERROR — At least one verification incomplete",
    10: "INFRASTRUCTURE ERROR — Assessment did not complete",
}


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def build_report_data(
    result_set: ResultSet,
    run_id: str,
    config: ToolConfig,
    spec_title: str = "Unknown",
    spec_version: str = "Unknown",
) -> ReportData:
    """
    Aggregate a completed ResultSet into a ReportData object for rendering.

    The spec_title and spec_version parameters allow the engine to pass
    metadata from the AttackSurface without requiring this module to import
    from discovery/. The previous two-function API (build_report_data and
    build_report_data_with_surface) has been unified into this single function
    with optional parameters and sensible defaults.

    Args:
        result_set: Completed ResultSet from the engine after Phase 6.
        run_id: Unique run identifier from the engine.
        config: ToolConfig for report metadata (target URL, strategies, etc.).
        spec_title: OpenAPI spec title from AttackSurface.spec_title.
                    Defaults to 'Unknown' when not provided.
        spec_version: OpenAPI spec version from AttackSurface.spec_version.
                      Defaults to 'Unknown' when not provided.

    Returns:
        Frozen ReportData ready for renderer.py.
    """
    log.info(
        "report_builder_aggregation_started",
        total_results=result_set.total_count,
        run_id=run_id,
    )

    all_rows = _build_all_rows(result_set)
    domains = _build_domain_summaries(all_rows)

    exit_code = result_set.compute_exit_code()
    executive_summary = _build_executive_summary(
        result_set=result_set,
        all_rows=all_rows,
        exit_code=exit_code,
    )

    min_priority_label = PRIORITY_LABELS.get(
        config.execution.min_priority,
        f"P{config.execution.min_priority}",
    )
    strategies_label = ", ".join(
        s.value for s in sorted(config.execution.strategies, key=lambda s: s.value)
    )

    report_data = ReportData(
        run_id=run_id,
        generated_at_utc=datetime.now(UTC).isoformat(),
        target_base_url=str(config.target.base_url),
        spec_title=spec_title,
        spec_version=spec_version,
        min_priority_label=min_priority_label,
        strategies_label=strategies_label,
        executive_summary=executive_summary,
        domains=domains,
        all_rows=all_rows,
    )

    log.info(
        "report_builder_aggregation_completed",
        pass_count=executive_summary.pass_count,
        fail_count=executive_summary.fail_count,
        skip_count=executive_summary.skip_count,
        error_count=executive_summary.error_count,
        total_findings=executive_summary.total_finding_count,
        exit_code=exit_code,
    )

    return report_data


# ---------------------------------------------------------------------------
# Internal aggregation helpers
# ---------------------------------------------------------------------------


def _build_all_rows(result_set: ResultSet) -> list[TestResultRow]:
    """
    Build a flat list of TestResultRow from all TestResult objects.

    Previously this function had to infer domain and priority from the
    test_id string (e.g., splitting '2.2' to get domain=2). That was a
    workaround for the absence of metadata on TestResult. Now that TestResult
    carries full metadata, this function is a straightforward mapping:
    each field on TestResultRow is read directly from the corresponding
    TestResult field.

    The domain_name is resolved from DOMAIN_NAMES using result.domain.
    If a result carries domain=-1 (default for results not constructed via
    BaseTest helpers), the domain_name falls back to 'Unknown Domain'.

    Args:
        result_set: Completed ResultSet.

    Returns:
        List of TestResultRow sorted by test_id.
    """
    rows: list[TestResultRow] = []

    for result in result_set.results:
        domain_name = DOMAIN_NAMES.get(result.domain, f"Domain {result.domain}")
        if result.domain == -1:
            domain_name = "Unknown Domain"

        row = TestResultRow(
            test_id=result.test_id,
            test_name=result.test_name if result.test_name else result.message,
            domain=result.domain,
            domain_name=domain_name,
            priority=result.priority,
            priority_label=PRIORITY_LABELS.get(result.priority, f"P{result.priority}"),
            strategy=result.strategy,
            status=result.status.value,
            message=result.message,
            skip_reason=result.skip_reason,
            duration_ms=result.duration_ms,
            finding_count=len(result.findings),
            findings=list(result.findings),
            tags=list(result.tags),
            cwe_id=result.cwe_id,
            transaction_log=list(result.transaction_log),
        )
        rows.append(row)

    rows.sort(key=lambda r: r.test_id)
    return rows


def _build_domain_summaries(all_rows: list[TestResultRow]) -> list[DomainSummary]:
    """
    Group TestResultRow objects by domain and compute per-domain statistics.

    Domains with no rows are excluded from the output list. The output
    list is sorted by domain number for consistent report section ordering.

    Args:
        all_rows: Flat list of all TestResultRow objects.

    Returns:
        List of DomainSummary, sorted by domain number, non-empty domains only.
    """
    domain_rows: dict[int, list[TestResultRow]] = {}
    for row in all_rows:
        domain_rows.setdefault(row.domain, []).append(row)

    summaries: list[DomainSummary] = []

    for domain_num in sorted(domain_rows.keys()):
        rows = domain_rows[domain_num]
        domain_name = DOMAIN_NAMES.get(domain_num, f"Domain {domain_num}")
        if domain_num == -1:
            domain_name = "Unknown Domain"

        pass_count = sum(1 for r in rows if r.status == TestStatus.PASS.value)
        fail_count = sum(1 for r in rows if r.status == TestStatus.FAIL.value)
        skip_count = sum(1 for r in rows if r.status == TestStatus.SKIP.value)
        error_count = sum(1 for r in rows if r.status == TestStatus.ERROR.value)
        total_finding_count = sum(r.finding_count for r in rows)

        summary = DomainSummary(
            domain=domain_num,
            domain_name=domain_name,
            rows=rows,
            pass_count=pass_count,
            fail_count=fail_count,
            skip_count=skip_count,
            error_count=error_count,
            total_finding_count=total_finding_count,
        )
        summaries.append(summary)

    return summaries


def _build_executive_summary(
    result_set: ResultSet,
    all_rows: list[TestResultRow],
    exit_code: int,
) -> ExecutiveSummary:
    """
    Compute the executive summary statistics from the ResultSet.

    The pass_rate_pct is computed over executed tests only (PASS + FAIL + ERROR),
    excluding SKIP. This is the most honest metric: SKIP tests did not contribute
    to the assessment outcome and should not inflate or deflate the pass rate.

    Args:
        result_set: Completed ResultSet.
        all_rows: Pre-built TestResultRow list (used for finding count).
        exit_code: Pre-computed exit code from ResultSet.compute_exit_code().

    Returns:
        Frozen ExecutiveSummary.
    """
    executed_count = result_set.pass_count + result_set.fail_count + result_set.error_count

    pass_rate = (
        round(result_set.pass_count / executed_count * 100.0, 1) if executed_count > 0 else 0.0
    )

    total_findings = sum(r.finding_count for r in all_rows)

    return ExecutiveSummary(
        total_tests=executed_count,
        pass_count=result_set.pass_count,
        fail_count=result_set.fail_count,
        skip_count=result_set.skip_count,
        error_count=result_set.error_count,
        total_finding_count=total_findings,
        exit_code=exit_code,
        exit_code_label=_EXIT_CODE_LABELS.get(exit_code, f"Exit code {exit_code}"),
        pass_rate_pct=pass_rate,
        assessment_duration_seconds=result_set.duration_seconds,
    )
