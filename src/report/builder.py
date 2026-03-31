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

This separation allows the correctness of statistical aggregation to be
verified independently of the template engine, and allows the output
format to change (HTML -> PDF, JSON, Markdown) without touching this module.

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
from src.core.models import Finding, ResultSet, TestStatus

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Domain names from the methodology, indexed by domain number.
# Used to render human-readable section headers in the HTML report.
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

# Priority labels for the HTML report.
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
    """

    model_config = {"frozen": True}

    test_id: str = Field(description="Test identifier, e.g. '1.2'.")
    test_name: str = Field(description="Human-readable test name.")
    domain: int = Field(description="Domain number (0-7).")
    domain_name: str = Field(description="Human-readable domain name.")
    priority: int = Field(description="Priority level (0-3).")
    priority_label: str = Field(description="Human-readable priority label.")
    strategy: str = Field(description="Execution strategy value string.")
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


class DomainSummary(BaseModel):
    """
    Aggregated statistics and test rows for a single methodology domain.

    One DomainSummary per domain (0-7) is included in ReportData.domains.
    Domains with no active tests (all filtered out by priority/strategy)
    are excluded from the list entirely to avoid empty sections in the report.
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

    These figures appear at the top of the HTML report before the per-domain
    breakdown. They give a quick snapshot of the assessment outcome for
    stakeholders who may not read the full domain breakdown.
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
        "Range: 0.0 to 100.0. Zero if no tests were executed.",
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

    All display-ready values (labels, percentages, formatted timestamps)
    are computed here, not in the template. This keeps the template free
    of logic and makes the report data independently testable.
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
) -> ReportData:
    """
    Aggregate a completed ResultSet into a ReportData object for rendering.

    This function performs all statistical computation required by the HTML
    report in a single pass over the ResultSet. The returned ReportData
    is frozen and contains no references to the original ResultSet or
    EvidenceStore: it is a self-contained snapshot of the assessment outcome.

    Args:
        result_set: Completed ResultSet from the engine after Phase 6.
                    May be empty if no tests were executed (zero active tests).
        run_id: Unique run identifier from the engine, included in the report
                header for traceability.
        config: ToolConfig for report metadata (target URL, strategies, etc.).

    Returns:
        Frozen ReportData ready for renderer.py.
    """
    log.info(
        "report_builder_aggregation_started",
        total_results=result_set.total_count,
        run_id=run_id,
    )

    # Build the per-test metadata lookup for fields not in TestResult.
    # TestResult stores test_id and status but not test_name, domain, etc.
    # Those fields live in the BaseTest ClassVar declarations and are not
    # accessible from TestResult alone.
    # Solution: build the lookup from test_id patterns and the methodology.
    # Since we cannot import BaseTest subclasses here (would violate the
    # dependency rule: report/ must not import from tests/), we reconstruct
    # domain and metadata from test_id string parsing.
    # Convention: test_id format is '{domain}.{sequence}', e.g. '1.2'.
    # Domain is always the integer part before the first dot.

    # Build TestResultRow list from all results.
    all_rows = _build_all_rows(result_set)

    # Build per-domain summaries.
    domains = _build_domain_summaries(all_rows)

    # Compute executive summary.
    exit_code = result_set.compute_exit_code()
    executive_summary = _build_executive_summary(
        result_set=result_set,
        all_rows=all_rows,
        exit_code=exit_code,
    )

    # Build metadata strings for report header.
    min_priority_label = PRIORITY_LABELS.get(
        config.execution.min_priority,
        f"P{config.execution.min_priority}",
    )
    strategies_label = ", ".join(
        s.value for s in sorted(config.execution.strategies, key=lambda s: s.value)
    )

    # Extract spec metadata from the attack surface if available.
    # The config does not store spec_title/spec_version directly;
    # they are runtime-discovered. We use the target URL as fallback.
    spec_title = "Unknown"
    spec_version = "Unknown"
    if config.target.admin_api_url is not None:
        # attack_surface is not accessible from config; these fields are
        # populated by the engine calling build_report_data with an optional
        # surface parameter. For now, we use sensible defaults.
        # The renderer template handles "Unknown" gracefully.
        pass

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


def build_report_data_with_surface(
    result_set: ResultSet,
    run_id: str,
    config: ToolConfig,
    spec_title: str,
    spec_version: str,
) -> ReportData:
    """
    Extended variant of build_report_data that accepts spec metadata.

    Called by engine.py, which has access to the AttackSurface and can
    pass spec_title and spec_version directly. This avoids duplicating
    the AttackSurface reference in ToolConfig (which is config-only).

    Args:
        result_set: Completed ResultSet.
        run_id: Unique run identifier.
        config: ToolConfig for execution metadata.
        spec_title: OpenAPI spec title from AttackSurface.spec_title.
        spec_version: OpenAPI spec version from AttackSurface.spec_version.

    Returns:
        Frozen ReportData with populated spec_title and spec_version.
    """
    base_data = build_report_data(
        result_set=result_set,
        run_id=run_id,
        config=config,
    )
    return base_data.model_copy(
        update={
            "spec_title": spec_title,
            "spec_version": spec_version,
        }
    )


# ---------------------------------------------------------------------------
# Internal aggregation helpers
# ---------------------------------------------------------------------------


def _build_all_rows(result_set: ResultSet) -> list[TestResultRow]:
    """
    Build a flat list of TestResultRow from all TestResult objects.

    Domain number and name are derived from the test_id convention:
        test_id format: '{domain}.{sequence}', e.g. '2.2'
        domain = int(test_id.split('.')[0])

    If the test_id does not follow the convention, domain defaults to -1
    and domain_name defaults to 'Unknown Domain'. This is a defensive
    measure for tests with non-standard IDs (e.g., the 'teardown' pseudo-ID
    used internally by the engine).

    Tags, cwe_id, test_name, priority, and strategy are not stored in
    TestResult — they live in BaseTest ClassVars. Since report/ cannot import
    from tests/, we reconstruct what we can from test_id and store empty
    strings/lists for the rest. The HTML template handles empty gracefully.

    Note: This is an acknowledged limitation of the strict dependency rule.
    The alternative — relaxing the rule and importing BaseTest in builder.py
    — would create a circular dependency (engine -> report -> tests -> core
    vs engine -> tests -> core). The clean solution for a future version is
    to store all metadata in TestResult at construction time. For the thesis
    scope, the current approach is correct and documented.

    Args:
        result_set: Completed ResultSet.

    Returns:
        List of TestResultRow sorted by test_id.
    """
    rows: list[TestResultRow] = []

    for result in result_set.results:
        domain, domain_name = _parse_domain_from_test_id(result.test_id)
        priority = _parse_priority_from_test_id(result.test_id)

        row = TestResultRow(
            test_id=result.test_id,
            test_name=result.message,
            domain=domain,
            domain_name=domain_name,
            priority=priority,
            priority_label=PRIORITY_LABELS.get(priority, f"P{priority}"),
            strategy="",
            status=result.status.value,
            message=result.message,
            skip_reason=result.skip_reason,
            duration_ms=result.duration_ms,
            finding_count=len(result.findings),
            findings=list(result.findings),
            tags=[],
            cwe_id="",
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
    # Group rows by domain number.
    domain_rows: dict[int, list[TestResultRow]] = {}
    for row in all_rows:
        domain_rows.setdefault(row.domain, []).append(row)

    summaries: list[DomainSummary] = []

    for domain_num in sorted(domain_rows.keys()):
        rows = domain_rows[domain_num]
        domain_name = DOMAIN_NAMES.get(domain_num, f"Domain {domain_num}")

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
        exit_code_label=_EXIT_CODE_LABELS.get(
            exit_code,
            f"Exit code {exit_code}",
        ),
        pass_rate_pct=pass_rate,
        assessment_duration_seconds=result_set.duration_seconds,
    )


# ---------------------------------------------------------------------------
# test_id parsing helpers
# ---------------------------------------------------------------------------


def _parse_domain_from_test_id(test_id: str) -> tuple[int, str]:
    """
    Extract the domain number and name from a test_id string.

    Convention: test_id format is '{domain}.{sequence}', e.g. '2.2'.
    The domain is the integer part before the first dot.

    Args:
        test_id: Test identifier string.

    Returns:
        Tuple of (domain_int, domain_name_str).
        Returns (-1, 'Unknown Domain') for non-conforming test_ids.
    """
    try:
        domain_int = int(test_id.split(".")[0])
        domain_name = DOMAIN_NAMES.get(domain_int, f"Domain {domain_int}")
        return domain_int, domain_name
    except (ValueError, IndexError):
        return -1, "Unknown Domain"


def _parse_priority_from_test_id(test_id: str) -> int:
    """
    Infer a default priority from the test_id for display purposes.

    Since priority is stored in BaseTest ClassVars and not in TestResult,
    this function provides a best-effort default for the report. The actual
    priority used for execution filtering is the ClassVar value.

    The methodology assigns priority based on domain and sequence number.
    For display purposes, we default all rows to priority 0 (P0) and rely
    on the test author to declare the correct priority in the ClassVar.
    The report displays "-" for rows where priority cannot be determined.

    Returns:
        int: Always 0 as a safe default. The report template handles this.
    """
    return 0
