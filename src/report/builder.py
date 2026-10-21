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

TestResult carries the declaration of its test (test_name, domain, priority,
strategy, tags, cwe_id, tool_name), copied from the test's ``info`` when the
result is built (src/core/assessment_test.py): this module reads them from each
TestResult, with no dependency on the tests/ packages.

Dependency rule:
    This module imports from stdlib, pydantic, structlog,
    src.core.models, and src.config.schema only.
    It must never import from engine.py, tests/, discovery/, or renderer.py.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal

import structlog
from pydantic import BaseModel, Field

from src.config.schema import ToolConfig
from src.core.models import (
    Coverage,
    ExitCode,
    Finding,
    InfoNote,
    NotRunEntry,
    ResultSet,
    SubTestResult,
    TestStatus,
    TlsSettings,
    TransactionSummary,
)
from src.core.models.enums import exit_code_text
from src.core.references import CalibrationPoint, PositiveControl, ReferenceResponses

log: structlog.BoundLogger = structlog.get_logger(__name__)

_PLAIN_HTTP_PREFIX: str = "http://"

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

    test_id: str = Field(description="`X.Y` (native) or `ext.X.Y.tool` (external).")
    test_name: str = Field(description="Human-readable name.")
    domain: int = Field(description="Methodology domain, 0-7.")
    domain_name: str = Field(description="Name of the domain.")
    priority: int = Field(description="Priority, 0-3.")
    priority_label: str = Field(description="Label of the priority (as `min_priority_label`).")
    strategy: str = Field(description="`BLACK_BOX`, `GREY_BOX` or `WHITE_BOX`.")
    effect: str = Field(
        default="",
        description=(
            "What the test does to the target: `READ_ONLY`, `CHANGES_DATA` or `STRESSES_TARGET`."
        ),
    )
    status: str = Field(
        description=(
            "`PASS`, `FAIL`, `INCONCLUSIVE`, `SKIP` or `ERROR` (see Status semantics below)."
        )
    )
    coverage: Coverage | None = Field(
        default=None,
        description="For a `PASS`: `complete`, or `partial` when cases were not verifiable.",
    )
    sub_tests: list[SubTestResult] = Field(
        default_factory=list,
        description="Every declared sub-test with its counters and status.",
    )
    message: str = Field(description="One-line outcome.")
    skip_reason: str | None = Field(
        default=None,
        description="Set only for `SKIP`: the missing precondition.",
    )
    duration_ms: float | None = Field(
        default=None,
        description="Execution time of the test.",
    )
    finding_count: int = Field(
        default=0,
        description="Length of `findings`.",
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description=(
            "At least one for `FAIL`, none for `PASS` and `INCONCLUSIVE` (enforced by the "
            "model); an `ERROR` result may carry findings collected before the error."
        ),
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Test tags (e.g. `OWASP-API9:2023`).",
    )
    cwe_id: str = Field(
        default="",
        description="Primary CWE (e.g. `CWE-306`).",
    )
    transaction_log: list[TransactionSummary] = Field(
        default_factory=list,
        description=("Every HTTP request of the test, PASS included."),
    )
    notes: list[InfoNote] = Field(
        default_factory=list,
        description=(
            "Informational context that is not a violation (e.g. a compensating control), "
            "on any status."
        ),
    )
    # --- Origin and external tool data ---
    # source is read directly from TestResult.source; drives the Domain-Centric Split.
    source: Literal["native", "external"] = Field(
        default="native",
        description=("`native` or `external`."),
    )
    tool_name: str = Field(
        default="",
        description=("External tool name (e.g. `nuclei`); empty for native tests."),
    )
    tool_artifact: dict[str, Any] | None = Field(
        default=None,
        description=(
            "External tests only: the tool's raw output (`command`, `command_json`, "
            "`results`, `all_count`, plus `_apiguard_meta_*` keys)."
        ),
    )
    tool_artifact_label: str | None = Field(
        default=None,
        description=(
            "External tests only: label of the tool output, the external test's ID (e.g. "
            "`ext.0.1.nuclei`)."
        ),
    )
    tool_artifact_record_id: str | None = Field(
        default=None,
        description=("External tests only: `record_id` of the tool output in `evidence.json`."),
    )


class DomainSummary(BaseModel):
    """
    Aggregated statistics and test rows for a single methodology domain.

    One DomainSummary per domain (0-7) is included in ReportData.domains.
    Domains with no active tests are excluded from the list entirely.
    """

    model_config = {"frozen": True}

    domain: int = Field(description="Methodology domain, 0-7.")
    domain_name: str = Field(description="Name of the domain (see Domain names below).")
    rows: list[TestResultRow] = Field(
        description="The results of this domain.",
    )
    pass_count: Annotated[int, Field(ge=0)] = Field(
        default=0, description="Results with status PASS."
    )
    fail_count: Annotated[int, Field(ge=0)] = Field(
        default=0, description="Results with status FAIL."
    )
    inconclusive_count: Annotated[int, Field(ge=0)] = Field(
        default=0, description="Results with status INCONCLUSIVE."
    )
    skip_count: Annotated[int, Field(ge=0)] = Field(
        default=0, description="Results with status SKIP."
    )
    error_count: Annotated[int, Field(ge=0)] = Field(
        default=0, description="Results with status ERROR."
    )
    total_finding_count: Annotated[int, Field(ge=0)] = Field(
        default=0, description="Findings of the results of this domain."
    )
    # Domain-Centric Split (docs/knowledge/archive/implementation-chapter.it.md §4.10).
    # native_rows and external_rows partition rows by source for template rendering.
    # They are a derived subset of rows (same objects, different references).
    native_rows: list[TestResultRow] = Field(
        default_factory=list,
        description="`rows` of the native tests.",
    )
    external_rows: list[TestResultRow] = Field(
        default_factory=list,
        description="`rows` of the external tests.",  # noqa: E501
    )

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

    scheduled_tests: Annotated[int, Field(ge=0)] = Field(
        description="PASS + FAIL + INCONCLUSIVE + ERROR + SKIP."
    )
    executed_tests: Annotated[int, Field(ge=0)] = Field(
        description="PASS + FAIL + INCONCLUSIVE + ERROR (SKIP excluded)."
    )
    pass_count: Annotated[int, Field(ge=0)] = Field(
        default=0, description="Results with status PASS."
    )
    fail_count: Annotated[int, Field(ge=0)] = Field(
        default=0, description="Results with status FAIL."
    )
    inconclusive_count: Annotated[int, Field(ge=0)] = Field(
        default=0, description="Results with status INCONCLUSIVE."
    )
    skip_count: Annotated[int, Field(ge=0)] = Field(
        default=0, description="Results with status SKIP."
    )
    error_count: Annotated[int, Field(ge=0)] = Field(
        default=0, description="Results with status ERROR."
    )
    not_run_count: Annotated[int, Field(ge=0)] = Field(
        default=0,
        description="Number of entries in `not_run`.",
    )
    total_finding_count: Annotated[int, Field(ge=0)] = Field(
        description="Findings of every result: FAIL results, and ERROR results that carry some.",
        default=0,
    )
    exit_code: int = Field(description="Same value as the process exit code.")
    exit_code_label: str = Field(
        description=(
            "Label and meaning of the exit code (exit-codes.md), e.g. "
            f"`{exit_code_text(ExitCode.FAIL)}`."
        )
    )
    pass_rate_pct: float = Field(
        description=(
            "`pass_count / executed_tests × 100`, one decimal; `0.0` when nothing executed."
        ),
        default=0.0,
    )
    assessment_duration_seconds: float | None = Field(
        default=None,
        description="Wall-clock duration of the run.",
    )


class ConnectionTrust(BaseModel):
    """How the certificate of one connection was checked (design decisions D2)."""

    model_config = {"frozen": True}

    name: str = Field(description="`target`, `specification`, `gateway.admin` or `gateway.health`.")
    url: str = Field(
        description=(
            "The connection's URL (the API's with a trailing `/`), or the specification's "
            "absolute file path."
        )
    )
    certificate_check: Literal[
        "verified_system", "verified_ca_bundle", "not_verified", "plain_http", "local_file"
    ] = Field(
        description=(
            "`verified_system` (the system's authorities plus certifi's list), "
            "`verified_ca_bundle` (only the configured `ca_bundle`), `not_verified` "
            "(`verify: false`: the run did not know whether it talked to the right server), "
            "`plain_http` (no TLS), `local_file` (the specification was read from a file)."
        )
    )
    client_certificate: bool = Field(
        description="`true` when the tool presented a client certificate (mutual TLS)."
    )


class ReferencesSummary(BaseModel):
    """The reference responses of the run (src/core/references.py)."""

    model_config = {"frozen": True}

    calibration_points: list[CalibrationPoint] = Field(
        default_factory=list,
        description=(
            'What "does not exist here" looked like for each sibling pattern, method and '
            "credential asked; a point not reliable is never used."
        ),
    )
    positive_controls: list[PositiveControl] = Field(
        default_factory=list,
        description="Whether each request asked worked with a valid credential.",
    )


class ReportData(BaseModel):
    """
    Complete, pre-computed data structure for the HTML report template.

    This model is the single input to renderer.py. The Jinja2 template
    accesses fields on this object directly, with no further computation.
    All display-ready values are computed here, not in the template.
    """

    model_config = {"frozen": True}

    tool_version: str = Field(
        description=(
            "APIGuard version that produced the report: the version of this format (see "
            "Versioning above)."
        )
    )
    run_id: str = Field(description="Identifier of the run: `apiguard-YYYYMMDD-HHMMSS-ffffff`.")
    generated_at_utc: str = Field(
        description=(
            "Generation time, ISO 8601 in UTC with `+00:00` offset (e.g. "
            "`2026-10-08T09:12:57.870747+00:00`), like `generated_at_utc` in "
            "`evidence.json`. The HTML report shows it in the reader's local time zone (UTC "
            "value in the tooltip)."
        )
    )
    target_base_url: str = Field(description="`target.base_url` of the configuration.")
    spec_title: str = Field(description="`info.title` of the OpenAPI specification.")
    spec_version: str = Field(description="`info.version` of the OpenAPI specification.")
    min_priority_label: str = Field(
        description=(
            "Label of `execution.min_priority`: one of "
            + ", ".join(f"`{label}`" for label in PRIORITY_LABELS.values())
            + "."
        )
    )
    strategies_label: str = Field(
        description="Enabled strategies, comma-separated (`BLACK_BOX, GREY_BOX, WHITE_BOX`)."
    )
    connections: list[ConnectionTrust] = Field(
        default_factory=list,
        description="How the certificate of each connection of the tool was checked.",
    )
    executive_summary: ExecutiveSummary = Field(description="Counts and verdict of the run.")
    domains: list[DomainSummary] = Field(
        description=(
            "The results by methodology domain, ordered by domain; domains without active "
            "tests are omitted."
        )
    )
    all_rows: list[TestResultRow] = Field(
        description="Every test result, ordered by `test_id` as text."
    )
    not_run: list[NotRunEntry] = Field(
        default_factory=list,
        description=(
            "The tests of the tool not executed in this run, ordered by `test_id` as text. "
            "`all_rows` + `not_run` = every test of the tool."
        ),
    )
    references: ReferencesSummary = Field(
        default_factory=ReferencesSummary,
        description=(
            "The reference responses the tests asked for: calibration points and positive "
            "controls, each with its records (`ref_NNN`) in `evidence.json`."
        ),
    )


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def build_report_data(
    result_set: ResultSet,
    run_id: str,
    config: ToolConfig,
    spec_title: str = "Unknown",
    spec_version: str = "Unknown",
    references: ReferenceResponses | None = None,
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
        references: The run's reference responses; None gives an empty section.

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

    from src import __version__ as _tool_version

    report_data = ReportData(
        tool_version=_tool_version,
        run_id=run_id,
        generated_at_utc=datetime.now(UTC).isoformat(),
        target_base_url=str(config.target.base_url),
        spec_title=spec_title,
        spec_version=spec_version,
        min_priority_label=min_priority_label,
        strategies_label=strategies_label,
        connections=_connection_trust(config),
        executive_summary=executive_summary,
        domains=domains,
        all_rows=all_rows,
        not_run=list(result_set.not_run),
        references=_references_summary(references),
    )

    log.info(
        "report_builder_aggregation_completed",
        pass_count=executive_summary.pass_count,
        fail_count=executive_summary.fail_count,
        skip_count=executive_summary.skip_count,
        error_count=executive_summary.error_count,
        total_findings=executive_summary.total_finding_count,
        exit_code=int(exit_code),
    )

    return report_data


# ---------------------------------------------------------------------------
# Internal aggregation helpers
# ---------------------------------------------------------------------------


def _connection_trust(config: ToolConfig) -> list[ConnectionTrust]:
    """
    Describe how the certificate of each connection was checked, from its tls block.

    Args:
        config: The run's configuration.

    Returns:
        One entry per connection: target, specification, and the gateway's
        Admin API and health API when configured.
    """
    connections: list[tuple[str, str, TlsSettings | None]] = [
        ("target", str(config.target.base_url), config.target.tls)
    ]
    spec = config.specification
    connections.append(("specification", spec.get_source(), spec.tls))
    if config.gateway is not None:
        connections.append(
            ("gateway.admin", str(config.gateway.admin.url), config.gateway.admin.tls)
        )
        if config.gateway.health is not None:
            health = config.gateway.health
            connections.append(("gateway.health", str(health.url), health.tls))
    entries: list[ConnectionTrust] = []
    for name, url, tls in connections:
        settings = tls if tls is not None else TlsSettings()
        check: Literal[
            "verified_system", "verified_ca_bundle", "not_verified", "plain_http", "local_file"
        ]
        if name == "specification" and spec.is_local:
            check = "local_file"
        elif url.lower().startswith(_PLAIN_HTTP_PREFIX):
            check = "plain_http"
        elif not settings.verify:
            check = "not_verified"
        elif settings.ca_bundle is not None:
            check = "verified_ca_bundle"
        else:
            check = "verified_system"
        entries.append(
            ConnectionTrust(
                name=name,
                url=url,
                certificate_check=check,
                client_certificate=settings.has_client_certificate and check != "plain_http",
            )
        )
    return entries


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
            effect=result.effect,
            status=result.status.value,
            coverage=result.coverage,
            sub_tests=list(result.sub_tests),
            message=result.message,
            skip_reason=result.skip_reason,
            duration_ms=result.duration_ms,
            finding_count=len(result.findings),
            findings=list(result.findings),
            tags=list(result.tags),
            cwe_id=result.cwe_id,
            transaction_log=list(result.transaction_log),
            notes=list(result.notes),
            # Domain-Centric Split fields — copied verbatim from TestResult.
            source=result.source,
            tool_name=result.tool_name,
            tool_artifact=result.tool_artifact,
            tool_artifact_label=result.tool_artifact_label,
            tool_artifact_record_id=result.tool_artifact_record_id,
        )
        rows.append(row)

    rows.sort(key=lambda r: r.test_id)
    return rows


def _references_summary(references: ReferenceResponses | None) -> ReferencesSummary:
    """The references section of the report, from the run's ReferenceResponses."""
    if references is None:
        return ReferencesSummary()
    points, controls = references.summary()
    return ReferencesSummary(calibration_points=points, positive_controls=controls)


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
        inconclusive_count = sum(1 for r in rows if r.status == TestStatus.INCONCLUSIVE.value)
        skip_count = sum(1 for r in rows if r.status == TestStatus.SKIP.value)
        error_count = sum(1 for r in rows if r.status == TestStatus.ERROR.value)
        total_finding_count = sum(r.finding_count for r in rows)

        native_rows = [r for r in rows if r.source == "native"]
        external_rows = [r for r in rows if r.source == "external"]

        summary = DomainSummary(
            domain=domain_num,
            domain_name=domain_name,
            rows=rows,
            pass_count=pass_count,
            fail_count=fail_count,
            inconclusive_count=inconclusive_count,
            skip_count=skip_count,
            error_count=error_count,
            total_finding_count=total_finding_count,
            native_rows=native_rows,
            external_rows=external_rows,
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

    The pass_rate_pct is computed over executed tests only (PASS + FAIL +
    INCONCLUSIVE + ERROR), excluding SKIP. This is the most honest metric: SKIP
    tests did not contribute to the assessment outcome and should not inflate or
    deflate the pass rate.

    Args:
        result_set: Completed ResultSet.
        all_rows: Pre-built TestResultRow list (used for finding count).
        exit_code: Pre-computed exit code from ResultSet.compute_exit_code().

    Returns:
        Frozen ExecutiveSummary.
    """
    executed_count = (
        result_set.pass_count
        + result_set.fail_count
        + result_set.inconclusive_count
        + result_set.error_count
    )
    scheduled_count = executed_count + result_set.skip_count

    pass_rate = (
        round(result_set.pass_count / executed_count * 100.0, 1) if executed_count > 0 else 0.0
    )

    total_findings = sum(r.finding_count for r in all_rows)

    return ExecutiveSummary(
        scheduled_tests=scheduled_count,
        executed_tests=executed_count,
        pass_count=result_set.pass_count,
        fail_count=result_set.fail_count,
        inconclusive_count=result_set.inconclusive_count,
        skip_count=result_set.skip_count,
        error_count=result_set.error_count,
        not_run_count=len(result_set.not_run),
        total_finding_count=total_findings,
        exit_code=exit_code,
        exit_code_label=exit_code_text(exit_code),
        pass_rate_pct=pass_rate,
        assessment_duration_seconds=result_set.duration_seconds,
    )
