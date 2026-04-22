"""
tests_integration/test_07_report.py

Phase 7 — Report Generation: Executable Documentation for the output pipeline.

This file documents the contracts of the engine's _phase_7_report() method:
how it serializes the EvidenceStore to JSON, how it builds and renders the
HTML report using AttackSurface metadata, and how it handles failures in each
sub-step without altering the assessment's exit code.

Key architectural guarantee documented here
-------------------------------------------
Phase 7 failures are isolated from the assessment outcome. An OSError writing
evidence.json, a crash in build_report_data(), or a Jinja2 render failure all
cause an error log entry — they do not raise, do not change the ResultSet,
and do not change the exit code. The assessment results are correct regardless
of whether the report was written to disk.

Isolation strategy
------------------
- All tests use tmp_path for output paths so that no file artifacts are left
  in the project directory after the suite completes.
- build_report_data() and render_html_report() are called via the engine's
  _phase_7_report() method, exercising the full integration path including
  error handling.
- The reference_surface fixture (session-scoped) and minimal_config_file
  fixture are reused from conftest.py for consistency with earlier phase tests.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from src.config.schema import ToolConfig
from src.core.evidence import EvidenceStore
from src.core.models import (
    AttackSurface,
    EvidenceRecord,
    Finding,
    ResultSet,
    SpecDialect,
    TestResult,
    TestStatus,
)
from src.engine import AssessmentEngine
from src.report.builder import ReportData, build_report_data

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_engine(minimal_config_file: Path) -> AssessmentEngine:
    return AssessmentEngine(config_path=minimal_config_file)


def _make_pass_result(test_id: str = "0.1") -> TestResult:
    return TestResult(
        test_id=test_id,
        status=TestStatus.PASS,
        message="Control verified",
        test_name=f"Stub test {test_id}",
        domain=0,
        priority=1,
        strategy="BLACK_BOX",
    )


def _make_fail_result(test_id: str = "0.2") -> TestResult:
    return TestResult(
        test_id=test_id,
        status=TestStatus.FAIL,
        message="Violation detected",
        findings=[Finding(title="Stub finding", detail="Stub violation detail")],
        test_name=f"Stub test {test_id}",
        domain=0,
        priority=0,
        strategy="BLACK_BOX",
    )


def _make_skip_result(test_id: str = "0.3") -> TestResult:
    return TestResult(
        test_id=test_id,
        status=TestStatus.SKIP,
        message="Prerequisite not met",
        skip_reason="Admin API not configured",
        test_name=f"Stub test {test_id}",
        domain=0,
        priority=3,
        strategy="WHITE_BOX",
    )


def _make_evidence_record(test_id: str = "0.1", seq: int = 1) -> EvidenceRecord:
    return EvidenceRecord(
        record_id=f"{test_id}_{seq:03d}",
        timestamp_utc=datetime.now(UTC),
        request_method="GET",
        request_url="http://localhost:8000/api/v1/users/me",
        response_status_code=200,
    )


def _make_loaded_config(tmp_path: Path, minimal_config_file: Path) -> ToolConfig:
    """Return a ToolConfig loaded from the minimal_config_file fixture."""
    from src.config.loader import load_config

    return load_config(minimal_config_file)


# ===========================================================================
# Section A — Evidence serialization
# ===========================================================================


class TestEvidenceSerializiation:
    """
    Phase 7 serializes the EvidenceStore to a JSON file at the path specified
    by config.output.evidence_path.

    The contract is:
        1. The output file is valid JSON with a top-level 'records' array.
        2. The number of records written matches EvidenceStore.record_count.
        3. The parent directory is created if it does not exist.
        4. An OSError is caught and logged — it must not propagate.
    """

    def test_evidence_file_is_created_at_configured_path(
        self, tmp_path: Path, minimal_config_file: Path, reference_surface: AttackSurface
    ) -> None:
        """
        After _phase_7_report(), a JSON file exists at config.output.evidence_path.

        This is the primary delivery artefact for human analysts. If it is
        missing, the assessment has no demonstrable proof of its findings.
        """
        config = _make_loaded_config(tmp_path, minimal_config_file)
        # Override output directory to tmp_path for test isolation
        from unittest.mock import PropertyMock

        evidence_path = tmp_path / "outputs" / "evidence.json"
        report_path = tmp_path / "outputs" / "report.html"

        result_set = ResultSet()
        result_set.add_result(_make_pass_result())
        store = EvidenceStore(tmp_path / "evidence_tmp")

        engine = _build_engine(minimal_config_file)

        with (
            patch.object(type(config.output), "evidence_path", new_callable=PropertyMock) as ep,
            patch.object(type(config.output), "report_path", new_callable=PropertyMock) as rp,
        ):
            ep.return_value = evidence_path
            rp.return_value = report_path

            engine._phase_7_report(
                result_set=result_set,
                store=store,
                config=config,
                attack_surface=reference_surface,
            )

        assert evidence_path.exists(), f"Evidence file must be created at {evidence_path}"

    def test_evidence_file_is_valid_json(
        self, tmp_path: Path, minimal_config_file: Path, reference_surface: AttackSurface
    ) -> None:
        """
        The serialized evidence file must be parseable as valid JSON.

        json.loads() must not raise on the file's content. A non-JSON file
        would be unreadable by external analysis tools.
        """
        from unittest.mock import PropertyMock

        evidence_path = tmp_path / "evidence.json"
        report_path = tmp_path / "report.html"
        config = _make_loaded_config(tmp_path, minimal_config_file)

        store = EvidenceStore(tmp_path / "evidence_tmp")
        record = _make_evidence_record("0.1")
        store.add_fail_evidence(record)

        engine = _build_engine(minimal_config_file)

        with (
            patch.object(type(config.output), "evidence_path", new_callable=PropertyMock) as ep,
            patch.object(type(config.output), "report_path", new_callable=PropertyMock) as rp,
        ):
            ep.return_value = evidence_path
            rp.return_value = report_path

            engine._phase_7_report(
                result_set=ResultSet(),
                store=store,
                config=config,
                attack_surface=reference_surface,
            )

        content = evidence_path.read_text(encoding="utf-8")
        parsed = json.loads(content)
        assert isinstance(parsed, dict), "Evidence file must be a JSON object at the root level"

    def test_evidence_file_record_count_matches_store(
        self, tmp_path: Path, minimal_config_file: Path, reference_surface: AttackSurface
    ) -> None:
        """
        The record_count field in evidence.json matches the number of stored records.

        Discrepancy between the envelope's record_count and the actual 'records'
        array length would indicate a serialization bug.
        """
        from unittest.mock import PropertyMock

        evidence_path = tmp_path / "evidence.json"
        report_path = tmp_path / "report.html"
        config = _make_loaded_config(tmp_path, minimal_config_file)

        store = EvidenceStore(tmp_path / "evidence_tmp")
        store.add_fail_evidence(_make_evidence_record("0.1", 1))
        store.add_fail_evidence(_make_evidence_record("0.2", 2))
        store.add_fail_evidence(_make_evidence_record("0.3", 3))

        engine = _build_engine(minimal_config_file)

        with (
            patch.object(type(config.output), "evidence_path", new_callable=PropertyMock) as ep,
            patch.object(type(config.output), "report_path", new_callable=PropertyMock) as rp,
        ):
            ep.return_value = evidence_path
            rp.return_value = report_path

            engine._phase_7_report(
                result_set=ResultSet(),
                store=store,
                config=config,
                attack_surface=reference_surface,
            )

        parsed = json.loads(evidence_path.read_text(encoding="utf-8"))
        assert parsed["record_count"] == 3
        assert len(parsed["records"]) == 3

    def test_oserror_during_evidence_write_does_not_propagate(
        self, tmp_path: Path, minimal_config_file: Path, reference_surface: AttackSurface
    ) -> None:
        """
        An OSError writing evidence.json is caught and logged — _phase_7_report must not raise.

        This covers permission errors, disk-full scenarios, and read-only
        filesystems. The assessment results are not invalidated by a write failure.
        """
        from unittest.mock import PropertyMock

        config = _make_loaded_config(tmp_path, minimal_config_file)
        report_path = tmp_path / "report.html"

        engine = _build_engine(minimal_config_file)

        with (
            patch.object(type(config.output), "evidence_path", new_callable=PropertyMock) as ep,
            patch.object(type(config.output), "report_path", new_callable=PropertyMock) as rp,
            patch("src.core.evidence.EvidenceStore.to_json_file", side_effect=OSError("disk full")),
        ):
            ep.return_value = tmp_path / "evidence.json"
            rp.return_value = report_path

            # Must not raise
            engine._phase_7_report(
                result_set=ResultSet(),
                store=EvidenceStore(tmp_path / "evidence_tmp"),
                config=config,
                attack_surface=reference_surface,
            )


# ===========================================================================
# Section B — HTML report rendering
# ===========================================================================


class TestHTMLReportRendering:
    """
    Phase 7 renders an HTML report at config.output.report_path.

    The engine calls build_report_data() (builder) then render_html_report()
    (renderer). The contract covers:
        1. The HTML file is created at the configured path.
        2. The file is non-empty and contains recognizable HTML structure.
        3. A render failure is caught and logged — it must not propagate.
    """

    def test_html_report_is_created_at_configured_path(
        self, tmp_path: Path, minimal_config_file: Path, reference_surface: AttackSurface
    ) -> None:
        """
        After _phase_7_report(), an HTML file exists at config.output.report_path.

        The HTML report is the primary human-readable output of the pipeline.
        Its absence means the assessment produced no deliverable for the operator.
        """
        from unittest.mock import PropertyMock

        evidence_path = tmp_path / "evidence.json"
        report_path = tmp_path / "report.html"
        config = _make_loaded_config(tmp_path, minimal_config_file)

        result_set = ResultSet()
        result_set.add_result(_make_pass_result())

        engine = _build_engine(minimal_config_file)

        with (
            patch.object(type(config.output), "evidence_path", new_callable=PropertyMock) as ep,
            patch.object(type(config.output), "report_path", new_callable=PropertyMock) as rp,
        ):
            ep.return_value = evidence_path
            rp.return_value = report_path

            engine._phase_7_report(
                result_set=result_set,
                store=EvidenceStore(tmp_path / "evidence_tmp"),
                config=config,
                attack_surface=reference_surface,
            )

        assert report_path.exists(), f"HTML report must be created at {report_path}"

    def test_html_report_contains_html_tag(
        self, tmp_path: Path, minimal_config_file: Path, reference_surface: AttackSurface
    ) -> None:
        """
        The rendered HTML file must contain an <html> or <!DOCTYPE html> tag.

        A file that starts with a Python traceback or an empty string is not
        a valid HTML report.
        """
        from unittest.mock import PropertyMock

        evidence_path = tmp_path / "evidence.json"
        report_path = tmp_path / "report.html"
        config = _make_loaded_config(tmp_path, minimal_config_file)

        result_set = ResultSet()
        result_set.add_result(_make_pass_result())

        engine = _build_engine(minimal_config_file)

        with (
            patch.object(type(config.output), "evidence_path", new_callable=PropertyMock) as ep,
            patch.object(type(config.output), "report_path", new_callable=PropertyMock) as rp,
        ):
            ep.return_value = evidence_path
            rp.return_value = report_path

            engine._phase_7_report(
                result_set=result_set,
                store=EvidenceStore(tmp_path / "evidence_tmp"),
                config=config,
                attack_surface=reference_surface,
            )

        content = report_path.read_text(encoding="utf-8")
        has_html = "<!DOCTYPE html>" in content or "<html" in content
        assert has_html, "Rendered file must contain an HTML root element"

    def test_html_render_failure_does_not_propagate(
        self, tmp_path: Path, minimal_config_file: Path, reference_surface: AttackSurface
    ) -> None:
        """
        A failure in render_html_report() is caught — _phase_7_report must not raise.

        This covers Jinja2 template errors, encoding issues, and any other
        render-time failure. The assessment is complete; only the report
        serialization failed.
        """
        from unittest.mock import PropertyMock

        config = _make_loaded_config(tmp_path, minimal_config_file)

        engine = _build_engine(minimal_config_file)

        with (
            patch.object(type(config.output), "evidence_path", new_callable=PropertyMock) as ep,
            patch.object(type(config.output), "report_path", new_callable=PropertyMock) as rp,
            patch(
                "src.report.renderer.render_html_report", side_effect=RuntimeError("template error")
            ),
        ):
            ep.return_value = tmp_path / "evidence.json"
            rp.return_value = tmp_path / "report.html"

            # Must not raise
            engine._phase_7_report(
                result_set=ResultSet(),
                store=EvidenceStore(tmp_path / "evidence_tmp"),
                config=config,
                attack_surface=reference_surface,
            )


# ===========================================================================
# Section C — Spec metadata propagation
# ===========================================================================


class TestSpecMetadataPropagation:
    """
    build_report_data() receives spec_title and spec_version from the AttackSurface.

    Prior to the fix documented in engine.py, these fields defaulted to 'Unknown'
    because the builder was called without surface metadata. This section verifies
    that the correct metadata flows from AttackSurface → engine → build_report_data
    → ReportData, so the HTML report header shows the real API name and version.

    These tests call build_report_data() directly (not via the engine) to pin
    the contract at the builder boundary, independent of filesystem I/O.
    """

    def test_spec_title_is_propagated_from_attack_surface(self, minimal_config_file: Path) -> None:
        """
        ReportData.spec_title matches AttackSurface.spec_title.

        An operator reading the HTML report must see the actual API name
        (e.g., 'Forgejo API'), not the placeholder 'Unknown'.
        """
        config = _make_loaded_config(Path("."), minimal_config_file)
        surface = AttackSurface(
            spec_title="Forgejo API",
            spec_version="1.20.0",
            dialect=SpecDialect.OPENAPI_3,
        )

        result_set = ResultSet()
        result_set.add_result(_make_pass_result())
        result_set.completed_at = datetime.now(UTC)

        report_data = build_report_data(
            result_set=result_set,
            run_id="apiguard-test-run",
            config=config,
            spec_title=surface.spec_title,
            spec_version=surface.spec_version,
        )

        assert report_data.spec_title == "Forgejo API", (
            f"Expected spec_title='Forgejo API', got '{report_data.spec_title}'"
        )

    def test_spec_version_is_propagated_from_attack_surface(
        self, minimal_config_file: Path
    ) -> None:
        """
        ReportData.spec_version matches AttackSurface.spec_version.

        Version information in the report header allows analysts to identify
        which API release was assessed.
        """
        config = _make_loaded_config(Path("."), minimal_config_file)

        result_set = ResultSet()
        result_set.add_result(_make_pass_result())
        result_set.completed_at = datetime.now(UTC)

        report_data = build_report_data(
            result_set=result_set,
            run_id="apiguard-test-run",
            config=config,
            spec_title="Test API",
            spec_version="3.14.0",
        )

        assert report_data.spec_version == "3.14.0"

    def test_default_spec_metadata_is_unknown_when_not_provided(
        self, minimal_config_file: Path
    ) -> None:
        """
        When spec_title and spec_version are not provided, they default to 'Unknown'.

        The default must be the documented sentinel value 'Unknown', not an
        empty string or None, which would render as a blank in the report header.
        """
        config = _make_loaded_config(Path("."), minimal_config_file)

        result_set = ResultSet()
        result_set.completed_at = datetime.now(UTC)

        report_data = build_report_data(
            result_set=result_set,
            run_id="apiguard-test-run",
            config=config,
            # spec_title and spec_version use their defaults
        )

        assert report_data.spec_title == "Unknown"
        assert report_data.spec_version == "Unknown"


# ===========================================================================
# Section D — ReportData statistics correctness
# ===========================================================================


class TestReportDataStatistics:
    """
    build_report_data() correctly aggregates ResultSet statistics into the
    ReportData.executive_summary for the HTML report header.

    These tests document the mapping between raw ResultSet counts and the
    display values rendered in the report. An analyst reading the report's
    summary table must see numbers that match the actual assessment results.

    A critical invariant of the executive summary
    ---------------------------------------------
    executive_summary.total_tests counts only EXECUTED tests:
        total_tests = pass_count + fail_count + error_count

    SKIP results are excluded from this count because skipped tests did not
    contribute to the assessment outcome. The pass_rate_pct denominator uses
    the same executed count to give an honest signal: a skipped test does not
    inflate or deflate the pass rate. This is documented in builder.py's
    _build_executive_summary() as "executed_count".

    Consequence for assertions: a ResultSet containing 1 PASS + 1 FAIL + 1 SKIP
    yields total_tests == 2 (not 3). Tests in this section are written to
    match this documented contract, not the raw result_set.total_count.
    """

    def _build_report(self, results: list[TestResult], minimal_config_file: Path) -> ReportData:
        config = _make_loaded_config(Path("."), minimal_config_file)
        result_set = ResultSet()
        for r in results:
            result_set.add_result(r)
        result_set.completed_at = datetime.now(UTC)
        return build_report_data(
            result_set=result_set,
            run_id="apiguard-stats-test",
            config=config,
        )

    def test_total_tests_counts_only_executed_not_skipped(self, minimal_config_file: Path) -> None:
        """
        executive_summary.total_tests equals pass + fail + error — SKIP is excluded.

        The builder defines total_tests as "executed_count":
            executed_count = pass_count + fail_count + error_count

        SKIP results represent tests that did not run (a prerequisite was absent
        or the strategy was filtered). Including them in total_tests would
        misrepresent the assessment scope to the operator.

        With 1 PASS + 1 FAIL + 1 SKIP: total_tests == 2 (not 3).
        """
        results = [_make_pass_result("0.1"), _make_fail_result("0.2"), _make_skip_result("0.3")]
        report = self._build_report(results, minimal_config_file)
        assert report.executive_summary.total_tests == 2, (
            "total_tests must count only executed (PASS+FAIL+ERROR) results; "
            "SKIP results are not included in the executed count"
        )

    def test_pass_count_in_summary_is_correct(self, minimal_config_file: Path) -> None:
        """
        executive_summary.pass_count equals the number of PASS results.
        """
        results = [_make_pass_result("0.1"), _make_pass_result("0.4"), _make_fail_result("0.2")]
        report = self._build_report(results, minimal_config_file)
        assert report.executive_summary.pass_count == 2

    def test_fail_count_in_summary_is_correct(self, minimal_config_file: Path) -> None:
        """
        executive_summary.fail_count equals the number of FAIL results.

        This is the most critical counter: the operator's first look at the
        report is the fail count in the summary header.
        """
        results = [_make_fail_result("0.2"), _make_fail_result("0.5"), _make_pass_result("0.1")]
        report = self._build_report(results, minimal_config_file)
        assert report.executive_summary.fail_count == 2

    def test_skip_count_in_summary_is_correct(self, minimal_config_file: Path) -> None:
        """
        executive_summary.skip_count equals the number of SKIP results.

        Even though SKIP results are excluded from total_tests, they are still
        tracked in skip_count so the operator can see how many tests were
        skipped due to missing prerequisites or strategy filters.
        """
        results = [_make_skip_result("0.3"), _make_pass_result("0.1")]
        report = self._build_report(results, minimal_config_file)
        assert report.executive_summary.skip_count == 1

    def test_all_pass_produces_exit_code_0_in_summary(self, minimal_config_file: Path) -> None:
        """
        A ResultSet with only PASS results produces exit_code=0 in the summary.

        The executive_summary embeds the exit code so the report header can
        display the overall assessment verdict prominently.
        """
        results = [_make_pass_result("0.1"), _make_pass_result("0.4")]
        report = self._build_report(results, minimal_config_file)
        assert report.executive_summary.exit_code == 0

    def test_any_fail_produces_exit_code_1_in_summary(self, minimal_config_file: Path) -> None:
        """
        A ResultSet with at least one FAIL produces exit_code=1 in the summary.
        """
        results = [_make_pass_result("0.1"), _make_fail_result("0.2")]
        report = self._build_report(results, minimal_config_file)
        assert report.executive_summary.exit_code == 1


# ===========================================================================
# Section E — build_report_data failure resilience
# ===========================================================================


class TestReportDataBuildFailure:
    """
    If build_report_data() raises an unexpected exception, _phase_7_report()
    must catch it, log an ERROR, and return without producing an HTML file.

    This is a defence-in-depth guard: build_report_data() is not expected to
    raise under normal conditions, but a corrupted ResultSet or an unexpected
    Pydantic validation failure must not crash the engine after the assessment
    has already completed.
    """

    def test_builder_exception_does_not_propagate(
        self, tmp_path: Path, minimal_config_file: Path, reference_surface: AttackSurface
    ) -> None:
        """
        A crash in build_report_data() is caught — _phase_7_report must not raise.

        After catching the exception, the engine must return gracefully.
        The evidence file may or may not have been written at this point
        (it is written before build_report_data() is called), but no further
        exception must propagate.
        """
        from unittest.mock import PropertyMock

        config = _make_loaded_config(tmp_path, minimal_config_file)

        engine = _build_engine(minimal_config_file)

        with (
            patch.object(type(config.output), "evidence_path", new_callable=PropertyMock) as ep,
            patch.object(type(config.output), "report_path", new_callable=PropertyMock) as rp,
            patch("src.engine.build_report_data", side_effect=ValueError("corrupted result set")),
        ):
            ep.return_value = tmp_path / "evidence.json"
            rp.return_value = tmp_path / "report.html"

            # Must not raise
            engine._phase_7_report(
                result_set=ResultSet(),
                store=EvidenceStore(tmp_path / "evidence_tmp"),
                config=config,
                attack_surface=reference_surface,
            )

    def test_builder_exception_prevents_html_render(
        self, tmp_path: Path, minimal_config_file: Path, reference_surface: AttackSurface
    ) -> None:
        """
        If build_report_data() fails, no HTML report file is produced.

        The renderer cannot be called without a ReportData object. When the
        builder fails, the engine returns early before reaching render_html_report(),
        so the HTML file must not exist after the call.
        """
        from unittest.mock import PropertyMock

        config = _make_loaded_config(tmp_path, minimal_config_file)
        report_path = tmp_path / "report.html"

        engine = _build_engine(minimal_config_file)

        with (
            patch.object(type(config.output), "evidence_path", new_callable=PropertyMock) as ep,
            patch.object(type(config.output), "report_path", new_callable=PropertyMock) as rp,
            patch("src.engine.build_report_data", side_effect=ValueError("corrupted")),
        ):
            ep.return_value = tmp_path / "evidence.json"
            rp.return_value = report_path

            engine._phase_7_report(
                result_set=ResultSet(),
                store=EvidenceStore(tmp_path / "evidence_tmp"),
                config=config,
                attack_surface=reference_surface,
            )

        assert not report_path.exists(), (
            "HTML report must not be created when build_report_data() fails"
        )
