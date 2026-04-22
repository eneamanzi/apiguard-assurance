"""
tests_integration/test_05_execution.py

Phase 5 — Execution: Executable Documentation for the test execution loop.

This file documents the contracts of the engine's _phase_5_execute() method:
how it iterates batches and tests in topological order, how it accumulates
results into a ResultSet, how it enforces the fail-fast condition, and how
it handles edge cases (missing test_id in lookup, empty schedule).

Every test class corresponds to a named contract extracted directly from
the engine's docstring. Reading the assertions tells you what guarantees
the execution loop provides to any test author or tool operator.

Isolation strategy
------------------
- SecurityClient is replaced by a MagicMock: Phase 5 tests must not open
  TCP connections. The client mock is never called in these tests because
  the stub tests below do not issue HTTP requests.
- BaseTest subclasses are defined inline as inner classes using a
  _make_stub_test() factory that returns a configured subclass in one call.
  This avoids polluting the test namespace with dozens of named classes.
- AssessmentEngine is instantiated with a real minimal config file (via
  minimal_config_file fixture) because its constructor only stores the path;
  all I/O happens inside run(). The phase methods are called directly,
  bypassing the full pipeline.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar
from unittest.mock import MagicMock

from src.core.context import TargetContext, TestContext
from src.core.dag import ScheduledBatch
from src.core.evidence import EvidenceStore
from src.core.models import Finding, ResultSet, TestResult, TestStatus, TestStrategy
from src.engine import AssessmentEngine
from src.tests.base import BaseTest

# ---------------------------------------------------------------------------
# Stub-test factory
# ---------------------------------------------------------------------------


def _make_stub_test(
    test_id: str,
    result_status: TestStatus = TestStatus.PASS,
    priority: int = 1,
    strategy: TestStrategy = TestStrategy.BLACK_BOX,
    side_effect: Exception | None = None,
) -> type[BaseTest]:
    """
    Return a minimal concrete BaseTest subclass that always returns a fixed result.

    Using a factory instead of a fixture avoids class-name collisions when
    multiple stubs with the same attribute values exist in the same test module.

    The returned class is a fully valid BaseTest implementation:
        - All ClassVar attributes are populated (TestRegistry would accept it).
        - execute() never raises — errors are pre-built as TestResult(status=ERROR).

    Implementation note on ClassVar capture
    ----------------------------------------
    The factory parameters (test_id, priority, strategy) are captured into
    private locals (_test_id, _priority, _strategy) before the class body is
    entered. This is required because Python class bodies do not form closures
    in the same way functions do: if a name appears as both an assignment target
    and a lookup in the same class body (e.g. ``test_id: ClassVar[str] = test_id``),
    the scoping rules are ambiguous and result in a NameError on some Python
    versions. Using distinct local names eliminates the ambiguity entirely.

    Args:
        test_id:       Unique test identifier for the stub.
        result_status: Status the stub returns. Defaults to PASS.
        priority:      Priority level. Defaults to 1 (non-critical).
        strategy:      Execution strategy. Defaults to BLACK_BOX.
        side_effect:   If not None, execute() returns status=ERROR with this
                       exception message (simulates unexpected failure).
    """
    # Capture parameters under distinct names before entering the class body.
    # This prevents the NameError that arises when a ClassVar assignment target
    # and the closure variable share the same identifier.
    _test_id = test_id
    _priority = priority
    _strategy = strategy

    findings = (
        [Finding(title="Stub finding", detail="Stub violation detail")]
        if result_status == TestStatus.FAIL
        else []
    )
    skip_reason = "Stub skip reason" if result_status == TestStatus.SKIP else None

    class _StubTest(BaseTest):
        __test__ = False

        test_id: ClassVar[str] = _test_id
        test_name: ClassVar[str] = f"Stub test {_test_id}"
        domain: ClassVar[int] = 0
        priority: ClassVar[int] = _priority
        strategy: ClassVar[TestStrategy] = _strategy
        depends_on: ClassVar[list[str]] = []
        tags: ClassVar[list[str]] = ["stub"]
        cwe_id: ClassVar[str] = ""

        def execute(
            self,
            target: TargetContext,
            context: TestContext,
            client: object,
            store: EvidenceStore,
        ) -> TestResult:
            if side_effect is not None:
                return TestResult(
                    test_id=self.__class__.test_id,
                    status=TestStatus.ERROR,
                    message=f"Unexpected error: {side_effect}",
                )
            return TestResult(
                test_id=self.__class__.test_id,
                status=result_status,
                message=f"Stub result: {result_status.value}",
                findings=findings,
                skip_reason=skip_reason,
                priority=_priority,
                strategy=_strategy.value,
                test_name=self.__class__.test_name,
                domain=self.__class__.domain,
                tags=self.__class__.tags,
                cwe_id=self.__class__.cwe_id,
            )

    _StubTest.__name__ = f"_StubTest_{_test_id.replace('.', '_')}"
    _StubTest.__qualname__ = _StubTest.__name__
    return _StubTest


def _build_engine(minimal_config_file: Path) -> AssessmentEngine:
    """Return a bare engine instance. Only the config path is stored at init."""
    return AssessmentEngine(config_path=minimal_config_file)


def _build_batches(test_ids: list[str]) -> list[ScheduledBatch]:
    """
    Build a trivial flat schedule: all test_ids in a single batch at index 0.

    Used when topological ordering is irrelevant to the test being written.
    """
    return [ScheduledBatch(batch_index=0, test_ids=test_ids)]


def _mock_config(fail_fast: bool = False) -> MagicMock:
    """
    Return a minimal ToolConfig mock for Phase 5 calls.

    Only the fields consumed by _phase_5_execute are mocked:
        config.execution.fail_fast
    """
    cfg = MagicMock()
    cfg.execution.fail_fast = fail_fast
    return cfg


# ===========================================================================
# Section A — Result accumulation
# ===========================================================================


class TestResultAccumulation:
    """
    Phase 5 accumulates one TestResult per executed test into the ResultSet.

    This is the core execution contract: every test that appears in the
    schedule is executed exactly once, and its result is appended to the
    ResultSet in execution order.
    """

    def test_each_executed_test_adds_exactly_one_result(
        self, tmp_path: Path, minimal_config_file: Path
    ) -> None:
        """
        Three scheduled tests produce a ResultSet with exactly three results.

        This ensures the engine does not double-execute tests (which would
        inflate finding counts) or silently skip them (which would produce
        a false-negative assessment).
        """
        StubA = _make_stub_test("A.1")
        StubB = _make_stub_test("A.2")
        StubC = _make_stub_test("A.3")

        active_tests = [StubA(), StubB(), StubC()]
        batches = _build_batches(["A.1", "A.2", "A.3"])
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=batches,
            active_tests=active_tests,
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(),
        )

        assert result_set.total_count == 3, (
            f"Expected exactly one TestResult per scheduled test; got {result_set.total_count}"
        )

    def test_pass_result_increments_pass_count(
        self, tmp_path: Path, minimal_config_file: Path
    ) -> None:
        """
        A PASS result from a test is reflected in ResultSet.pass_count.

        PASS means the security guarantee was verified — the operator needs
        to see an accurate count to trust the assessment coverage.
        """
        StubPass = _make_stub_test("B.1", result_status=TestStatus.PASS)
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=_build_batches(["B.1"]),
            active_tests=[StubPass()],
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(),
        )

        assert result_set.pass_count == 1
        assert result_set.fail_count == 0

    def test_fail_result_increments_fail_count(
        self, tmp_path: Path, minimal_config_file: Path
    ) -> None:
        """
        A FAIL result from a test is reflected in ResultSet.fail_count.

        FAIL means a security violation was detected. The operator's
        primary decision signal is fail_count > 0 → exit code 1.
        """
        StubFail = _make_stub_test("C.1", result_status=TestStatus.FAIL)
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=_build_batches(["C.1"]),
            active_tests=[StubFail()],
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(),
        )

        assert result_set.fail_count == 1
        assert result_set.pass_count == 0

    def test_results_preserve_insertion_order(
        self, tmp_path: Path, minimal_config_file: Path
    ) -> None:
        """
        Results are appended to ResultSet in the order tests are executed.

        The report's table of results must match the topological execution
        order so that prerequisite tests appear before the tests that depend
        on them. Out-of-order results would confuse analysts reading the report.
        """
        StubFirst = _make_stub_test("D.1")
        StubSecond = _make_stub_test("D.2")
        StubThird = _make_stub_test("D.3")

        batches = [
            ScheduledBatch(batch_index=0, test_ids=["D.1"]),
            ScheduledBatch(batch_index=1, test_ids=["D.2"]),
            ScheduledBatch(batch_index=2, test_ids=["D.3"]),
        ]
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=batches,
            active_tests=[StubFirst(), StubSecond(), StubThird()],
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(),
        )

        result_ids = [r.test_id for r in result_set.results]
        assert result_ids == ["D.1", "D.2", "D.3"], (
            f"Expected execution order D.1 → D.2 → D.3, got {result_ids}"
        )

    def test_duration_ms_is_populated_on_every_result(
        self, tmp_path: Path, minimal_config_file: Path
    ) -> None:
        """
        The engine measures wall-clock time for each test and stores it in duration_ms.

        duration_ms is displayed in the HTML report. A None value would
        render as '—' (em dash), which is acceptable only for edge cases.
        For normally executed tests, the field must always be populated.
        """
        StubTimed = _make_stub_test("E.1")
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=_build_batches(["E.1"]),
            active_tests=[StubTimed()],
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(),
        )

        result = result_set.results[0]
        assert result.duration_ms is not None, (
            "duration_ms must be populated by the engine for every executed test"
        )
        assert result.duration_ms >= 0.0, (
            f"duration_ms must be non-negative; got {result.duration_ms}"
        )


# ===========================================================================
# Section B — Empty schedule
# ===========================================================================


class TestEmptySchedule:
    """
    When the schedule is empty (no active tests passed Phase 4 filters),
    Phase 5 must produce an empty ResultSet without raising.

    An empty ResultSet → exit code 0 → the operator sees a warning in the
    log that no tests ran, not a crash.
    """

    def test_empty_batches_produce_empty_result_set(
        self, tmp_path: Path, minimal_config_file: Path
    ) -> None:
        """
        Zero batches → zero results. The engine must not raise.

        This covers the case where the configuration's min_priority and
        strategy filters are so restrictive that no test survives discovery.
        """
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=[],
            active_tests=[],
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(),
        )

        assert result_set.total_count == 0
        assert result_set.compute_exit_code() == 0


# ===========================================================================
# Section C — Lookup miss (DAGScheduler / TestRegistry inconsistency)
# ===========================================================================


class TestLookupMiss:
    """
    If a test_id appears in the schedule but has no corresponding BaseTest
    instance, the engine must skip it and continue — not raise.

    This inconsistency indicates a bug in TestRegistry or DAGScheduler.
    The engine must be resilient to it: skipping one test is preferable to
    aborting the assessment and producing no results at all.
    """

    def test_unknown_test_id_in_batch_is_skipped_silently(
        self, tmp_path: Path, minimal_config_file: Path
    ) -> None:
        """
        A batch containing a test_id with no corresponding instance is skipped.

        The test that does have a matching instance must still execute and
        produce its result. The missing test_id must not appear in the ResultSet.
        """
        StubReal = _make_stub_test("F.1")
        batches = _build_batches(["GHOST.ID", "F.1"])
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=batches,
            active_tests=[StubReal()],  # GHOST.ID has no instance here
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(),
        )

        result_ids = [r.test_id for r in result_set.results]
        assert "GHOST.ID" not in result_ids, (
            "A test_id with no matching instance must not appear in the ResultSet"
        )
        assert "F.1" in result_ids, (
            "Valid tests in the same batch must still execute despite a lookup miss"
        )

    def test_lookup_miss_does_not_raise(self, tmp_path: Path, minimal_config_file: Path) -> None:
        """
        A missing test_id in the lookup table must not raise any exception.

        The engine catches this case with a log.error() and a continue,
        matching the best-effort resilience philosophy of Phase 6.
        """
        batches = _build_batches(["NONEXISTENT.1"])
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        # Must not raise
        engine._phase_5_execute(
            scheduled_batches=batches,
            active_tests=[],
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(),
        )
        assert result_set.total_count == 0


# ===========================================================================
# Section D — Fail-fast condition
# ===========================================================================


class TestFailFastCondition:
    """
    When config.execution.fail_fast is True, a P0 test returning FAIL or ERROR
    must halt the execution loop immediately.

    Fail-fast is a critical gate for high-assurance pipelines: a P0 failure
    indicates a fundamental perimeter control is broken. Continuing to run
    lower-priority tests in that state would produce misleading results
    (authenticated tests can't work if auth is broken).

    The fail-fast condition has four dimensions:
        - Only P0 tests can trigger it (priority == 0).
        - Both FAIL and ERROR are blocking statuses for P0.
        - Tests scheduled AFTER the trigger must not execute.
        - Tests in the SAME batch before the trigger must have already executed.
    """

    def test_p0_fail_triggers_fail_fast_when_enabled(
        self, tmp_path: Path, minimal_config_file: Path
    ) -> None:
        """
        A P0 FAIL result halts execution of subsequent tests when fail_fast=True.

        Tests scheduled after the P0 failure must not appear in the ResultSet.
        The test before the trigger must have its result recorded.
        """
        StubP0Fail = _make_stub_test("G.1", result_status=TestStatus.FAIL, priority=0)
        StubAfter = _make_stub_test("G.2", result_status=TestStatus.PASS, priority=1)

        batches = [
            ScheduledBatch(batch_index=0, test_ids=["G.1"]),
            ScheduledBatch(batch_index=1, test_ids=["G.2"]),
        ]
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=batches,
            active_tests=[StubP0Fail(), StubAfter()],
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(fail_fast=True),
        )

        result_ids = [r.test_id for r in result_set.results]
        assert "G.1" in result_ids, "The triggering P0 test must have its result recorded"
        assert "G.2" not in result_ids, "Tests scheduled after a fail-fast trigger must not execute"

    def test_p0_error_also_triggers_fail_fast(
        self, tmp_path: Path, minimal_config_file: Path
    ) -> None:
        """
        A P0 ERROR result halts execution of subsequent tests when fail_fast=True.

        Both FAIL and ERROR are treated as blocking for P0. ERROR means the
        test encountered an unexpected failure — the assessment integrity is
        equally compromised in both cases.
        """
        StubP0Error = _make_stub_test(
            "H.1",
            result_status=TestStatus.ERROR,
            priority=0,
            side_effect=RuntimeError("Simulated infra failure"),
        )
        StubAfter = _make_stub_test("H.2")

        batches = [
            ScheduledBatch(batch_index=0, test_ids=["H.1"]),
            ScheduledBatch(batch_index=1, test_ids=["H.2"]),
        ]
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=batches,
            active_tests=[StubP0Error(), StubAfter()],
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(fail_fast=True),
        )

        result_ids = [r.test_id for r in result_set.results]
        assert "H.2" not in result_ids, "P0 ERROR must trigger fail-fast identically to P0 FAIL"

    def test_non_p0_fail_does_not_trigger_fail_fast(
        self, tmp_path: Path, minimal_config_file: Path
    ) -> None:
        """
        A P1/P2/P3 FAIL does not trigger fail-fast even when fail_fast=True.

        Only P0 tests represent perimeter controls whose failure invalidates
        the entire assessment. Lower-priority failures are violations to record
        and report, not reasons to halt the pipeline.
        """
        StubP1Fail = _make_stub_test("I.1", result_status=TestStatus.FAIL, priority=1)
        StubAfter = _make_stub_test("I.2", result_status=TestStatus.PASS)

        batches = [
            ScheduledBatch(batch_index=0, test_ids=["I.1"]),
            ScheduledBatch(batch_index=1, test_ids=["I.2"]),
        ]
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=batches,
            active_tests=[StubP1Fail(), StubAfter()],
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(fail_fast=True),
        )

        result_ids = [r.test_id for r in result_set.results]
        assert "I.2" in result_ids, "P1 FAIL must not trigger fail-fast; I.2 must execute normally"

    def test_fail_fast_disabled_p0_fail_does_not_halt(
        self, tmp_path: Path, minimal_config_file: Path
    ) -> None:
        """
        When fail_fast=False, a P0 FAIL must not stop execution.

        The fail_fast flag is opt-in. By default (fail_fast=False), the engine
        must run all scheduled tests regardless of individual outcomes.
        """
        StubP0Fail = _make_stub_test("J.1", result_status=TestStatus.FAIL, priority=0)
        StubAfter = _make_stub_test("J.2")

        batches = [
            ScheduledBatch(batch_index=0, test_ids=["J.1"]),
            ScheduledBatch(batch_index=1, test_ids=["J.2"]),
        ]
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=batches,
            active_tests=[StubP0Fail(), StubAfter()],
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(fail_fast=False),
        )

        result_ids = [r.test_id for r in result_set.results]
        assert "J.2" in result_ids, (
            "With fail_fast=False, all tests must run regardless of P0 failures"
        )
        assert result_set.total_count == 2

    def test_p0_pass_does_not_trigger_fail_fast(
        self, tmp_path: Path, minimal_config_file: Path
    ) -> None:
        """
        A P0 test that returns PASS must not trigger fail-fast.

        Only FAIL and ERROR are blocking statuses. PASS means the control is
        satisfied — execution must continue normally.
        """
        StubP0Pass = _make_stub_test("K.1", result_status=TestStatus.PASS, priority=0)
        StubAfter = _make_stub_test("K.2")

        batches = [
            ScheduledBatch(batch_index=0, test_ids=["K.1"]),
            ScheduledBatch(batch_index=1, test_ids=["K.2"]),
        ]
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=batches,
            active_tests=[StubP0Pass(), StubAfter()],
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(fail_fast=True),
        )

        assert result_set.total_count == 2, (
            "P0 PASS must not trigger fail-fast; both tests must execute"
        )


# ===========================================================================
# Section E — Exit code mapping
# ===========================================================================


class TestExitCodeMapping:
    """
    The ResultSet.compute_exit_code() method implements the exit code contract
    defined in Implementazione.md Section 7. Phase 5 populates the ResultSet;
    the exit code is computed at the end of _run_pipeline() before Phase 7.

    Testing exit code computation here — rather than in a separate unit test
    file — documents the relationship between execution outcomes and the
    process exit code that operators observe in CI pipelines.
    """

    def test_all_pass_produces_exit_code_0(self, tmp_path: Path, minimal_config_file: Path) -> None:
        """
        All PASS → exit code 0 (clean assessment).

        Exit code 0 means: every security guarantee was verified and satisfied.
        CI pipelines treat 0 as success.
        """
        StubA = _make_stub_test("L.1", result_status=TestStatus.PASS)
        StubB = _make_stub_test("L.2", result_status=TestStatus.PASS)
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=_build_batches(["L.1", "L.2"]),
            active_tests=[StubA(), StubB()],
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(),
        )

        assert result_set.compute_exit_code() == 0

    def test_any_fail_produces_exit_code_1(self, tmp_path: Path, minimal_config_file: Path) -> None:
        """
        At least one FAIL → exit code 1, even when other tests PASS.

        Exit code 1 signals that a security violation was detected.
        FAIL takes precedence over ERROR in the exit code hierarchy.
        """
        StubPass = _make_stub_test("M.1", result_status=TestStatus.PASS)
        StubFail = _make_stub_test("M.2", result_status=TestStatus.FAIL)
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=_build_batches(["M.1", "M.2"]),
            active_tests=[StubPass(), StubFail()],
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(),
        )

        assert result_set.compute_exit_code() == 1

    def test_error_without_fail_produces_exit_code_2(
        self, tmp_path: Path, minimal_config_file: Path
    ) -> None:
        """
        ERROR (without any FAIL) → exit code 2.

        Exit code 2 signals that the assessment integrity is uncertain —
        at least one test could not complete. An operator must investigate
        the ERROR before trusting the absence of FAIL results.
        """
        StubError = _make_stub_test(
            "N.1",
            result_status=TestStatus.ERROR,
            side_effect=RuntimeError("infra"),
        )
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=_build_batches(["N.1"]),
            active_tests=[StubError()],
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(),
        )

        assert result_set.compute_exit_code() == 2

    def test_fail_takes_precedence_over_error_for_exit_code(
        self, tmp_path: Path, minimal_config_file: Path
    ) -> None:
        """
        When both FAIL and ERROR are present, exit code is 1 (not 2).

        FAIL is the more actionable signal: a security violation was detected.
        The priority ordering (FAIL > ERROR > PASS/SKIP) is documented in
        Implementazione.md Section 7.
        """
        StubFail = _make_stub_test("O.1", result_status=TestStatus.FAIL)
        StubError = _make_stub_test(
            "O.2",
            result_status=TestStatus.ERROR,
            side_effect=RuntimeError("infra"),
        )
        result_set = ResultSet()
        engine = _build_engine(minimal_config_file)

        engine._phase_5_execute(
            scheduled_batches=_build_batches(["O.1", "O.2"]),
            active_tests=[StubFail(), StubError()],
            target=MagicMock(),
            context=TestContext(),
            client=MagicMock(),
            store=EvidenceStore(tmp_path / "evidence_tmp"),
            result_set=result_set,
            config=_mock_config(),
        )

        assert result_set.compute_exit_code() == 1, (
            "FAIL must take precedence over ERROR in exit code computation"
        )
