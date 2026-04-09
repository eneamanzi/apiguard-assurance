"""
src/engine.py

Assessment pipeline orchestrator for the APIGuard Assurance tool.

The engine is the only module with full visibility across all components.
Its responsibility is exclusively orchestrative: it calls the right modules
in the right order, passes the right objects, and records the results.

The engine contains NO domain logic, NO test interpretation, NO decisions
about what to test. Every such decision is delegated to the appropriate
component:
    - What to test:        TestRegistry + DAGScheduler
    - How to test:         BaseTest.execute() implementations
    - What HTTP to send:   SecurityClient
    - What to record:      EvidenceStore (populated by tests)
    - What to report:      report/builder.py + report/renderer.py

Pipeline phases (Implementazione.md, Section 5):

    Phase 1 — Initialization:
        Load and validate config.yaml via config/loader.py.
        Raises ConfigurationError on failure [BLOCKS STARTUP].

    Phase 2 — OpenAPI Discovery:
        Fetch, dereference, and validate the OpenAPI spec (with timeout watchdog).
        Build AttackSurface from the dereferenced spec.
        Raises OpenAPILoadError on failure [BLOCKS STARTUP].

    Phase 3 — Context Construction:
        Build TargetContext (frozen) from ToolConfig + AttackSurface.
        Build TestContext (mutable, empty).
        Build EvidenceStore (deque, maxlen=100).
        Build SecurityClient (context manager, not yet open).

    Phase 4 — Test Discovery and Scheduling:
        TestRegistry discovers and filters active tests.
        DAGScheduler builds the topological execution order.
        Raises DAGCycleError on dependency cycle [BLOCKS STARTUP].

    Phase 5 — Execution:
        For each ScheduledBatch in topological order:
            For each test in the batch (sequential):
                Call test.execute(target, context, client, store).
                Add TestResult to ResultSet.
                Check fail-fast condition.

    Phase 6 — Teardown (Best-Effort):
        Drain TestContext resource registry in LIFO order.
        DELETE each registered resource via SecurityClient.
        Log TeardownError as WARNING; continue on failure.

    Phase 7 — Report Generation:
        Aggregate ResultSet statistics via report/builder.py.
        Serialize EvidenceStore to config.output.evidence_path.
        Render HTML report to config.output.report_path.
        Compute and return exit code.

Dependency rule:
    engine.py imports from all src/ layers (config/, core/, discovery/,
    tests/, report/). It is the only module permitted to do so.
    No other module imports from engine.py.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

import structlog

from src.config.loader import load_config
from src.config.schema import ToolConfig
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.dag import DAGScheduler, ScheduledBatch
from src.core.evidence import EvidenceStore
from src.core.exceptions import (
    ConfigurationError,
    DAGCycleError,
    OpenAPILoadError,
    TeardownError,
)
from src.core.models import AttackSurface, ResultSet, TestResult, TestStatus
from src.discovery.openapi import load_openapi_spec
from src.discovery.surface import build_attack_surface
from src.report.builder import build_report_data
from src.report.renderer import render_html_report
from src.tests.base import BaseTest
from src.tests.registry import TestRegistry

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXIT_CODE_CLEAN: int = 0
EXIT_CODE_FAIL: int = 1
EXIT_CODE_ERROR: int = 2
EXIT_CODE_INFRASTRUCTURE: int = 10


# ---------------------------------------------------------------------------
# AssessmentEngine
# ---------------------------------------------------------------------------


class AssessmentEngine:
    """
    Orchestrator for the APIGuard Assurance assessment pipeline.

    One AssessmentEngine instance is created per pipeline run by cli.py.
    The run() method executes all seven phases sequentially and returns
    the process exit code.

    The engine is intentionally not reusable across multiple runs: each
    run creates fresh instances of all shared state objects (TargetContext,
    TestContext, EvidenceStore, ResultSet). Reusing an engine instance would
    risk contaminating results from a previous run.
    """

    def __init__(self, config_path: Path) -> None:
        """
        Initialize the engine with the path to the configuration file.

        Does not load the configuration or perform any I/O at construction
        time. All I/O begins in run() Phase 1.

        Args:
            config_path: Path to the config.yaml file.
        """
        self._config_path: Path = config_path
        self._run_id: str = _generate_run_id()

        log.info(
            "assessment_engine_initialized",
            run_id=self._run_id,
            config_path=str(config_path),
        )

    def run(self) -> int:
        """
        Execute the complete assessment pipeline and return the exit code.

        Returns:
            int: Process exit code. One of: 0, 1, 2, 10.
        """
        log.info("assessment_pipeline_started", run_id=self._run_id)
        wall_start = time.monotonic()

        try:
            exit_code = self._run_pipeline()
        except (ConfigurationError, OpenAPILoadError, DAGCycleError) as exc:
            log.error(
                "assessment_pipeline_infrastructure_failure",
                run_id=self._run_id,
                exc_type=type(exc).__name__,
                detail=str(exc),
            )
            exit_code = EXIT_CODE_INFRASTRUCTURE
        except Exception as exc:  # noqa: BLE001
            log.error(
                "assessment_pipeline_unexpected_engine_error",
                run_id=self._run_id,
                exc_type=type(exc).__name__,
                detail=str(exc),
            )
            exit_code = EXIT_CODE_INFRASTRUCTURE

        elapsed = time.monotonic() - wall_start
        log.info(
            "assessment_pipeline_completed",
            run_id=self._run_id,
            exit_code=exit_code,
            elapsed_seconds=round(elapsed, 2),
        )

        return exit_code

    # ------------------------------------------------------------------
    # Internal pipeline runner
    # ------------------------------------------------------------------

    def _run_pipeline(self) -> int:
        """
        Execute all seven pipeline phases and return the exit code.

        Phases 1-4 are blocking: exceptions propagate to run() which converts
        them to EXIT_CODE_INFRASTRUCTURE. Phases 5-7 are non-blocking.
        """
        config = self._phase_1_initialize()
        attack_surface = self._phase_2_openapi_discovery(config)
        target, context, store = self._phase_3_build_contexts(
            config=config,
            attack_surface=attack_surface,
        )
        scheduled_batches, active_tests = self._phase_4_discover_and_schedule(config)

        result_set = ResultSet()

        with SecurityClient(
            base_url=target.endpoint_base_url(),
            connect_timeout=config.execution.connect_timeout,
            read_timeout=config.execution.read_timeout,
            max_retry_attempts=config.execution.max_retry_attempts,
        ) as client:
            self._phase_5_execute(
                scheduled_batches=scheduled_batches,
                active_tests=active_tests,
                target=target,
                context=context,
                client=client,
                store=store,
                result_set=result_set,
                config=config,
            )
            self._phase_6_teardown(
                context=context,
                client=client,
                target=target,
            )

        result_set.completed_at = datetime.now(UTC)

        self._phase_7_report(
            result_set=result_set,
            store=store,
            config=config,
            attack_surface=attack_surface,
        )

        return result_set.compute_exit_code()

    # ------------------------------------------------------------------
    # Phase 1 — Initialization
    # ------------------------------------------------------------------

    def _phase_1_initialize(self) -> ToolConfig:
        """
        Load and validate config.yaml.

        Returns:
            Frozen ToolConfig instance.

        Raises:
            ConfigurationError: If config.yaml is missing, unreadable,
                                 contains unresolved env vars, or fails
                                 Pydantic validation.
        """
        log.info("pipeline_phase_1_initialization_started")

        config = load_config(self._config_path)

        log.info(
            "pipeline_phase_1_initialization_completed",
            base_url=str(config.target.base_url),
            min_priority=config.execution.min_priority,
            strategies=[s.value for s in config.execution.strategies],
            fail_fast=config.execution.fail_fast,
            output_directory=str(config.output.directory),
            openapi_fetch_timeout_seconds=config.execution.openapi_fetch_timeout_seconds,
        )

        return config

    # ------------------------------------------------------------------
    # Phase 2 — OpenAPI Discovery
    # ------------------------------------------------------------------

    def _phase_2_openapi_discovery(self, config: ToolConfig) -> AttackSurface:
        """
        Fetch the OpenAPI spec and build the AttackSurface.

        The spec fetch runs with an explicit timeout from
        config.execution.openapi_fetch_timeout_seconds. If prance does not
        complete within that budget, OpenAPILoadError is raised and the
        pipeline is aborted (Phase 2 is blocking).

        The source_url is forwarded to build_attack_surface() so that any
        OpenAPILoadError raised in surface.py carries the full context needed
        for structured error logging.

        Returns:
            Populated AttackSurface instance.

        Raises:
            OpenAPILoadError: If the spec cannot be fetched, dereferenced,
                              validated, or if the fetch times out.
        """
        log.info("pipeline_phase_2_openapi_discovery_started")

        # Capture the spec URL string once to pass consistently to both
        # load_openapi_spec (for prance) and build_attack_surface (for
        # diagnostic context in any OpenAPILoadError raised there).
        spec_url: str = str(config.target.openapi_spec_url)

        spec, dialect = load_openapi_spec(
            spec_url,
            timeout_seconds=config.execution.openapi_fetch_timeout_seconds,
        )
        attack_surface = build_attack_surface(spec, dialect, source_url=spec_url)

        log.info(
            "pipeline_phase_2_openapi_discovery_completed",
            spec_title=attack_surface.spec_title,
            spec_version=attack_surface.spec_version,
            dialect=attack_surface.dialect,
            total_endpoints=attack_surface.total_endpoint_count,
            unique_paths=attack_surface.unique_path_count,
        )

        return attack_surface

    # ------------------------------------------------------------------
    # Phase 3 — Context Construction
    # ------------------------------------------------------------------

    def _phase_3_build_contexts(
        self,
        config: ToolConfig,
        attack_surface: AttackSurface,
    ) -> tuple[TargetContext, TestContext, EvidenceStore]:
        """
        Construct the three shared state objects for the pipeline run.

        TargetContext is frozen and populated from config + attack_surface.
        TestContext is mutable and starts empty.
        EvidenceStore starts empty.

        Returns:
            Tuple of (TargetContext, TestContext, EvidenceStore).
        """
        log.info("pipeline_phase_3_context_construction_started")

        target = TargetContext(
            base_url=config.target.base_url,
            openapi_spec_url=config.target.openapi_spec_url,
            admin_api_url=config.target.admin_api_url,
            attack_surface=attack_surface,
        )

        context = TestContext()
        store = EvidenceStore()

        log.info(
            "pipeline_phase_3_context_construction_completed",
            admin_api_available=target.admin_api_available,
        )

        return target, context, store

    # ------------------------------------------------------------------
    # Phase 4 — Test Discovery and Scheduling
    # ------------------------------------------------------------------

    def _phase_4_discover_and_schedule(
        self,
        config: ToolConfig,
    ) -> tuple[list[ScheduledBatch], list[BaseTest]]:
        """
        Discover active tests and build the topological execution schedule.

        Returns:
            Tuple of (list[ScheduledBatch], list[BaseTest]).

        Raises:
            DAGCycleError: If a circular dependency is detected.
        """
        log.info("pipeline_phase_4_discovery_and_scheduling_started")

        registry = TestRegistry()
        active_tests = registry.discover(
            min_priority=config.execution.min_priority,
            enabled_strategies=set(config.execution.strategies),
        )

        if not active_tests:
            log.warning(
                "pipeline_phase_4_no_active_tests",
                min_priority=config.execution.min_priority,
                strategies=[s.value for s in config.execution.strategies],
                detail=(
                    "No tests matched the configured priority and strategy filters. "
                    "The assessment will produce an empty report."
                ),
            )
            return [], active_tests

        dependency_map = registry.build_dependency_map(active_tests)

        scheduler = DAGScheduler()
        active_test_ids = {t.__class__.test_id for t in active_tests}
        scheduled_batches = scheduler.build_schedule(
            dependencies=dependency_map,
            active_test_ids=active_test_ids,
        )

        total_scheduled = sum(b.size for b in scheduled_batches)
        log.info(
            "pipeline_phase_4_discovery_and_scheduling_completed",
            active_tests=len(active_tests),
            batch_count=len(scheduled_batches),
            total_scheduled=total_scheduled,
        )

        return scheduled_batches, active_tests

    # ------------------------------------------------------------------
    # Phase 5 — Execution
    # ------------------------------------------------------------------

    def _phase_5_execute(
        self,
        scheduled_batches: list[ScheduledBatch],
        active_tests: list[BaseTest],
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
        result_set: ResultSet,
        config: ToolConfig,
    ) -> None:
        """
        Execute all scheduled tests in topological order.

        For each ScheduledBatch, iterates over test_ids sequentially.
        Each test is located by test_id in the active_tests list, then
        executed via test.execute(). The TestResult is added to result_set.

        Fail-fast condition (Implementazione.md, Section 4.7):
            If config.execution.fail_fast is True and a P0 test returns
            FAIL or ERROR, execution stops immediately.
        """
        log.info(
            "pipeline_phase_5_execution_started",
            batch_count=len(scheduled_batches),
        )

        test_lookup: dict[str, BaseTest] = {t.__class__.test_id: t for t in active_tests}
        fail_fast_triggered = False

        for batch in scheduled_batches:
            if fail_fast_triggered:
                break

            log.debug(
                "pipeline_phase_5_batch_starting",
                batch_index=batch.batch_index,
                batch_size=batch.size,
                test_ids=batch.test_ids,
            )

            for test_id in batch.test_ids:
                if fail_fast_triggered:
                    break

                test = test_lookup.get(test_id)
                if test is None:
                    log.error(
                        "pipeline_phase_5_test_id_not_in_lookup",
                        test_id=test_id,
                        detail=(
                            "A test_id appeared in the scheduled batch but has "
                            "no corresponding BaseTest instance in the active "
                            "tests lookup. This indicates a DAGScheduler / "
                            "TestRegistry inconsistency."
                        ),
                    )
                    continue

                result = self._execute_single_test(
                    test=test,
                    target=target,
                    context=context,
                    client=client,
                    store=store,
                )
                result_set.add_result(result)

                if config.execution.fail_fast:
                    fail_fast_triggered = self._check_fail_fast(
                        result=result,
                        test=test,
                    )

            log.debug(
                "pipeline_phase_5_batch_completed",
                batch_index=batch.batch_index,
            )

        if fail_fast_triggered:
            log.warning(
                "pipeline_phase_5_fail_fast_triggered",
                results_recorded=result_set.total_count,
                detail="Execution aborted by fail-fast condition. A P0 test returned FAIL or ERROR.",  # noqa: E501
            )

        log.info(
            "pipeline_phase_5_execution_completed",
            total_results=result_set.total_count,
            pass_count=result_set.pass_count,
            fail_count=result_set.fail_count,
            skip_count=result_set.skip_count,
            error_count=result_set.error_count,
        )

    def _execute_single_test(
        self,
        test: BaseTest,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Execute a single test and return its TestResult with timing.

        Measures wall-clock execution time and stores it in duration_ms.
        The contract that execute() never raises is assumed here.
        """
        cls = test.__class__
        test_id = cls.test_id
        test_name = cls.test_name

        log.info(
            "test_execution_started",
            test_id=test_id,
            test_name=test_name,
            priority=cls.priority,
            strategy=cls.strategy.value,
        )

        wall_start = time.monotonic()
        result = test.execute(target, context, client, store)
        elapsed_ms = (time.monotonic() - wall_start) * 1000.0

        result = result.model_copy(update={"duration_ms": round(elapsed_ms, 2)})

        log.info(
            "test_execution_completed",
            test_id=test_id,
            status=result.status.value,
            finding_count=len(result.findings),
            duration_ms=round(elapsed_ms, 2),
        )

        return result

    @staticmethod
    def _check_fail_fast(result: TestResult, test: BaseTest) -> bool:
        """
        Determine whether the fail-fast condition is triggered.

        Condition: test has priority P0 AND status is FAIL or ERROR.
        Both FAIL and ERROR are treated as blocking for P0 tests because
        an ERROR means the verification of a critical guarantee did not
        complete — proceeding would produce an assessment without foundation.
        """
        is_p0 = test.__class__.priority == 0
        is_blocking_status = result.status in (TestStatus.FAIL, TestStatus.ERROR)

        if is_p0 and is_blocking_status:
            log.warning(
                "fail_fast_condition_met",
                test_id=test.__class__.test_id,
                status=result.status.value,
                priority=test.__class__.priority,
            )
            return True

        return False

    # ------------------------------------------------------------------
    # Phase 6 — Teardown
    # ------------------------------------------------------------------

    def _phase_6_teardown(
        self,
        context: TestContext,
        client: SecurityClient,
        target: TargetContext,
    ) -> None:
        """
        Delete all resources registered during Phase 5 in LIFO order.

        Each DELETE request is attempted via SecurityClient. Failures are
        caught, logged as WARNING, and execution continues. A teardown failure
        does not affect the ResultSet or the exit code.
        """
        log.info(
            "pipeline_phase_6_teardown_started",
            pending_resources=context.registered_resource_count(),
        )

        resources = context.drain_resources()

        if not resources:
            log.info("pipeline_phase_6_teardown_completed_no_resources")
            return

        success_count = 0
        failure_count = 0
        acceptable_codes = {200, 204, 404}

        for method, path in resources:
            try:
                response, _ = client.request(
                    method=method,
                    path=path,
                    test_id="teardown",
                )
                if response.status_code not in acceptable_codes:
                    raise TeardownError(
                        message=(
                            f"DELETE {path} returned unexpected status "
                            f"{response.status_code}. "
                            f"Expected one of: {sorted(acceptable_codes)}."
                        ),
                        resource_method=method,
                        resource_path=path,
                        failed_status_code=response.status_code,
                    )
                success_count += 1
                log.debug(
                    "teardown_resource_deleted",
                    method=method,
                    path=path,
                    status_code=response.status_code,
                )

            except TeardownError as exc:
                failure_count += 1
                log.warning(
                    "teardown_resource_deletion_failed",
                    method=exc.resource_method,
                    path=exc.resource_path,
                    failed_status_code=exc.failed_status_code,
                    detail=exc.message,
                    manual_cleanup_required=True,
                )

            except Exception as exc:  # noqa: BLE001
                failure_count += 1
                log.warning(
                    "teardown_resource_unexpected_error",
                    method=method,
                    path=path,
                    exc_type=type(exc).__name__,
                    detail=str(exc),
                    manual_cleanup_required=True,
                )

        log.info(
            "pipeline_phase_6_teardown_completed",
            total_resources=len(resources),
            success_count=success_count,
            failure_count=failure_count,
        )

    # ------------------------------------------------------------------
    # Phase 7 — Report Generation
    # ------------------------------------------------------------------

    def _phase_7_report(
        self,
        result_set: ResultSet,
        store: EvidenceStore,
        config: ToolConfig,
        attack_surface: AttackSurface,
    ) -> None:
        """
        Serialize evidence and generate the HTML assessment report.

        Errors during report generation are logged as ERROR but do not
        change the exit code: assessment results are correct regardless of
        whether the report was successfully written to disk.
        """
        evidence_path = config.output.evidence_path
        report_path = config.output.report_path

        log.info(
            "pipeline_phase_7_report_generation_started",
            total_results=result_set.total_count,
            evidence_records=store.record_count,
            evidence_path=str(evidence_path),
            report_path=str(report_path),
        )

        try:
            records_written = store.to_json_file(evidence_path)
            log.info(
                "pipeline_phase_7_evidence_serialized",
                output_path=str(evidence_path),
                records_written=records_written,
            )
        except OSError as exc:
            log.error(
                "pipeline_phase_7_evidence_serialization_failed",
                output_path=str(evidence_path),
                detail=str(exc),
            )

        try:
            report_data = build_report_data(
                result_set=result_set,
                run_id=self._run_id,
                config=config,
                spec_title=attack_surface.spec_title,
                spec_version=attack_surface.spec_version,
            )
        except Exception as exc:  # noqa: BLE001
            log.error(
                "pipeline_phase_7_report_data_build_failed",
                exc_type=type(exc).__name__,
                detail=str(exc),
            )
            return

        try:
            render_html_report(
                report_data=report_data,
                output_path=report_path,
            )
            log.info(
                "pipeline_phase_7_html_report_rendered",
                output_path=str(report_path),
            )
        except Exception as exc:  # noqa: BLE001
            log.error(
                "pipeline_phase_7_html_report_render_failed",
                exc_type=type(exc).__name__,
                detail=str(exc),
            )

        log.info("pipeline_phase_7_report_generation_completed")


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def _generate_run_id() -> str:
    """
    Generate a unique run identifier for this pipeline execution.

    Format: 'apiguard-{YYYYMMDD}-{HHMMSS}-{microseconds}'
    Example: 'apiguard-20260328-142305-123456'

    Timestamp-based rather than UUID: human-readable in log output
    and chronologically sortable.
    """
    now = datetime.now(UTC)
    return f"apiguard-{now.strftime('%Y%m%d-%H%M%S')}-{now.microsecond:06d}"
