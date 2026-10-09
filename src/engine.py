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

Pipeline phases (docs/architecture/overview.md, "Pipeline"):

    Phase 1 -- Initialization:
        Load and validate config.yaml via config/loader.py.
        Raises ConfigurationError on failure [BLOCKS STARTUP].

    Phase 2 -- OpenAPI Discovery:
        Resolve the spec source via TargetConfig.get_openapi_source().
        This returns either an HTTP/HTTPS URL or a local filesystem path,
        depending on which field is set in config.yaml. The distinction is
        transparent to the rest of the engine: load_openapi_spec() accepts
        both formats natively.
        Fetch or read, dereference, and validate the OpenAPI spec.
        Build AttackSurface from the dereferenced spec.
        Raises OpenAPILoadError on failure [BLOCKS STARTUP].

    Phase 3 -- Context Construction:
        Build TargetContext (frozen) from ToolConfig + AttackSurface.
        Propagates both openapi_spec_url and openapi_spec_path from
        TargetConfig to TargetContext (exactly one will be non-None).
        Build TestContext (mutable, empty).
        Build EvidenceStore (streaming JSONL, unbounded capacity).

    Phase 4 -- Test Discovery and Scheduling:
        TestRegistry discovers and filters active tests.
        DAGScheduler builds the topological execution order.
        Raises DAGCycleError on dependency cycle [BLOCKS STARTUP].

    Phase 5 -- Execution:
        For each ScheduledBatch in topological order:
            For each test in the batch (sequential):
                Call test.execute(target, context, client, store).
                Add TestResult to ResultSet.
                Check fail-fast condition.

    Phase 6 -- Teardown (Best-Effort):
        Drain TestContext resource registry in LIFO order.
        DELETE each registered resource via SecurityClient.
        Log TeardownError as WARNING; continue on failure.

    Phase 7 -- Report Generation:
        Serialize EvidenceStore to config.output.evidence_path via merge_and_finalize().
        Aggregate ResultSet statistics via report/builder.py -> ReportData.
        Render HTML report to config.output.report_path via report/renderer.py.
        Write JSON report via ReportData.model_dump_json().
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

from src.config.loader import closest_match, load_config
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
    TestDefinitionError,
    raise_for_test_definition_problems,
)
from src.core.gateway.kong import KongGatewayAdapter
from src.core.models import (
    AttackSurface,
    ExitCode,
    NotRunEntry,
    NotRunReason,
    ResultSet,
    RuntimeCredentials,
    TestResult,
    TestStatus,
)
from src.core.test_metadata import is_external_test_id
from src.discovery.openapi import load_openapi_spec
from src.discovery.surface import build_attack_surface
from src.external_tests.base import ExternalToolTest
from src.external_tests.registry import ExternalTestRegistry
from src.report.builder import build_report_data
from src.report.renderer import render_html_report
from src.test_config.runtime import RuntimeTestsConfig
from src.tests.base import BaseTest
from src.tests.registry import TestRegistry

log: structlog.BoundLogger = structlog.get_logger(__name__)

# Similarity threshold for suggesting a test ID in place of an unknown one.
# Higher than for configuration keys (0.6): test IDs are short and close to
# each other, so 0.6 would suggest "1.6" for "1.7"; 0.8 keeps real typos
# ("ext.1.5.sslyzee" -> "ext.1.5.sslyze", "ext.0.1.nucle" -> "ext.0.1.nuclei").
_TEST_ID_SUGGESTION_CUTOFF: float = 0.8


def check_tests(config: ToolConfig) -> None:
    """
    Check the test declarations and the execution.test_ids entries.

    Called by the engine right after Phase 1, before any contact with the
    target, and by ``apiguard validate-config``. Two checks, in order:

    1. Test declarations (src/core/test_metadata.py): both registries are
       scanned, native and external (even with external tools disabled), and
       the problems of both are listed together.
    2. execution.test_ids content (its format is checked by the
       configuration schema): an entry is rejected when no test has that ID
       (with the closest ID as a suggestion), or when it is an external test
       whose tool is disabled (master switch or per-tool switch): test_ids
       chooses among available tests and never enables a tool.

    Args:
        config: The validated configuration.

    Raises:
        TestDefinitionError: Listing every declaration problem.
        ConfigurationError: Listing every rejected test_ids entry.
    """
    definition_problems: list[str] = []
    native_ids: set[str] = set()
    external_tools: dict[str, str] = {}
    try:
        native_ids = TestRegistry().list_test_ids()
    except TestDefinitionError as exc:
        definition_problems.extend(exc.problems)
    try:
        external_tools = ExternalTestRegistry().list_test_tools()
    except TestDefinitionError as exc:
        definition_problems.extend(exc.problems)
    raise_for_test_definition_problems(definition_problems)

    requested = config.execution.test_ids
    if not requested:
        return
    known_ids = sorted(native_ids | set(external_tools))

    problems: list[str] = []
    for test_id in requested:
        if test_id in native_ids:
            continue
        tool_name = external_tools.get(test_id)
        if tool_name is None:
            suggestion = closest_match(test_id, known_ids, _TEST_ID_SUGGESTION_CUTOFF)
            hint = f" (did you mean '{suggestion}'?)" if suggestion is not None else ""
            problems.append(f"unknown test '{test_id}'{hint}")
        elif not config.external_tools.is_tool_enabled(tool_name):
            switch = (
                f"external_tools.{tool_name}.enabled is false"
                if config.external_tools.enabled
                else "external_tools.enabled is false"
            )
            problems.append(f"'{test_id}' cannot run: {switch}")

    if problems:
        raise ConfigurationError(
            message=(
                f"Test selection invalid with {len(problems)} error(s):\n"
                + "\n".join(f"  - execution.test_ids: {problem}" for problem in problems)
            ),
            config_path="execution.test_ids",
        )


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
            int: Process exit code (an ExitCode member): 0, 1, 3 or 10.
        """
        log.info("assessment_pipeline_started", run_id=self._run_id)
        wall_start = time.monotonic()

        try:
            exit_code = self._run_pipeline()
        except (ConfigurationError, OpenAPILoadError, DAGCycleError, TestDefinitionError) as exc:
            log.error(
                "assessment_pipeline_infrastructure_failure",
                run_id=self._run_id,
                exc_type=type(exc).__name__,
                detail=str(exc),
            )
            exit_code = ExitCode.INFRASTRUCTURE
        except Exception as exc:  # noqa: BLE001
            log.error(
                "assessment_pipeline_unexpected_engine_error",
                run_id=self._run_id,
                exc_type=type(exc).__name__,
                detail=str(exc),
            )
            exit_code = ExitCode.INFRASTRUCTURE

        elapsed = time.monotonic() - wall_start
        log.info(
            "assessment_pipeline_completed",
            run_id=self._run_id,
            exit_code=int(exit_code),
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
        them to ExitCode.INFRASTRUCTURE. Phases 5-7 are non-blocking.
        """
        config = self._phase_1_initialize()
        check_tests(config)
        attack_surface = self._phase_2_openapi_discovery(config)
        target, context, store = self._phase_3_build_contexts(
            config=config,
            attack_surface=attack_surface,
        )
        scheduled_batches, active_tests, not_run = self._phase_4_discover_and_schedule(config)

        result_set = ResultSet(not_run=not_run)

        with SecurityClient(
            base_url=target.endpoint_base_url(),
            connect_timeout=config.execution.connect_timeout,
            read_timeout=config.execution.read_timeout,
            max_retry_attempts=config.execution.max_retry_attempts,
            verify_tls=config.target.verify_tls,
        ) as client:
            # Phase 6 (teardown) MUST run even if Phase 5 is interrupted by
            # KeyboardInterrupt (Ctrl+C) or terminated by an unexpected
            # exception.  Tests in Phase 5 register real resources on the
            # target (Forgejo tokens, repos, gateway routes) via
            # context.register_resource_for_teardown(); skipping Phase 6
            # would leave those resources dangling on the target and could
            # conflict with subsequent runs.
            #
            # The try/finally guarantees teardown is always attempted; the
            # teardown loop itself swallows individual TeardownError instances
            # (logged as WARNING with manual_cleanup_required=True), so a
            # single resource failure cannot abort the cleanup of the rest.
            try:
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
            finally:
                self._phase_6_teardown(
                    context=context,
                    client=client,
                    target=target,
                )

        result_set.completed_at = datetime.now(UTC)
        not_run_by_reason: dict[str, int] = {}
        for entry in result_set.not_run:
            not_run_by_reason[entry.reason.value] = not_run_by_reason.get(entry.reason.value, 0) + 1
        log.info(
            "pipeline_tests_not_run",
            not_run_count=len(result_set.not_run),
            by_reason=not_run_by_reason,
        )

        self._phase_7_report(
            result_set=result_set,
            store=store,
            config=config,
            attack_surface=attack_surface,
        )

        return result_set.compute_exit_code()

    # ------------------------------------------------------------------
    # Phase 1 -- Initialization
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
            openapi_source=config.target.get_openapi_source(),
            openapi_source_type="local_path" if config.target.is_local_spec else "url",
            min_priority=config.execution.min_priority,
            strategies=[s.value for s in config.execution.strategies],
            fail_fast=config.execution.fail_fast,
            output_directory=str(config.output.directory),
            openapi_fetch_timeout_seconds=config.execution.openapi_fetch_timeout_seconds,
        )

        return config

    # ------------------------------------------------------------------
    # Phase 2 -- OpenAPI Discovery
    # ------------------------------------------------------------------

    def _phase_2_openapi_discovery(self, config: ToolConfig) -> AttackSurface:
        """
        Fetch or read the OpenAPI spec and build the AttackSurface.

        The spec source is resolved via TargetConfig.get_openapi_source(),
        which returns either an HTTP/HTTPS URL or an absolute filesystem path
        depending on which config field is set. load_openapi_spec() accepts
        both formats; the distinction is handled transparently inside that
        function, including a pre-flight existence check for local paths.

        For local files the network timeout still applies but is never the
        limiting factor: file I/O completes well within any reasonable budget.

        Returns:
            Populated AttackSurface instance.

        Raises:
            OpenAPILoadError: If the spec cannot be fetched/read, dereferenced,
                              validated, or if a network fetch times out.
        """
        log.info("pipeline_phase_2_openapi_discovery_started")

        spec_source: str = config.target.get_openapi_source()

        log.info(
            "pipeline_phase_2_openapi_source_resolved",
            spec_source=spec_source,
            source_type="local_path" if config.target.is_local_spec else "url",
        )

        spec, dialect = load_openapi_spec(
            spec_source,
            timeout_seconds=config.execution.openapi_fetch_timeout_seconds,
        )
        attack_surface = build_attack_surface(spec, dialect, source_url=spec_source)

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
    # Phase 3 -- Context Construction
    # ------------------------------------------------------------------

    def _phase_3_build_contexts(
        self,
        config: ToolConfig,
        attack_surface: AttackSurface,
    ) -> tuple[TargetContext, TestContext, EvidenceStore]:
        """
        Construct the three shared state objects for the pipeline run.

        TargetContext is frozen and populated from config + attack_surface.
        Both openapi_spec_url and openapi_spec_path are propagated from
        TargetConfig; exactly one will be non-None, preserving the source
        type information for test_0_1's shadow-API exclusion set builder
        and for the HTML report header.

        TestContext is mutable and starts empty.

        EvidenceStore is initialized with:
            tmp_dir:   streaming JSONL directory for per-test evidence files.
            tools_dir: optional directory where pin_artifact() writes a
                       standalone JSON copy of each external tool's raw output.
                       Set to config.output.directory / "tools" so that tool
                       outputs are directly inspectable without parsing
                       evidence.json.

        Returns:
            Tuple of (TargetContext, TestContext, EvidenceStore).
        """
        log.info("pipeline_phase_3_context_construction_started")

        # One model per test: the validated models of config.tests are collected
        # by name (no copy, no hand-written wiring; all models are frozen).
        # A test declared on one side only stops the run here (see from_domains).
        tests_config = RuntimeTestsConfig.from_domains(config.tests)

        # Instantiate the gateway adapter when configured.
        # Injected into TargetContext so that WHITE_BOX tests access the admin plane
        # via target.gateway.get_services() / .get_plugins() etc.
        gateway = None
        if config.target.gateway_adapter == "kong" and config.target.admin_api_url is not None:
            gateway = KongGatewayAdapter(
                admin_base_url=str(config.target.admin_api_url).rstrip("/"),
                connect_timeout=config.target.admin_connect_timeout_seconds,
                read_timeout=config.target.admin_read_timeout_seconds,
            )
            log.info(
                "pipeline_phase_3_gateway_adapter_instantiated",
                adapter=gateway.adapter_name,
                admin_base_url=str(config.target.admin_api_url).rstrip("/"),
            )

        target = TargetContext(
            base_url=config.target.base_url,
            openapi_spec_url=config.target.openapi_spec_url,
            openapi_spec_path=(
                config.target.openapi_spec_path.resolve()
                if config.target.openapi_spec_path is not None
                else None
            ),
            admin_api_url=config.target.admin_api_url,
            admin_connect_timeout_seconds=config.target.admin_connect_timeout_seconds,
            admin_read_timeout_seconds=config.target.admin_read_timeout_seconds,
            attack_surface=attack_surface,
            credentials=RuntimeCredentials.model_validate(config.credentials.model_dump()),
            tests_config=tests_config,
            path_seed=dict(config.target.path_seed),
            verify_tls=config.target.verify_tls,
            external_tools=config.external_tools,
            gateway=gateway,
        )

        context = TestContext()

        # FIX: tools_dir receives config.output.directory / "tools" so that
        # pin_artifact() writes a standalone JSON copy of each external tool's
        # raw output to outputs/tools/<label>.json alongside the main report.
        store = EvidenceStore(
            tmp_dir=config.output.evidence_tmp_path,
            tools_dir=config.output.directory / "tools",
        )

        log.info(
            "pipeline_phase_3_context_construction_completed",
            admin_api_available=target.admin_api_available,
            openapi_source=target.get_openapi_source(),
            is_local_spec=target.is_local_spec,
            path_seed_param_count=len(target.path_seed),
            path_seed_param_names=sorted(target.path_seed.keys()),
        )

        return target, context, store

    # ------------------------------------------------------------------
    # Phase 4 -- Test Discovery and Scheduling
    # ------------------------------------------------------------------

    def _phase_4_discover_and_schedule(
        self,
        config: ToolConfig,
    ) -> tuple[list[ScheduledBatch], list[BaseTest | ExternalToolTest], list[NotRunEntry]]:
        """
        Discover active tests (native + external) and build the topological schedule.

        Also returns the tests excluded by the filters, with the reason
        (NotRunEntry, from both registries), for the report section not_run.

        Merges two independent discovery passes:
            1. TestRegistry         -> list[BaseTest]          (native Python tests)
            2. ExternalTestRegistry -> list[ExternalToolTest]  (binary-wrapper tests)

        The two lists are merged before being passed to DAGScheduler.  Both
        hierarchies declare test_id and depends_on ClassVars, which is all the
        scheduler reads.  Cross-hierarchy dependencies are fully supported:
        an ExternalToolTest may declare depends_on referencing a BaseTest test_id.

        Selection by execution.test_ids:
            Not set: each registry receives allowed_ids=None and applies its
            normal filters (priority, strategy, tool enablement).
            Set: only the listed tests run.  IDs prefixed with "ext." go to
            ExternalTestRegistry, the others to TestRegistry; each registry
            receives its part as a set, possibly empty, and an empty set
            means "no test of this kind" (not "no filter").  A listed test
            of a disabled external tool still does not run.

        Returns:
            Tuple of (list[ScheduledBatch], combined list BaseTest | ExternalToolTest,
            tests excluded by the filters sorted by test_id).

        Raises:
            DAGCycleError: If a circular dependency is detected.
        """
        log.info("pipeline_phase_4_discovery_and_scheduling_started")

        # --- Split execution.test_ids by registry ---
        # None: no test_ids, normal filters. A set (possibly empty): run only
        # these IDs; an empty part means no test of that kind.
        native_allowed_ids: set[str] | None = None
        external_allowed_ids: set[str] | None = None
        if config.execution.test_ids:
            requested_ids = set(config.execution.test_ids)
            external_allowed_ids = {tid for tid in requested_ids if is_external_test_id(tid)}
            native_allowed_ids = requested_ids - external_allowed_ids

        # --- Native test discovery ---
        registry = TestRegistry()
        native_tests: list[BaseTest] = registry.discover(
            min_priority=config.execution.min_priority,
            enabled_strategies=set(config.execution.strategies),
            allowed_ids=native_allowed_ids,
        )

        # --- External test discovery ---
        ext_registry = ExternalTestRegistry()
        external_tests: list[ExternalToolTest] = ext_registry.discover(
            external_tools_config=config.external_tools,
            min_priority=config.execution.min_priority,
            enabled_strategies=set(config.execution.strategies),
            allowed_ids=external_allowed_ids,
        )

        # --- Merge both lists ---
        all_tests: list[BaseTest | ExternalToolTest] = [*native_tests, *external_tests]
        not_run = sorted([*registry.not_run, *ext_registry.not_run], key=lambda e: e.test_id)

        # A run that checks nothing must not end CLEAN (exit 0): stop with
        # INFRASTRUCTURE (no verdict). With test_ids every entry was already
        # checked to be runnable, so this is reached only through the filters.
        if not all_tests:
            raise ConfigurationError(
                message=(
                    "No test selected: no test matches execution.min_priority="
                    f"{config.execution.min_priority} and execution.strategies="
                    f"{[s.value for s in config.execution.strategies]} with the "
                    "enabled external tools. Widen the filters or list the tests "
                    "in execution.test_ids."
                ),
                config_path="execution",
            )

        # Build dependency map from the union of both lists.
        dependency_map: dict[str, list[str]] = {
            t.__class__.test_id: list(getattr(t.__class__, "depends_on", [])) for t in all_tests
        }

        scheduler = DAGScheduler()
        active_test_ids = {t.__class__.test_id for t in all_tests}
        scheduled_batches = scheduler.build_schedule(
            dependencies=dependency_map,
            active_test_ids=active_test_ids,
        )

        total_scheduled = sum(b.size for b in scheduled_batches)
        log.info(
            "pipeline_phase_4_discovery_and_scheduling_completed",
            native_tests=len(native_tests),
            external_tests=len(external_tests),
            total_active=len(all_tests),
            batch_count=len(scheduled_batches),
            total_scheduled=total_scheduled,
        )

        return scheduled_batches, all_tests, not_run

    # ------------------------------------------------------------------
    # Phase 5 -- Execution
    # ------------------------------------------------------------------

    def _phase_5_execute(
        self,
        scheduled_batches: list[ScheduledBatch],
        active_tests: list[BaseTest | ExternalToolTest],
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
        result_set: ResultSet,
        config: ToolConfig,
    ) -> None:
        """
        Execute all scheduled tests (native + external) in topological order.

        For each ScheduledBatch, iterates over test_ids sequentially.
        Each test is located by test_id in the active_tests list, then
        executed via test.execute(). The TestResult is added to result_set.

        Fail-fast condition (docs/architecture/assessment-model.md, "Fail-fast"):
            If config.execution.fail_fast is True and a P0 test returns
            FAIL or ERROR, execution stops immediately.
        """
        log.info(
            "pipeline_phase_5_execution_started",
            batch_count=len(scheduled_batches),
        )

        test_lookup: dict[str, BaseTest | ExternalToolTest] = {
            t.__class__.test_id: t for t in active_tests
        }
        fail_fast_triggered = False
        fail_fast_result: TestResult | None = None
        # Position of the test in the run, logged as "<position>/<total>".
        position = 0
        total = len(active_tests)

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
                            "no corresponding test instance (BaseTest or ExternalToolTest) "
                            "in the active tests lookup. This indicates a DAGScheduler / "
                            "TestRegistry inconsistency."
                        ),
                    )
                    continue

                position += 1
                result = self._execute_single_test(
                    test=test,
                    target=target,
                    context=context,
                    client=client,
                    store=store,
                    progress=f"{position}/{total}",
                    timeout_seconds=self._external_timeout_seconds(test, config),
                )
                result_set.add_result(result)

                if config.execution.fail_fast:
                    fail_fast_triggered = self._check_fail_fast(
                        result=result,
                        test=test,
                    )
                    if fail_fast_triggered:
                        fail_fast_result = result

            log.debug(
                "pipeline_phase_5_batch_completed",
                batch_index=batch.batch_index,
            )

        if fail_fast_result is not None:
            self._record_fail_fast_not_run(
                scheduled_batches=scheduled_batches,
                test_lookup=test_lookup,
                result_set=result_set,
                trigger=fail_fast_result,
            )
            log.warning(
                "pipeline_phase_5_fail_fast_triggered",
                results_recorded=result_set.total_count,
                detail=(
                    "Execution aborted by fail-fast condition. A P0 test returned FAIL or ERROR."
                ),
            )

        log.info(
            "pipeline_phase_5_execution_completed",
            total_results=result_set.total_count,
            pass_count=result_set.pass_count,
            fail_count=result_set.fail_count,
            skip_count=result_set.skip_count,
            error_count=result_set.error_count,
        )

    @staticmethod
    def _external_timeout_seconds(
        test: BaseTest | ExternalToolTest,
        config: ToolConfig,
    ) -> int | None:
        """
        Return the configured timeout of an external test's tool, else None.

        Args:
            test:   The test about to run.
            config: The validated configuration (external_tools.<tool>).

        Returns:
            external_tools.<tool>.timeout_seconds, or None for a native test.
        """
        if not isinstance(test, ExternalToolTest):
            return None
        tool_config = getattr(config.external_tools, str(getattr(test, "tool_name", "")), None)
        timeout: int | None = getattr(tool_config, "timeout_seconds", None)
        return timeout

    @staticmethod
    def _record_fail_fast_not_run(
        scheduled_batches: list[ScheduledBatch],
        test_lookup: dict[str, BaseTest | ExternalToolTest],
        result_set: ResultSet,
        trigger: TestResult,
    ) -> None:
        """
        Add the scheduled tests that fail-fast prevented from running to not_run.

        Args:
            scheduled_batches: The Phase 4 schedule.
            test_lookup:       test_id -> test instance.
            result_set:        The run's results (not_run is extended and re-sorted).
            trigger:           The result that triggered fail-fast.
        """
        executed = {r.test_id for r in result_set.results}
        detail = (
            f"execution.fail_fast: the run stopped after {trigger.test_id} "
            f"returned {trigger.status.value}"
        )
        for batch in scheduled_batches:
            for test_id in batch.test_ids:
                test = test_lookup.get(test_id)
                if test is None or test_id in executed:
                    continue
                cls = test.__class__
                result_set.not_run.append(
                    NotRunEntry(
                        test_id=test_id,
                        test_name=cls.test_name,
                        source=cls.source,
                        reason=NotRunReason.FAIL_FAST,
                        detail=detail,
                    )
                )
        result_set.not_run.sort(key=lambda e: e.test_id)

    def _execute_single_test(
        self,
        test: BaseTest | ExternalToolTest,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
        progress: str,
        timeout_seconds: int | None,
    ) -> TestResult:
        """
        Execute a single test (native or external) and return its TestResult.

        The start log carries progress ("5/18") and, for an external test,
        the tool's timeout_seconds, so that a long run shows where it is and
        how long the current test may take.

        Dispatch logic:
            - BaseTest:         calls test.execute(target, context, client, store)
                                SecurityClient is required for HTTP requests.
            - ExternalToolTest: calls test.execute(target, context, store)
                                SecurityClient is intentionally absent -- external
                                tests invoke subprocesses, not httpx.

        The store.begin_test() / end_test() lifecycle is managed by each
        hierarchy's execute() method, not here -- to avoid double-calling.
        This method only measures wall-clock time and attaches duration_ms.
        """
        cls = test.__class__
        test_id = cls.test_id
        test_name = getattr(cls, "test_name", "")
        source = getattr(cls, "source", "native")

        timeout_field: dict[str, int] = (
            {"timeout_seconds": timeout_seconds} if timeout_seconds is not None else {}
        )
        log.info(
            "test_execution_started",
            progress=progress,
            test_id=test_id,
            test_name=test_name,
            priority=getattr(cls, "priority", 0),
            strategy=getattr(cls, "strategy", "BLACK_BOX"),
            source=source,
            **timeout_field,
        )

        wall_start = time.monotonic()

        if isinstance(test, ExternalToolTest):
            result = test.execute(target, context, store)
        else:
            store.begin_test(test_id)
            try:
                result = test.execute(target, context, client, store)
            finally:
                store.end_test()

        elapsed_ms = (time.monotonic() - wall_start) * 1000.0
        result = result.model_copy(update={"duration_ms": round(elapsed_ms, 2)})

        log.info(
            "test_execution_completed",
            test_id=test_id,
            status=result.status.value,
            finding_count=len(result.findings),
            duration_ms=round(elapsed_ms, 2),
            source=source,
        )

        return result

    @staticmethod
    def _check_fail_fast(result: TestResult, test: BaseTest | ExternalToolTest) -> bool:
        """
        Determine whether the fail-fast condition is triggered.

        Condition: test has priority P0 AND status is FAIL or ERROR.
        Both FAIL and ERROR are treated as blocking for P0 tests because
        an ERROR means the verification of a critical guarantee did not
        complete -- proceeding would produce an assessment without foundation.
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
    # Phase 6 -- Teardown
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

        for method, path, teardown_headers in resources:
            try:
                response, _ = client.request(
                    method=method,
                    path=path,
                    test_id="teardown",
                    headers=teardown_headers if teardown_headers else None,
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
    # Phase 7 -- Report Generation
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
        json_report_path = config.output.json_report_path

        log.info(
            "pipeline_phase_7_report_generation_started",
            total_results=result_set.total_count,
            evidence_records=store.record_count,
            evidence_path=str(evidence_path),
            report_path=str(report_path),
        )

        try:
            records_written = store.merge_and_finalize(evidence_path)
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

        try:
            json_report_path.parent.mkdir(parents=True, exist_ok=True)
            json_report_path.write_text(
                report_data.model_dump_json(indent=2),
                encoding="utf-8",
            )
            log.info(
                "pipeline_phase_7_json_report_written",
                output_path=str(json_report_path),
                size_bytes=json_report_path.stat().st_size,
            )
        except OSError as exc:
            log.error(
                "pipeline_phase_7_json_report_write_failed",
                output_path=str(json_report_path),
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
