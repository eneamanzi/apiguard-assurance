"""
src/external_tests/registry.py

ExternalTestRegistry: dynamic discoverer and filter for ExternalToolTest subclasses.

This module mirrors the architecture of src/tests/registry.py (TestRegistry)
adapted to the ExternalToolTest hierarchy.  The design decisions are identical;
the differences are:

    1. Scanned package: src.external_tests (not src.tests).
    2. Base class: ExternalToolTest (not BaseTest).
    3. File naming convention: ext_test_<D>_<N>_<description>.py
       Example: ext_test_1_5_tls_analysis.py, ext_test_0_1_shadow_api_nuclei.py.
    4. Master-switch integration: with ExternalToolsConfig.enabled False the
       modules are still scanned (no tool is invoked), so that every external
       test is listed in not_run as tool_disabled; none is scheduled.

Naming convention (non-optional, enables discovery):
    src/external_tests/ext_test_<tool>_<description>.py

    Modules that do not start with ext_test_ (base.py, registry.py) are not
    test modules. A test module that cannot be used stops the run
    (src/core/test_discovery.py), as for native tests.

DA-2 -- Phase R4 (_inject_connectors):
    After filtering (R3), the registry groups the surviving tests by tool (info.tool)
    and performs availability checking once per tool.  For each group:

        - If available: one shared connector instance is injected into every
          test in the group via ExternalToolTest._injected_connector.  The
          is_available() syscall is paid exactly once per tool, regardless of
          how many tests use that tool.

        - If not available: a single WARNING is logged for the tool.  Every
          test in the group receives _skip_reason_from_registry set to a
          standardised message.  _run() returns SKIP immediately without
          constructing a connector.

    This collapses N "connector_not_available" log entries (one per test) into
    a single "external_test_registry_tool_not_available" WARNING, and eliminates
    redundant syscalls for tools used by multiple tests.

Dependency rule:
    Imports from: stdlib, structlog, src.external_tests.base, src.core.
    Must never import from: tests/, connectors/ (indirectly via ExternalToolTest),
                            engine.py, discovery/, report/.
"""

from __future__ import annotations

from collections import defaultdict

import structlog

from src.core.models import NotRunEntry, NotRunReason, TestStrategy
from src.core.models.external_tools import ExternalToolsConfig
from src.core.test_discovery import discover_tests
from src.external_tests.base import ExternalToolTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Safety check threshold: log WARNING if more external tests than this are found.
# The current methodology defines a handful of external tests per tool.
# Exceeding this count likely indicates a naming convention violation causing
# unintended modules to be imported.
_SANITY_CHECK_MAX_EXTERNAL_TESTS: int = 50

# The package that contains the external tests.
_EXTERNAL_TESTS_PACKAGE: str = "src.external_tests"

# Prefix that all external test module filenames must start with.
_MODULE_PREFIX: str = "ext_test_"


# ---------------------------------------------------------------------------
# ExternalTestRegistry
# ---------------------------------------------------------------------------


class ExternalTestRegistry:
    """
    Dynamic discoverer and filter for ExternalToolTest subclasses.

    The registry is instantiated once per pipeline run during Phase 4 (Test
    Discovery and Scheduling), alongside TestRegistry.  The engine passes the
    combined list (native tests + external tests) to DAGScheduler for ordering.

    Master switch semantics:
        If ExternalToolsConfig.enabled is False, discover() returns [] and lists
        every external test in self.not_run (tool_disabled). The modules are
        imported but no tool is invoked (availability is checked only for the
        scheduled tests, Phase R4), so this works where no external binary is
        installed: no DAG nodes are added, no SKIPs are generated.

    Per-tool filtering:
        Even when the master switch is on, tests for a specific tool are
        excluded if that tool's ExternalToolsConfig.<tool>.enabled is False.
        The registry reads the tool name from the test's declaration (info.tool)
        and delegates the enabled check to ExternalToolsConfig.is_tool_enabled().

    DA-2 connector injection (Phase R4):
        After filtering, the registry groups tests by tool_name and performs
        a single availability check per tool.  Available tools get a shared
        connector instance injected into all their tests; unavailable tools
        get _skip_reason_from_registry set on all their tests.  This reduces
        redundant syscalls and produces a single log entry per absent tool.

    Usage in engine.py:

        ext_registry = ExternalTestRegistry()
        ext_tests = ext_registry.discover(
            external_tools_config=config.external_tools,
            min_priority=config.execution.min_priority,
            enabled_strategies=set(config.execution.strategies),
        )
        # Merge with native_tests before passing to DAGScheduler
    """

    def __init__(self) -> None:
        """Start with an empty list of excluded tests (filled by discover())."""
        # Tests excluded by the filters of the last discover(), with the reason.
        self.not_run: list[NotRunEntry] = []

    def discover(
        self,
        external_tools_config: ExternalToolsConfig,
        min_priority: int,
        enabled_strategies: set[TestStrategy],
        allowed_ids: set[str] | None = None,
    ) -> list[ExternalToolTest]:
        """
        Discover, instantiate, filter, and inject-prepare all ExternalToolTest subclasses.

        Four-phase pipeline:
            R1+R2: Import every ext_test_*.py module of src/external_tests and
                   instantiate its tests (src/core/test_discovery.py).
            R3: Apply priority, strategy, per-tool, and allowed_ids filters.
            R4: Group surviving tests by tool; inject shared connectors or
                set _skip_reason_from_registry (DA-2).

        Args:
            external_tools_config: Parsed ExternalToolsConfig from config.yaml.
                                   Used for master-switch check and per-tool
                                   enabled state.
            min_priority:          Maximum priority (inclusive) to include.
                                   (ext.0.1.nuclei is P0, the TLS tests P2.)
            enabled_strategies:    Strategies to include (execution.strategies),
                                   as for native tests.
            allowed_ids:           None means no ID filter (normal priority and
                                   strategy filtering). A set, even empty,
                                   includes ONLY the tests whose test_id is in
                                   it (an empty set: no external test) and
                                   overrides min_priority and
                                   enabled_strategies. A test of a disabled
                                   tool is excluded even when listed.

        Returns:
            Sorted list of instantiated ExternalToolTest subclasses that passed
            all filters.  Empty list if master switch is off or no tests match.
        """
        # Master switch off: the tests are still scanned, so that they are
        # listed in not_run (tool_disabled); none is scheduled (Filter 3).
        if not external_tools_config.enabled:
            log.info(
                "external_test_registry_master_switch_off",
                detail=(
                    "external_tools.enabled=false in config.yaml. "
                    "All ExternalToolTest subclasses are excluded from this run."
                ),
            )

        log.info(
            "external_test_registry_discovery_started",
            min_priority=min_priority,
            allowed_ids=sorted(allowed_ids) if allowed_ids is not None else None,
        )

        # Phases R1+R2: import the test modules and instantiate the tests.
        all_tests = self.list_tests()

        # Phase R3: apply filters (excluded tests go to self.not_run).
        self.not_run = []
        active_tests = self._apply_filters(
            tests=all_tests,
            external_tools_config=external_tools_config,
            min_priority=min_priority,
            enabled_strategies=enabled_strategies,
            allowed_ids=allowed_ids,
        )

        # Sort deterministically by test_id before injection.
        active_tests.sort(key=lambda t: t.info.id)

        if len(active_tests) > _SANITY_CHECK_MAX_EXTERNAL_TESTS:
            log.warning(
                "external_test_registry_unusually_large_count",
                count=len(active_tests),
                threshold=_SANITY_CHECK_MAX_EXTERNAL_TESTS,
            )

        # Phase R4: connector dependency injection (DA-2).
        self._inject_connectors(active_tests)

        log.info(
            "external_test_registry_discovery_completed",
            total_discovered=len(all_tests),
            total_active=len(active_tests),
            excluded_count=len(all_tests) - len(active_tests),
        )
        return active_tests

    def list_tests(self) -> list[ExternalToolTest]:
        """
        Return every concrete external test, without filtering.

        Scans the modules even when external tools are disabled, so that the
        prerequisites can be checked and an execution.test_ids entry can be
        told apart as unknown or as belonging to a disabled tool
        (engine.check_tests).

        Returns:
            One instance per external test.

        Raises:
            TestDefinitionError: Listing every test that cannot be used.
        """
        # The base is abstract and only used for issubclass(): mypy rejects an
        # abstract class for type[...] all the same (python/mypy#4717).
        return discover_tests(
            _EXTERNAL_TESTS_PACKAGE,
            _MODULE_PREFIX,
            ExternalToolTest,  # type: ignore[type-abstract]
            external=True,
        )

    # ------------------------------------------------------------------
    # Phase R3 -- Filtering
    # ------------------------------------------------------------------

    def _apply_filters(
        self,
        tests: list[ExternalToolTest],
        external_tools_config: ExternalToolsConfig,
        min_priority: int,
        enabled_strategies: set[TestStrategy],
        allowed_ids: set[str] | None,
    ) -> list[ExternalToolTest]:
        """
        Apply priority, strategy, per-tool, and allowed_ids filters to the discovered tests.

        Filter cascade (applied in order, first exclusion wins):
            1. allowed_ids: if not None, exclude tests whose test_id is not
               in the set (an empty set excludes every test).  When it is not
               None it replaces the priority filter (Filter 2), allowing
               targeted runs of high-priority tests without changing
               min_priority.
            2. priority and strategy: exclude tests with priority >
               min_priority or whose strategy is not in enabled_strategies
               (same rule as native tests). Skipped when allowed_ids is not
               None (see above).
            3. per-tool enabled: ALWAYS applied, regardless of allowed_ids.
               A tool with enabled=False in config has not been declared ready
               (binary not installed, timeout not set, etc.).  Forcing execution
               via allowed_ids does not make the tool available; it would just
               ERROR at connector invocation.  This check is intentionally not
               bypassable via allowed_ids so that the config flag behaves as a
               hard gate, not an advisory.

        Design rationale for Filter 3 invariance:
            ``allowed_ids`` is a developer shortcut for targeted runs (e.g.
            CI pipeline that exercises a single domain).  It is not intended to
            override tool readiness.  If the intention is to force-run a
            disabled tool, the correct action is to set ``enabled: true`` in
            config.yaml, not to rely on ``test_ids`` to bypass the check.

        Args:
            tests:                 Full list of discovered ExternalToolTest instances.
            external_tools_config: For per-tool enabled checks.
            min_priority:          Maximum priority to include (inclusive).
            enabled_strategies:    Strategies to include.
            allowed_ids:           If not None, replaces the priority and
                                   strategy filters (not the per-tool check).

        Returns:
            list[ExternalToolTest]: Filtered list of tests to execute.
        """
        active: list[ExternalToolTest] = []
        for test in tests:
            test_id = test.info.id

            # --- Filter 1 / Filter 2 (mutually exclusive) ---
            # When allowed_ids is not None, it replaces the priority filter.
            # When allowed_ids is None, the priority filter applies normally.
            if allowed_ids is not None:
                if test_id not in allowed_ids:
                    self._exclude(
                        test, NotRunReason.NOT_IN_TEST_IDS, "execution.test_ids does not list it"
                    )
                    continue
            else:
                priority = test.info.priority
                if priority > min_priority:
                    self._exclude(
                        test,
                        NotRunReason.PRIORITY,
                        f"priority P{priority} is above execution.min_priority (P{min_priority})",
                    )
                    continue
                strategy = test.info.strategy
                if strategy not in enabled_strategies:
                    self._exclude(
                        test,
                        NotRunReason.STRATEGY,
                        f"strategy {strategy.value} is not in execution.strategies "
                        f"({', '.join(sorted(s.value for s in enabled_strategies))})",
                    )
                    continue

            # --- Filter 3: per-tool enabled (ALWAYS applied) ---
            # This check is intentionally not bypassable via allowed_ids.
            # See docstring rationale above.
            tool_name = test.tool_name
            if not external_tools_config.is_tool_enabled(tool_name):
                switch = (
                    f"external_tools.{tool_name}.enabled is false"
                    if external_tools_config.enabled
                    else "external_tools.enabled is false"
                )
                self._exclude(test, NotRunReason.TOOL_DISABLED, switch)
                continue

            active.append(test)

        return active

    def _exclude(self, test: ExternalToolTest, reason: NotRunReason, detail: str) -> None:
        """
        Record a test excluded by a filter in self.not_run.

        Args:
            test:   The excluded test.
            reason: The filter that excluded it.
            detail: The values that excluded it.
        """
        self.not_run.append(
            NotRunEntry(
                test_id=test.info.id,
                test_name=test.info.name,
                source=test.source,
                reason=reason,
                detail=detail,
            )
        )
        log.debug(
            "external_test_registry_excluded",
            test_id=test.info.id,
            reason=reason.value,
            detail=detail,
        )

    # ------------------------------------------------------------------
    # Phase R4 -- Connector dependency injection (DA-2)
    # ------------------------------------------------------------------

    def _inject_connectors(self, tests: list[ExternalToolTest]) -> None:
        """
        Check tool availability once per tool and inject connectors into all tests.

        This phase is the heart of DA-2.  It collapses the N-per-tool availability
        checks (one per test that uses the same tool) into a single check per tool,
        producing exactly one log entry per absent tool regardless of how many
        tests depend on it.

        Algorithm:
            1. Group tests by tool (info.tool, set on every external test).
            2. For each group, call _build_connector() on the first test instance
               to obtain ONE connector -- this is just object construction, no I/O.
            3. Call connector.is_available() ONCE for the group.
            4a. If available:
                   - Inject the connector into every test in the group via
                     test._injected_connector = connector.
                   - Log INFO once ("nuclei available -- injected into 3 tests").
            4b. If not available:
                   - Set test._skip_reason_from_registry on every test in the group.
                   - Log WARNING once ("nuclei not found -- 3 tests will SKIP").
                   - Do NOT inject a connector (it remains None).

        Invariant maintained:
            For any test after _inject_connectors():
                (_injected_connector is not None) XOR
                (_skip_reason_from_registry is not None).

        Args:
            tests: Filtered and sorted list of ExternalToolTest instances.
                   Modified in-place via attribute assignment.

        Returns:
            None (modifies test instances in-place).
        """
        # --- Group tests by tool_name ---
        groups: dict[str, list[ExternalToolTest]] = defaultdict(list)
        for test in tests:
            groups[test.tool_name].append(test)

        # --- Process each tool group ---
        for tool_name, group in groups.items():
            self._inject_connector_for_group(tool_name=tool_name, group=group)

    def _inject_connector_for_group(
        self,
        tool_name: str,
        group: list[ExternalToolTest],
    ) -> None:
        """
        Perform availability check and injection for one tool's test group.

        Separated from _inject_connectors() for readability and testability.
        Called once per distinct tool_name found in the active test list.

        If _build_connector() raises on the first test, the entire group is
        marked with _skip_reason_from_registry (ERROR-safe fallback -- the
        tests will SKIP rather than ERROR, because a missing connector at
        injection time is the same operational condition as a missing binary).

        Args:
            tool_name: The tool identifier (e.g. "testssl", "nuclei", "ffuf").
            group:     Non-empty list of ExternalToolTest instances for this tool.
        """
        first_test = group[0]
        test_count = len(group)

        # --- Build one connector instance for the group ---
        try:
            connector = first_test._build_connector()  # noqa: SLF001
            # Accessing a protected method of a sibling class instance is
            # architecturally acceptable here: _inject_connector_for_group is
            # part of the registry's lifecycle management responsibility (DA-2),
            # which is explicitly documented in ExternalToolTest as "called by
            # ExternalTestRegistry".  This is not arbitrary external access; it
            # is a defined protocol between the two classes.
        except Exception as exc:  # noqa: BLE001
            skip_reason = (
                f"External tool '{tool_name}' connector could not be instantiated: {exc}. "
                f"Affect {test_count} test(s) in this group -- all will SKIP."
            )
            log.warning(
                "external_test_registry_connector_build_failed",
                tool=tool_name,
                affected_tests=[t.info.id for t in group],
                error=str(exc),
            )
            for test in group:
                test._skip_reason_from_registry = skip_reason  # noqa: SLF001
            return

        # --- Check availability once ---
        try:
            available = connector.is_available()
        except Exception as exc:  # noqa: BLE001
            # is_available() must not raise, but if it does: treat as unavailable.
            log.warning(
                "external_test_registry_availability_check_exception",
                tool=tool_name,
                error=str(exc),
            )
            available = False

        if available:
            # --- Inject shared connector into all tests in the group ---
            for test in group:
                test._injected_connector = connector  # noqa: SLF001
            log.info(
                "external_test_registry_tool_available",
                tool=tool_name,
                test_count=test_count,
                test_ids=[t.info.id for t in group],
                detail=(
                    f"Shared connector injected into {test_count} test(s). "
                    "is_available() will not be called again during execution."
                ),
            )
        else:
            # --- Mark all tests as pre-determined SKIP ---
            skip_reason = (
                f"External tool '{tool_name}' is not available on this system. "
                "Install it: binaries with ./install_tools.sh (./tools/) or in PATH; "
                "Python libraries with their extra (e.g. sslyze: [sslyze]). "
                f"This affects {test_count} test(s)."
            )
            for test in group:
                test._skip_reason_from_registry = skip_reason  # noqa: SLF001
            log.warning(
                "external_test_registry_tool_not_available",
                tool=tool_name,
                test_count=test_count,
                test_ids=[t.info.id for t in group],
                detail=(
                    f"{test_count} test(s) will SKIP. "
                    "This message appears once per tool, not once per test."
                ),
            )
