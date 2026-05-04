"""
src/external_tests/registry.py

ExternalTestRegistry: dynamic discoverer and filter for ExternalToolTest subclasses.

This module mirrors the architecture of src/tests/registry.py (TestRegistry)
adapted to the ExternalToolTest hierarchy.  The design decisions are identical;
the differences are:

    1. Scanned package: src.external_tests (not src.tests).
    2. Base class: ExternalToolTest (not BaseTest).
    3. File naming convention: ext_test_<tool>_<description>.py
       Example: ext_test_tls_enforcement.py, ext_test_shadow_api_ffuf.py.
    4. Master-switch integration: ExternalToolsConfig.enabled is checked
       BEFORE scanning.  If the master switch is off, discover() returns []
       immediately without touching the filesystem.

Naming convention (non-optional, enables discovery):
    src/external_tests/ext_test_<tool>_<description>.py

    Where <tool> is one of: tls, ffuf, nuclei, (future tools).
    Files that do not match the ext_test_ prefix are silently skipped.

DA-2 -- Phase R4 (_inject_connectors):
    After filtering (R3), the registry groups the surviving tests by tool_name
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
    Imports from: stdlib, structlog, src.external_tests.base,
                  src.config.schema.external_tools, src.core.models.
    Must never import from: tests/, connectors/ (indirectly via ExternalToolTest),
                            engine.py, discovery/, report/.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import pkgutil
import types
from collections import defaultdict

import structlog

import src.external_tests as _ext_tests_pkg
from src.config.schema.external_tools import ExternalToolsConfig
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

# Prefix that all external test module filenames must start with (after src.).
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
        If ExternalToolsConfig.enabled is False, discover() returns [] without
        scanning the filesystem.  This is the intended behaviour for CI
        environments where no external binaries are available: the engine sees
        an empty list, no DAG nodes are added, no SKIPs are generated.

    Per-tool filtering:
        Even when the master switch is on, tests for a specific tool are
        excluded if that tool's ExternalToolsConfig.<tool>.enabled is False.
        The registry reads the tool name from the test's `tool_name` ClassVar
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
        )
        # Merge with native_tests before passing to DAGScheduler
    """

    def discover(
        self,
        external_tools_config: ExternalToolsConfig,
        min_priority: int,
        allowed_ids: set[str] | None = None,
    ) -> list[ExternalToolTest]:
        """
        Discover, instantiate, filter, and inject-prepare all ExternalToolTest subclasses.

        Four-phase pipeline:
            R1: Scan src/external_tests and import all ext_test_*.py modules.
            R2: Extract concrete ExternalToolTest subclasses from imported modules.
            R3: Apply priority, per-tool, and allowed_ids filters.
            R4: Group surviving tests by tool_name; inject shared connectors or
                set _skip_reason_from_registry (DA-2).

        Args:
            external_tools_config: Parsed ExternalToolsConfig from config.yaml.
                                   Used for master-switch check and per-tool
                                   enabled state.
            min_priority:          Maximum priority (inclusive) to include.
                                   ExternalToolTests typically run at P1/P2 since
                                   they require tool availability (not pure Black Box).
            allowed_ids:           If non-empty, include ONLY tests with matching
                                   test_id. Overrides min_priority and per-tool
                                   filtering. For development / targeted runs.

        Returns:
            Sorted list of instantiated ExternalToolTest subclasses that passed
            all filters.  Empty list if master switch is off or no tests match.
        """
        # --- Master switch: bail out immediately without scanning ---
        if not external_tools_config.enabled:
            log.info(
                "external_test_registry_master_switch_off",
                detail=(
                    "external_tools.enabled=false in config.yaml. "
                    "All ExternalToolTest subclasses are excluded from this run. "
                    "No filesystem scan will be performed."
                ),
            )
            return []

        log.info(
            "external_test_registry_discovery_started",
            min_priority=min_priority,
            allowed_ids=sorted(allowed_ids) if allowed_ids else [],
        )

        # Phase R1: scan and import ext_test_*.py modules.
        imported_modules = self._scan_and_import_modules()

        # Phase R2: extract concrete ExternalToolTest subclasses.
        all_tests = self._extract_concrete_subclasses(imported_modules)

        # Phase R3: apply filters.
        active_tests = self._apply_filters(
            tests=all_tests,
            external_tools_config=external_tools_config,
            min_priority=min_priority,
            allowed_ids=allowed_ids or set(),
        )

        # Sort deterministically by test_id before injection.
        active_tests.sort(key=lambda t: t.__class__.test_id)

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

    # ------------------------------------------------------------------
    # Phase R1 -- Module scan and import
    # ------------------------------------------------------------------

    def _scan_and_import_modules(self) -> list[types.ModuleType]:
        """
        Recursively scan src.external_tests and import all ext_test_*.py modules.

        Uses pkgutil.walk_packages on the src.external_tests package path.
        Only modules whose final dotted name component starts with 'ext_test_'
        are imported; others (base.py, registry.py, __init__.py) are silently
        skipped to avoid importing non-test modules.

        Import errors are logged as WARNING and do not abort discovery of
        other modules -- a broken ext_test file must not block valid ones.

        Returns:
            list[types.ModuleType]: Successfully imported test modules.
        """
        imported: list[types.ModuleType] = []
        pkg_path = _ext_tests_pkg.__path__
        pkg_prefix = _ext_tests_pkg.__name__ + "."

        try:
            module_infos = list(pkgutil.walk_packages(path=pkg_path, prefix=pkg_prefix))
        except Exception as exc:  # noqa: BLE001
            log.error(
                "external_test_registry_scan_failed",
                error=str(exc),
                detail="Cannot scan src.external_tests. No external tests will run.",
            )
            return []

        for module_info in module_infos:
            # Only process modules whose leaf name starts with _MODULE_PREFIX.
            leaf_name = module_info.name.split(".")[-1]
            if not leaf_name.startswith(_MODULE_PREFIX):
                continue

            try:
                module = importlib.import_module(module_info.name)
                imported.append(module)
                log.debug(
                    "external_test_registry_module_imported",
                    module=module_info.name,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "external_test_registry_module_import_failed",
                    module=module_info.name,
                    error=str(exc),
                    detail=(
                        "This module will be skipped. Other ext_test modules "
                        "are unaffected. Fix the import error to include this test."
                    ),
                )

        log.debug(
            "external_test_registry_scan_complete",
            module_count=len(imported),
        )
        return imported

    # ------------------------------------------------------------------
    # Phase R2 -- Subclass extraction
    # ------------------------------------------------------------------

    def _extract_concrete_subclasses(
        self,
        modules: list[types.ModuleType],
    ) -> list[ExternalToolTest]:
        """
        Inspect imported modules and instantiate concrete ExternalToolTest subclasses.

        A class is considered concrete if it satisfies all three conditions:
            1. It is a subclass of ExternalToolTest.
            2. It is NOT ExternalToolTest itself (the ABC must be excluded).
            3. It does not have abstractmethods remaining (inspect.isabstract == False).

        Classes missing required ClassVar attributes (test_id, test_name, domain,
        priority, strategy, depends_on, tags, cwe_id, tool_name) generate a WARNING
        log entry but are not excluded -- the registry is permissive at discovery time
        to maintain parity with TestRegistry's "warn but don't block" policy.

        Args:
            modules: Imported modules from _scan_and_import_modules().

        Returns:
            list[ExternalToolTest]: Instantiated concrete subclass instances.
        """
        instances: list[ExternalToolTest] = []
        seen_class_ids: set[str] = set()

        for module in modules:
            for _name, obj in inspect.getmembers(module, inspect.isclass):
                if not (
                    issubclass(obj, ExternalToolTest)
                    and obj is not ExternalToolTest
                    and not inspect.isabstract(obj)
                ):
                    continue

                test_id = getattr(obj, "test_id", None)
                if test_id is None:
                    log.warning(
                        "external_test_registry_missing_test_id",
                        class_name=obj.__name__,
                        module=obj.__module__,
                    )
                    continue

                if test_id in seen_class_ids:
                    log.warning(
                        "external_test_registry_duplicate_test_id",
                        test_id=test_id,
                        class_name=obj.__name__,
                        detail=(
                            "Duplicate test_id detected. Only the first occurrence "
                            "will be included. Fix the test_id to ensure uniqueness."
                        ),
                    )
                    continue

                # Warn on missing optional ClassVars (non-blocking).
                for attr in (
                    "test_name",
                    "domain",
                    "priority",
                    "strategy",
                    "tags",
                    "cwe_id",
                    "tool_name",
                ):
                    if not hasattr(obj, attr):
                        log.warning(
                            "external_test_registry_missing_classvar",
                            test_id=test_id,
                            class_name=obj.__name__,
                            missing_attr=attr,
                        )

                try:
                    instance = obj()
                    instances.append(instance)
                    seen_class_ids.add(test_id)
                    log.debug(
                        "external_test_registry_test_instantiated",
                        test_id=test_id,
                        class_name=obj.__name__,
                    )
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "external_test_registry_instantiation_failed",
                        test_id=test_id,
                        class_name=obj.__name__,
                        error=str(exc),
                    )

        return instances

    # ------------------------------------------------------------------
    # Phase R3 -- Filtering
    # ------------------------------------------------------------------

    def _apply_filters(
        self,
        tests: list[ExternalToolTest],
        external_tools_config: ExternalToolsConfig,
        min_priority: int,
        allowed_ids: set[str],
    ) -> list[ExternalToolTest]:
        """
        Apply priority, per-tool, and allowed_ids filters to the discovered tests.

        Filter cascade (applied in order, first exclusion wins):
            1. allowed_ids override: if non-empty, include ONLY matching test_ids.
            2. priority: exclude tests with priority > min_priority.
            3. per-tool enabled: exclude tests whose tool_name resolves to
               ExternalToolsConfig.is_tool_enabled(tool_name) == False.

        Args:
            tests:                 Full list of discovered ExternalToolTest instances.
            external_tools_config: For per-tool enabled checks.
            min_priority:          Maximum priority to include (inclusive).
            allowed_ids:           If non-empty, overrides priority + tool filters.

        Returns:
            list[ExternalToolTest]: Filtered list of tests to execute.
        """
        active: list[ExternalToolTest] = []
        for test in tests:
            cls = test.__class__
            test_id = getattr(cls, "test_id", "unknown")

            # --- Filter 1: allowed_ids override ---
            if allowed_ids:
                if test_id not in allowed_ids:
                    log.debug(
                        "external_test_registry_excluded_not_in_allowed_ids",
                        test_id=test_id,
                    )
                    continue
                active.append(test)
                continue

            # --- Filter 2: priority ---
            priority = int(getattr(cls, "priority", 0))
            if priority > min_priority:
                log.debug(
                    "external_test_registry_excluded_priority",
                    test_id=test_id,
                    test_priority=priority,
                    min_priority=min_priority,
                )
                continue

            # --- Filter 3: per-tool enabled ---
            tool_name: str = str(getattr(cls, "tool_name", ""))
            if tool_name and not external_tools_config.is_tool_enabled(tool_name):
                log.debug(
                    "external_test_registry_excluded_tool_disabled",
                    test_id=test_id,
                    tool_name=tool_name,
                )
                continue

            active.append(test)

        return active

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
            1. Group tests by tool_name ClassVar.  Tests without tool_name are
               skipped with a WARNING (they will fall back to _build_connector()
               on first execute()).
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
                (_skip_reason_from_registry is not None) XOR
                (both None -- no tool_name or fallback mode).

        Args:
            tests: Filtered and sorted list of ExternalToolTest instances.
                   Modified in-place via attribute assignment.

        Returns:
            None (modifies test instances in-place).
        """
        # --- Group tests by tool_name ---
        groups: dict[str, list[ExternalToolTest]] = defaultdict(list)
        no_tool_name_count: int = 0

        for test in tests:
            tool_name: str = str(getattr(test.__class__, "tool_name", ""))
            if not tool_name:
                no_tool_name_count += 1
                log.warning(
                    "external_test_registry_missing_tool_name_for_injection",
                    test_id=getattr(test.__class__, "test_id", "unknown"),
                    detail=(
                        "This test has no tool_name ClassVar and will not benefit "
                        "from DA-2 connector injection.  It will call _build_connector() "
                        "and is_available() independently on each execute() invocation."
                    ),
                )
                continue
            groups[tool_name].append(test)

        if no_tool_name_count > 0:
            log.debug(
                "external_test_registry_injection_skipped_no_tool_name",
                count=no_tool_name_count,
            )

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
                affected_tests=[getattr(t.__class__, "test_id", "?") for t in group],
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
                test_ids=[getattr(t.__class__, "test_id", "?") for t in group],
                detail=(
                    f"Shared connector injected into {test_count} test(s). "
                    "is_available() will not be called again during execution."
                ),
            )
        else:
            # --- Mark all tests as pre-determined SKIP ---
            skip_reason = (
                f"External tool '{tool_name}' is not available on this system. "
                "Install it in PATH or configure its discovery environment variable. "
                f"This affects {test_count} test(s)."
            )
            for test in group:
                test._skip_reason_from_registry = skip_reason  # noqa: SLF001
            log.warning(
                "external_test_registry_tool_not_available",
                tool=tool_name,
                test_count=test_count,
                test_ids=[getattr(t.__class__, "test_id", "?") for t in group],
                detail=(
                    f"{test_count} test(s) will SKIP. "
                    "This message appears once per tool, not once per test."
                ),
            )
