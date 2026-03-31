"""
src/tests/registry.py

TestRegistry: dynamic discovery and filtering of BaseTest subclasses.

The registry eliminates the need for a central, manually-maintained list of
tests. Adding a new test requires only two things:
    1. Create a file in the correct domain directory following the naming
       convention: src/tests/domain_{X}/test_{X}_{Y}_{description}.py
    2. Define a concrete subclass of BaseTest with all required ClassVar
       metadata attributes.

No other file needs to be modified. The registry discovers the test at the
next pipeline run via pkgutil.walk_packages.

Discovery pipeline:

    Phase R1 — Module scan:
        pkgutil.walk_packages recursively scans the src.tests package.
        Only modules whose name component starts with 'test_' are imported.
        Import errors in individual test modules are caught and logged as
        WARNING; they do not abort the discovery of other modules.

    Phase R2 — Subclass extraction:
        For each successfully imported module, inspect.getmembers finds all
        classes that are concrete subclasses of BaseTest (not BaseTest itself,
        not abstract subclasses with unimplemented methods).
        BaseTest.has_required_metadata() filters out incomplete implementations.

    Phase R3 — Filtering:
        Discovered tests are filtered by:
            - priority: tests with priority > min_priority are excluded.
            - strategy: tests whose strategy is not in enabled_strategies are excluded.
        Filtering is logged at DEBUG level for each excluded test.

    Output:
        A list of BaseTest instances, one per discovered and filtered test.
        The list is ordered by test_id lexicographically for deterministic
        output, matching the reproducibility guarantee in Implementazione.md.

Dependency rule:
    This module imports from stdlib (pkgutil, inspect, importlib, types),
    structlog, src.core.models, and src.tests.base only.
    It must never import from config/, discovery/, report/, or engine.py.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import types
from typing import TYPE_CHECKING

import structlog

from src.core.models import TestStrategy
from src.tests.base import BaseTest

if TYPE_CHECKING:
    pass

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# The root package that contains all test domain subdirectories.
# pkgutil.walk_packages uses this as the starting point for recursive scan.
_TESTS_ROOT_PACKAGE: str = "src.tests"

# Only modules whose final name component starts with this prefix are imported.
# Files like '__init__.py', 'base.py', 'registry.py', 'strategy.py' are excluded.
_TEST_MODULE_PREFIX: str = "test_"

# Maximum number of tests expected in a single discovery run.
# Used only for a sanity-check WARNING if exceeded — not a hard limit.
_SANITY_CHECK_MAX_TESTS: int = 200


# ---------------------------------------------------------------------------
# TestRegistry
# ---------------------------------------------------------------------------


class TestRegistry:
    """
    Dynamic discoverer and filter for BaseTest subclasses.

    A new TestRegistry instance is created once per pipeline run during
    Phase 4 (Test Discovery and Scheduling). It is stateless between calls
    to discover(): calling discover() twice with different parameters produces
    two independent filtered lists without side effects.

    The registry does not cache discovered tests between calls. Since discovery
    is called exactly once per pipeline run, the overhead of repeated scanning
    is not a concern, and the absence of caching avoids stale-state bugs during
    iterative development (where a test file might be edited between runs in
    the same Python process).

    Usage in engine.py:

        registry = TestRegistry()
        active_tests = registry.discover(
            min_priority=config.execution.min_priority,
            enabled_strategies=set(config.execution.strategies),
        )
        # Pass active_tests to DAGScheduler.build_schedule()
    """

    def discover(
        self,
        min_priority: int,
        enabled_strategies: set[TestStrategy],
    ) -> list[BaseTest]:
        """
        Discover, instantiate, and filter all concrete BaseTest subclasses.

        This is the single public method of TestRegistry. It performs all
        three discovery phases (scan, extract, filter) and returns a sorted
        list of BaseTest instances ready for the DAGScheduler.

        The returned list is sorted by test_id lexicographically. This produces
        a deterministic output regardless of filesystem directory traversal order,
        satisfying the Reproducibility constraint in Implementazione.md Section 1.

        Args:
            min_priority: Maximum priority level (inclusive) to include.
                          Tests with priority > min_priority are excluded.
                          Range: 0 (P0 only) to 3 (all tests).
            enabled_strategies: Set of TestStrategy values to include.
                                 Tests whose strategy is not in this set are excluded.
                                 Must not be empty (validated by ToolConfig schema).

        Returns:
            Sorted list of instantiated BaseTest subclasses that passed all
            filters. Empty list if no tests match the filter criteria.
        """
        log.info(
            "test_registry_discovery_started",
            min_priority=min_priority,
            enabled_strategies=[s.value for s in enabled_strategies],
        )

        # Phase R1: scan and import test modules.
        imported_modules = self._scan_and_import_modules()

        # Phase R2: extract concrete BaseTest subclasses.
        all_tests = self._extract_concrete_subclasses(imported_modules)

        # Phase R3: apply priority and strategy filters.
        active_tests = self._apply_filters(
            tests=all_tests,
            min_priority=min_priority,
            enabled_strategies=enabled_strategies,
        )

        # Sort by test_id for deterministic ordering.
        active_tests.sort(key=lambda t: t.__class__.test_id)

        if len(active_tests) > _SANITY_CHECK_MAX_TESTS:
            log.warning(
                "test_registry_unusually_large_test_count",
                count=len(active_tests),
                threshold=_SANITY_CHECK_MAX_TESTS,
                detail=(
                    "Discovered more tests than expected. Verify that the "
                    "test module naming convention is correctly followed and "
                    "that no test class is being included unintentionally."
                ),
            )

        log.info(
            "test_registry_discovery_completed",
            total_discovered=len(all_tests),
            total_active=len(active_tests),
            excluded_count=len(all_tests) - len(active_tests),
        )

        return active_tests

    # ------------------------------------------------------------------
    # Phase R1 — Module scan and import
    # ------------------------------------------------------------------

    def _scan_and_import_modules(self) -> list[types.ModuleType]:
        """
        Recursively scan src.tests and import all test_*.py modules.

        Uses pkgutil.walk_packages to traverse the package tree starting
        from src.tests. For each module whose dotted name's final component
        starts with 'test_', importlib.import_module is called.

        Import errors (SyntaxError, ImportError, ModuleNotFoundError) in
        individual test modules are caught and logged as WARNING. They do not
        abort the discovery of other modules: a broken test file should not
        prevent valid tests from being discovered and executed.

        The src.tests root package must be importable for walk_packages to
        work. If it is not (e.g., missing __init__.py), a structured ERROR
        is logged and an empty list is returned.

        Returns:
            List of successfully imported module objects.
        """
        imported: list[types.ModuleType] = []

        try:
            root_package = importlib.import_module(_TESTS_ROOT_PACKAGE)
        except ImportError as exc:
            log.error(
                "test_registry_root_package_import_failed",
                package=_TESTS_ROOT_PACKAGE,
                error=str(exc),
                detail=(
                    "Cannot import the tests root package. "
                    "Ensure src/tests/__init__.py exists and is importable."
                ),
            )
            return imported

        # pkgutil.walk_packages requires the __path__ attribute of the package.
        # For a namespace package, __path__ may be a _NamespacePath object,
        # which walk_packages handles correctly.
        root_path = getattr(root_package, "__path__", None)
        if root_path is None:
            log.error(
                "test_registry_root_package_has_no_path",
                package=_TESTS_ROOT_PACKAGE,
            )
            return imported

        # The prefix argument ensures that module names returned by
        # walk_packages include the full dotted path from the root,
        # e.g., 'src.tests.domain_1.test_1_2_jwt_signature_validation'.
        prefix = f"{_TESTS_ROOT_PACKAGE}."

        for module_info in pkgutil.walk_packages(
            path=root_path,
            prefix=prefix,
            onerror=self._handle_walk_error,
        ):
            module_name = module_info.name
            # Extract the final component of the dotted name.
            final_component = module_name.rsplit(".", 1)[-1]

            if not final_component.startswith(_TEST_MODULE_PREFIX):
                log.debug(
                    "test_registry_skipping_non_test_module",
                    module_name=module_name,
                    final_component=final_component,
                )
                continue

            module = self._import_module_safely(module_name)
            if module is not None:
                imported.append(module)

        log.debug(
            "test_registry_module_scan_completed",
            modules_found=len(imported),
        )

        return imported

    @staticmethod
    def _handle_walk_error(module_name: str) -> None:
        """
        Error handler passed to pkgutil.walk_packages.

        Called when walk_packages encounters an error while scanning a package
        (e.g., a directory with a broken __init__.py). Logs a WARNING instead
        of raising, preserving best-effort discovery behavior.

        Args:
            module_name: The name of the package that caused the scan error.
        """
        log.warning(
            "test_registry_walk_packages_scan_error",
            module_name=module_name,
            detail=(
                "pkgutil.walk_packages encountered an error scanning this package. "
                "Tests in this package may not be discovered. "
                "Check for syntax errors in __init__.py."
            ),
        )

    @staticmethod
    def _import_module_safely(module_name: str) -> types.ModuleType | None:
        """
        Import a single module by dotted name, catching all import errors.

        Args:
            module_name: Full dotted module name,
                         e.g. 'src.tests.domain_1.test_1_2_jwt_signature_validation'.

        Returns:
            The imported module object, or None if import failed.
        """
        try:
            module = importlib.import_module(module_name)
            log.debug(
                "test_registry_module_imported",
                module_name=module_name,
            )
            return module
        except SyntaxError as exc:
            log.warning(
                "test_registry_module_import_syntax_error",
                module_name=module_name,
                error=str(exc),
                line=exc.lineno,
                detail="Fix the syntax error to include this test in discovery.",
            )
        except ImportError as exc:
            log.warning(
                "test_registry_module_import_error",
                module_name=module_name,
                error=str(exc),
                detail=(
                    "The module could not be imported. Check for missing "
                    "dependencies or incorrect import paths within the test file."
                ),
            )
        except Exception as exc:  # noqa: BLE001
            # Broad catch intentional: a test module may raise any exception
            # at import time (e.g., due to a top-level function call that fails).
            # We must not let a single broken module abort the entire discovery.
            log.warning(
                "test_registry_module_import_unexpected_error",
                module_name=module_name,
                exc_type=type(exc).__name__,
                error=str(exc),
                detail=(
                    "An unexpected error occurred while importing this test module. "
                    "This test will not be included in the discovery results."
                ),
            )
        return None

    # ------------------------------------------------------------------
    # Phase R2 — Subclass extraction
    # ------------------------------------------------------------------

    def _extract_concrete_subclasses(
        self,
        modules: list[types.ModuleType],
    ) -> list[BaseTest]:
        """
        Extract and instantiate all concrete BaseTest subclasses from the modules.

        For each module, inspect.getmembers retrieves all class objects.
        A class is included if and only if all of the following are true:
            1. It is a subclass of BaseTest (issubclass check).
            2. It is not BaseTest itself (identity check).
            3. It does not have unimplemented abstract methods (concreteness check).
            4. It passes BaseTest.has_required_metadata() (metadata completeness).
            5. It is defined in the module being inspected (not imported into it).

        Condition 5 prevents double-counting: if test_1_2.py imports a helper
        class from test_1_1.py, the helper would appear in both modules' members
        without the __module__ guard.

        Args:
            modules: List of imported module objects from Phase R1.

        Returns:
            List of instantiated BaseTest objects, one per concrete subclass.
            May contain duplicates if the same class appears in multiple modules
            (extremely unlikely but guarded against by the deduplication set).
        """
        instances: list[BaseTest] = []
        seen_class_ids: set[int] = set()

        for module in modules:
            module_name = module.__name__

            for class_name, cls in inspect.getmembers(module, inspect.isclass):
                # Guard 1: must be a subclass of BaseTest.
                if not (isinstance(cls, type) and issubclass(cls, BaseTest)):
                    continue

                # Guard 2: must not be BaseTest itself.
                if cls is BaseTest:
                    continue

                # Guard 3: must be defined in this module (not imported into it).
                if cls.__module__ != module_name:
                    log.debug(
                        "test_registry_skipping_imported_class",
                        class_name=class_name,
                        defined_in=cls.__module__,
                        found_in=module_name,
                    )
                    continue

                # Guard 4: deduplication by class identity.
                class_id = id(cls)
                if class_id in seen_class_ids:
                    continue
                seen_class_ids.add(class_id)

                # Guard 5: must be concrete (no unimplemented abstract methods).
                abstract_methods: frozenset[str] = getattr(cls, "__abstractmethods__", frozenset())
                if abstract_methods:
                    log.debug(
                        "test_registry_skipping_abstract_class",
                        class_name=class_name,
                        module_name=module_name,
                        abstract_methods=sorted(abstract_methods),
                    )
                    continue

                # Guard 6: must have all required metadata attributes.
                if not cls.has_required_metadata():
                    log.warning(
                        "test_registry_missing_metadata",
                        class_name=class_name,
                        module_name=module_name,
                        detail=(
                            "This BaseTest subclass is missing one or more required "
                            "ClassVar attributes (test_id, priority, strategy, "
                            "depends_on, test_name, domain, tags, cwe_id). "
                            "The test will not be included in the discovery results. "
                            "Declare all required attributes to enable discovery."
                        ),
                    )
                    continue

                # All guards passed: instantiate and register.
                try:
                    instance = cls()
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "test_registry_instantiation_failed",
                        class_name=class_name,
                        module_name=module_name,
                        exc_type=type(exc).__name__,
                        error=str(exc),
                        detail=(
                            "BaseTest subclasses must be instantiable with no "
                            "arguments. Ensure __init__ does not require parameters."
                        ),
                    )
                    continue

                instances.append(instance)
                log.debug(
                    "test_registry_test_discovered",
                    test_id=cls.test_id,
                    class_name=class_name,
                    module_name=module_name,
                    priority=cls.priority,
                    strategy=cls.strategy.value,
                )

        return instances

    # ------------------------------------------------------------------
    # Phase R3 — Filtering
    # ------------------------------------------------------------------

    def _apply_filters(
        self,
        tests: list[BaseTest],
        min_priority: int,
        enabled_strategies: set[TestStrategy],
    ) -> list[BaseTest]:
        """
        Apply priority and strategy filters to the discovered test list.

        Filter order:
            1. Priority: exclude tests with priority > min_priority.
            2. Strategy: exclude tests whose strategy is not in enabled_strategies.

        Both filters are applied in a single pass over the list.
        Each excluded test is logged at DEBUG level with the exclusion reason,
        providing a complete audit trail of what was excluded and why.

        Args:
            tests: Full list of discovered BaseTest instances.
            min_priority: Maximum priority value to include (inclusive).
            enabled_strategies: Set of strategies to include.

        Returns:
            Filtered list of BaseTest instances.
        """
        active: list[BaseTest] = []

        for test in tests:
            cls = test.__class__
            test_id = cls.test_id
            priority = cls.priority
            strategy = cls.strategy

            # Priority filter.
            if priority > min_priority:
                log.debug(
                    "test_registry_excluded_by_priority",
                    test_id=test_id,
                    test_priority=priority,
                    min_priority=min_priority,
                )
                continue

            # Strategy filter.
            if strategy not in enabled_strategies:
                log.debug(
                    "test_registry_excluded_by_strategy",
                    test_id=test_id,
                    test_strategy=strategy.value,
                    enabled_strategies=[s.value for s in enabled_strategies],
                )
                continue

            active.append(test)

        return active

    # ------------------------------------------------------------------
    # DAGScheduler input builder
    # ------------------------------------------------------------------

    def build_dependency_map(
        self,
        tests: list[BaseTest],
    ) -> dict[str, list[str]]:
        """
        Build the dependency map required by DAGScheduler.build_schedule().

        Extracts the test_id and depends_on ClassVar from each test instance
        and returns a dict mapping test_id to its dependency list.

        This method is called by engine.py immediately after discover() returns,
        to prepare the input for DAGScheduler without requiring the engine to
        know the internal structure of BaseTest.

        Args:
            tests: List of active BaseTest instances from discover().

        Returns:
            Dict mapping test_id -> list[str] of prerequisite test_ids.
            Example: {"1.1": [], "1.2": ["1.1"], "2.2": ["1.1", "1.2"]}
        """
        dependency_map: dict[str, list[str]] = {}

        for test in tests:
            cls = test.__class__
            test_id = cls.test_id
            depends_on = list(cls.depends_on)

            if test_id in dependency_map:
                log.warning(
                    "test_registry_duplicate_test_id",
                    test_id=test_id,
                    detail=(
                        "Two concrete BaseTest subclasses declare the same test_id. "
                        "test_id values must be unique across the entire test suite. "
                        "The second occurrence will overwrite the first in the "
                        "dependency map, which may cause incorrect DAG scheduling."
                    ),
                )

            dependency_map[test_id] = depends_on

        log.debug(
            "test_registry_dependency_map_built",
            test_count=len(dependency_map),
            test_ids=sorted(dependency_map.keys()),
        )

        return dependency_map
