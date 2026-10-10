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
        An incomplete or invalid declaration (src/core/test_metadata.py) stops
        the run with TestDefinitionError.

    Phase R3 — Filtering:
        Discovered tests are filtered by:
            - priority: tests with priority > min_priority are excluded.
            - strategy: tests whose strategy is not in enabled_strategies are excluded.
        Filtering is logged at DEBUG level for each excluded test.

    Output:
        A list of BaseTest instances, one per discovered and filtered test.
        The list is ordered by test_id lexicographically for deterministic
        output (reproducibility: docs/architecture/overview.md, "Pipeline").

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

import structlog

from src.core.exceptions import raise_for_test_definition_problems
from src.core.models import NotRunEntry, NotRunReason, TestStrategy
from src.core.test_metadata import PRIVATE_CLASS_PREFIX, metadata_problems
from src.tests.base import BaseTest

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

    def __init__(self) -> None:
        """Start with an empty list of excluded tests (filled by discover())."""
        # Tests excluded by the filters of the last discover(), with the reason.
        self.not_run: list[NotRunEntry] = []

    def discover(
        self,
        min_priority: int,
        enabled_strategies: set[TestStrategy],
        allowed_ids: set[str] | None = None,
    ) -> list[BaseTest]:
        """
        Discover, instantiate, and filter all concrete BaseTest subclasses.

        This is the single public method of TestRegistry. It performs all
        three discovery phases (scan, extract, filter) and returns a sorted
        list of BaseTest instances ready for the DAGScheduler.

        The returned list is sorted by test_id lexicographically. This produces
        a deterministic output regardless of filesystem directory traversal order,
        satisfying the reproducibility constraint (docs/architecture/overview.md).

        Args:
            min_priority: Maximum priority level (inclusive) to include.
                          Tests with priority > min_priority are excluded.
                          Range: 0 (P0 only) to 3 (all tests).
                          Ignored when allowed_ids is not None.
            enabled_strategies: Set of TestStrategy values to include.
                                 Tests whose strategy is not in this set are excluded.
                                 Must not be empty (validated by ToolConfig schema).
                                 Ignored when allowed_ids is not None.
            allowed_ids: None means no ID filter (normal priority+strategy
                         filtering). A set, even empty, includes ONLY the tests
                         whose test_id is in it (an empty set: no native test)
                         and overrides min_priority and enabled_strategies.

        Returns:
            Sorted list of instantiated BaseTest subclasses that passed all
            filters. Empty list if no tests match the filter criteria.
        """
        log.info(
            "test_registry_discovery_started",
            min_priority=min_priority,
            enabled_strategies=[s.value for s in enabled_strategies],
            allowed_ids=sorted(allowed_ids) if allowed_ids is not None else None,
        )

        # Phase R1: scan and import test modules.
        imported_modules = self._scan_and_import_modules()

        # Phase R2: extract concrete BaseTest subclasses.
        all_tests = self._extract_concrete_subclasses(imported_modules)

        # Phase R3: apply filters (excluded tests go to self.not_run).
        self.not_run = []
        active_tests = self._apply_filters(
            tests=all_tests,
            min_priority=min_priority,
            enabled_strategies=enabled_strategies,
            allowed_ids=allowed_ids,
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

    def list_tests(self) -> list[BaseTest]:
        """
        Return every concrete native test, without filtering.

        Used to check the declarations, their prerequisites and
        execution.test_ids before the run (engine.check_tests).

        Returns:
            One instance per native test.
        """
        modules = self._scan_and_import_modules()
        return self._extract_concrete_subclasses(modules)

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
            4. Its declaration is complete and valid (metadata_problems(); a
               problem is collected and raised as TestDefinitionError).
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
        # Every declaration problem found; raised together at the end.
        problems: list[str] = []
        owner_by_test_id: dict[str, str] = {}

        for module in modules:
            module_name = module.__name__

            for class_name, cls in inspect.getmembers(module, inspect.isclass):
                # Guard 1: must be a subclass of BaseTest.
                if not (isinstance(cls, type) and issubclass(cls, BaseTest)):
                    continue

                # Guard 2: must not be BaseTest itself.
                if cls is BaseTest:
                    continue

                # Guard 2b: a name starting with "_" marks a helper base class
                # shared by tests of the module, not a test (no declaration).
                if class_name.startswith(PRIVATE_CLASS_PREFIX):
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

                # Guard 6: the declaration must be complete and valid, and the
                # test_id unique (src/core/test_metadata.py). A problem is
                # collected, not skipped: the run stops after the scan.
                where = f"{class_name} ({module_name})"
                declaration_problems = metadata_problems(cls, external=False)
                if declaration_problems:
                    problems.extend(f"{where}: {problem}" for problem in declaration_problems)
                    continue
                if cls.test_id in owner_by_test_id:
                    problems.append(
                        f"{where}: test_id {cls.test_id!r} already used by "
                        f"{owner_by_test_id[cls.test_id]}"
                    )
                    continue
                owner_by_test_id[cls.test_id] = where

                # All guards passed: instantiate and register.
                try:
                    instance = cls()
                except Exception as exc:  # noqa: BLE001 -- any failure is reported
                    problems.append(
                        f"{where}: cannot be instantiated without arguments "
                        f"({type(exc).__name__}: {exc})"
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

        raise_for_test_definition_problems(problems)
        return instances

    # ------------------------------------------------------------------
    # Phase R3 — Filtering
    # ------------------------------------------------------------------

    def _apply_filters(
        self,
        tests: list[BaseTest],
        min_priority: int,
        enabled_strategies: set[TestStrategy],
        allowed_ids: set[str] | None,
    ) -> list[BaseTest]:
        """
        Apply filters to the discovered test list.

        Filter mode is determined by whether allowed_ids is None:

        ID filter mode (allowed_ids is a set, possibly empty):
            Include ONLY tests whose test_id is in allowed_ids.
            The min_priority and enabled_strategies parameters are ignored
            entirely. This is the intended behaviour: when the operator
            explicitly names specific tests, priority and strategy are not
            relevant constraints.

        Normal filter mode (allowed_ids is None):
            1. Priority: exclude tests with priority > min_priority.
            2. Strategy: exclude tests whose strategy is not in enabled_strategies.
            Both filters are applied in a single pass. Each excluded test is
            logged at DEBUG level with the exclusion reason.

        Args:
            tests:             Full list of discovered BaseTest instances.
            min_priority:      Maximum priority value to include (inclusive).
            enabled_strategies: Set of strategies to include.
            allowed_ids:       If not None, the only filter applied is
                               membership in this set (empty: no test).

        Returns:
            Filtered list of BaseTest instances.
        """
        active: list[BaseTest] = []

        if allowed_ids is not None:
            # ID filter mode: allowed_ids overrides everything else.
            for test in tests:
                test_id = test.__class__.test_id
                if test_id in allowed_ids:
                    active.append(test)
                else:
                    self._exclude(
                        test, NotRunReason.NOT_IN_TEST_IDS, "execution.test_ids does not list it"
                    )
            # Unknown IDs never reach this point: engine.check_tests()
            # rejects them before Phase 2.
            return active

        # Normal filter mode: priority + strategy.
        for test in tests:
            cls = test.__class__
            test_id = cls.test_id
            priority = cls.priority
            strategy = cls.strategy

            if priority > min_priority:
                self._exclude(
                    test,
                    NotRunReason.PRIORITY,
                    f"priority P{priority} is above execution.min_priority (P{min_priority})",
                )
                continue

            if strategy not in enabled_strategies:
                self._exclude(
                    test,
                    NotRunReason.STRATEGY,
                    f"strategy {strategy.value} is not in execution.strategies "
                    f"({', '.join(sorted(s.value for s in enabled_strategies))})",
                )
                continue

            active.append(test)

        return active

    def _exclude(self, test: BaseTest, reason: NotRunReason, detail: str) -> None:
        """
        Record a test excluded by a filter in self.not_run.

        Args:
            test:   The excluded test.
            reason: The filter that excluded it.
            detail: The values that excluded it.
        """
        cls = test.__class__
        self.not_run.append(
            NotRunEntry(
                test_id=cls.test_id,
                test_name=cls.test_name,
                source=cls.source,
                reason=reason,
                detail=detail,
            )
        )
        log.debug("test_registry_excluded", test_id=cls.test_id, reason=reason.value, detail=detail)
