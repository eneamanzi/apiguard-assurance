"""
src/tests/registry.py

TestRegistry: dynamic discovery and filtering of BaseTest subclasses.

The registry eliminates the need for a central, manually-maintained list of
tests. Adding a new test requires only two things:
    1. Create a file in the correct domain directory following the naming
       convention: src/tests/domain_{X}/test_{X}_{Y}_{description}.py
    2. Define a concrete subclass of BaseTest declaring
       ``info = TestInfo(...)`` (src/core/test_metadata.py).

No other file needs to be modified. The registry discovers the test at the
next pipeline run via pkgutil.walk_packages.

Discovery pipeline:

    Phase R1+R2 — Module scan and class extraction (src/core/test_discovery.py):
        every module test_*.py of src.tests is imported and its concrete
        BaseTest subclasses are instantiated. A module that cannot be
        imported (an invalid declaration included), a test module outside a
        package, a class without a valid ``info`` or a duplicate ID stops the
        run with TestDefinitionError listing every problem: a test is never
        left out silently.

    Phase R3 — Filtering:
        Discovered tests are filtered by:
            - priority: tests with priority > min_priority are excluded.
            - strategy: tests whose strategy is not in enabled_strategies are excluded.
        Filtering is logged at DEBUG level for each excluded test.

    Output:
        A list of BaseTest instances, one per discovered and filtered test.
        The list is ordered by test_id lexicographically for deterministic
        output (reproducibility: docs/04-architecture/01-overview.md, "Pipeline").

Dependency rule:
    This module imports from structlog, src.core and src.tests.base only.
    It must never import from config/, discovery/, report/, or engine.py.
"""

from __future__ import annotations

import structlog

from src.core.models import NotRunEntry, NotRunReason, TestStrategy
from src.core.test_discovery import discover_tests
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# The root package that contains all test domain subdirectories.
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
        satisfying the reproducibility constraint (docs/04-architecture/01-overview.md).

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

        # Phases R1+R2: import the test modules and instantiate the tests.
        all_tests = self.list_tests()

        # Phase R3: apply filters (excluded tests go to self.not_run).
        self.not_run = []
        active_tests = self._apply_filters(
            tests=all_tests,
            min_priority=min_priority,
            enabled_strategies=enabled_strategies,
            allowed_ids=allowed_ids,
        )

        # Sort by test_id for deterministic ordering.
        active_tests.sort(key=lambda t: t.info.id)

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

        Raises:
            TestDefinitionError: Listing every test that cannot be used.
        """
        # The base is abstract and only used for issubclass(): mypy rejects an
        # abstract class for type[...] all the same (python/mypy#4717).
        return discover_tests(
            _TESTS_ROOT_PACKAGE,
            _TEST_MODULE_PREFIX,
            BaseTest,  # type: ignore[type-abstract]
            external=False,
        )

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
                if test.info.id in allowed_ids:
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
            priority = test.info.priority
            strategy = test.info.strategy

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
            "test_registry_excluded", test_id=test.info.id, reason=reason.value, detail=detail
        )
