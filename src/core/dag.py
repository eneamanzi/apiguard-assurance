"""
src/core/dag.py

DAGScheduler: topological ordering of test execution based on declared dependencies.

The scheduler answers two questions before the pipeline enters Phase 5:
    1. Are there any circular dependencies in the test suite? (fatal if yes)
    2. In what order must the tests execute to satisfy all depends_on declarations?

It uses graphlib.TopologicalSorter from the Python 3.9+ stdlib, which implements
a parallel-ready topological sort. The scheduler wraps its output into an ordered
list of batches: each batch contains tests that have no mutual dependencies and
could theoretically run in parallel. In Version 1.0, the engine executes batches
and the tests within each batch strictly sequentially (no ThreadPoolExecutor).

The batch abstraction preserves the option for future parallelism without
implementing it now (Implementazione.md, Section 4.3).

Dependency rule: this module imports from stdlib and src.core.exceptions only.
It operates on plain strings (test_id values) and does not import BaseTest or
any test-specific type to avoid circular dependencies with tests/.
"""

from __future__ import annotations

import graphlib
from dataclasses import dataclass, field

import structlog

from src.core.exceptions import DAGCycleError

log: structlog.BoundLogger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ScheduledBatch:
    """
    An ordered group of test IDs that share no mutual dependencies.

    Tests within a batch may theoretically execute in parallel (no test
    in the batch depends on another test in the same batch). In Version 1.0,
    the engine iterates over batch.test_ids sequentially.

    The batch_index is 0-based and reflects the topological level: all tests
    in batch 0 have no dependencies, all tests in batch 1 depend only on tests
    in batch 0, and so on.

    Using a frozen dataclass rather than a plain tuple or list makes the
    batch immutable after construction and provides a named interface
    (batch.test_ids, batch.batch_index) that is more readable at call sites
    in engine.py than indexing into a raw tuple.
    """

    batch_index: int
    test_ids: list[str] = field(default_factory=list)

    @property
    def size(self) -> int:
        """Number of tests in this batch."""
        return len(self.test_ids)

    def __repr__(self) -> str:
        return (
            f"ScheduledBatch(batch_index={self.batch_index}, "
            f"test_ids={self.test_ids!r}, size={self.size})"
        )


# ---------------------------------------------------------------------------
# DAGScheduler
# ---------------------------------------------------------------------------


class DAGScheduler:
    """
    Topological scheduler for BaseTest execution ordering.

    Accepts a mapping from test_id to its declared dependencies and produces
    an ordered list of ScheduledBatch objects. The engine iterates over batches
    in order and executes each test within a batch sequentially.

    The scheduler is stateless after construction: build_schedule() can be
    called multiple times on different dependency maps without side effects.
    In practice, it is called exactly once per pipeline run during Phase 4.

    Usage:

        scheduler = DAGScheduler()
        batches = scheduler.build_schedule(
            dependencies={"1.2": ["1.1"], "2.2": ["1.1", "1.2"], "1.1": []},
            active_test_ids={"1.1", "1.2", "2.2"},
        )
        # batches[0].test_ids -> ["1.1"]        (no dependencies)
        # batches[1].test_ids -> ["1.2"]        (depends on 1.1)
        # batches[2].test_ids -> ["2.2"]        (depends on 1.1 and 1.2)
    """

    def build_schedule(
        self,
        dependencies: dict[str, list[str]],
        active_test_ids: set[str],
    ) -> list[ScheduledBatch]:
        """
        Build a topologically ordered list of ScheduledBatch objects.

        This is the single public method of DAGScheduler. It performs three
        sequential operations:

            1. Sanitize the dependency graph: remove references to test IDs
               that are not in active_test_ids (filtered out by TestRegistry).
               Log a WARNING for each removed dependency.

            2. Feed the sanitized graph to graphlib.TopologicalSorter and
               detect cycles. A CycleError from graphlib is converted to
               DAGCycleError with structured diagnostic information.

            3. Drain the sorter into ScheduledBatch objects, one batch per
               topological level.

        Args:
            dependencies: Mapping from test_id to list of test_id prerequisites.
                          Every active test must appear as a key, even if its
                          dependency list is empty. Example:
                              {"1.1": [], "1.2": ["1.1"], "2.2": ["1.1", "1.2"]}

            active_test_ids: Set of test_id values that survived the TestRegistry
                             filter (priority + strategy). Dependencies referencing
                             IDs outside this set are silently dropped with a WARNING.

        Returns:
            Ordered list of ScheduledBatch. Index 0 contains tests with no
            active dependencies; subsequent indices contain tests whose
            prerequisites all appear in earlier batches.
            Returns an empty list if dependencies is empty.

        Raises:
            DAGCycleError: If a circular dependency is detected among the active
                           tests. This is a fatal error that blocks pipeline startup.
        """
        if not dependencies:
            log.warning("dag_build_schedule_called_with_empty_dependency_map")
            return []

        log.debug(
            "dag_build_schedule_started",
            total_tests=len(dependencies),
            active_test_ids_count=len(active_test_ids),
        )

        # Step 1: sanitize the dependency graph.
        sanitized = self._sanitize_dependencies(dependencies, active_test_ids)

        # Step 2: build the topological sort and detect cycles.
        sorter = self._build_sorter(sanitized)

        # Step 3: drain the sorter into batches.
        batches = self._drain_into_batches(sorter)

        total_scheduled = sum(b.size for b in batches)
        log.info(
            "dag_schedule_built",
            batch_count=len(batches),
            total_tests_scheduled=total_scheduled,
        )

        return batches

    # ------------------------------------------------------------------
    # Internal steps
    # ------------------------------------------------------------------

    def _sanitize_dependencies(
        self,
        dependencies: dict[str, list[str]],
        active_test_ids: set[str],
    ) -> dict[str, list[str]]:
        """
        Remove dependency references to test IDs not in active_test_ids.

        When TestRegistry filters out a test (e.g., a P0 prerequisite excluded
        because min_priority=1), tests that declared depends_on that test would
        cause graphlib to reference an unknown node. Rather than treating this
        as a fatal error, we drop the reference and log a WARNING per
        Implementazione.md Section 4.5:

            "If a declared dependency is not in the active set (because filtered
            by priority), DAGScheduler ignores it with a WARNING — without error."

        This is semantically safe because the filtered test either passed
        (and its postconditions are assumed satisfied) or was not needed for
        the current execution scope.

        Args:
            dependencies: Raw dependency map from TestRegistry.
            active_test_ids: Set of test IDs that will actually run.

        Returns:
            Sanitized dependency map where every referenced test_id is active.
        """
        sanitized: dict[str, list[str]] = {}

        for test_id, deps in dependencies.items():
            active_deps: list[str] = []
            for dep in deps:
                if dep in active_test_ids:
                    active_deps.append(dep)
                else:
                    log.warning(
                        "dag_dependency_removed_not_active",
                        test_id=test_id,
                        missing_dependency=dep,
                        reason=(
                            "The declared dependency is not in the active test set. "
                            "It was likely filtered out by priority or strategy. "
                            "The dependency edge is dropped; execution continues."
                        ),
                    )
            sanitized[test_id] = active_deps

        return sanitized

    def _build_sorter(
        self,
        sanitized_dependencies: dict[str, list[str]],
    ) -> graphlib.TopologicalSorter:  # type: ignore[type-arg]
        """
        Construct and prepare a graphlib.TopologicalSorter from the dependency map.

        graphlib.TopologicalSorter accepts a graph as {node: {predecessors}}.
        Our dependency map uses lists; we convert to sets for graphlib compatibility.

        prepare() must be called after construction to enable get_ready() and done().
        If a cycle exists in the graph, prepare() raises graphlib.CycleError with
        a tuple of nodes involved in the cycle. We catch this and raise our own
        DAGCycleError with the cycle nodes converted to a sorted list for deterministic
        diagnostic output.

        Args:
            sanitized_dependencies: Cleaned dependency map (no missing references).

        Returns:
            A prepared TopologicalSorter ready for batch extraction.

        Raises:
            DAGCycleError: Wraps graphlib.CycleError with structured diagnostics.
        """
        # Convert list values to sets as required by graphlib's internal API.
        graph: dict[str, set[str]] = {
            test_id: set(deps) for test_id, deps in sanitized_dependencies.items()
        }

        sorter: graphlib.TopologicalSorter = graphlib.TopologicalSorter(graph)  # type: ignore[type-arg]

        try:
            sorter.prepare()
        except graphlib.CycleError as cycle_exc:
            # graphlib.CycleError.args[1] is a tuple of node names in the cycle.
            # We extract it defensively: if the structure changes in a future
            # Python version, we fall back to an empty cycle list rather than
            # raising a secondary exception inside the except block.
            cycle_nodes: list[str] = []
            if len(cycle_exc.args) >= 2 and hasattr(cycle_exc.args[1], "__iter__"):
                cycle_nodes = sorted(str(node) for node in cycle_exc.args[1])

            log.error(
                "dag_cycle_detected",
                cycle_nodes=cycle_nodes,
                detail=(
                    "A circular dependency was found among the active tests. "
                    "This is a design error in the test suite and blocks pipeline "
                    "startup. Inspect the depends_on declarations of the listed tests."
                ),
            )

            raise DAGCycleError(
                message=(
                    f"Circular dependency detected among tests: {cycle_nodes}. "
                    "Inspect the depends_on attribute of each listed test and "
                    "break the cycle before restarting the assessment."
                ),
                cycle=cycle_nodes,
            ) from cycle_exc

        return sorter

    def _drain_into_batches(
        self,
        sorter: graphlib.TopologicalSorter,  # type: ignore[type-arg]
    ) -> list[ScheduledBatch]:
        """
        Extract topological levels from the prepared sorter into ScheduledBatch objects.

        graphlib.TopologicalSorter operates as a stateful iterator:
            - get_ready() returns nodes whose dependencies have all been marked done.
            - done(*nodes) marks nodes as completed, potentially unblocking dependents.
            - is_active() returns False when all nodes have been yielded and marked done.

        We drain the sorter level by level:
            - Call get_ready() to get the current batch of unblocked nodes.
            - Mark all of them as done simultaneously (simulating sequential execution
              completing before the next batch starts).
            - Repeat until is_active() returns False.

        Each call to get_ready() before the corresponding done() represents one
        topological level — a ScheduledBatch. The batch_index is 0-based.

        The test_ids within each batch are sorted lexicographically for
        deterministic ordering. graphlib does not guarantee ordering within a level,
        and deterministic output is required by the Reproducibility constraint
        (Implementazione.md, Section 1).

        Args:
            sorter: A prepared TopologicalSorter (prepare() already called).

        Returns:
            Ordered list of ScheduledBatch, one per topological level.
        """
        batches: list[ScheduledBatch] = []
        batch_index: int = 0

        while sorter.is_active():
            # get_ready() returns nodes with all dependencies satisfied.
            # Sorting ensures deterministic ordering within a batch.
            ready_nodes: list[str] = sorted(sorter.get_ready())

            if not ready_nodes:
                # is_active() is True but get_ready() returned nothing.
                # This should not occur after a successful prepare() with no cycles,
                # but we guard against it to avoid an infinite loop.
                log.error(
                    "dag_drain_stalled",
                    batch_index=batch_index,
                    detail=(
                        "TopologicalSorter reports is_active()=True but get_ready() "
                        "returned no nodes. This indicates an internal graphlib state "
                        "inconsistency. Assessment cannot proceed safely."
                    ),
                )
                break

            batch = ScheduledBatch(
                batch_index=batch_index,
                test_ids=ready_nodes,
            )
            batches.append(batch)

            log.debug(
                "dag_batch_created",
                batch_index=batch_index,
                test_ids=ready_nodes,
                batch_size=len(ready_nodes),
            )

            # Mark all nodes in this batch as done before extracting the next level.
            # In a parallel execution model, done() would be called per-node as each
            # test completes. In sequential V1.0, we mark all as done at once.
            sorter.done(*ready_nodes)
            batch_index += 1

        return batches
