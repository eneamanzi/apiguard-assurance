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
implementing it now (docs/04-architecture/01-overview.md, "Pipeline").

Two kinds of prerequisite (docs/04-architecture/03-assessment-model.md,
"Dependencies between tests"), both of which also order the run:
    depends_on     data: the test uses something only the prerequisite
                   produces (TestContext shared data). It runs if the
                   prerequisite completed (PASS or FAIL).
    requires_pass  logic: the test is meaningful only if the prerequisite
                   holds. It runs if the prerequisite returned PASS.
Otherwise the engine records the test as SKIP with the reason returned by
prerequisite_skip_reason(); a prerequisite that is not in the run counts as
not completed.

Dependency rule: this module imports from stdlib, src.core.exceptions and
src.core.models only. It operates on plain strings (test_id values) and does
not import BaseTest or any test-specific type to avoid circular dependencies
with tests/.
"""

from __future__ import annotations

import graphlib
import heapq
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import structlog

from src.core.exceptions import DAGCycleError
from src.core.models import TestStatus

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

    The batch_index is 0-based and follows the run order: the batches are
    consecutive pieces of one sequence (prerequisites first, then the declared
    effect, then the test ID), cut where a test depends on one of the current
    batch; a test's prerequisites are always in earlier batches.

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
        order_rank: Mapping[str, int] | None = None,
    ) -> list[ScheduledBatch]:
        """
        Build a topologically ordered list of ScheduledBatch objects.

        This is the single public method of DAGScheduler. It performs three
        sequential operations:

            1. Sanitize the dependency graph: remove references to test IDs
               that are not in active_test_ids (left out by the selection).

            2. Feed the sanitized graph to graphlib.TopologicalSorter and
               detect cycles. A CycleError from graphlib is converted to
               DAGCycleError with structured diagnostic information.

            3. Drain the sorter into one sequence: whenever several tests are
               ready (their prerequisites already placed), the lowest
               order_rank goes first, then the test ID; then cut the sequence
               into ScheduledBatch objects, a new batch starting where a test
               depends on one of the current batch.

        Args:
            dependencies: Mapping from test_id to list of test_id prerequisites.
                          Every active test must appear as a key, even if its
                          dependency list is empty. Example:
                              {"1.1": [], "1.2": ["1.1"], "2.2": ["1.1", "1.2"]}

            active_test_ids: Set of test_id values selected for the run.
                             Edges to IDs outside this set are dropped (the
                             engine skips the dependent test).

            order_rank: Rank of each test among the ready ones (lower first);
                        the engine gives the rank of the declared effect
                        (READ_ONLY, CHANGES_DATA, STRESSES_TARGET), so that the
                        tests that change or stress the target run last, as far
                        as the prerequisites allow. Missing: rank 0.

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
        batches = self._drain_into_batches(
            sorter,
            expected_test_ids=set(sanitized.keys()),
            dependencies=sanitized,
            order_rank=order_rank or {},
        )

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

        When the selection leaves out a prerequisite (e.g. excluded by
        min_priority, strategies or test_ids), its edge would make graphlib
        reference an unknown node. The edge is only an ordering constraint, so
        it is dropped here; the dependent test is still scheduled, and the
        engine records it as SKIP before executing it
        (prerequisite_skip_reason(): a prerequisite not in the run counts as
        not completed).

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
                    log.debug(
                        "dag_dependency_not_in_run",
                        test_id=test_id,
                        missing_dependency=dep,
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
        expected_test_ids: set[str],
        dependencies: Mapping[str, Sequence[str]],
        order_rank: Mapping[str, int],
    ) -> list[ScheduledBatch]:
        """
        Extract the run order from the prepared sorter and cut it into batches.

        graphlib.TopologicalSorter operates as a stateful iterator:
            - get_ready() returns the nodes that became ready (all their
              predecessors marked done) since the previous call.
            - done(node) marks one node as completed, possibly unblocking others.
            - is_active() returns False when every node has been marked done.

        One node is taken at a time: among the ready ones, the lowest
        (order_rank, test_id) first. The result is a single sequence that
        respects every prerequisite and, within that, the rank (the declared
        effect) across the whole run, not only within a topological level;
        the test ID makes it deterministic (docs/04-architecture/01-overview.md,
        "Pipeline", Reproducibility).

        The sequence is then cut into ScheduledBatch objects: a new batch
        starts where a test depends on a test of the current batch, so that no
        test of a batch depends on another of the same batch (the batch
        contract, kept for a future parallel execution).

        Stall detection
        ---------------
        If is_active() returns True but nothing is ready, the sorter has
        entered an irrecoverable state. This should not occur after a clean
        prepare() without cycles; on stall, a structured ERROR names every test
        that was never extracted, then the drain stops.

        Args:
            sorter:            A prepared TopologicalSorter (prepare() already called).
            expected_test_ids: Complete set of test IDs the sorter should yield,
                               for the stall diagnostics.
            dependencies:      The sanitized prerequisites of each test.
            order_rank:        Rank of each test among the ready ones (default 0).

        Returns:
            Ordered list of ScheduledBatch.
        """
        sequence: list[str] = []
        ready: list[tuple[int, str]] = []

        while sorter.is_active():
            for node in sorter.get_ready():
                heapq.heappush(ready, (order_rank.get(node, 0), node))
            if not ready:
                unscheduled = sorted(expected_test_ids - set(sequence))
                log.error(
                    "dag_drain_stalled",
                    unscheduled_test_ids=unscheduled,
                    scheduled_count=len(sequence),
                    expected_count=len(expected_test_ids),
                    detail=(
                        "TopologicalSorter reports is_active()=True but nothing is ready. "
                        "The listed test IDs were never extracted from the sorter and will "
                        "not be executed: inspect their depends_on declarations."
                    ),
                )
                break
            _, node = heapq.heappop(ready)
            sequence.append(node)
            sorter.done(node)

        batches: list[ScheduledBatch] = []
        current: list[str] = []
        for test_id in sequence:
            if any(dep in current for dep in dependencies.get(test_id, ())):
                batches.append(ScheduledBatch(batch_index=len(batches), test_ids=current))
                current = []
            current.append(test_id)
        if current:
            batches.append(ScheduledBatch(batch_index=len(batches), test_ids=current))

        for batch in batches:
            log.debug(
                "dag_batch_created",
                batch_index=batch.batch_index,
                test_ids=batch.test_ids,
                batch_size=batch.size,
            )
        return batches


# ---------------------------------------------------------------------------
# Prerequisite check (Phase 5)
# ---------------------------------------------------------------------------

# Statuses with which a prerequisite has completed: it ran to the end, so
# whatever it produces for its dependents exists (INCONCLUSIVE too: it ran to
# the end, it only could not verify).
_COMPLETED_STATUSES: frozenset[TestStatus] = frozenset(
    {TestStatus.PASS, TestStatus.FAIL, TestStatus.INCONCLUSIVE}
)


def prerequisite_skip_reason(
    depends_on: Sequence[str],
    requires_pass: Sequence[str],
    statuses: Mapping[str, TestStatus],
) -> str | None:
    """
    Return why a test must be skipped because of its prerequisites, or None.

    Called by the engine right before a test runs. The schedule guarantees
    that every prerequisite in the run has already finished, so a
    prerequisite missing from statuses is not in the run.

    Rules (one reason per unmet prerequisite, depends_on first):
        depends_on X:    X must have completed (PASS, FAIL or INCONCLUSIVE).
        requires_pass X: X must have returned PASS.

    Args:
        depends_on:    Test IDs whose data the test uses.
        requires_pass: Test IDs that must hold for the test to be meaningful.
        statuses:      Status of every test already finished in this run.

    Returns:
        The SKIP reason, naming each unmet prerequisite, or None when the
        test can run.
    """
    unmet: list[str] = []
    for dep in depends_on:
        status = statuses.get(dep)
        if status is None:
            unmet.append(f"it needs data from {dep}, which is not in this run")
        elif status not in _COMPLETED_STATUSES:
            unmet.append(f"it needs data from {dep}, which returned {status.value}")
    for dep in requires_pass:
        status = statuses.get(dep)
        if status is None:
            unmet.append(f"it is meaningful only if {dep} passes; {dep} is not in this run")
        elif status != TestStatus.PASS:
            unmet.append(f"it is meaningful only if {dep} passes; {dep} returned {status.value}")
    if not unmet:
        return None
    return "Prerequisite not met: " + "; ".join(unmet) + "."
