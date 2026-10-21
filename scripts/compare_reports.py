"""
scripts/compare_reports.py

Development helper: compare two ``apiguard_report.json`` files test by test.

Used during refactoring to check that a change did not alter the verdicts: run
the same tests before and after the change, then compare the two reports.
The comparison covers, for every test present in either report: status,
coverage of a PASS, finding count and the counts of the judgements in the
transaction log (``OUTCOME/DETAIL``); plus the run's exit code. It does not
judge whether a result is correct, only whether it changed.

Reports of the old tool (before the test review, docs/project/test-review.md)
label transactions with a free ``oracle_state``; the new ones with ``outcome``
and ``detail``. When one report uses each, the two vocabularies cannot be
compared: their counts are shown side by side and not counted as differences.

This file lives in ``scripts/`` (development only): it is excluded from the
distributed package and from the ruff and mypy checks (``pyproject.toml``).

Usage:
    hatch run python scripts/compare_reports.py BEFORE.json AFTER.json

Exit code: 0 if the reports are equivalent, 1 if any difference is found,
2 if a file cannot be read.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

EXIT_EQUIVALENT: int = 0
EXIT_DIFFERENT: int = 1
EXIT_UNREADABLE: int = 2

MISSING: str = "-"

console = Console()


def load_rows(path: Path) -> tuple[int | None, dict[str, dict[str, Any]]]:
    """
    Read a report and index its rows by test ID.

    Args:
        path: Path to an ``apiguard_report.json`` file.

    Returns:
        Tuple of (run exit code or None if absent, mapping test_id -> row).

    Raises:
        OSError: If the file cannot be read.
        ValueError: If the file is not valid JSON or has no ``all_rows`` list.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = data.get("all_rows")
    if not isinstance(rows, list):
        raise ValueError(f"{path}: no 'all_rows' list, not an APIGuard report")
    exit_code = data.get("executive_summary", {}).get("exit_code")
    return exit_code, {row["test_id"]: row for row in rows}


def transaction_label(tx: dict[str, Any]) -> str:
    """
    The label of one transaction: ``OUTCOME/DETAIL``, the old ``oracle_state``,
    or ``STEP`` for a request that is not judged.

    Args:
        tx: One entry of a transaction log.

    Returns:
        The label.
    """
    if "outcome" in tx or "category" in tx:
        return f"{tx['outcome']}/{tx['detail']}" if tx.get("outcome") else "STEP"
    return str(tx.get("oracle_state"))


def uses_outcomes(rows: dict[str, dict[str, Any]]) -> bool:
    """True when a report labels transactions with outcomes (the new format)."""
    return any(
        "outcome" in tx or "category" in tx
        for row in rows.values()
        for tx in row.get("transaction_log") or []
    )


def oracle_state_counts(row: dict[str, Any] | None) -> Counter[str]:
    """
    Count the transaction labels of a row (transaction_label).

    Args:
        row: A report row, or None when the test is absent from the report.

    Returns:
        Counter of labels (empty for an absent test).
    """
    if row is None:
        return Counter()
    log = row.get("transaction_log") or []
    return Counter(transaction_label(tx) for tx in log)


def describe_counts(counts: Counter[str]) -> str:
    """The counts as text, e.g. ``ENFORCED/AUTH_REQUIRED 67, STEP 2``."""
    return ", ".join(f"{label} {n}" for label, n in sorted(counts.items()))


def describe_state_changes(before: Counter[str], after: Counter[str]) -> str:
    """
    Describe how the oracle-state counts changed between two runs.

    Args:
        before: Counts in the first report.
        after: Counts in the second report.

    Returns:
        Text such as ``ENFORCED 311->300, AUTH_BYPASS 78->89``; empty if unchanged.
    """
    changes = [
        f"{state} {before.get(state, 0)}->{after.get(state, 0)}"
        for state in sorted(set(before) | set(after))
        if before.get(state, 0) != after.get(state, 0)
    ]
    return ", ".join(changes)


def field(row: dict[str, Any] | None, key: str) -> str:
    """
    Return a row field as text, or a placeholder when the test is absent.

    Args:
        row: A report row, or None.
        key: Field name.

    Returns:
        The field value as string, or ``-``.
    """
    return MISSING if row is None else str(row.get(key))


def compare(before_path: Path, after_path: Path) -> int:
    """
    Compare two reports and print a table of the differences.

    Args:
        before_path: Report produced before the change.
        after_path: Report produced after the change.

    Returns:
        Process exit code (see module docstring).
    """
    try:
        exit_before, rows_before = load_rows(before_path)
        exit_after, rows_after = load_rows(after_path)
    except (OSError, ValueError, KeyError) as exc:
        console.print(f"[red]Cannot read the reports:[/red] {exc}")
        return EXIT_UNREADABLE

    same_vocabulary = uses_outcomes(rows_before) == uses_outcomes(rows_after)
    table = Table(title=f"{before_path}  ->  {after_path}")
    states_title = "States changed" if same_vocabulary else "States (old | new, not compared)"
    for column in ("Test", "Status", "Coverage", "Findings", states_title):
        table.add_column(column)

    differences = 0
    for test_id in sorted(set(rows_before) | set(rows_after)):
        old, new = rows_before.get(test_id), rows_after.get(test_id)
        status = (field(old, "status"), field(new, "status"))
        coverage = (field(old, "coverage"), field(new, "coverage"))
        findings = (field(old, "finding_count"), field(new, "finding_count"))
        if same_vocabulary:
            states = describe_state_changes(oracle_state_counts(old), oracle_state_counts(new))
            states_changed = bool(states)
        else:
            states = (
                f"{describe_counts(oracle_state_counts(old))} | "
                f"{describe_counts(oracle_state_counts(new))}"
            )
            states_changed = False
        changed = (
            status[0] != status[1]
            or (same_vocabulary and coverage[0] != coverage[1])
            or findings[0] != findings[1]
            or states_changed
        )
        differences += int(changed)
        style = "red" if changed else ""
        table.add_row(
            test_id,
            status[0] if status[0] == status[1] else f"{status[0]} -> {status[1]}",
            coverage[1] if coverage[0] == coverage[1] else f"{coverage[0]} -> {coverage[1]}",
            findings[0] if findings[0] == findings[1] else f"{findings[0]} -> {findings[1]}",
            states,
            style=style,
        )

    console.print(table)
    if exit_before != exit_after:
        differences += 1
        console.print(f"[red]Exit code changed: {exit_before} -> {exit_after}[/red]")

    if differences:
        console.print(f"[red]{differences} difference(s).[/red]")
        return EXIT_DIFFERENT
    console.print(
        "[green]No differences in tests, statuses, coverage, findings, states, exit code.[/green]"
    )
    return EXIT_EQUIVALENT


def main() -> int:
    """
    Parse the command line and run the comparison.

    Returns:
        Process exit code.
    """
    parser = argparse.ArgumentParser(description="Compare two apiguard_report.json files.")
    parser.add_argument("before", type=Path, help="report produced before the change")
    parser.add_argument("after", type=Path, help="report produced after the change")
    args = parser.parse_args()
    return compare(args.before, args.after)


if __name__ == "__main__":
    sys.exit(main())
