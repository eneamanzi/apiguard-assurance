"""
experiments/e2-complete-run/complete_run.py

E2: every test on each lab as built, from a freshly reset lab, with the lab's
committed configuration and nothing else (README.md).

For each lab: reset it, run the tool once with every test, keep the report. The
result (results/) is one table of every test on every lab (its status, its
findings, the reason of a SKIP), the findings of each lab, and each run's cost
(duration, requests). E3 reads crAPI's run from it.

Usage: hatch run dev:e2-complete-run [--lab LAB]
"""

from __future__ import annotations

import argparse
import copy
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))

from experiment import (  # noqa: E402
    LABS,
    ROOT,
    RUNS_SUFFIX,
    Stamp,
    console,
    header,
    lab_config,
    reset_lab,
    run_tool,
    start,
    write_result,
)

RESULTS_DIR: Path = Path(__file__).resolve().parent / "results"
_STATUSES: tuple[str, ...] = ("PASS", "FAIL", "INCONCLUSIVE", "SKIP", "ERROR")
_MS_PER_SECOND: float = 1000.0
# A SKIP reason is cut to this length in the table of every test (the full one is in the JSON).
_SHORT_REASON: int = 90


def summarize(report: dict[str, Any]) -> dict[str, Any]:
    """What E2 keeps of one lab's report: per test, its verdict, findings, cost and cases."""
    tests: dict[str, Any] = {}
    for row in report.get("all_rows", []):
        tests[row["test_id"]] = {
            "name": row["test_name"],
            "status": row["status"],
            "coverage": row.get("coverage"),
            "message": row.get("message"),
            "skip_reason": row.get("skip_reason"),
            "findings": [
                {"title": f["title"], "confidence": f.get("confidence")}
                for f in row.get("findings", [])
            ],
            "cases": {sub["name"]: sub.get("cases", []) for sub in row.get("sub_tests", [])},
            "duration_ms": row.get("duration_ms"),
            "requests": len(row.get("transaction_log") or []),
        }
    not_run = {
        entry["test_id"]: f"{entry['reason']}: {entry.get('detail', '')}"
        for entry in report.get("not_run", [])
    }
    summary = report.get("executive_summary", {})
    return {
        "no_report": report.get("no_report"),
        "duration_seconds": summary.get("assessment_duration_seconds"),
        "requests": sum(test["requests"] for test in tests.values()),
        "tests": tests,
        "not_run": not_run,
    }


def _cell(test: dict[str, Any] | None, not_run: str | None) -> str:
    """One test on one lab, in a few words."""
    if test is None:
        return f"not run ({not_run})" if not_run else "-"
    status = str(test["status"])
    if status == "FAIL":
        count = len(test["findings"])
        return f"**FAIL**, {count} finding{'s' if count != 1 else ''}"
    if status == "PASS":
        return "PASS" + (f" ({test['coverage']})" if test.get("coverage") == "partial" else "")
    if status == "SKIP":
        reason = str(test.get("skip_reason") or "")
        short = reason if len(reason) <= _SHORT_REASON else reason[:_SHORT_REASON] + "..."
        return f"SKIP: {short}"
    return status


def markdown(stamp: Stamp, labs: dict[str, dict[str, Any]]) -> str:
    """The readable result: the cost of each run, every test on every lab, each lab's findings."""
    lines = [f"# E2, complete run, {stamp.meta['date']}", "", header(stamp), ""]
    lines += [
        "Each lab reset, then every test run once with the lab's committed configuration.",
        "",
        "## Each lab's run",
        "",
        "| Lab | " + " | ".join(_STATUSES) + " | Not run | Findings | Duration | Requests |",
        "|---|" + "---|" * (len(_STATUSES) + 4),
    ]
    for lab, run in labs.items():
        if run["no_report"]:
            lines.append(f"| {lab} | {run['no_report']} |" + " |" * (len(_STATUSES) + 3))
            continue
        counts = [
            sum(1 for t in run["tests"].values() if t["status"] == status) for status in _STATUSES
        ]
        findings = sum(len(t["findings"]) for t in run["tests"].values())
        duration = run["duration_seconds"] or 0.0
        lines.append(
            f"| {lab} | " + " | ".join(str(c) for c in counts) + f" | {len(run['not_run'])} | "
            f"{findings} | {duration:.0f} s | {run['requests']} |"
        )
    every = sorted(
        {test for run in labs.values() for test in (*run["tests"], *run["not_run"])},
        key=_test_order,
    )
    lines += ["", "## Every test on every lab", "", "| Test | " + " | ".join(labs) + " |"]
    lines.append("|---|" + "---|" * len(labs))
    for test in every:
        name = next((r["tests"][test]["name"] for r in labs.values() if test in r["tests"]), "")
        cells = [_cell(run["tests"].get(test), run["not_run"].get(test)) for run in labs.values()]
        lines.append(f"| {test} {name} | " + " | ".join(cells) + " |")
    lines += ["", "## Findings", ""]
    for lab, run in labs.items():
        found = [
            (test, f)
            for test in sorted(run["tests"], key=_test_order)
            for f in run["tests"][test]["findings"]
        ]
        lines += [f"### {lab}: {len(found)}", ""]
        if found:
            lines += ["| Test | Finding | Confidence |", "|---|---|---|"]
            lines += [f"| {test} | {f['title']} | {f['confidence']} |" for test, f in found]
            lines.append("")
    return "\n".join(lines) + "\n"


def _test_order(test_id: str) -> tuple[int, ...]:
    """Native tests by number, then the external ones by number."""
    parts = test_id.removeprefix("ext.").split(".")
    numbers = tuple(int(p) for p in parts if p.isdigit())
    return (int(test_id.startswith("ext.")), *numbers)


def main() -> int:
    """Reset each lab, run every test on it, write the result."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[1] if __doc__ else None)
    parser.add_argument("--lab", choices=LABS, help="Only this lab (a trial).")
    args = parser.parse_args()
    stamp = start(partial=args.lab is not None)
    labs = [args.lab] if args.lab else list(LABS)
    console.print(
        f"{header(stamp)} Every test on {', '.join(labs)}, each lab reset first.", highlight=False
    )
    work = RESULTS_DIR / f"{stamp.name}{RUNS_SUFFIX}"
    results: dict[str, dict[str, Any]] = {}
    for index, lab in enumerate(labs, start=1):
        console.print(f"[{index}/{len(labs)}] {lab}", highlight=False)
        reset_lab(lab)
        report = run_tool(
            copy.deepcopy(lab_config(lab)), work / lab, f"[{index}/{len(labs)}] {lab}"
        )
        results[lab] = summarize(report)
        run = results[lab]
        verdicts = ", ".join(
            f"{status} {sum(1 for t in run['tests'].values() if t['status'] == status)}"
            for status in _STATUSES
        )
        console.print(f"  {run['no_report'] or verdicts}", highlight=False)
    path = write_result(RESULTS_DIR, stamp, {"labs": results}, markdown(stamp, results))
    console.print(f"Result: {path.relative_to(ROOT)}", highlight=False)
    return 0 if all(not run["no_report"] for run in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
