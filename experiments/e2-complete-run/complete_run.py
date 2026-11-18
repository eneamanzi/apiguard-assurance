"""
experiments/e2-complete-run/complete_run.py

E2: every test on each lab as built, from a freshly reset lab, with the lab's
committed configuration and nothing else (README.md).

For each lab: reset it, run the tool once with every test, keep the report. The
result (results/) is one table of every test on every lab (its status, its
findings, the reason of a SKIP), the findings of each lab with where each comes
from (finding_origins.yaml: the application, the lab, the specification; a
finding no rule covers is "to classify"), and each run's cost (duration,
requests). E3 reads crAPI's run from it.

Usage: hatch run dev:e2-complete-run [--lab LAB]
       hatch run dev:e2-complete-run --classify   (the latest result, its origins read again)
"""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))

from experiment import (  # noqa: E402
    LABS,
    ROOT,
    RUNS_SUFFIX,
    Stamp,
    console,
    header,
    lab_config,
    latest,
    reset_lab,
    run_tool,
    start,
    write_result,
)

HERE: Path = Path(__file__).resolve().parent
RESULTS_DIR: Path = HERE / "results"
ORIGINS_FILE: Path = HERE / "finding_origins.yaml"
# The origin of a finding no rule covers.
TO_CLASSIFY: str = "to classify"
_STATUSES: tuple[str, ...] = ("PASS", "FAIL", "INCONCLUSIVE", "SKIP", "ERROR")
_MS_PER_SECOND: float = 1000.0
# A SKIP reason is cut to this length in the table of every test (the full one is in the JSON).
_SHORT_REASON: int = 90


class OriginRule(BaseModel):
    """Where one kind of finding comes from: its test, its title, the labs it holds on."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    test: str
    finding: str = Field(description="A regular expression the finding's title matches.")
    labs: list[str] = Field(default_factory=list, description="The labs it holds on; empty: all.")
    origin: str
    why: str


def load_origins() -> tuple[dict[str, str], list[OriginRule]]:
    """The origins and their meaning, and the rules (finding_origins.yaml)."""
    data = yaml.safe_load(ORIGINS_FILE.read_text(encoding="utf-8"))
    origins = {str(k): str(v) for k, v in data["origins"].items()}
    rules = [OriginRule.model_validate(rule) for rule in data["rules"]]
    for rule in rules:
        if rule.origin not in origins:
            raise ValueError(
                f"rule on {rule.test} {rule.finding!r}: unknown origin {rule.origin!r}"
            )
        if unknown := set(rule.labs) - set(LABS):
            raise ValueError(f"rule on {rule.test} {rule.finding!r}: unknown labs {unknown}")
    return origins, rules


def classify(labs: dict[str, dict[str, Any]], rules: list[OriginRule]) -> int:
    """Give every finding its origin and why (the first matching rule); count those none covers."""
    unclassified = 0
    for lab, run in labs.items():
        for test_id, test in run["tests"].items():
            for finding in test["findings"]:
                rule = next(
                    (
                        r
                        for r in rules
                        if r.test == test_id
                        and (not r.labs or lab in r.labs)
                        and re.search(r.finding, finding["title"])
                    ),
                    None,
                )
                finding["origin"] = rule.origin if rule else TO_CLASSIFY
                finding["why"] = rule.why if rule else ""
                unclassified += rule is None
    return unclassified


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


def markdown(stamp: Stamp, labs: dict[str, dict[str, Any]], origins: dict[str, str]) -> str:
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
    kinds = [*origins, TO_CLASSIFY]
    lines += ["", "## Where the findings come from", ""]
    lines += [f"- **{origin}**: {meaning}" for origin, meaning in origins.items()]
    lines += [
        f"- **{TO_CLASSIFY}**: no rule of `finding_origins.yaml` covers it yet",
        "",
        "| Lab | " + " | ".join(kinds) + " | Findings |",
        "|---|" + "---|" * (len(kinds) + 1),
    ]
    for lab, run in labs.items():
        found = [f for t in run["tests"].values() for f in t["findings"]]
        counts = [sum(1 for f in found if f.get("origin") == kind) for kind in kinds]
        lines.append(f"| {lab} | " + " | ".join(str(c) for c in counts) + f" | {len(found)} |")
    lines += ["", "## Findings", ""]
    for lab, run in labs.items():
        found = [
            (test, f)
            for test in sorted(run["tests"], key=_test_order)
            for f in run["tests"][test]["findings"]
        ]
        lines += [f"### {lab}: {len(found)}", ""]
        if found:
            lines += ["| Test | Finding | Confidence | Origin | Why |", "|---|---|---|---|---|"]
            lines += [
                f"| {test} | {f['title']} | {f['confidence']} | {f.get('origin', '')} | "
                f"{' '.join(str(f.get('why', '')).split())} |"
                for test, f in found
            ]
            lines.append("")
    return "\n".join(lines) + "\n"


def reclassify() -> int:
    """Read the origins of the latest result again, after finding_origins.yaml changed."""
    path = latest(RESULTS_DIR)
    if path is None:
        console.print("[red]No E2 result yet.[/red]")
        return 2
    data = json.loads(path.read_text(encoding="utf-8"))
    origins, rules = load_origins()
    unclassified = classify(data["labs"], rules)
    meta = data.pop("meta")
    stamp = Stamp(
        name=path.stem,
        campaign=not (meta["dirty"] or meta["partial"]),
        meta=meta,
    )
    path.write_text(json.dumps({"meta": meta, **data}, indent=2), encoding="utf-8")
    path.with_suffix(".md").write_text(markdown(stamp, data["labs"], origins), encoding="utf-8")
    _report_unclassified(unclassified)
    console.print(f"Result: {path.with_suffix('.md').relative_to(ROOT)}", highlight=False)
    return 0


def _report_unclassified(unclassified: int) -> None:
    """Say how many findings no rule covers."""
    if unclassified:
        console.print(
            f"[yellow]{unclassified} finding(s) to classify: add a rule to "
            "finding_origins.yaml, then hatch run dev:e2-complete-run --classify[/yellow]",
            highlight=False,
        )


def _test_order(test_id: str) -> tuple[int, ...]:
    """Native tests by number, then the external ones by number."""
    parts = test_id.removeprefix("ext.").split(".")
    numbers = tuple(int(p) for p in parts if p.isdigit())
    return (int(test_id.startswith("ext.")), *numbers)


def main() -> int:
    """Reset each lab, run every test on it, write the result."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[1] if __doc__ else None)
    parser.add_argument("--lab", choices=LABS, help="Only this lab (a trial).")
    parser.add_argument(
        "--classify", action="store_true", help="Read the origins of the latest result again."
    )
    args = parser.parse_args()
    if args.classify:
        return reclassify()
    origins, rules = load_origins()
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
    unclassified = classify(results, rules)
    path = write_result(RESULTS_DIR, stamp, {"labs": results}, markdown(stamp, results, origins))
    _report_unclassified(unclassified)
    console.print(f"Result: {path.relative_to(ROOT)}", highlight=False)
    return 0 if all(not run["no_report"] for run in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
