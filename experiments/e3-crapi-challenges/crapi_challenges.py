"""
experiments/e3-crapi-challenges/crapi_challenges.py

E3: the weaknesses OWASP crAPI declares, read in E2's run on the crAPI lab
(README.md). Nothing is run: the latest E2 result (campaign or trial) is read.

Each challenge of challenges.yaml (crAPI's own list) is caught, named, attempted
or missed by the rules written there before the run, or declared out of scope or
absent with its reason. The result counts both ways: over every challenge, and
over those in scope.

Usage: hatch run dev:e3-crapi-challenges
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared"))

from experiment import ROOT, Stamp, console, header, latest, start, write_result  # noqa: E402

HERE: Path = Path(__file__).resolve().parent
RESULTS_DIR: Path = HERE / "results"
CHALLENGES_FILE: Path = HERE / "challenges.yaml"
E2_RESULTS: Path = HERE.parent / "e2-complete-run" / "results"
CRAPI_LAB: str = "crapi-kong"
_INCONCLUSIVE: str = "INCONCLUSIVE"
# The verdicts, in the order a challenge is checked against them, and the two declared ones.
CAUGHT, NAMED, ATTEMPTED, MISSED = "caught", "named, not exploited", "attempted", "missed"
OUT_OF_SCOPE, ABSENT = "out of scope", "absent from the lab"
_MEASURED: tuple[str, ...] = (CAUGHT, NAMED, ATTEMPTED, MISSED)


class Rule(BaseModel):
    """What in a test's results shows the challenge: a finding naming its endpoint, or a case."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    test: str
    finding_matches: str | None = Field(
        default=None,
        description="A regular expression a finding's title matches (its endpoint); '' any.",
    )
    detail: str | None = Field(default=None, description="A case's detail recorded by the test.")

    @model_validator(mode="after")
    def one_kind(self) -> Rule:
        """A rule reads a finding or a case, not both."""
        if (self.finding_matches is None) == (self.detail is None):
            raise ValueError(f"rule on {self.test}: give finding_matches or detail, one of them")
        return self


class Challenge(BaseModel):
    """One challenge crAPI publishes, and how it is read."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    number: int
    title: str
    category: str
    caught_by: list[Rule] = Field(default_factory=list)
    named_by: list[Rule] = Field(default_factory=list)
    out_of_scope: str | None = None
    absent: str | None = None

    @model_validator(mode="after")
    def measured_or_declared(self) -> Challenge:
        """A challenge has rules, or a reason it is not measured: never both."""
        declared = self.out_of_scope is not None or self.absent is not None
        if declared == bool(self.caught_by):
            raise ValueError(f"challenge {self.number}: rules (caught_by) or a reason, one of them")
        return self


def load_challenges() -> tuple[str, list[Challenge]]:
    """The source of the list and its challenges."""
    data = yaml.safe_load(CHALLENGES_FILE.read_text(encoding="utf-8"))
    return str(data["source"]), [Challenge.model_validate(c) for c in data["challenges"]]


def _matches(rule: Rule, tests: dict[str, Any]) -> list[str]:
    """What of the test's results the rule finds: finding titles, or the case's detail."""
    test = tests.get(rule.test)
    if test is None:
        return []
    if rule.finding_matches is not None:
        pattern = re.compile(rule.finding_matches)
        return [f["title"] for f in test["findings"] if pattern.search(f["title"])]
    cases = [case for sub in test["cases"].values() for case in sub]
    return [f"{rule.test} {case['detail']}" for case in cases if case["detail"] == rule.detail]


def judge(challenge: Challenge, tests: dict[str, Any]) -> dict[str, Any]:
    """The verdict on one challenge, and what shows it."""
    if challenge.absent is not None:
        return {"verdict": ABSENT, "evidence": challenge.absent}
    if challenge.out_of_scope is not None:
        return {"verdict": OUT_OF_SCOPE, "evidence": challenge.out_of_scope}
    for verdict, rules in ((CAUGHT, challenge.caught_by), (NAMED, challenge.named_by)):
        found = [item for rule in rules for item in _matches(rule, tests)]
        if found:
            return {"verdict": verdict, "evidence": "; ".join(dict.fromkeys(found))}
    tried = sorted(
        {
            r.test
            for r in challenge.caught_by
            if tests.get(r.test, {}).get("status") == _INCONCLUSIVE
        }
    )
    if tried:
        return {"verdict": ATTEMPTED, "evidence": f"{', '.join(tried)} could not decide"}
    statuses = ", ".join(
        f"{r.test} {tests[r.test]['status'] if r.test in tests else 'not run'}"
        for r in challenge.caught_by
    )
    return {"verdict": MISSED, "evidence": f"no finding on the endpoint ({statuses})"}


def markdown(stamp: Stamp, e2: str, source: str, rows: list[dict[str, Any]]) -> str:
    """The readable result: every challenge, then the counts both ways."""
    lines = [f"# E3, crAPI challenges, {stamp.meta['date']}", "", header(stamp), ""]
    lines += [
        f"The challenges are crAPI's ({source}); the run is E2's on {CRAPI_LAB} (`{e2}`).",
        "",
        "| # | Challenge (crAPI's category) | Verdict | What shows it |",
        "|---|---|---|---|",
    ]
    lines += [
        f"| {r['number']} | {r['title']} ({r['category']}) | **{r['verdict']}** | {r['evidence']} |"
        for r in rows
    ]
    in_scope = [r for r in rows if r["verdict"] in _MEASURED]
    lines += ["", "| Verdict | Of all | Of those in the lab |", "|---|---|---|"]
    for verdict in (*_MEASURED, OUT_OF_SCOPE, ABSENT):
        count = sum(1 for r in rows if r["verdict"] == verdict)
        if not count and verdict not in _MEASURED:
            continue
        scoped = f"{count} of {len(in_scope)}" if verdict in _MEASURED else "-"
        lines.append(f"| {verdict} | {count} of {len(rows)} | {scoped} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    """Read E2's crAPI run, judge every challenge, write the result."""
    e2_file = latest(E2_RESULTS)
    if e2_file is None:
        console.print("[red]No E2 result: run hatch run dev:e2-complete-run first.[/red]")
        return 2
    e2 = json.loads(e2_file.read_text(encoding="utf-8"))
    crapi = e2["labs"].get(CRAPI_LAB)
    if crapi is None or crapi["no_report"]:
        console.print(f"[red]{e2_file.name} has no run of {CRAPI_LAB}.[/red]")
        return 2
    # The result is a campaign only when E2's is one, on the same commit.
    stamp = start(partial=bool(e2["meta"]["partial"]) or e2["meta"]["dirty"])
    source, challenges = load_challenges()
    rows = [
        {"number": c.number, "title": c.title, "category": c.category, **judge(c, crapi["tests"])}
        for c in challenges
    ]
    payload = {"e2": e2_file.name, "source": source, "challenges": rows}
    path = write_result(RESULTS_DIR, stamp, payload, markdown(stamp, e2_file.stem, source, rows))
    for row in rows:
        console.print(f"  {row['number']:>2} {row['verdict']}", highlight=False)
    console.print(f"Result: {path.relative_to(ROOT)}", highlight=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
