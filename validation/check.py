"""
validation/check.py

The alignment check, run by dev:check (README.md): every case file holds
exactly the cases the code declares, with the fields copied from the code
equal to it; every case filled in names a lab and a variant that exist; no
case file belongs to a test that does not exist. Then the counts: cases
produced by a variant, not producible, still to fill.

Exit 0 when aligned, 1 otherwise; with --complete, also 1 while a case is left
to fill (the state a validation run needs).

Usage: python validation/check.py [--complete]
"""

from __future__ import annotations

import sys

from catalogue import (
    AS_BUILT,
    CASES_DIR,
    LABS,
    declared_cases,
    load_case_file,
    load_variants,
)
from rich.console import Console

console = Console()


def main() -> int:
    """Check every case file against the code; print the problems and the counts."""
    problems: list[str] = []
    declared = declared_cases()
    variants = {lab: load_variants(lab) for lab in LABS}
    produced = not_producible = to_fill = 0
    for path in sorted(CASES_DIR.glob("*.yaml")):
        if path.stem not in declared:
            problems.append(f"{path.name}: no test {path.stem} in the code")
    for test, (name, cases) in declared.items():
        case_file = load_case_file(test)
        if case_file is None:
            problems.append(f"{test}: no case file (run validation/sync.py)")
            continue
        if case_file.test != test or case_file.name != name:
            problems.append(f"{test}: the file names test {case_file.test!r} {case_file.name!r}")
        written = [entry.id for entry in case_file.cases]
        if written != [case.id for case in cases]:
            missing = sorted({c.id for c in cases} - set(written))
            extra = sorted(set(written) - {c.id for c in cases})
            problems.append(
                f"{test}: cases differ from the code (missing {missing}, not declared {extra}, or "
                "another order): run validation/sync.py"
            )
            continue
        for case, entry in zip(cases, case_file.cases, strict=True):
            copied = (entry.sub_test, entry.situation, entry.expected)
            if copied != (case.sub_test, case.situation, case.expected):
                problems.append(f"{test} {case.id}: differs from the code: run validation/sync.py")
            if entry.review:
                problems.append(f"{test} {case.id}: to review ({entry.review}): check its how")
            if entry.not_producible is not None:
                not_producible += 1
            elif entry.variant:
                produced += 1
                if entry.variant != AS_BUILT and entry.variant not in variants[entry.lab]:
                    problems.append(
                        f"{test} {case.id}: no variant {entry.variant!r} in "
                        f"variants/{entry.lab}.yaml"
                    )
            else:
                to_fill += 1
    for problem in problems:
        console.print(f"[red]error[/red] {problem}", highlight=False)
    total = produced + not_producible + to_fill
    console.print(
        f"validation cases {total}: produced by a variant {produced}, not producible "
        f"{not_producible}, to fill {to_fill}; problems {len(problems)}",
        highlight=False,
    )
    if problems:
        return 1
    return 1 if "--complete" in sys.argv and to_fill else 0


if __name__ == "__main__":
    sys.exit(main())
