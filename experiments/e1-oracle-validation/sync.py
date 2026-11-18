"""
experiments/e1-oracle-validation/sync.py

Bring every case file in line with the code (README.md): a case the code
declares and the file lacks is added, to fill; the fields copied from the code
(sub_test, situation, expected) are refreshed, and a filled case whose
situation changed is marked `review` (dev:check fails until it is removed); a
case the code no longer declares is removed and named, with what it said (git
shows the change). The fields we write (how, lab, variant, config,
not_producible) are never touched: they say how a case is produced, which only
we know.

Usage: python experiments/e1-oracle-validation/sync.py
"""

from __future__ import annotations

import sys

from catalogue import (
    CASES_DIR,
    CaseEntry,
    CaseFile,
    case_file_path,
    declared_cases,
    dump_case_file,
    load_case_file,
)
from rich.console import Console

console = Console()


def main() -> int:
    """Write every case file from the code, keeping what was written in it."""
    CASES_DIR.mkdir(exist_ok=True)
    for test, (name, declared) in declared_cases().items():
        current = load_case_file(test)
        kept = {entry.id: entry for entry in current.cases} if current else {}
        entries: list[CaseEntry] = []
        for case in declared:
            old = kept.pop(case.id, None)
            fields = {
                "id": case.id,
                "sub_test": case.sub_test,
                "situation": case.situation,
                "expected": case.expected,
            }
            if old is None:
                entries.append(CaseEntry.model_validate(fields))
                console.print(f"added    {test} {case.id}", highlight=False)
            else:
                update: dict[str, object] = dict(fields)
                if old.filled and old.situation != case.situation:
                    update["review"] = f"the situation was: {old.situation}"
                    console.print(f"[yellow]review[/yellow]   {test} {case.id}", highlight=False)
                entries.append(old.model_copy(update=update))
        for gone in kept.values():
            console.print(
                f"[yellow]removed[/yellow]  {test} {gone.id} (it said: variant "
                f"{gone.variant or '-'}, how {gone.how or '-'})",
                highlight=False,
            )
        text = dump_case_file(CaseFile(test=test, name=name, cases=entries))
        path = case_file_path(test)
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
