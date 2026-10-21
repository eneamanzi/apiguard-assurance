"""
src/cli_console.py

The console interface of ``apiguard run`` (log format ``console``).

ConsoleObserver implements engine.RunObserver: the engine reports the
progress of the run (plan, each test, cleanup, end, or why it stopped) and
this module prints it for a person: a header, one line per test with its
findings grouped by kind, the cleanup, and a summary with the paths of the
reports, or the reason of a run that stopped (exit 10). The technical log
(``--log-level``) is printed through the same rich Console, so that it never
breaks the line of the test in progress.

The interface is always shown in console mode; ``--log-level`` only decides
how much technical log appears below it. In JSON mode there is no interface.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from src.connectors.base import BaseSubprocessConnector
from src.core.models import Coverage, ExitCode, ResultSet, TestResult, TestStatus
from src.core.models.enums import exit_code_text

if TYPE_CHECKING:
    # Type only: importing the engine here would load the whole tool for every
    # command (apiguard version included).
    from src.engine import RunPlan

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Width of the test name column; longer names are cut with an ellipsis.
TEST_NAME_WIDTH: int = 52
# Width of the test ID column when the run did not report its plan; normally
# the column is as wide as the longest selected test ID.
DEFAULT_TEST_ID_WIDTH: int = 16
# Width of the "<n> findings" column (two spaces and 12 characters).
FINDINGS_COLUMN_WIDTH: int = 14
# Kinds of finding listed under a FAILed test (by title, most frequent first).
MAX_FINDING_KINDS: int = 5
# Characters of a SKIP reason or ERROR message shown on the test line.
MAX_REASON_LENGTH: int = 90
ELLIPSIS: str = "…"

# Style of each status and of each exit code.
STATUS_STYLES: dict[str, str] = {
    TestStatus.PASS: "green",
    TestStatus.FAIL: "bold red",
    TestStatus.INCONCLUSIVE: "bold yellow",
    TestStatus.SKIP: "yellow",
    TestStatus.ERROR: "bold magenta",
}
# Width of the status column: the longest status (INCONCLUSIVE).
STATUS_WIDTH: int = max(len(status.value) for status in TestStatus)
# Shown after a PASS whose coverage is partial (some cases not verifiable).
PARTIAL_LABEL: str = "partial"
# Colour of the exit code line; its text is exit_code_text (src/core/models/enums.py).
EXIT_STYLES: dict[int, str] = {
    ExitCode.CLEAN: "green",
    ExitCode.FAIL: "bold red",
    ExitCode.ERROR: "bold magenta",
    ExitCode.INFRASTRUCTURE: "yellow",
}
# Labels of the section headings in the final summary (aligned).
_HEADING_WIDTH: int = 10


def _cut(text: str, width: int) -> str:
    """Return text cut to width characters, ending with an ellipsis if cut."""
    return text if len(text) <= width else text[: width - len(ELLIPSIS)] + ELLIPSIS


def _first_sentence(text: str) -> str:
    """Return the first sentence of text (up to '. '), cut to MAX_REASON_LENGTH."""
    sentence = text.split(". ", 1)[0].strip()
    return _cut(sentence, MAX_REASON_LENGTH)


def _plural(count: int, word: str) -> str:
    """Return '<count> <word>' with an 's' unless count is 1."""
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


class ConsoleObserver:
    """
    Prints the progress of a run for a person (implements engine.RunObserver).

    On a terminal, the test in progress is shown on a line that updates in
    place with the elapsed time; elsewhere (output redirected to a file), a
    test with a time limit (an external tool) prints a "running" line first.
    """

    def __init__(self, console: Console, show_header: bool, tool_version: str) -> None:
        """
        Prepare the observer.

        Args:
            console:      The rich Console shared with the technical log.
            show_header:  Print the header and the final summary (--banner).
            tool_version: Version shown in the header.
        """
        self._console = console
        self._show_header = show_header
        self._tool_version = tool_version
        self._progress: Progress | None = None
        self._cleanup: tuple[int, int] | None = None
        self._id_width: int = DEFAULT_TEST_ID_WIDTH
        self._stop_reason: str | None = None
        self.finished: bool = False

    # ------------------------------------------------------------------
    # RunObserver
    # ------------------------------------------------------------------

    def run_planned(self, plan: RunPlan) -> None:
        """Print the header: target, specification, selection."""
        if plan.selected_ids:
            self._id_width = max(len(test_id) for test_id in plan.selected_ids) + 1
        if not self._show_header:
            return
        if plan.test_ids:
            scope = f"test_ids {', '.join(plan.test_ids)}"
        else:
            scope = f"min priority P{plan.min_priority} · {', '.join(plan.strategies)}"
        not_run = ""
        if plan.not_run:
            reasons = Counter(entry.reason.value for entry in plan.not_run).most_common()
            if len(reasons) == 1:
                detail = reasons[0][0]
            else:
                detail = ", ".join(f"{reason} {count}" for reason, count in reasons)
            not_run = f" · {len(plan.not_run)} not run ({detail})"
        self._console.print(Text(f"APIGuard Assurance {self._tool_version}", style="bold"))
        self._heading(
            "Target",
            f"{plan.target_url} · {plan.spec_title} {plan.spec_version} "
            f"({_plural(plan.endpoint_count, 'endpoint')})",
        )
        self._heading("Selection", f"{_plural(len(plan.selected_ids), 'test')} ({scope}){not_run}")
        self._console.print()

    def test_started(
        self, position: int, total: int, test_id: str, test_name: str, timeout_seconds: int | None
    ) -> None:
        """Show the test in progress (live elapsed time on a terminal)."""
        label = self._test_label(position, total, test_id, test_name)
        limit = f"(limit {timeout_seconds}s)" if timeout_seconds is not None else ""
        if self._console.is_terminal:
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn(f"{label} running"),
                TimeElapsedColumn(),
                TextColumn(limit),
                console=self._console,
                transient=True,
            )
            self._progress.add_task("test", total=None)
            self._progress.start()
        elif timeout_seconds is not None:
            self._console.print(f"{label} running {limit}")

    def test_finished(self, position: int, total: int, result: TestResult) -> None:
        """
        Print the test line and what follows it.

        FAIL: the finding count, then the findings grouped by kind. PASS: "partial"
        when some cases were not verifiable, with the summary of the judgements.
        INCONCLUSIVE: the summary (why nothing could be verified). SKIP: the
        reason. ERROR: the message.
        """
        self.stop_live()
        line = Text(self._test_label(position, total, result.test_id, result.test_name) + " ")
        line.append(
            f"{result.status.value:<{STATUS_WIDTH}}", style=STATUS_STYLES.get(result.status, "")
        )
        findings = result.findings
        partial = result.coverage == Coverage.PARTIAL
        timed = result.duration_ms is not None and result.status in (
            TestStatus.PASS,
            TestStatus.FAIL,
            TestStatus.INCONCLUSIVE,
        )
        if result.status == TestStatus.FAIL:
            line.append(f"  {_plural(len(findings), 'finding'):<12}")
        elif partial:
            line.append(f"  {PARTIAL_LABEL:<12}", style="yellow")
        elif timed:
            line.append(" " * FINDINGS_COLUMN_WIDTH)
        if timed and result.duration_ms is not None:
            line.append(f"{result.duration_ms / 1000:.1f}s", style="dim")
        self._console.print(line)
        indent = " " * (len(self._counter(position, total)) + 1 + self._id_width)
        # SKIP, ERROR, INCONCLUSIVE, partial PASS: the reason on the next line
        # (first sentence).
        reason = result.skip_reason if result.status == TestStatus.SKIP else None
        if result.status in (TestStatus.ERROR, TestStatus.INCONCLUSIVE) or partial:
            reason = result.message
        if reason:
            self._console.print(Text(f"{indent}{_first_sentence(reason)}", style="dim"))
        kinds = Counter(finding.title for finding in findings).most_common()
        for title, count in kinds[:MAX_FINDING_KINDS]:
            self._console.print(Text(f"{indent}{count:>3} × {title}", style="red"))
        hidden = len(kinds) - MAX_FINDING_KINDS
        if hidden > 0:
            self._console.print(
                Text(f"{indent}    … and {hidden} more kinds (see the report)", style="dim")
            )

    def stop_live(self) -> None:
        """Stop the live line of the test in progress (on an interruption)."""
        if self._progress is not None:
            self._progress.stop()
            self._progress = None

    def cleanup_started(self) -> None:
        """Stop the live line: on an interruption the cleanup messages follow."""
        self.stop_live()

    def cleanup_finished(self, removed: int, failed: int) -> None:
        """Remember the cleanup counts for the summary."""
        self._cleanup = (removed, failed)

    def run_finished(self, result_set: ResultSet, exit_code: int, report_paths: list[Path]) -> None:
        """Print the summary: cleanup, results, exit code, reports."""
        self.finished = True
        if not self._show_header:
            return
        self._console.print()
        if self._cleanup is not None:
            removed, failed = self._cleanup
            if failed:
                self._heading(
                    "Cleanup",
                    f"{failed} of {removed + failed} resources NOT removed from the target: "
                    "remove them by hand (log event teardown_resource_deletion_failed)",
                    style="bold red",
                )
            elif removed:
                self._heading("Cleanup", f"{_plural(removed, 'resource')} removed from the target")
        findings = sum(len(r.findings) for r in result_set.results)
        duration = result_set.duration_seconds
        parts = [
            f"{result_set.pass_count} passed",
            f"{result_set.fail_count} failed",
            f"{result_set.inconclusive_count} inconclusive",
            f"{result_set.skip_count} skipped",
            f"{result_set.error_count} errors",
            f"{len(result_set.not_run)} not run",
            _plural(findings, "finding"),
        ]
        if duration is not None:
            parts.append(f"{duration:.1f}s")
        self._heading("Result", " · ".join(parts))
        self.print_exit(exit_code)
        if report_paths:
            for index, path in enumerate(report_paths):
                note = "   (open in a browser)" if path.suffix == ".html" else ""
                display = BaseSubprocessConnector._relativize_display_path(str(path))  # noqa: SLF001
                self._heading("Reports" if index == 0 else "", display + note)
            self._heading("", "Every finding, request and response is in the reports.", "dim")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def run_stopped(self, reason: str) -> None:
        """Remember why the run stopped: printed in full under the exit code line."""
        self._stop_reason = reason

    def print_exit(self, exit_code: int) -> None:
        """
        Print the exit code line (also used when the run did not start).

        When the run stopped (exit 10), the reason follows in full, wrapped
        under the text column: the technical log cuts long values.
        """
        style = EXIT_STYLES.get(exit_code, "white")
        self._heading(f"Exit {exit_code}", exit_code_text(exit_code), style)
        if self._stop_reason is not None:
            grid = Table.grid()
            grid.add_column(width=_HEADING_WIDTH, style="bold", no_wrap=True)
            grid.add_column(overflow="fold")
            grid.add_row("Reason", Text(self._stop_reason))
            self._console.print(grid)

    def _heading(self, heading: str, text: str, style: str = "") -> None:
        """Print one summary line: an aligned heading, then the text."""
        line = Text(f"{heading:<{_HEADING_WIDTH}}", style="bold")
        line.append(text, style=style)
        self._console.print(line)

    @staticmethod
    def _counter(position: int, total: int) -> str:
        """Return '[ 4/15]': the position padded to the width of the total."""
        return f"[{position:>{len(str(total))}}/{total}]"

    def _test_label(self, position: int, total: int, test_id: str, test_name: str) -> str:
        """Return '[ 4/15] 1.1  Only Authenticated ...' with aligned columns."""
        name = _cut(test_name, TEST_NAME_WIDTH)
        return (
            f"{self._counter(position, total)} {test_id:<{self._id_width}}{name:<{TEST_NAME_WIDTH}}"
        )


def make_console() -> Console:
    """
    Return the Console for the interface and the technical log.

    Colours and live updates only on a terminal (rich decides); NO_COLOR is
    honoured by rich itself.
    """
    return Console(highlight=False, soft_wrap=True, emoji=False)
