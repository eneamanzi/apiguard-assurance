"""
src/core/models/enums.py

Shared enumerations for the APIGuard Assurance tool.

TestStatus, TestStrategy, SpecDialect and NotRunReason inherit from StrEnum so their
values serialize natively to JSON strings without extra configuration.
ExitCode inherits from IntEnum: its values are process exit codes.

Dependency rule: this module imports only from the stdlib.
It must never import from any other src/ module.
"""

from __future__ import annotations

import signal
from dataclasses import dataclass
from enum import IntEnum, StrEnum


class TestStatus(StrEnum):
    """
    Possible outcomes of a single test execution.

    Inherits from str so values serialize natively to JSON strings.

    Semantic contract (docs/04-architecture/03-assessment-model.md, "Outcomes"):
        PASS  -- Control executed, security guarantee satisfied.
        FAIL  -- Control executed, guarantee NOT satisfied. Requires a Finding.
        SKIP  -- Not executed for an explicit, documented reason. Not a failure.
        ERROR -- Unexpected exception. Result uncertain, requires investigation.
    """

    __test__ = False

    PASS = "PASS"  # noqa: S105
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"


class ExitCode(IntEnum):
    """
    Process exit codes of ``apiguard run`` (docs/03-reference/03-exit-codes.md).

    The single definition of every code: the ResultSet, the engine, the CLI
    summary and the report all use these members. What each code means is in
    EXIT_CODES below, the one text of the report, the console, `run --help`
    and docs/03-reference/03-exit-codes.md. USAGE is emitted by Typer before the
    tool starts; it is listed so that no other outcome reuses the code.

    130 (Ctrl+C) and 143 (SIGTERM) are not members: after teardown the tool
    ends by the signal itself, and the shell reports 128 + signal number.
    """

    CLEAN = 0
    FAIL = 1
    USAGE = 2
    ERROR = 3
    INFRASTRUCTURE = 10


@dataclass(frozen=True)
class ExitCodeInfo:
    """What an exit code of ``apiguard run`` says: a label and its meaning."""

    label: str
    meaning: str


# How the shell reports a process ended by a signal: 128 + the signal number.
SIGNAL_EXIT_BASE: int = 128

# Every exit code of `apiguard run`, the ExitCode members and the two stop
# signals, with its label and meaning: the one text of every output.
EXIT_CODES: dict[int, ExitCodeInfo] = {
    ExitCode.CLEAN: ExitCodeInfo(
        "CLEAN", "no test returned FAIL or ERROR: no violation detected (a SKIP verifies nothing)"
    ),
    ExitCode.FAIL: ExitCodeInfo("FAIL", "at least one security guarantee is violated"),
    ExitCode.USAGE: ExitCodeInfo("USAGE", "invalid invocation: the assessment did not start"),
    ExitCode.ERROR: ExitCodeInfo(
        "ERROR",
        "at least one verification did not complete and no test returned FAIL; an ERROR "
        "result may carry findings",
    ),
    ExitCode.INFRASTRUCTURE: ExitCodeInfo(
        "INFRA", "the assessment did not run or did not complete: no security verdict"
    ),
    SIGNAL_EXIT_BASE + signal.SIGINT: ExitCodeInfo(
        "INTERRUPTED",
        "stopped by Ctrl+C: teardown removes the resources created on the target, no report",
    ),
    SIGNAL_EXIT_BASE + signal.SIGTERM: ExitCodeInfo(
        "TERMINATED",
        "stopped by SIGTERM: teardown removes the resources created on the target, no report",
    ),
}


def exit_code_text(code: int) -> str:
    """
    The text of an exit code: 'FAIL - at least one test returned FAIL: ...'.

    Args:
        code: The exit code.

    Returns:
        Its label and meaning, or 'exit code N' for a code the tool does not use.
    """
    info = EXIT_CODES.get(code)
    return f"{info.label} - {info.meaning}" if info is not None else f"exit code {code}"


class NotRunReason(StrEnum):
    """
    Why a test of the tool was not executed in a run (report section not_run).

    A test that is not run is not a SKIP: SKIP means selected but something
    was missing; these are deliberate exclusions or a stop of the run.

        PRIORITY        -- its priority is above execution.min_priority.
        STRATEGY        -- its strategy is not in execution.strategies.
        NOT_IN_TEST_IDS -- execution.test_ids is set and does not list it.
        TOOL_DISABLED   -- an external test whose tool is disabled
                           (external_tools.enabled or the per-tool switch).
        FAIL_FAST       -- selected, but the run stopped earlier because of
                           execution.fail_fast.
    """

    PRIORITY = "priority"
    STRATEGY = "strategy"
    NOT_IN_TEST_IDS = "not_in_test_ids"
    TOOL_DISABLED = "tool_disabled"
    FAIL_FAST = "fail_fast"


class TestStrategy(StrEnum):
    """
    What the tester has, to run a test (docs/04-architecture/03-assessment-model.md,
    "Strategies"). A test is labelled with the access it needs to run in full.

    BLACK_BOX -- An external user: network access and the OpenAPI
                 specification only, no credentials.
    GREY_BOX  -- A normal user: credentials of an ordinary account of the API
                 (how many accounts is not the point).
    WHITE_BOX -- A super user: the API's administrator account, or internal
                 access (gateway configuration through the Admin API, files,
                 internal systems).
    """

    __test__ = False

    BLACK_BOX = "BLACK_BOX"
    GREY_BOX = "GREY_BOX"
    WHITE_BOX = "WHITE_BOX"


class SpecDialect(StrEnum):
    """
    Detected dialect of the API specification source document.

    SWAGGER_2 -- Swagger 2.0 (top-level ``swagger: "2.0"`` key).
    OPENAPI_3 -- OpenAPI 3.x (top-level ``openapi: "3.x"`` key).
    """

    SWAGGER_2 = "swagger_2"
    OPENAPI_3 = "openapi_3"
