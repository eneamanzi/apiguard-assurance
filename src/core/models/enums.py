"""
src/core/models/enums.py

Shared enumerations for the APIGuard Assurance tool.

TestStatus, TestStrategy and SpecDialect inherit from StrEnum so their
values serialize natively to JSON strings without extra configuration.
ExitCode inherits from IntEnum: its values are process exit codes.

Dependency rule: this module imports only from the stdlib.
It must never import from any other src/ module.
"""

from __future__ import annotations

from enum import IntEnum, StrEnum


class TestStatus(StrEnum):
    """
    Possible outcomes of a single test execution.

    Inherits from str so values serialize natively to JSON strings.

    Semantic contract (docs/architecture/assessment-model.md, "Outcomes"):
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
    Process exit codes of ``apiguard run`` (docs/reference/exit-codes.md).

    The single definition of every code: the ResultSet, the engine, the CLI
    summary and the report all use these members.

        CLEAN          -- Every executed test returned PASS or SKIP.
        FAIL           -- At least one test returned FAIL.
        USAGE          -- Invalid invocation. Emitted by Typer/Click before
                          the tool starts; listed so that no other outcome
                          reuses the code.
        ERROR          -- No FAIL, at least one test returned ERROR.
        INFRASTRUCTURE -- The assessment did not run (Phases 1-4 or an
                          unexpected engine exception).

    130 (Ctrl+C) and 143 (SIGTERM) are not members: after teardown the tool
    ends by the signal itself, and the shell reports 128 + signal number.
    """

    CLEAN = 0
    FAIL = 1
    USAGE = 2
    ERROR = 3
    INFRASTRUCTURE = 10


class TestStrategy(StrEnum):
    """
    Execution privilege level mapping to the Black/Grey/White Box gradient
    defined in the methodology (docs/architecture/assessment-model.md, "Strategies").

    BLACK_BOX -- Zero credentials. Simulates anonymous external attacker.
    GREY_BOX  -- Valid JWT tokens for at least two distinct roles.
    WHITE_BOX -- Read access to Gateway configuration via Admin API.
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
