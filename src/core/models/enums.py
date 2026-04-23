"""
src/core/models/enums.py

Shared enumerations for the APIGuard Assurance tool.

All three enums inherit from StrEnum so their values serialize natively
to JSON strings without extra configuration.

Dependency rule: this module imports only from the stdlib.
It must never import from any other src/ module.
"""

from __future__ import annotations

from enum import StrEnum


class TestStatus(StrEnum):
    """
    Possible outcomes of a single test execution.

    Inherits from str so values serialize natively to JSON strings.

    Semantic contract (Implementazione.md, Section 4.6):
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


class TestStrategy(StrEnum):
    """
    Execution privilege level mapping to the Black/Grey/White Box gradient
    defined in the methodology (3_TOP_metodologia.md).

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
