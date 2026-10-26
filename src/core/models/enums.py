"""
src/core/models/enums.py

Shared enumerations for the APIGuard Assurance tool.

TestStatus, Coverage, ResponseCategory, Outcome, TransportError, Confidence,
TestStrategy, SpecDialect and NotRunReason inherit from StrEnum so their values
serialize natively to JSON strings without extra configuration. ExitCode inherits
from IntEnum: its values are process exit codes.

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
        PASS         -- No violation, and at least one case verified; complete
                        or partial (Coverage).
        FAIL         -- At least one violation. Requires a Finding.
        INCONCLUSIVE -- Run to the end, no violation and nothing verified: only
                        cases that could not be verified.
        SKIP         -- Not run (something needed to start is missing), or
                        nothing the test applies to. Not a failure.
        ERROR        -- The test broke while running. Result uncertain.

    PASS, FAIL and INCONCLUSIVE are computed from the outcomes the test
    recorded, never chosen by the test (src/core/assessment_test.py).
    """

    __test__ = False

    PASS = "PASS"  # noqa: S105
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    SKIP = "SKIP"
    ERROR = "ERROR"


class Coverage(StrEnum):
    """
    How much of what a PASS applies to was verified.

    COMPLETE -- Every applicable case was verified.
    PARTIAL  -- No violation, but some cases could not be verified (a sub-test
                INCONCLUSIVE, or not verifiable cases inside a PASS); the
                report shows it next to the status.
    """

    COMPLETE = "complete"
    PARTIAL = "partial"


class ResponseCategory(StrEnum):
    """
    What a response is, the first step of every judgement, common to all tests.

    Assigned from the HTTP status (RFC 9110 section 15 and the IANA HTTP Status
    Code registry; an unregistered code counts as the x00 of its class) by
    src/core/response_category.py; the reference responses of a run can
    correct a misleading status. Each test then says what a category means for
    its guarantee (an Outcome).

    SERVED               -- 2xx: the target served the request.
    REDIRECT             -- 300, 301, 302, 303, 305, 307, 308.
    UNAUTHENTICATED      -- 401, 407, 511: the caller is not identified.
    FORBIDDEN            -- 403: identified, but not allowed.
    NOT_FOUND            -- 404, 410: the path does not exist.
    METHOD_NOT_ALLOWED   -- 405, 501.
    INVALID_REQUEST      -- 400, 406, 409, 411-417, 421-426, 428, 431: rejected
                            because of the request's content or state.
    RATE_LIMITED         -- 429.
    SERVER_ERROR         -- 500, 505-508, 510: the application failed.
    UPSTREAM_UNAVAILABLE -- 502, 503, 504: the gateway could not reach the
                            backend, or the backend did not answer in time.
    NO_RESPONSE          -- No HTTP response: timeout, connection refused, TLS
                            error, connection reset.
    OTHER                -- Rare codes never decisive alone: 1xx, 304, 306,
                            402, 408, 418, 451.
    """

    SERVED = "SERVED"
    REDIRECT = "REDIRECT"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"
    INVALID_REQUEST = "INVALID_REQUEST"
    RATE_LIMITED = "RATE_LIMITED"
    SERVER_ERROR = "SERVER_ERROR"
    UPSTREAM_UNAVAILABLE = "UPSTREAM_UNAVAILABLE"
    NO_RESPONSE = "NO_RESPONSE"
    OTHER = "OTHER"


class Outcome(StrEnum):
    """
    What a judged case means for the guarantee, the second step of a judgement.

    Each test maps the categories to these four values in its oracle table; the
    detail next to the outcome (e.g. VIOLATION/AUTH_BYPASS) is the test's own.
    They correspond to the SARIF 2.1.0 result kinds named in brackets.

    VIOLATION      -- The guarantee is violated (fail): it becomes a Finding.
    ENFORCED       -- The guarantee holds, verified (pass).
    NOT_VERIFIABLE -- It cannot be established (open), for a reason the detail
                      states.
    NOT_APPLICABLE -- The check does not concern this case (notApplicable).
    """

    VIOLATION = "VIOLATION"
    ENFORCED = "ENFORCED"
    NOT_VERIFIABLE = "NOT_VERIFIABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class Confidence(StrEnum):
    """
    How sure the tool is that a finding is a real violation (not how serious it is).

    Each detail of a test's oracle table has its level, written on the test
    page; a test does not choose it case by case (docs/project/test-review.md,
    topic 5). Every finding states one.

    CERTAIN   -- the violation is the observed behaviour itself (a header
                 missing, a value read from the gateway configuration), or is
                 proven by a reference of the same request (a positive control).
    FIRM      -- observed directly, but its meaning rests on one stated
                 assumption (an existence only indicated by a difference from an
                 unknown sibling).
    TENTATIVE -- rests on a heuristic or an indirect sign (a keyword, a timing,
                 a candidate derived by a heuristic rule).
    """

    CERTAIN = "CERTAIN"
    FIRM = "FIRM"
    TENTATIVE = "TENTATIVE"


class TransportError(StrEnum):
    """
    Why a request got no HTTP response (its record has no status code).

    Set by src/core/client.py from the transport exception, after the retries
    (a TLS failure is not retried). The response category is NO_RESPONSE.

    TIMEOUT           -- connect, read, write or pool timeout.
    CONNECTION_FAILED -- the connection could not be opened (refused, name not
                         resolved, network unreachable).
    TLS_ERROR         -- the TLS handshake or the certificate check failed.
    PROTOCOL_ERROR    -- the server closed the connection or broke the HTTP
                         protocol before a complete response.
    """

    TIMEOUT = "timeout"
    CONNECTION_FAILED = "connection_failed"
    TLS_ERROR = "tls_error"
    PROTOCOL_ERROR = "protocol_error"


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
        "CLEAN",
        "no test returned FAIL, ERROR or INCONCLUSIVE: no violation detected (a SKIP verifies "
        "nothing)",
    ),
    ExitCode.FAIL: ExitCodeInfo("FAIL", "at least one security guarantee is violated"),
    ExitCode.USAGE: ExitCodeInfo("USAGE", "invalid invocation: the assessment did not start"),
    ExitCode.ERROR: ExitCodeInfo(
        "ERROR",
        "at least one verification did not complete (a test returned ERROR or INCONCLUSIVE) "
        "and no test returned FAIL; an ERROR result may carry findings",
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
