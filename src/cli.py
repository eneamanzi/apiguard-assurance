"""
src/cli.py

Command-line interface entry point for the APIGuard Assurance tool.

This module is the boundary between the external world (shell, CI/CD pipeline,
interactive terminal) and the tool's assessment engine. Its responsibilities
are strictly limited to:

    1. Defining the CLI interface via Typer (arguments, options, help text).
    2. Configuring the structlog logging pipeline before any other operation.
    3. Instantiating AssessmentEngine with the parsed configuration path.
    4. Translating the engine's integer exit code into sys.exit().

No business logic, no domain knowledge, and no assessment logic lives here.
If a behavior is not directly related to argument parsing or process-level
setup, it belongs in engine.py or a dedicated module.

Entry point registration (pyproject.toml):
    [project.scripts]
    apiguard = "src.cli:app"

After `pip install -e .`, the tool is invoked as:
    apiguard run [OPTIONS]
    apiguard run --config path/to/config.yaml
    apiguard run --config config.yaml --log-format json --log-level debug

Dependency rule:
    This module imports from stdlib, typer, rich, structlog, and
    src.engine only. It must never import from core/, config/, discovery/,
    tests/, or report/ directly — all orchestration is delegated to engine.py.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated, TextIO

import structlog
import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from src import __version__
from src.cli_console import make_console
from src.connectors.base import BaseSubprocessConnector

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Tool metadata displayed in CLI help and startup banner.
# TOOL_VERSION is sourced from pyproject.toml via importlib.metadata
# (single source of truth -- see src/__init__.py).
TOOL_NAME: str = "APIGuard Assurance"
TOOL_VERSION: str = __version__
# Exit code of a command line used wrongly (as typer's own usage errors).
_EXIT_USAGE: int = 2
# File loaded from the current working directory when --env-file is not given.
DEFAULT_ENV_FILENAME: str = ".env"

TOOL_DESCRIPTION: str = (
    "Automated security assessment tool for REST APIs in Cloud environments. "
    "Executes the APIGuard methodology (8 domains, 29 guarantees) against "
    "any API Gateway protecting a REST API documented with OpenAPI 3.x."
)

# Default paths, relative to the working directory.
DEFAULT_CONFIG_PATH: Path = Path("config.yaml")
DEFAULT_LOG_LEVEL: str = "warning"

# Console format of the technical log of `run`: short local time, and values
# cut to this length so that each event stays on one line (JSON keeps all).
CONSOLE_LOG_TIME_FORMAT: str = "%H:%M:%S"
CONSOLE_LOG_MAX_VALUE_LENGTH: int = 160

# Rich console instances: stdout for normal output, stderr for errors.
# Using stderr for errors ensures that structured log output piped to a
# file is not contaminated by error messages.
_console_out: Console = Console(stderr=False)
_console_err: Console = Console(stderr=True)


# ---------------------------------------------------------------------------
# Enumerations for CLI options
# ---------------------------------------------------------------------------


class LogFormat(StrEnum):
    """
    Log output format selector.

    CONSOLE: human-readable, colorized output for interactive terminal use.
             Produced by structlog's ConsoleRenderer.
    JSON:    machine-readable JSON output for CI/CD pipelines and log aggregators.
             One JSON object per line, compatible with Elasticsearch, Splunk,
             Datadog, and similar systems.
    """

    CONSOLE = "console"
    JSON = "json"


class LogLevel(StrEnum):
    """
    Logging verbosity level selector.

    Maps directly to Python's stdlib logging levels. The tool uses structlog
    bound to the stdlib backend, so these levels control both structlog and
    any third-party library that uses stdlib logging (e.g., httpx, prance).
    """

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Typer application
# ---------------------------------------------------------------------------

app: typer.Typer = typer.Typer(
    name="apiguard",
    help=TOOL_DESCRIPTION,
    add_completion=False,
    rich_markup_mode="rich",
    no_args_is_help=True,
)


# ---------------------------------------------------------------------------
# Stop signals (Ctrl+C, SIGTERM)
# ---------------------------------------------------------------------------


class _TerminationRequestedError(BaseException):
    """
    Raised in the main thread when the process receives SIGTERM during a run.

    The SIGTERM counterpart of KeyboardInterrupt (raised for Ctrl+C by the
    same handler, _handle_stop_signal).

    A BaseException, like KeyboardInterrupt (Ctrl+C), so that no
    ``except Exception`` in the tool or in a test can swallow it: it unwinds
    through the engine's try/finally, which runs Phase 6 (teardown), and is
    caught only by run_assessment(). Without it, Python's default SIGTERM
    action ends the process at once and the resources created on the target
    are left behind.
    """


# Messages written by the stop-signal handlers. Written with os.write() on
# stderr, not through logging: a signal can arrive while the logger holds its
# lock, and logging again from the handler would deadlock.
_STOP_MESSAGES: dict[int, bytes] = {
    signal.SIGINT: (
        b"\nCtrl+C received: stopping the assessment and removing the resources "
        b"created on the target. Please wait.\n"
    ),
    signal.SIGTERM: (
        b"\nSIGTERM received: stopping the assessment and removing the resources "
        b"created on the target. Please wait.\n"
    ),
}
_STOP_REPEAT_MESSAGE: bytes = b"Still removing the resources created on the target. Please wait.\n"

# Signals that stop a run: Ctrl+C (SIGINT) and SIGTERM, handled alike.
_STOP_SIGNALS: tuple[signal.Signals, ...] = (signal.SIGINT, signal.SIGTERM)


def _install_stop_handlers() -> None:
    """
    Install _handle_stop_signal for Ctrl+C (SIGINT) and SIGTERM.

    Called by run_assessment() only, so the other commands keep Python's
    default behaviour.
    """
    for stop_signal in _STOP_SIGNALS:
        signal.signal(stop_signal, _handle_stop_signal)


def _handle_stop_signal(signum: int, _frame: object) -> None:
    """
    Handler for the first Ctrl+C or SIGTERM of a run.

    Says on stderr that the tool is cleaning up, replaces the handlers of
    both signals with _handle_repeated_stop_signal (so that no further
    signal, of either kind, interrupts the teardown), then raises in the
    main thread: KeyboardInterrupt for Ctrl+C, _TerminationRequestedError
    for SIGTERM. Both unwind through the engine's try/finally, which runs
    Phase 6 (teardown); run_assessment() then calls _exit_by_signal().

    Args:
        signum: The signal number (SIGINT or SIGTERM).
        _frame: The interrupted stack frame (unused).

    Raises:
        KeyboardInterrupt: For SIGINT.
        _TerminationRequestedError: For SIGTERM.
    """
    for stop_signal in _STOP_SIGNALS:
        signal.signal(stop_signal, _handle_repeated_stop_signal)
    os.write(sys.stderr.fileno(), _STOP_MESSAGES[signum])
    if signum == signal.SIGINT:
        raise KeyboardInterrupt
    raise _TerminationRequestedError(signum)


def _exit_by_signal(stop_signal: signal.Signals) -> None:
    """
    End the process by stop_signal, after teardown.

    Ignores every stop signal from now on, flushes stdout and stderr, then
    restores the default action of stop_signal and sends it to this process.
    The exit status therefore depends only on the first signal received, and
    the caller sees a process ended by SIGINT (130) or SIGTERM (143), as if
    the signal had not been handled (Python does the same for an uncaught
    KeyboardInterrupt).

    Args:
        stop_signal: The first signal received (SIGINT or SIGTERM).
    """
    for each_signal in _STOP_SIGNALS:
        signal.signal(each_signal, signal.SIG_IGN)
    sys.stdout.flush()
    sys.stderr.flush()
    signal.signal(stop_signal, signal.SIG_DFL)
    os.kill(os.getpid(), stop_signal)


def _handle_repeated_stop_signal(_signum: int, _frame: object) -> None:
    """
    Handler for any Ctrl+C or SIGTERM after the first: the cleanup goes on.

    Does not raise, so the teardown in progress is not interrupted; only
    says on stderr that the tool is still working. (SIGKILL cannot be
    handled and still ends the process at once.)

    Args:
        _signum: The signal number (unused).
        _frame:  The interrupted stack frame (unused).
    """
    os.write(sys.stderr.fileno(), _STOP_REPEAT_MESSAGE)


# ---------------------------------------------------------------------------
# Shared options
# ---------------------------------------------------------------------------

# --env-file, shared by the commands that load config.yaml. exists=True: a
# path that is not an existing file is an invalid invocation (exit 2).
EnvFileOption = Annotated[
    Path | None,
    typer.Option(
        "--env-file",
        help=(
            "Load environment variables from this file instead of "
            f"'{DEFAULT_ENV_FILENAME}' in the current working directory. "
            "Variables already set in the environment take precedence."
        ),
        exists=True,
        file_okay=True,
        dir_okay=False,
        resolve_path=True,
    ),
]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command(name="run")
def run_assessment(
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            "-c",
            help=(
                "Path to the config.yaml configuration file. "
                "Environment variables referenced as ${VAR_NAME} in the file "
                "must be exported before invoking this command."
            ),
            exists=False,
            file_okay=True,
            dir_okay=False,
            resolve_path=True,
        ),
    ] = DEFAULT_CONFIG_PATH,
    log_format: Annotated[
        LogFormat,
        typer.Option(
            "--log-format",
            help=(
                "Log output format. "
                "'console' produces human-readable colorized output (default). "
                "'json' produces one JSON object per line for log aggregators."
            ),
            case_sensitive=False,
        ),
    ] = LogFormat.CONSOLE,
    log_level: Annotated[
        LogLevel,
        typer.Option(
            "--log-level",
            help=(
                "Level of the technical log shown below the progress output. "
                "'warning' (default): only problems. 'info': also the steps of the run "
                "and each test result. 'debug': also every HTTP transaction. "
                "'error': only failures of the tool."
            ),
            case_sensitive=False,
        ),
    ] = LogLevel.WARNING,
    show_banner: Annotated[
        bool,
        typer.Option(
            "--banner/--no-banner",
            help=(
                "Show or suppress the header and the final summary (console format). Default: show."
            ),
        ),
    ] = True,
    env_file: EnvFileOption = None,
) -> None:
    """
    Run the API security assessment against the configured target.

    Reads target configuration from CONFIG (default: config.yaml in the
    current working directory). Credentials must be provided via environment
    variables referenced in config.yaml as ${VAR_NAME} placeholders: exported
    in the environment, or in a .env file (the one in the current working
    directory, or the file given with --env-file).

    Exit codes:
        0   All tests passed or skipped. No violations detected.
        1   At least one FAIL. A security guarantee was violated.
        2   Invalid invocation (unknown option or command). Nothing ran.
        3   At least one ERROR (no FAIL). A verification was incomplete.
        10  Infrastructure error. Assessment did not start or complete.
        130 Interrupted by Ctrl+C: teardown ran, no report.
        143 Terminated by SIGTERM: teardown ran, no report.

    Examples:

        # Run all tests with default config
        apiguard run

        # Run with explicit config path and JSON logging for CI
        apiguard run --config /etc/apiguard/config.yaml --log-format json

        # Debug mode with verbose output
        apiguard run --log-level debug

        # Suppress startup banner (useful in scripts)
        apiguard run --no-banner --log-format json
    """
    # Step 1: configure logging before any other operation. In console format
    # the interface and the technical log share one rich Console.
    console = make_console()
    _configure_logging(
        log_format=log_format,
        log_level=log_level,
        console=console if log_format == LogFormat.CONSOLE else None,
    )
    _load_env_file(env_file)

    # Step 2: import engine here (after logging is configured) so that
    # any module-level structlog calls in engine.py use the configured pipeline.
    from src.cli_console import ConsoleObserver
    from src.engine import AssessmentEngine

    # Step 3: the console interface (header, one line per test, summary).
    observer = (
        ConsoleObserver(console, show_header=show_banner, tool_version=TOOL_VERSION)
        if log_format == LogFormat.CONSOLE
        else None
    )
    engine = AssessmentEngine(config_path=config, observer=observer)

    # Step 4: run the assessment pipeline. Ctrl+C and SIGTERM are handled
    # alike: the first one unwinds through the engine so that teardown
    # (Phase 6) runs, later ones only say that cleanup is in progress; then
    # the process ends by the first signal (exit 130 or 143).
    _install_stop_handlers()
    try:
        exit_code = engine.run()
    except (KeyboardInterrupt, _TerminationRequestedError) as exc:
        if observer is not None:
            observer.stop_live()
        stop_signal = signal.SIGINT if isinstance(exc, KeyboardInterrupt) else signal.SIGTERM
        structlog.get_logger("cli.run").warning(
            "assessment_interrupted",
            signal=stop_signal.name,
            detail="Teardown ran; no report was written.",
        )
        _exit_by_signal(stop_signal)

    # Step 5: a run that did not start (exit 10) has no summary: show the code.
    if observer is not None and not observer.finished and show_banner:
        observer.print_exit(exit_code)

    # Step 6: exit with the engine's exit code.
    # raise typer.Exit(code=exit_code) is the Typer-idiomatic way to set
    # the process exit code without triggering Typer's exception handling.
    raise typer.Exit(code=exit_code)


@app.command(name="version")
def show_version() -> None:
    """
    Display the tool version and exit.
    """
    _console_out.print(f"[bold]{TOOL_NAME}[/bold] version [cyan]{TOOL_VERSION}[/cyan]")
    raise typer.Exit(code=0)


@app.command(name="validate-config")
def validate_config(
    config: Annotated[
        Path,
        typer.Option(
            "--config",
            "-c",
            help="Path to the config.yaml file to validate.",
            exists=False,
            file_okay=True,
            dir_okay=False,
            resolve_path=True,
        ),
    ] = DEFAULT_CONFIG_PATH,
    log_format: Annotated[
        LogFormat,
        typer.Option(
            "--log-format",
            help="Log output format.",
            case_sensitive=False,
        ),
    ] = LogFormat.CONSOLE,
    env_file: EnvFileOption = None,
    show_config: Annotated[
        bool,
        typer.Option(
            "--show-config",
            help=(
                "Print on stdout the configuration a run would use (config_used.yaml): every "
                "key, specified or default. The other messages go to stderr."
            ),
        ),
    ] = False,
) -> None:
    """
    Validate config.yaml without running the assessment.

    Performs Phase 1 (configuration loading and validation) and the test
    checks: every test is declared correctly, and every execution.test_ids
    entry exists and can run. When credentials are configured it also reads
    the specification (download or local file, as the run does) and checks
    that the credentials determine where and how they are sent.
    Useful for verifying that the configuration file is correct and all
    required environment variables are exported before running a full
    assessment.

    Exit codes:
        0   Configuration is valid.
        10  Configuration is invalid (see error output for details).
    """
    _configure_logging(log_format=log_format, log_level=LogLevel.WARNING)
    _load_env_file(env_file)

    from src import __version__
    from src.config.config_used import config_used_yaml
    from src.config.loader import read_config
    from src.core.exceptions import ConfigurationError, OpenAPILoadError, TestDefinitionError
    from src.core.models.enums import ExitCode

    log = structlog.get_logger("cli.validate_config")
    # With --show-config, stdout carries only the configuration (redirectable to a file).
    summary = _console_err if show_config else _console_out

    from src.engine import (
        build_connection_contexts,
        check_credentials,
        check_tests,
        configuration_facts,
        describe_resources,
        select_tests,
        unmet_needs_by_test,
    )

    try:
        loaded = read_config(config)
        tool_config = loaded.config
        test_params = check_tests(tool_config)
        build_connection_contexts(tool_config)
        placement = check_credentials(tool_config)
        summary.print(
            f"[bold green]Configuration valid.[/bold green] Target: {tool_config.target.base_url}"
        )
        if placement is not None:
            method = str(tool_config.credentials.auth_type)
            if tool_config.credentials.login_resource is not None:
                method += f", resource '{tool_config.credentials.login_resource}'"
            summary.print(
                f"Credentials ({method}) sent in the "
                f"{placement.location.value} '{placement.name}' ({placement.source})."
            )
        if tool_config.resources:
            summary.print(f"Resources: {describe_resources(tool_config, test_params)}.")
        selected, _ = select_tests(tool_config)
        unmet = unmet_needs_by_test(selected, test_params, configuration_facts(tool_config))
        if unmet:
            summary.print(
                f"{len(unmet)} of the {len(selected)} selected tests will SKIP "
                "(what they need is not configured):"
            )
            for test_id, reasons in unmet.items():
                summary.print(f"  {test_id}: {' '.join(reasons)}", markup=False)
        if show_config:
            sys.stdout.write(
                config_used_yaml(tool_config, loaded.written, test_params, __version__)
            )
        raise typer.Exit(code=0)
    except ConfigurationError as exc:
        log.error(
            "config_validation_failed",
            detail=exc.message,
            variable_name=exc.variable_name,
            config_path=exc.config_path,
        )
        _console_err.print(f"[bold red]Configuration invalid:[/bold red] {exc.message}")
        raise typer.Exit(code=ExitCode.INFRASTRUCTURE) from None
    except OpenAPILoadError as exc:
        # Raised by check_credentials(): the specification is needed to check
        # how the credentials are sent, and it cannot be read.
        log.error("config_validation_spec_unreadable", detail=exc.message)
        _console_err.print(
            "[bold red]Specification not readable[/bold red] (needed to check how the "
            f"credentials are sent): {exc.message}"
        )
        raise typer.Exit(code=ExitCode.INFRASTRUCTURE) from None
    except TestDefinitionError as exc:
        # Raised by check_tests() when it scans the test modules: an error
        # in the code of a test, reported like the engine does (exit 10).
        log.error("test_definitions_invalid", detail=exc.message)
        _console_err.print(f"[bold red]Test definitions invalid:[/bold red] {exc.message}")
        raise typer.Exit(code=ExitCode.INFRASTRUCTURE) from None


@app.command(name="list-tests")
def list_tests(
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help=(
                "Also say, for this config.yaml, which tests the run selects and which "
                "will SKIP because what they need is not configured."
            ),
            exists=False,
            file_okay=True,
            dir_okay=False,
            resolve_path=True,
        ),
    ] = None,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Print the list as JSON on stdout, for programs."),
    ] = False,
    env_file: EnvFileOption = None,
) -> None:
    """
    List the tests with their declaration, needs and parameters.

    Every test, native and external: ID, name, domain, priority, strategy,
    CWE, tags, prerequisites, tool, what it needs from the configuration and
    the JSON Schema of its parameters (docs/reference/cli.md, "list-tests").
    With --config, also whether the run selects it and why it would SKIP.
    Does not contact the target.

    Exit codes:
        0   Listed.
        10  A test cannot be used, or the configuration is invalid.
    """
    import json

    from src.config.loader import load_config
    from src.core.exceptions import ConfigurationError, TestDefinitionError
    from src.core.models.enums import ExitCode
    from src.engine import describe_tests

    _configure_logging(log_format=LogFormat.CONSOLE, log_level=LogLevel.WARNING)
    try:
        tool_config = None
        if config is not None:
            _load_env_file(env_file)
            tool_config = load_config(config)
        tests = describe_tests(tool_config)
    except (ConfigurationError, TestDefinitionError) as exc:
        _console_err.print(f"[bold red]Cannot list the tests:[/bold red] {exc}")
        raise typer.Exit(code=ExitCode.INFRASTRUCTURE) from None
    if as_json:
        sys.stdout.write(json.dumps({"tests": tests}, indent=2) + "\n")
        raise typer.Exit(code=0)
    width = max(len(test["id"]) for test in tests)
    for test in tests:
        needs = [*test["needs"], *test["needed_parameters"]]
        line = f"{test['id']:<{width}}  P{test['priority']}  {test['strategy']:<9}  {test['name']}"
        if needs:
            line += f"  [needs {', '.join(needs)}]"
        _console_out.print(Text(line))
        if tool_config is not None:
            if not test["selected"]:
                status = "not selected"
            elif test["unmet_needs"]:
                status = "SKIP: " + " ".join(test["unmet_needs"])
            else:
                status = "runs"
            _console_out.print(Text(f"{'':<{width}}  {status}", style="dim"))
    raise typer.Exit(code=0)


@app.command(name="generate-seed")
def generate_seed(
    spec: Annotated[
        str | None,
        typer.Argument(
            help=(
                "OpenAPI specification source. Accepts either: "
                "(1) an HTTP/HTTPS URL (e.g. https://api.example.com/openapi.json), or "
                "(2) a local filesystem path (e.g. ./specs/openapi.yaml). "
                "The spec is fetched or read as-is without full $ref dereferencing, "
                "which makes this command fast and usable before the target is fully running. "
                "Omit it with --config to take the specification of a configuration file."
            ),
        ),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help=(
                "Take the specification from this config.yaml: its source, its timeout and "
                "its certificate settings (specification.tls). Instead of the SPEC argument."
            ),
            exists=False,
            file_okay=True,
            dir_okay=False,
            resolve_path=True,
        ),
    ] = None,
    env_file: EnvFileOption = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help=(
                "Path where the generated seed template YAML file will be written. "
                "If omitted, the template is printed to stdout so it can be "
                "piped or redirected manually. "
                "Example: --output seed_template.yaml"
            ),
            file_okay=True,
            dir_okay=False,
            resolve_path=False,
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            help=(
                "HTTP fetch timeout in seconds for remote spec URLs. "
                "Ignored for local filesystem paths. Default: 30s."
            ),
            min=1.0,
            max=120.0,
        ),
    ] = 30.0,
    log_format: Annotated[
        LogFormat,
        typer.Option(
            "--log-format",
            help="Log output format.",
            case_sensitive=False,
        ),
    ] = LogFormat.CONSOLE,
) -> None:
    """
    Generate a path_seed YAML template from an OpenAPI specification.

    Reads the specification, extracts all unique path parameter names declared
    inside curly braces (e.g. ``{owner}``, ``{repo}``, ``{id}``), and writes a
    YAML template where every parameter is pre-filled with the placeholder value
    ``FILL_ME``.

    The generated template is designed to be pasted directly under the
    ``target:`` section of ``config.yaml``.  After replacing every ``FILL_ME``
    with a real resource identifier from the target deployment, parametric
    endpoints (e.g. ``/repos/{owner}/{repo}``) will receive real, routable paths
    during the assessment instead of generic placeholders that return 404 before
    reaching the authentication middleware.

    Examples:

        # Generate from the specification of a configuration (its URL or file,
        # and its certificate settings) and print to stdout
        apiguard generate-seed -c test-environments/forgejo-kong/config.yaml

        # Generate from a local spec file and save to disk
        apiguard generate-seed ./specs/openapi.yaml --output seed_template.yaml

        # Generate from URL with extended timeout and save
        apiguard generate-seed https://api.example.com/openapi.json \\
            --output my_seed.yaml --timeout 60

        # Take the specification of a configuration (source, timeout, specification.tls)
        apiguard generate-seed -c config.yaml --env-file .env -o seed_template.yaml

    Exit codes:
        0   Template generated successfully.
        1   Fetch or parse error (spec unreachable or malformed).
        2   Neither SPEC nor --config, or both.
        10  The configuration given with --config is invalid.

    Streams: stdout carries only the YAML template (without --output), so
    that it can be redirected to a file; the panel, logs and messages always go
    to stderr.
    """
    _configure_logging(log_format=log_format, log_level=LogLevel.INFO, stream=sys.stderr)

    from src.discovery.seed_generator import (
        SeedGeneratorFetchError,
        SeedGeneratorParseError,
        extract_path_param_names,
        render_seed_template,
    )

    log_inner = structlog.get_logger("cli.generate_seed")

    if (spec is None) == (config is None):
        _console_err.print(
            "[bold red]Give either a SPEC (URL or path) or --config, not both.[/bold red]"
        )
        raise typer.Exit(code=_EXIT_USAGE)
    spec_source, fetch_timeout, tls_context = (spec or "", timeout, None)
    if config is not None:
        from src.config.loader import load_config
        from src.core.exceptions import ConfigurationError
        from src.core.models.enums import ExitCode
        from src.engine import specification_connection

        _load_env_file(env_file)
        try:
            spec_source, fetch_timeout, tls_context = specification_connection(load_config(config))
        except ConfigurationError as exc:
            _console_err.print(f"[bold red]Configuration invalid:[/bold red] {exc.message}")
            raise typer.Exit(code=ExitCode.INFRASTRUCTURE) from None

    if log_format == LogFormat.CONSOLE:
        _console_err.print(
            Panel(
                f"[dim]Spec source:[/dim] [white]{spec_source}[/white]",
                title="[bold cyan]APIGuard — Generate Seed[/bold cyan]",
                border_style="bright_blue",
                padding=(0, 2),
                expand=False,
            )
        )

    try:
        param_names = extract_path_param_names(
            spec_source=spec_source,
            timeout_seconds=fetch_timeout,
            tls_context=tls_context,
        )
    except SeedGeneratorFetchError as exc:
        log_inner.error(
            "generate_seed_fetch_failed",
            spec_source=exc.spec_source,
            reason=exc.reason,
        )
        _console_err.print(
            f"[bold red]Fetch error:[/bold red] {exc.reason}\n[dim]Source:[/dim] {exc.spec_source}"
        )
        raise typer.Exit(code=1) from None
    except SeedGeneratorParseError as exc:
        log_inner.error(
            "generate_seed_parse_failed",
            spec_source=exc.spec_source,
            reason=exc.reason,
        )
        _console_err.print(
            f"[bold red]Parse error:[/bold red] {exc.reason}\n[dim]Source:[/dim] {exc.spec_source}"
        )
        raise typer.Exit(code=1) from None

    yaml_content = render_seed_template(param_names=param_names, spec_source=spec_source)

    if output is None:
        # stdout carries only the template, written raw (no wrapping, no markup)
        # so that `generate-seed SPEC > seed.yaml` produces valid YAML.
        _console_out.out(yaml_content, highlight=False, end="")
        if log_format == LogFormat.CONSOLE:
            _console_err.print(
                f"[dim]Found [bold]{len(param_names)}[/bold] unique path parameter(s). "
                "Paste the block above under 'target:' in config.yaml.[/dim]"
            )
    else:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(yaml_content, encoding="utf-8")

        log_inner.info(
            "generate_seed_template_written",
            output_path=str(output_path.resolve()),
            param_count=len(param_names),
            param_names=param_names,
        )

        if log_format == LogFormat.CONSOLE:
            _console_err.print(
                f"[bold green]Seed template written:[/bold green] {output_path.resolve()}\n"
                f"[dim]Found [bold]{len(param_names)}[/bold] unique path parameter(s): "
                f"{', '.join(param_names) if param_names else '(none)'}[/dim]\n"
                "[dim]Next steps:[/dim]\n"
                "  [white]1.[/white] Open the generated file and replace each [yellow]FILL_ME[/yellow] "  # noqa: E501
                "with a real resource identifier.\n"
                "  [white]2.[/white] Paste the [cyan]path_seed:[/cyan] block under [cyan]target:[/cyan] "  # noqa: E501
                "in your [white]config.yaml[/white].\n"
                "  [white]3.[/white] Re-run [bold]apiguard run[/bold] for an assessment with real paths."  # noqa: E501
            )

    raise typer.Exit(code=0)


# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------


def _load_env_file(env_file: Path | None) -> None:
    """
    Load environment variables from a .env file into os.environ.

    With env_file, that file is loaded (its existence is checked by Typer).
    Without it, '.env' in the current working directory is loaded if present;
    no other location is searched (not the tool's installation folder, not
    parent folders). Variables already set in the environment are never
    overwritten (override=False), so values injected by a CI pipeline, a
    container or a calling program take precedence. Must run before
    config/loader.py resolves the ${VAR} placeholders.

    Args:
        env_file: Path given with --env-file, or None.
    """
    log = structlog.get_logger("cli.env")
    path = env_file if env_file is not None else Path.cwd() / DEFAULT_ENV_FILENAME
    if env_file is None and not path.is_file():
        log.debug("env_file_not_found", path=str(path))
        return
    load_dotenv(dotenv_path=path, override=False)
    log.info("env_file_loaded", path=str(path))


class _ConsoleLineLogger:
    """
    structlog logger that prints each rendered line through a rich Console.

    Used in console format so that technical log lines and the interface
    (src/cli_console.py) share one Console: a log line printed while a test
    is in progress appears above its live line instead of breaking it.
    """

    def __init__(self, console: Console) -> None:
        """Remember the Console to print on."""
        self._console = console

    def msg(self, message: str) -> None:
        """Print one rendered log line (ANSI colours kept on a terminal)."""
        self._console.print(Text.from_ansi(message))

    log = debug = info = warning = warn = error = err = critical = exception = msg


def _relativize_paths(
    _logger: object, _method_name: str, event_dict: structlog.types.EventDict
) -> structlog.types.EventDict:
    """Console processor: show paths inside the working directory as relative."""
    for key, value in event_dict.items():
        if isinstance(value, str) and value.startswith(os.sep):
            event_dict[key] = BaseSubprocessConnector._relativize_display_path(value)  # noqa: SLF001
    return event_dict


def _cut_long_values(
    _logger: object, _method_name: str, event_dict: structlog.types.EventDict
) -> structlog.types.EventDict:
    """Console processor: cut long values (text, or the text of a list or dict)."""
    for key, value in event_dict.items():
        text = value if isinstance(value, str) else repr(value)
        if len(text) > CONSOLE_LOG_MAX_VALUE_LENGTH:
            event_dict[key] = text[: CONSOLE_LOG_MAX_VALUE_LENGTH - 1] + "…"
    return event_dict


def _configure_logging(
    log_format: LogFormat,
    log_level: LogLevel,
    stream: TextIO | None = None,
    console: Console | None = None,
) -> None:
    """
    Configure the structlog logging pipeline for this process run.

    Must be called once, before any structlog.get_logger() call is used
    to emit a log entry. Calling it multiple times is safe (idempotent)
    because structlog.configure() overwrites the previous configuration.

    Pipeline design:
        All log entries flow through a shared list of processors:
            1. Add log level to the event dict.
            2. Add ISO 8601 timestamp.
            3. Add caller information (module, function, line) in DEBUG mode.
            4. Format exceptions as strings.
            5. Render as ConsoleRenderer (human) or JSONRenderer (machine).

        Third-party libraries that use stdlib logging (httpx, prance,
        openapi-spec-validator) are configured with logging.basicConfig: their
        entries go to the same stream as plain text, not through the structlog
        processors (so they are not JSON in --log-format json).

    Args:
        log_format: CONSOLE or JSON output format.
        log_level: Minimum log level to emit.
        stream: Destination of every log entry. Default stdout; commands whose
                stdout is data (generate-seed) pass stderr.
        console: In console format, the rich Console shared with the
                 interface (apiguard run): lines are printed through it, with
                 a short local time, paths relative to the working directory
                 and long values cut. None: plain lines on stream.
    """
    log_stream: TextIO = sys.stdout if stream is None else stream
    level_int = getattr(logging, log_level.value.upper(), logging.INFO)

    # Shared processors applied to every log entry before rendering.
    shared_processors: list[structlog.types.Processor] = [
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.ExceptionRenderer(),
    ]

    if log_format == LogFormat.JSON:
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(
            colors=True,
            exception_formatter=structlog.dev.plain_traceback,
        )

    logger_factory: structlog.types.WrappedLogger = structlog.PrintLoggerFactory(file=log_stream)
    if console is not None:
        # Console format of `run`: the full ISO timestamp is replaced with a
        # short local time; JSON lines keep every value complete.
        shared_processors[1] = structlog.processors.TimeStamper(fmt=CONSOLE_LOG_TIME_FORMAT)
        shared_processors += [_relativize_paths, _cut_long_values]
        shared_console = console

        def logger_factory(*_args: object) -> _ConsoleLineLogger:
            return _ConsoleLineLogger(shared_console)

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level_int),
        context_class=dict,
        logger_factory=logger_factory,
        cache_logger_on_first_use=True,
    )

    # Third-party libraries (httpx, prance, openapi-spec-validator, yaml) log
    # through stdlib logging: plain text on the same stream, not the structlog
    # pipeline.
    logging.basicConfig(
        format="%(message)s",
        stream=log_stream,
        level=level_int,
    )

    # Silence overly verbose third-party loggers that produce noise
    # even at INFO level in normal operation.
    _silence_noisy_loggers(level_int)


# Logger of the Python warnings captured by logging.captureWarnings().
_PY_WARNINGS_LOGGER: str = "py.warnings"


def _silence_noisy_loggers(base_level: int) -> None:
    """
    Set minimum log levels for third-party libraries that are overly verbose.

    At DEBUG level, we allow everything through. At INFO and above,
    httpx connection lifecycle events and prance resolver debug messages
    are suppressed because they add noise without informational value
    in a security assessment context.

    Args:
        base_level: The base log level configured for the tool.
    """
    # Python warnings raised inside libraries (e.g. a deprecation notice of
    # cryptography during an sslyze scan) are addressed to the developers of
    # those libraries: they go through the logging system, under the
    # "py.warnings" logger, and are shown only at DEBUG.
    logging.captureWarnings(True)
    logging.getLogger(_PY_WARNINGS_LOGGER).setLevel(
        logging.DEBUG if base_level <= logging.DEBUG else logging.CRITICAL
    )

    if base_level <= logging.DEBUG:
        return

    noisy_loggers: list[str] = [
        "httpx",
        "httpcore",
        "prance",
        "openapi_spec_validator",
        "urllib3",
        "chardet",
        # sslyze logs each HTTP probe at INFO in plain text, which would break
        # the one-JSON-object-per-line stream of --log-format json.
        "sslyze",
    ]

    for logger_name in noisy_loggers:
        logging.getLogger(logger_name).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Display helpers (console mode only)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Entry point guard
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    # Allows invoking the CLI directly as `python -m src.cli` during development.
    # In production, the entry point `apiguard` registered in pyproject.toml
    # calls app() directly without this guard.
    app()
