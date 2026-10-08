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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Tool metadata displayed in CLI help and startup banner.
# TOOL_VERSION is sourced from pyproject.toml via importlib.metadata
# (single source of truth -- see src/__init__.py).
TOOL_NAME: str = "APIGuard Assurance"
TOOL_VERSION: str = __version__
# File loaded from the current working directory when --env-file is not given.
DEFAULT_ENV_FILENAME: str = ".env"

TOOL_DESCRIPTION: str = (
    "Automated security assessment tool for REST APIs in Cloud environments. "
    "Executes the APIGuard methodology (8 domains, 29 guarantees) against "
    "any API Gateway protecting a REST API documented with OpenAPI 3.x."
)

# Default paths, relative to the working directory.
DEFAULT_CONFIG_PATH: Path = Path("config.yaml")
DEFAULT_LOG_LEVEL: str = "info"

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
        b"Ctrl+C received: stopping the assessment and removing the resources "
        b"created on the target. Please wait.\n"
    ),
    signal.SIGTERM: (
        b"SIGTERM received: stopping the assessment and removing the resources "
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
                "Logging verbosity level. "
                "'info' is the recommended level for normal use. "
                "'debug' produces verbose output including every HTTP transaction."
            ),
            case_sensitive=False,
        ),
    ] = LogLevel.INFO,
    show_banner: Annotated[
        bool,
        typer.Option(
            "--banner/--no-banner",
            help="Show or suppress the startup banner. Default: show.",
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
    # Step 1: configure logging before any other operation.
    _configure_logging(log_format=log_format, log_level=log_level)
    _load_env_file(env_file)

    # Step 2: display startup banner (human-readable mode only).
    if show_banner and log_format == LogFormat.CONSOLE:
        _display_startup_banner(config_path=config)

    # Step 3: import engine here (after logging is configured) so that
    # any module-level structlog calls in engine.py use the configured pipeline.
    from src.engine import AssessmentEngine

    engine = AssessmentEngine(config_path=config)

    # Step 4: run the assessment pipeline. Ctrl+C and SIGTERM are handled
    # alike: the first one unwinds through the engine so that teardown
    # (Phase 6) runs, later ones only say that cleanup is in progress; then
    # the process ends by the first signal (exit 130 or 143).
    _install_stop_handlers()
    try:
        exit_code = engine.run()
    except (KeyboardInterrupt, _TerminationRequestedError) as exc:
        stop_signal = signal.SIGINT if isinstance(exc, KeyboardInterrupt) else signal.SIGTERM
        structlog.get_logger("cli.run").warning(
            "assessment_interrupted",
            signal=stop_signal.name,
            detail="Teardown ran; no report was written.",
        )
        _exit_by_signal(stop_signal)

    # Step 5: display completion summary in console mode.
    if show_banner and log_format == LogFormat.CONSOLE:
        _display_completion_summary(exit_code=exit_code)

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
) -> None:
    """
    Validate config.yaml without running the assessment.

    Performs Phase 1 (configuration loading and validation) and the
    execution.test_ids check (every listed test exists and can run).
    Useful for verifying that the configuration file is correct and all
    required environment variables are exported before running a full
    assessment.

    Exit codes:
        0   Configuration is valid.
        10  Configuration is invalid (see error output for details).
    """
    _configure_logging(log_format=log_format, log_level=LogLevel.INFO)
    _load_env_file(env_file)

    from src.config.loader import load_config
    from src.core.exceptions import ConfigurationError
    from src.core.models.enums import ExitCode

    log = structlog.get_logger("cli.validate_config")

    from src.engine import check_test_ids

    try:
        tool_config = load_config(config)
        check_test_ids(tool_config)
        _console_out.print(
            f"[bold green]Configuration valid.[/bold green] Target: {tool_config.target.base_url}"
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


@app.command(name="generate-seed")
def generate_seed(
    spec: Annotated[
        str,
        typer.Argument(
            help=(
                "OpenAPI specification source. Accepts either: "
                "(1) an HTTP/HTTPS URL (e.g. http://localhost:3000/swagger.v1.json), or "
                "(2) a local filesystem path (e.g. ./specs/openapi.yaml). "
                "The spec is fetched or read as-is without full $ref dereferencing, "
                "which makes this command fast and usable before the target is fully running."
            ),
        ),
    ],
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

        # Generate from a running target and print to stdout
        apiguard generate-seed http://localhost:3000/swagger.v1.json

        # Generate from a local spec file and save to disk
        apiguard generate-seed ./specs/openapi.yaml --output seed_template.yaml

        # Generate from URL with extended timeout and save
        apiguard generate-seed https://api.example.com/openapi.json \\
            --output my_seed.yaml --timeout 60

    Exit codes:
        0   Template generated successfully.
        1   Fetch or parse error (spec unreachable or malformed).

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

    if log_format == LogFormat.CONSOLE:
        _console_err.print(
            Panel(
                f"[dim]Spec source:[/dim] [white]{spec}[/white]",
                title="[bold cyan]APIGuard — Generate Seed[/bold cyan]",
                border_style="bright_blue",
                padding=(0, 2),
                expand=False,
            )
        )

    try:
        param_names = extract_path_param_names(
            spec_source=spec,
            timeout_seconds=timeout,
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

    yaml_content = render_seed_template(param_names=param_names, spec_source=spec)

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


def _configure_logging(
    log_format: LogFormat, log_level: LogLevel, stream: TextIO | None = None
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

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(level_int),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=log_stream),
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
    if base_level <= logging.DEBUG:
        return

    noisy_loggers: list[str] = [
        "httpx",
        "httpcore",
        "prance",
        "openapi_spec_validator",
        "urllib3",
        "chardet",
    ]

    for logger_name in noisy_loggers:
        logging.getLogger(logger_name).setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# Display helpers (console mode only)
# ---------------------------------------------------------------------------


def _display_startup_banner(config_path: Path) -> None:
    """
    Display a formatted startup banner in the terminal.

    Called only in CONSOLE log format mode. In JSON mode, the banner
    would corrupt the JSON stream consumed by log aggregators.

    Args:
        config_path: Resolved path to the config file being used.
    """
    banner_text = Text()
    banner_text.append(f"{TOOL_NAME} ", style="bold white")
    banner_text.append(f"v{TOOL_VERSION}", style="cyan")
    banner_text.append("\n")
    banner_text.append("Automated API Security Assessment", style="dim white")
    banner_text.append("\n\n")
    banner_text.append("Config:  ", style="dim")
    banner_text.append(str(config_path), style="white")

    _console_out.print(
        Panel(
            banner_text,
            border_style="bright_blue",
            padding=(0, 2),
            expand=False,
        )
    )


def _display_completion_summary(exit_code: int) -> None:
    """
    Display a formatted completion summary with the exit code and its meaning.

    Called only in CONSOLE log format mode after the engine returns.

    Args:
        exit_code: The integer exit code returned by AssessmentEngine.run().
    """
    from src.core.models.enums import ExitCode

    labels: dict[int, tuple[str, str]] = {
        ExitCode.CLEAN: ("green", "CLEAN  — No violations detected. Assessment passed."),
        ExitCode.FAIL: ("red", "FAIL   — At least one security guarantee was violated."),
        ExitCode.ERROR: ("purple", "ERROR  — At least one verification was incomplete."),
        ExitCode.INFRASTRUCTURE: (
            "yellow",
            "INFRA  — Infrastructure error. Assessment did not complete.",
        ),
    }

    color, label = labels.get(exit_code, ("white", f"Exit {exit_code}"))

    _console_out.print()
    _console_out.print(
        Panel(
            Text(f"Exit {exit_code}  —  {label}", style=f"bold {color}"),
            border_style=color,
            padding=(0, 2),
            expand=False,
            title="Assessment Complete",
            title_align="left",
        )
    )
    _console_out.print(
        "[dim]Outputs: "
        "[white]assessment_report.html[/white]  "
        "[white]evidence.json[/white]  "
        "[white]apiguard_report.json[/white]"
        "[/dim]"
    )


# ---------------------------------------------------------------------------
# Entry point guard
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    # Allows invoking the CLI directly as `python -m src.cli` during development.
    # In production, the entry point `apiguard` registered in pyproject.toml
    # calls app() directly without this guard.
    app()
