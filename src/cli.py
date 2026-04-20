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
import sys
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import structlog
import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Load .env file from the project root (the working directory where the tool
# is invoked). This must happen before any other import or operation reads
# os.environ, including structlog configuration and config/loader.py.
# load_dotenv() is a no-op if the .env file does not exist, so it is safe
# to call unconditionally in all environments (CI/CD, production, dev).
# Variables already set in the environment take precedence: load_dotenv()
# does NOT overwrite existing env vars, which is the correct behavior for
# CI/CD pipelines that inject secrets via the orchestrator.
load_dotenv(override=False)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Tool metadata displayed in CLI help and startup banner.
TOOL_NAME: str = "APIGuard Assurance"
TOOL_VERSION: str = "1.0.0"
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
) -> None:
    """
    Run the API security assessment against the configured target.

    Reads target configuration from CONFIG (default: config.yaml in the
    current working directory). Credentials must be provided via environment
    variables referenced in config.yaml as ${VAR_NAME} placeholders.

    Exit codes:
        0   All tests passed or skipped. No violations detected.
        1   At least one FAIL. A security guarantee was violated.
        2   At least one ERROR (no FAIL). A verification was incomplete.
        10  Infrastructure error. Assessment did not start or complete.

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

    # Step 2: display startup banner (human-readable mode only).
    if show_banner and log_format == LogFormat.CONSOLE:
        _display_startup_banner(config_path=config)

    # Step 3: import engine here (after logging is configured) so that
    # any module-level structlog calls in engine.py use the configured pipeline.
    from src.engine import AssessmentEngine

    engine = AssessmentEngine(config_path=config)

    # Step 4: run the assessment pipeline.
    exit_code = engine.run()

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
) -> None:
    """
    Validate config.yaml without running the assessment.

    Performs Phase 1 (configuration loading and validation) only.
    Useful for verifying that the configuration file is correct and all
    required environment variables are exported before running a full
    assessment.

    Exit codes:
        0   Configuration is valid.
        10  Configuration is invalid (see error output for details).
    """
    _configure_logging(log_format=log_format, log_level=LogLevel.INFO)

    from src.config.loader import load_config
    from src.core.exceptions import ConfigurationError

    log = structlog.get_logger("cli.validate_config")

    try:
        tool_config = load_config(config)
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
        raise typer.Exit(code=10) from None


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
    """
    _configure_logging(log_format=log_format, log_level=LogLevel.INFO)

    from src.discovery.seed_generator import (
        SeedGeneratorFetchError,
        SeedGeneratorParseError,
        extract_path_param_names,
        render_seed_template,
    )

    log_inner = structlog.get_logger("cli.generate_seed")

    if log_format == LogFormat.CONSOLE:
        _console_out.print(
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
        # Print to stdout: the user can redirect or copy-paste manually.
        _console_out.print(yaml_content)
        if log_format == LogFormat.CONSOLE:
            _console_out.print(
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
            _console_out.print(
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


def _configure_logging(log_format: LogFormat, log_level: LogLevel) -> None:
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

        The stdlib logging bridge (structlog.stdlib.ProcessorFormatter) is
        configured so that third-party libraries that use stdlib logging
        (httpx, prance, openapi-spec-validator) emit their log entries
        through the same pipeline and appear in the same output stream.

    Args:
        log_format: CONSOLE or JSON output format.
        log_level: Minimum log level to emit.
    """
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
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Bridge stdlib logging to structlog so that third-party libraries
    # (httpx, prance, openapi-spec-validator, yaml) use the same pipeline.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
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
    labels: dict[int, tuple[str, str]] = {
        0: ("green", "CLEAN  — No violations detected. Assessment passed."),
        1: ("red", "FAIL   — At least one security guarantee was violated."),
        2: ("purple", "ERROR  — At least one verification was incomplete."),
        10: ("yellow", "INFRA  — Infrastructure error. Assessment did not complete."),
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
