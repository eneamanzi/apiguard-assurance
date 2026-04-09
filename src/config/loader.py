"""
src/config/loader.py

Configuration loader for the APIGuard Assurance tool.

This module is the single point of contact between the tool and the external
environment (filesystem + OS environment variables). After load_config() returns,
the rest of the pipeline operates exclusively on the returned ToolConfig object.
No other module in src/ reads files or calls os.environ directly.

Environment variable loading
-----------------------------
This module does NOT call load_dotenv(). The authoritative call lives in
src/cli.py, which is the process entry point. Centralising the call there
guarantees a single, predictable point of environment initialisation regardless
of how the tool is invoked (CLI, tests, scripts). If load_config() is called
from tests without going through the CLI, the test's own conftest.py is
responsible for loading the .env file before the call.

Loading pipeline (three sequential, non-overlapping phases):

    Phase A — Raw read:
        Read config.yaml from disk as a raw UTF-8 string.
        Raises ConfigurationError immediately on FileNotFoundError or
        PermissionError, before any YAML parsing is attempted.

    Phase B — Environment variable interpolation:
        Scan the raw string for ${VAR_NAME} patterns using a compiled regex.
        Resolve each pattern against os.environ.
        Raises ConfigurationError for the first unresolved variable, with
        ConfigurationError.variable_name populated for structured logging.
        This phase runs BEFORE YAML parsing so that the error message
        unambiguously identifies an environment problem, not a YAML problem.

    Phase C — YAML parsing and Pydantic validation:
        Parse the interpolated string with yaml.safe_load().
        Pass the resulting dict to ToolConfig.model_validate().
        Convert Pydantic ValidationError to ConfigurationError with
        config_path extracted from the first error location.
        Emit structured warnings for coherence conditions detected by
        ToolConfig.model_validator (WHITE_BOX without admin_api_url, etc.).

Dependency rule:
    This module imports from stdlib, PyYAML, structlog, pydantic,
    src.core.exceptions, and src.config.schema only.
    It must never import from engine.py, tests/, discovery/, or report/.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import structlog
import yaml
from pydantic import ValidationError

from src.config.schema import ToolConfig
from src.core.exceptions import ConfigurationError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Regex pattern for environment variable placeholders in config.yaml.
# Matches ${VAR_NAME} where VAR_NAME is one or more uppercase letters,
# digits, or underscores. This is the POSIX convention for env var names.
# Named group 'var_name' allows extraction without index-based slicing.
_ENV_VAR_PATTERN: re.Pattern[str] = re.compile(r"\$\{(?P<var_name>[A-Z][A-Z0-9_]*)\}")

# Default config file name, resolved relative to the caller's working directory.
# The CLI passes an explicit Path, but this constant documents the convention.
DEFAULT_CONFIG_FILENAME: str = "config.yaml"


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def load_config(config_path: Path) -> ToolConfig:
    """
    Load, interpolate, and validate the tool configuration from a YAML file.

    This is the single public function of this module. It is called once by
    engine.py during Phase 1 (Initialization) and returns a frozen ToolConfig
    object that is valid for the entire pipeline run.

    The function never returns a partially-loaded configuration: it either
    returns a fully valid ToolConfig or raises ConfigurationError with enough
    structured information to diagnose the problem without reading source code.

    Args:
        config_path: Filesystem path to the config.yaml file.
                     Typically Path("config.yaml") in the project root.
                     Resolved to an absolute path internally for unambiguous
                     error messages.

    Returns:
        A fully validated, frozen ToolConfig instance.

    Raises:
        ConfigurationError: For any of the following conditions:
            - config_path does not exist (FileNotFoundError).
            - config_path exists but cannot be read (PermissionError).
            - The file contains a ${VAR_NAME} placeholder whose corresponding
              environment variable is not set.
            - The YAML content is syntactically invalid.
            - The configuration structure fails Pydantic validation
              (missing required fields, invalid URL format, out-of-range values,
              incomplete credential pairs, empty strategies list, etc.).
    """
    absolute_path = config_path.resolve()

    log.info(
        "config_loading_started",
        config_path=str(absolute_path),
    )

    # Phase A: raw file read.
    raw_content = _read_raw_file(absolute_path)

    # Phase B: environment variable interpolation.
    interpolated_content = _interpolate_env_vars(raw_content, absolute_path)

    # Phase C: YAML parsing and Pydantic validation.
    config = _parse_and_validate(interpolated_content, absolute_path)

    # Post-validation: emit structured warnings for coherence conditions.
    _emit_coherence_warnings(config)

    log.info(
        "config_loading_completed",
        config_path=str(absolute_path),
        base_url=str(config.target.base_url),
        min_priority=config.execution.min_priority,
        strategies=[s.value for s in config.execution.strategies],
        fail_fast=config.execution.fail_fast,
        admin_api_configured=config.target.admin_api_url is not None,
    )

    return config


# ---------------------------------------------------------------------------
# Phase A — Raw file read
# ---------------------------------------------------------------------------


def _read_raw_file(absolute_path: Path) -> str:
    """
    Read the config file from disk as a raw UTF-8 string.

    Separating this from YAML parsing ensures that I/O errors produce a
    ConfigurationError with a clear filesystem-level message, not a YAML
    parse error with a confusing traceback.

    Args:
        absolute_path: Resolved absolute path to the config file.

    Returns:
        The raw file content as a string.

    Raises:
        ConfigurationError: On FileNotFoundError or PermissionError.
    """
    try:
        content = absolute_path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigurationError(
            message=(
                f"Configuration file not found: '{absolute_path}'. "
                "Create the file or pass the correct path via --config."
            ),
            config_path=str(absolute_path),
        ) from exc
    except PermissionError as exc:
        raise ConfigurationError(
            message=(
                f"Permission denied reading configuration file: '{absolute_path}'. "
                "Check file permissions and ensure the current user has read access."
            ),
            config_path=str(absolute_path),
        ) from exc

    if not content.strip():
        raise ConfigurationError(
            message=(
                f"Configuration file is empty: '{absolute_path}'. "
                "Provide a valid config.yaml with at least the 'target' section."
            ),
            config_path=str(absolute_path),
        )

    log.debug(
        "config_raw_file_read",
        config_path=str(absolute_path),
        content_length_chars=len(content),
    )

    return content


# ---------------------------------------------------------------------------
# Phase B — Environment variable interpolation
# ---------------------------------------------------------------------------


def _interpolate_env_vars(raw_content: str, config_path: Path) -> str:
    """
    Replace all ${VAR_NAME} placeholders with their environment variable values.

    The interpolation is eager and exhaustive: all placeholders are resolved
    in a single pass using re.sub with a callable replacement function.
    The first unresolved variable causes an immediate ConfigurationError
    with ConfigurationError.variable_name populated for structured logging.

    The design choice to fail on the first missing variable (rather than
    collecting all missing variables) is intentional: in practice, a missing
    variable almost always indicates a forgotten export or a misconfigured
    deployment environment, and fixing one at a time with a clear error
    message is faster than receiving a list of twenty missing variables at once.

    Args:
        raw_content: The raw YAML content string, possibly containing
                     ${VAR_NAME} placeholders.
        config_path: Path of the source file, used only for error messages.

    Returns:
        The interpolated YAML string with all ${VAR_NAME} replaced.

    Raises:
        ConfigurationError: If any ${VAR_NAME} placeholder has no corresponding
                            environment variable set.
    """
    # Collect all unique placeholder names before substitution to provide
    # a complete diagnostic in the error message (how many are missing).
    all_placeholders = set(_ENV_VAR_PATTERN.findall(raw_content))

    if not all_placeholders:
        log.debug("config_no_env_placeholders_found")
        return raw_content

    log.debug(
        "config_env_placeholders_found",
        placeholder_count=len(all_placeholders),
        placeholder_names=sorted(all_placeholders),
    )

    # Verify all required variables are present before substitution.
    # This produces a complete list of missing variables in one pass,
    # which is more useful than discovering them one by one during re.sub.
    missing_variables: list[str] = [
        name for name in sorted(all_placeholders) if name not in os.environ
    ]

    if missing_variables:
        # Report all missing variables in a single error to help the user
        # configure the environment in one step.
        first_missing = missing_variables[0]
        all_missing_str = ", ".join(missing_variables)

        raise ConfigurationError(
            message=(
                f"Environment variable(s) not set: {all_missing_str}. "
                f"Export the required variable(s) before running the tool. "
                f"Example: export {first_missing}=<value>"
            ),
            variable_name=first_missing,
            config_path=str(config_path),
        )

    def _replace_placeholder(match: re.Match[str]) -> str:
        """
        Replacement function for re.sub.

        At this point all variables are verified present (checked above),
        so os.environ access is guaranteed to succeed. The KeyError guard
        is a defensive measure against a race condition where an environment
        variable is unset between the verification loop and this substitution.
        """
        var_name = match.group("var_name")
        value = os.environ.get(var_name)
        if value is None:
            raise ConfigurationError(
                message=(
                    f"Environment variable '{var_name}' was present during "
                    "validation but disappeared before substitution. "
                    "This indicates a race condition in the shell environment."
                ),
                variable_name=var_name,
                config_path=str(config_path),
            )
        return value

    interpolated = _ENV_VAR_PATTERN.sub(_replace_placeholder, raw_content)

    log.debug(
        "config_env_interpolation_completed",
        variables_resolved=len(all_placeholders),
    )

    return interpolated


# ---------------------------------------------------------------------------
# Phase C — YAML parsing and Pydantic validation
# ---------------------------------------------------------------------------


def _parse_and_validate(interpolated_content: str, config_path: Path) -> ToolConfig:
    """
    Parse the interpolated YAML string and validate it against ToolConfig.

    Two distinct failure modes are handled separately:

    1. yaml.YAMLError: The content is syntactically invalid YAML. This is a
       formatting error in config.yaml, not an environment problem. The error
       message from PyYAML is included verbatim because it already pinpoints
       the line and column of the syntax error.

    2. pydantic.ValidationError: The YAML structure is valid but does not
       conform to ToolConfig's schema. The first validation error's location
       is extracted and stored in ConfigurationError.config_path to give the
       user a dotted-path pointer into config.yaml (e.g., 'target.base_url').

    Args:
        interpolated_content: YAML string with all ${VAR_NAME} resolved.
        config_path: Path of the source file, used only for error messages.

    Returns:
        A fully validated, frozen ToolConfig instance.

    Raises:
        ConfigurationError: On YAML syntax errors or Pydantic validation failures.
    """
    # YAML parsing.
    try:
        raw_dict = yaml.safe_load(interpolated_content)
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            message=(f"YAML syntax error in configuration file '{config_path}': {exc}"),
            config_path=str(config_path),
        ) from exc

    if not isinstance(raw_dict, dict):
        raise ConfigurationError(
            message=(
                f"Configuration file '{config_path}' must contain a YAML mapping "
                f"at the top level. Got: {type(raw_dict).__name__}. "
                "Ensure the file starts with keys like 'target:', 'execution:', etc."
            ),
            config_path=str(config_path),
        )

    # Pydantic validation.
    try:
        config = ToolConfig.model_validate(raw_dict)
    except ValidationError as exc:
        # Extract the first error's location as a dotted config path.
        # Pydantic v2 errors() returns a list of TypedDict with 'loc' as a
        # tuple of (str | int) representing the path into the model.
        first_error = exc.errors(include_url=False)[0]
        loc_parts = first_error.get("loc", ())
        dotted_path = ".".join(str(part) for part in loc_parts)
        pydantic_message = first_error.get("msg", str(exc))
        error_count = exc.error_count()

        raise ConfigurationError(
            message=(
                f"Configuration validation failed with {error_count} error(s). "
                f"First error at '{dotted_path}': {pydantic_message}. "
                "Review the config.yaml structure against the expected schema."
            ),
            config_path=dotted_path if dotted_path else str(config_path),
        ) from exc

    log.debug(
        "config_pydantic_validation_passed",
        model_fields_validated=len(ToolConfig.model_fields),
    )

    return config


# ---------------------------------------------------------------------------
# Post-validation coherence warnings
# ---------------------------------------------------------------------------


def _emit_coherence_warnings(config: ToolConfig) -> None:
    """
    Emit structured warnings for configuration coherence conditions.

    These conditions are not validation errors: the tool will run and produce
    results. However, the results will include many SKIP entries that might
    surprise the user if they did not anticipate the coherence issue.

    Emitting warnings here — at load time, before Phase 2 begins — gives the
    user the opportunity to reconfigure and restart rather than discovering
    the issue in the final report.

    The conditions are detected by ToolConfig.model_validator and stored as
    private attributes accessed via property methods.

    Args:
        config: The fully validated ToolConfig instance.
    """
    if config.white_box_without_admin_api:
        log.warning(
            "config_coherence_warning",
            condition="white_box_without_admin_api",
            detail=(
                "execution.strategies includes WHITE_BOX but target.admin_api_url "
                "is not configured. All P3 (WHITE_BOX) tests will return SKIP "
                "with reason 'Admin API not configured'. "
                "Set target.admin_api_url in config.yaml to enable WHITE_BOX tests."
            ),
        )

    if config.grey_box_without_credentials:
        log.warning(
            "config_coherence_warning",
            condition="grey_box_without_credentials",
            detail=(
                "execution.strategies includes GREY_BOX but no credentials are "
                "configured (admin, user_a, and user_b are all absent). "
                "All P1/P2 (GREY_BOX) tests will return SKIP "
                "with reason 'No credentials available'. "
                "Set credential environment variables to enable GREY_BOX tests."
            ),
        )

    if not config.white_box_without_admin_api and not config.grey_box_without_credentials:
        log.debug("config_coherence_check_passed")
