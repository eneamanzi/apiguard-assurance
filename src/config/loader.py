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

Loading pipeline (four sequential, non-overlapping phases):

    Phase A — Raw read:
        Read config.yaml from disk as a raw UTF-8 string.
        Raises ConfigurationError immediately on FileNotFoundError or
        PermissionError, before any YAML parsing is attempted.

    Phase B — YAML parsing:
        Parse the file as written, with PyYAML's safe loader, rejecting a key
        repeated in the same mapping. ${VAR_NAME} placeholders are still
        plain text here, so a YAML error never shows a value from the
        environment.

    Phase C — Environment variable interpolation:
        Replace ${VAR_NAME} inside the parsed string values with the variable's
        value (never in keys). A value from the environment is never read as
        YAML structure, so any character in a password arrives unchanged, and
        a placeholder in a comment is ignored (Q-69). An unquoted placeholder
        that is the whole value takes the type of its value when that is a
        number, a boolean or empty, as if written in its place; quoted, it is
        always text. Raises ConfigurationError
        naming every unset variable, with ConfigurationError.variable_name
        set to the first for structured logging.

    Phase D — Pydantic validation:
        A declared block written empty (every line under it commented) is the
        block with its defaults, as if it were not written (without_empty_blocks).
        Pass the interpolated dict to ToolConfig.model_validate().
        Convert Pydantic ValidationError to ConfigurationError listing every
        error (an unknown key with the closest declared key, if any), with
        config_path extracted from the first error location.
    (Which tests will SKIP for an unmet need is said by the engine, once the
    tests are discovered: src/core/test_needs.py.)

Dependency rule:
    This module imports from stdlib, PyYAML, structlog, pydantic,
    src.core.exceptions, and src.config.schema only.
    It must never import from engine.py, tests/, discovery/, or report/.
"""

from __future__ import annotations

import difflib
import os
import re
import typing
from dataclasses import dataclass
from pathlib import Path

import structlog
import yaml
from pydantic import BaseModel, ValidationError
from pydantic_core import ErrorDetails

from src.config.schema import ToolConfig
from src.core.exceptions import ConfigurationError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# YAML tag of a merge key ("<<: *anchor"): repeating a key over a merged mapping
# is how YAML overrides it, so merges are not duplicates.
_YAML_MERGE_TAG: str = "tag:yaml.org,2002:merge"

# Regex pattern for environment variable placeholders in config.yaml.
# Matches ${VAR_NAME} where VAR_NAME is one or more uppercase letters,
# digits, or underscores. This is the POSIX convention for env var names.
# Named group 'var_name' allows extraction without index-based slicing.
# Limitation: the bash-style default-value syntax ${VAR:-default} is NOT
# supported. Writing ${ADMIN_URL:-http://localhost} leaves the literal
# string "${ADMIN_URL:-http://localhost}" in the YAML, which Pydantic
# then rejects with a confusing validation error rather than a clear one.
ENV_VAR_PATTERN: re.Pattern[str] = re.compile(r"\$\{(?P<var_name>[A-Z][A-Z0-9_]*)\}")

# YAML tag of a string scalar: the constructor that marks an unquoted placeholder.
_YAML_STR_TAG: str = "tag:yaml.org,2002:str"

# Types an unquoted placeholder can take from its value, as if the value were written
# in its place; any other value (text, a list, a mapping, a date) stays the exact text.
_PLACEHOLDER_SCALAR_TYPES: tuple[type, ...] = (bool, int, float, type(None))

# Pydantic error type raised by extra="forbid" for a key the schema does not
# declare (every configuration model forbids unknown keys, so a typo stops
# Phase 1 instead of silently applying a default).
_PYDANTIC_EXTRA_FORBIDDEN: str = "extra_forbidden"

# Similarity threshold (difflib ratio, 0-1) for suggesting a known key in place
# of an unknown one. 0.6 is difflib's own default: it matches common typos
# ("min_prioriti" -> "min_priority") without suggesting unrelated keys.
_KEY_SUGGESTION_CUTOFF: float = 0.6

# Validation errors listed one by one in the error message; beyond this the
# remaining ones are only counted, to keep the message readable.
_MAX_LISTED_VALIDATION_ERRORS: int = 20


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LoadedConfig:
    """
    A configuration file, validated and as written.

    Attributes:
        config:  The validated configuration.
        written: The file as parsed, before any placeholder is replaced (an
                 unquoted ${VAR} alone is an UnquotedPlaceholder): what the
                 user wrote, for the configuration a run used
                 (src/config/config_used.py).
    """

    config: ToolConfig
    written: dict[str, object]


def load_config(config_path: Path) -> ToolConfig:
    """
    Load, interpolate, and validate the tool configuration from a YAML file.

    The validated part of read_config(), for the callers that need only it.

    Args:
        config_path: Filesystem path to the config.yaml file.

    Returns:
        A fully validated, frozen ToolConfig instance.

    Raises:
        ConfigurationError: As read_config().
    """
    return read_config(config_path).config


def read_config(config_path: Path) -> LoadedConfig:
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
        The validated configuration and the file as written.

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

    # Phase B: YAML parsing of the file as written.
    written = _parse_yaml(raw_content, absolute_path)

    # Phase C: environment variable interpolation in the parsed values.
    interpolated = _interpolate_env_vars(written, absolute_path)

    # Phase D: Pydantic validation.
    config = _validate(interpolated, absolute_path)

    log.info(
        "config_loading_completed",
        config_path=str(absolute_path),
        base_url=str(config.target.base_url),
        min_priority=config.execution.min_priority,
        strategies=[s.value for s in config.execution.strategies],
        fail_fast=config.execution.fail_fast,
        gateway_configured=config.gateway is not None,
    )

    return LoadedConfig(config=config, written=written)


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
# Phase B — YAML parsing
# ---------------------------------------------------------------------------


class _DuplicateKeyError(yaml.YAMLError):
    """A key written twice in the same mapping of config.yaml."""

    def __init__(self, key: object, first_line: int, second_line: int) -> None:
        """
        Record the key and the two lines where it is written.

        Args:
            key:         The repeated key.
            first_line:  Line (1-based) of its first occurrence.
            second_line: Line (1-based) of the repetition.
        """
        super().__init__(f"duplicate key {key!r}")
        self.key = key
        self.first_line = first_line
        self.second_line = second_line


class UnquotedPlaceholder(str):
    """
    A value written as an unquoted ${VAR_NAME} alone: it takes the type of its value.

    Kept in LoadedConfig.written, so the configuration a run used writes it
    unquoted again.
    """

    __slots__ = ()


class _UniqueKeyLoader(yaml.SafeLoader):
    """
    PyYAML's safe loader, rejecting a key repeated in the same mapping.

    PyYAML keeps the last value of a repeated key and says nothing (Q-68), so a
    setting written twice would silently lose its first value. Each mapping is
    checked on its own: the same key under different parents, or in different
    items of a list, is not a repetition; a merge key (<<) is not checked.

    An unquoted scalar that is a ${VAR_NAME} alone is built as an
    UnquotedPlaceholder (Phase C types it); quoted, it is a plain str.
    """

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[object, object]:
        """Build the mapping as PyYAML does, after checking its keys are unique."""
        first_line: dict[object, int] = {}
        for key_node, _value_node in node.value:
            if key_node.tag == _YAML_MERGE_TAG:
                continue
            key = self.construct_object(key_node, deep=True)
            try:
                line = first_line.setdefault(key, key_node.start_mark.line + 1)
            except TypeError:
                continue  # an unhashable key: PyYAML reports it below
            if line != key_node.start_mark.line + 1:
                raise _DuplicateKeyError(key, line, key_node.start_mark.line + 1)
        return super().construct_mapping(node, deep=deep)

    def construct_placeholder_or_str(self, node: yaml.ScalarNode) -> str:
        """Build a string scalar, marking an unquoted ${VAR_NAME} alone."""
        value = self.construct_scalar(node)
        if node.style is None and ENV_VAR_PATTERN.fullmatch(value):
            return UnquotedPlaceholder(value)
        return value


_UniqueKeyLoader.add_constructor(_YAML_STR_TAG, _UniqueKeyLoader.construct_placeholder_or_str)


def _parse_yaml(raw_content: str, config_path: Path) -> dict[str, object]:
    """
    Parse config.yaml as written, before any placeholder is replaced.

    Three failure modes, each a ConfigurationError:

    1. A key written twice in the same mapping (PyYAML would keep the last
       one silently): rejected, naming the key and both lines.
    2. yaml.YAMLError: the file is not valid YAML. PyYAML's message is
       included verbatim because it pinpoints the line and column; it can
       quote the file, never a value from the environment (not yet replaced).
    3. The top level is not a mapping.

    Args:
        raw_content: The file content.
        config_path: Path of the source file, used only for error messages.

    Returns:
        The top-level mapping, with ${VAR_NAME} placeholders as written.

    Raises:
        ConfigurationError: On any of the failures above.
    """
    try:
        # _UniqueKeyLoader is a yaml.SafeLoader subclass: no arbitrary object is built.
        written = yaml.load(raw_content, Loader=_UniqueKeyLoader)  # noqa: S506  # nosec B506
    except _DuplicateKeyError as exc:
        raise ConfigurationError(
            message=(
                f"Configuration invalid: key '{exc.key}' written twice in the same mapping "
                f"(lines {exc.first_line} and {exc.second_line} of {config_path}): keep one."
            ),
            config_path=str(config_path),
        ) from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            message=(f"YAML syntax error in configuration file '{config_path}': {exc}"),
            config_path=str(config_path),
        ) from exc

    if not isinstance(written, dict):
        raise ConfigurationError(
            message=(
                f"Configuration file '{config_path}' must contain a YAML mapping "
                f"at the top level. Got: {type(written).__name__}. "
                "Ensure the file starts with keys like 'target:', 'execution:', etc."
            ),
            config_path=str(config_path),
        )
    return written


# ---------------------------------------------------------------------------
# Phase C — Environment variable interpolation
# ---------------------------------------------------------------------------


def _placeholders_in(value: object) -> set[str]:
    """
    Return the names of the ${VAR_NAME} placeholders in the string values of a parsed tree.

    Args:
        value: A parsed YAML value (mapping, list, scalar).

    Returns:
        The variable names; keys are not searched.
    """
    if isinstance(value, str):
        return set(ENV_VAR_PATTERN.findall(value))
    if isinstance(value, dict):
        return set().union(*(_placeholders_in(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_placeholders_in(item) for item in value))
    return set()


def _scalar_of(text: str) -> object:
    """
    Return the value an unquoted placeholder takes: text read as one YAML scalar.

    Only a number, a boolean or an empty value is taken ("5" -> 5, "true" ->
    True, "" -> None), as YAML reads them when written in place; anything
    else stays the exact text, so a value never becomes a list, a mapping, or
    a truncated string ("ab #cd").

    Args:
        text: The variable's value.

    Returns:
        The typed scalar, or text unchanged.
    """
    try:
        scalar = yaml.safe_load(text)
    except yaml.YAMLError:
        return text
    return scalar if isinstance(scalar, _PLACEHOLDER_SCALAR_TYPES) else text


def _replace_placeholders(value: object, variables: dict[str, str]) -> object:
    """
    Return a copy of a parsed tree with ${VAR_NAME} replaced in its string values.

    Args:
        value:     A parsed YAML value (mapping, list, scalar).
        variables: The value of every placeholder name found in the tree.

    Returns:
        The same structure. An unquoted placeholder alone takes the type of
        its value (_scalar_of); any other string stays a str (the schema
        converts it, e.g. "30" for an integer field). Keys and non-string
        scalars are unchanged.
    """
    if isinstance(value, str):
        replaced = ENV_VAR_PATTERN.sub(lambda match: variables[match.group("var_name")], value)
        return _scalar_of(replaced) if isinstance(value, UnquotedPlaceholder) else replaced
    if isinstance(value, dict):
        return {key: _replace_placeholders(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [_replace_placeholders(item, variables) for item in value]
    return value


def _interpolate_env_vars(written: dict[str, object], config_path: Path) -> dict[str, object]:
    """
    Replace every ${VAR_NAME} in the parsed string values with its environment value.

    The replacement works on values already parsed, never on the text: a value
    from the environment is not read as YAML structure, so it cannot add keys,
    end in a comment, or appear in a YAML error (Q-69). A placeholder is a
    whole value or part of one ("Bearer ${TOKEN}"); in a key or a comment it
    is not replaced. Unquoted and alone, it takes the type of a number, a
    boolean or an empty value, as if written in its place (count: ${N} with
    N=5 is 5; "${N}" is "5"). Every variable is read once, after checking
    they are all set.

    Args:
        written:     The parsed configuration, placeholders as written.
        config_path: Path of the source file, used only for error messages.

    Returns:
        The configuration with every placeholder replaced.

    Raises:
        ConfigurationError: If a placeholder's environment variable is not
                            set; the message names every one.
    """
    names = _placeholders_in(written)
    if not names:
        log.debug("config_no_env_placeholders_found")
        return written

    log.debug(
        "config_env_placeholders_found",
        placeholder_count=len(names),
        placeholder_names=sorted(names),
    )

    missing_variables = [name for name in sorted(names) if name not in os.environ]
    if missing_variables:
        first_missing = missing_variables[0]
        raise ConfigurationError(
            message=(
                f"Environment variable(s) not set: {', '.join(missing_variables)}. "
                f"Export the required variable(s) before running the tool. "
                f"Example: export {first_missing}=<value>"
            ),
            variable_name=first_missing,
            config_path=str(config_path),
        )

    variables = {name: os.environ[name] for name in names}
    interpolated = _replace_placeholders(written, variables)
    log.debug("config_env_interpolation_completed", variables_resolved=len(names))
    return typing.cast("dict[str, object]", interpolated)


# ---------------------------------------------------------------------------
# Phase D — Pydantic validation
# ---------------------------------------------------------------------------


def _validate(interpolated: dict[str, object], config_path: Path) -> ToolConfig:
    """
    Validate the interpolated configuration against ToolConfig.

    A structure that does not conform to ToolConfig's schema (wrong type, out
    of range, missing, or an unknown key) is a ConfigurationError listing
    every error as a dotted path into config.yaml (e.g., 'target.base_url');
    the first one is also stored in ConfigurationError.config_path.

    Args:
        interpolated: The parsed configuration with every placeholder replaced.
        config_path:  Path of the source file, used only for error messages.

    Returns:
        A fully validated, frozen ToolConfig instance.

    Raises:
        ConfigurationError: On Pydantic validation failures.
    """
    try:
        config = ToolConfig.model_validate(without_empty_blocks(interpolated, ToolConfig))
    except ValidationError as exc:
        # Pydantic v2 errors() returns a list of TypedDict with 'loc' as a
        # tuple of (str | int) representing the path into the model.
        errors = exc.errors(include_url=False)
        listed = describe_validation_errors(exc, ToolConfig)
        first_path = ".".join(str(part) for part in errors[0]["loc"])

        raise ConfigurationError(
            message=(
                f"Configuration validation failed with {exc.error_count()} error(s):\n"
                + "\n".join(f"  - {line}" for line in listed)
            ),
            config_path=first_path if first_path else str(config_path),
        ) from exc

    log.debug(
        "config_pydantic_validation_passed",
        model_fields_validated=len(ToolConfig.model_fields),
    )

    return config


def without_empty_blocks(data: dict[str, object], model: type[BaseModel]) -> dict[str, object]:
    """
    Return data without the declared blocks written empty, so they take their defaults.

    YAML reads a key with nothing under it (every line commented) as null, and
    a block's model rejects null. A block written empty means "nothing set
    here": it is dropped when the schema declares it as a block (a model or a
    mapping), it has a default, and null is not one of its valid values.
    Applied to the whole configuration and, after test discovery, to the tests
    section (src/config/tests_section.py). Everything else is unchanged: a
    required block written empty is still an error, a scalar written empty
    ("max_requests:") is still an error, and free data (a resource body, header
    values, path_seed values) is never inspected.

    Args:
        data:  A mapping of config.yaml, as parsed.
        model: The model it is validated with.

    Returns:
        A copy of data without the empty blocks, at every level the model
        declares.
    """
    fields = {field.alias or name: field for name, field in model.model_fields.items()}
    kept: dict[str, object] = {}
    for key, value in data.items():
        field = fields.get(key)
        if field is None:
            kept[key] = value  # an unknown key: validation reports it
            continue
        if value is None:
            if (
                _is_block(field.annotation)
                and not field.is_required()
                and not _accepts_none(field.annotation)
            ):
                continue
            kept[key] = value
            continue
        kept[key] = _without_empty_blocks_in(value, field.annotation)
    return kept


def _without_empty_blocks_in(value: object, annotation: object) -> object:
    """
    Apply without_empty_blocks to a value of a field, at the levels its annotation declares.

    Args:
        value:      The value as parsed.
        annotation: The field annotation.

    Returns:
        The value, its empty blocks dropped where it is a model or a mapping of
        names to a model (resources); any other value unchanged.
    """
    if not isinstance(value, dict):
        return value
    entry_model = mapping_entry_model(annotation)
    if entry_model is not None:
        return {
            name: without_empty_blocks(entry, entry_model) if isinstance(entry, dict) else entry
            for name, entry in value.items()
        }
    block_model = model_in_annotation(annotation)
    return without_empty_blocks(value, block_model) if block_model is not None else value


def _is_block(annotation: object) -> bool:
    """
    True when a field annotation is a block of config.yaml: a model or a mapping.

    Handles wrappers such as Optional[...] and Annotated[...].

    Args:
        annotation: A field annotation from model_fields.

    Returns:
        Whether a value of the field is written as a mapping.
    """
    if model_in_annotation(annotation) is not None:
        return True
    if typing.get_origin(annotation) is dict:
        return True
    return any(_is_block(argument) for argument in typing.get_args(annotation))


def _accepts_none(annotation: object) -> bool:
    """
    True when null is a valid value of a field annotation (Optional[...], X | None).

    Args:
        annotation: A field annotation from model_fields.

    Returns:
        Whether None is one of the annotation's members.
    """
    return annotation is None or type(None) in typing.get_args(annotation)


def closest_match(value: str, candidates: list[str], cutoff: float) -> str | None:
    """
    Return the candidate most similar to value, if similar enough.

    The single implementation of the "did you mean ...?" suggestion, used for
    unknown configuration keys and for unknown execution.test_ids entries.

    Args:
        value:      The unknown value as written by the user.
        candidates: The valid values.
        cutoff:     Minimum similarity (difflib ratio, 0-1).

    Returns:
        The closest candidate, or None when none reaches the cutoff.
    """
    matches = difflib.get_close_matches(value, candidates, n=1, cutoff=cutoff)
    return matches[0] if matches else None


def describe_validation_errors(
    exc: ValidationError, root: type[BaseModel], prefix: str = ""
) -> list[str]:
    """
    Render the errors of a validation as '<dotted.path>: <message>' lines.

    The single rendering of configuration errors: ToolConfig, and the tests
    section validated after test discovery (src/config/tests_section.py).
    At most _MAX_LISTED_VALIDATION_ERRORS lines, then "... and N more".

    Args:
        exc:    The validation error.
        root:   The model that was validated (for the "did you mean" keys).
        prefix: Dotted key of that model in config.yaml ('' for the root).

    Returns:
        One line per error.
    """
    lines = [
        _describe_validation_error(error, root, prefix) for error in exc.errors(include_url=False)
    ]
    listed = lines[:_MAX_LISTED_VALIDATION_ERRORS]
    not_listed = len(lines) - len(listed)
    if not_listed:
        listed.append(f"... and {not_listed} more")
    return listed


def _describe_validation_error(error: ErrorDetails, root: type[BaseModel], prefix: str) -> str:
    """
    Render one Pydantic validation error as '<dotted.path>: <message>'.

    An unknown key (extra="forbid") is reported as 'unknown key', with the
    closest key declared at the same level when one is similar enough. An
    error of the whole model (a check across sections) has no path: its
    message names the keys.

    Args:
        error:  One entry of ValidationError.errors().
        root:   The model that was validated.
        prefix: Dotted key of that model in config.yaml ('' for the root).

    Returns:
        A single-line description of the error.
    """
    loc: tuple[str | int, ...] = tuple(error["loc"])
    dotted_path = prefix + ".".join(str(part) for part in loc)
    if not loc:
        return f"{prefix.rstrip('.')}: {error['msg']}" if prefix else str(error["msg"])
    if error["type"] != _PYDANTIC_EXTRA_FORBIDDEN:
        return f"{dotted_path}: {error['msg']}"

    suggestion = closest_match(str(loc[-1]), _known_keys_at(loc[:-1], root), _KEY_SUGGESTION_CUTOFF)
    if suggestion is not None:
        return f"{dotted_path}: unknown key (did you mean '{suggestion}'?)"
    return f"{dotted_path}: unknown key"


def _known_keys_at(loc: tuple[str | int, ...], root: type[BaseModel]) -> list[str]:
    """
    Return the keys the schema declares at a location of config.yaml.

    Walks the root model field by field along loc. In a mapping of names to a
    model (resources), the name is chosen by the user and the walk continues
    in the model. Returns an empty list when the location is not a model
    (e.g. a free-form mapping such as path_seed).

    Args:
        loc:  Location of the mapping, as in a Pydantic error 'loc'.
        root: The model loc is relative to.

    Returns:
        The declared keys at that location, as written in config.yaml (a
        field's alias when it has one, e.g. 'in' for send_as.location).
    """
    model: type[BaseModel] | None = root
    # Model of the entries when the previous part was a name -> model mapping.
    entry_model: type[BaseModel] | None = None
    for part in loc:
        if entry_model is not None:
            model, entry_model = entry_model, None  # 'part' is a name chosen by the user
            continue
        if model is None:
            return []
        fields = {field.alias or name: field for name, field in model.model_fields.items()}
        field = fields.get(str(part))
        if field is None:
            return []
        entry_model = mapping_entry_model(field.annotation)
        model = None if entry_model is not None else model_in_annotation(field.annotation)
    if model is None:
        return []
    return [field.alias or name for name, field in model.model_fields.items()]


def mapping_entry_model(annotation: object) -> type[BaseModel] | None:
    """
    Return the model of the values of a mapping annotation (dict[str, Model]).

    Handles wrappers such as Optional[...] and Annotated[...].

    Args:
        annotation: A field annotation from model_fields.

    Returns:
        The model of the mapping's values, or None when the annotation is not
        a mapping of names to a model (e.g. dict[str, str]).
    """
    if typing.get_origin(annotation) is dict:
        arguments = typing.get_args(annotation)
        return model_in_annotation(arguments[-1]) if arguments else None
    for argument in typing.get_args(annotation):
        model = mapping_entry_model(argument)
        if model is not None:
            return model
    return None


def model_in_annotation(annotation: object) -> type[BaseModel] | None:
    """
    Return the Pydantic model inside a field annotation, if any.

    Handles plain models and wrappers such as Optional[...] and Annotated[...].

    Args:
        annotation: A field annotation from model_fields.

    Returns:
        The first BaseModel subclass found, or None.
    """
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    for argument in typing.get_args(annotation):
        model = model_in_annotation(argument)
        if model is not None:
            return model
    return None
