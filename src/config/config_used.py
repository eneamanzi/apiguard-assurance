"""
src/config/config_used.py

The configuration a run used, written as a config.yaml that runs the same assessment.

A key the user leaves out takes the default of its model, which no other output
shows. Every run writes config_used.yaml among its outputs (engine, right after
the test checks; ``apiguard validate-config --show-config`` prints the same
text): every key of the schema, the tests section included, each marked
``# specified`` (written in the user's config.yaml) or ``# default``. Passed
back to ``apiguard run --config``, it runs the same assessment.

What it never contains is a value from the environment or a secret:

    - a value written with a ${VAR} placeholder is written as the user wrote
      it (quoted or not), never resolved: the tool cannot know whether the
      value of a variable is a secret (a key in a body), and the same
      environment (.env) resolves it again on the re-run;
    - a field marked SECRET_VALUE (passwords, tokens, Admin API header values)
      written in clear becomes a placeholder named after its key
      (``${APIGUARD_CREDENTIALS_ADMIN_PASSWORD}``), with a note: the re-run
      stops naming the variable until it is exported;
    - any other value is the one the run used, as validated (an absolute
      path, a default).

Dependency rule: imports from the stdlib, PyYAML, pydantic, src.config and
src.core; never from tests/ (the parameters are passed in).
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping

from pydantic import BaseModel
from pydantic.fields import FieldInfo

from src.config.loader import (
    ENV_VAR_PATTERN,
    UnquotedPlaceholder,
    mapping_entry_model,
    model_in_annotation,
)
from src.config.schema import ToolConfig
from src.config.tests_section import TESTS_SECTION, config_model
from src.core.assessment_test import has_marker
from src.core.models.runtime import SECRET_VALUE
from src.core.test_metadata import section_keys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# The mark of each value: written by the user, or the tool's default.
SPECIFIED_MARK: str = "specified"
DEFAULT_MARK: str = "default"

# Prefix of the placeholder that replaces a secret written in clear.
GENERATED_VARIABLE_PREFIX: str = "APIGUARD"

# Note on a secret written in clear, replaced by a generated placeholder.
_IN_CLEAR_NOTE: str = "written in clear in your config.yaml: export {name} to re-run"

# One level of indentation, as in config.example.yaml.
_INDENT: str = "  "

# A key written without quotes: letters, digits, '_', '-', '.', not starting
# with a digit or a sign, and not a word YAML 1.1 reads as a boolean or null.
_PLAIN_KEY: re.Pattern[str] = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
_YAML_SPECIAL_WORDS: frozenset[str] = frozenset(
    {"y", "n", "yes", "no", "on", "off", "true", "false", "null", "~"}
)

_HEADER: str = """\
# The configuration of this assessment: every value it uses (APIGuard Assurance {version}).
# Every key: "# specified" is written in your config.yaml, "# default" is the tool's
# default. Pass this file to `apiguard run --config` to run the same assessment.
# Values written as ${{VAR}} are resolved from the environment (or .env), as in your
# config.yaml; no secret and no value from the environment is written here.
"""

# Stands for a key absent from the user's file.
_NOT_WRITTEN: object = object()


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def config_used_yaml(
    config: ToolConfig,
    written: Mapping[str, object],
    test_params: Mapping[str, BaseModel],
    tool_version: str,
) -> str:
    """
    Return the configuration a run used, as the text of a config.yaml.

    Args:
        config:       The validated configuration.
        written:      The file as written (LoadedConfig.written).
        test_params:  Test ID -> its validated parameters (engine.check_tests).
        tool_version: The tool's version, named in the header.

    Returns:
        The YAML text: every key of the schema in its order, each value
        marked specified or default.
    """
    used: dict[str, object] = config.model_dump(mode="json", by_alias=True)
    tests_used: dict[str, dict[str, object]] = {}
    for test_id in sorted(test_params):
        domain_key, test_key = section_keys(test_id)
        tests_used.setdefault(domain_key, {})[test_key] = test_params[test_id].model_dump(
            mode="json", by_alias=True
        )
    used[TESTS_SECTION] = tests_used

    model = config_model({test_id: type(params) for test_id, params in test_params.items()})
    lines = [_HEADER.format(version=tool_version)]
    _emit_model(used, written, model, (), 0, lines)
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Walking the schema
# ---------------------------------------------------------------------------


def _emit_model(
    used: Mapping[str, object],
    written: object,
    model: type[BaseModel],
    path: tuple[str, ...],
    depth: int,
    lines: list[str],
) -> None:
    """
    Write the keys of one block of the schema, in the model's order.

    Args:
        used:    The block's values as the run used them.
        written: The block as written, or _NOT_WRITTEN.
        model:   The block's model.
        path:    Keys from the root, for the generated variable names.
        depth:   Indentation level.
        lines:   Output lines, appended to.
    """
    fields = {field.alias or name: field for name, field in model.model_fields.items()}
    written_block = written if isinstance(written, Mapping) else {}
    for key, value in used.items():
        _emit_field(
            key,
            value,
            written_block.get(key, _NOT_WRITTEN),
            fields[key],
            path + (key,),
            depth,
            lines,
        )


def _emit_field(
    key: str,
    value: object,
    written: object,
    field: FieldInfo,
    path: tuple[str, ...],
    depth: int,
    lines: list[str],
) -> None:
    """
    Write one key: a block of the schema is walked, anything else is a value.

    A mapping of names to a model (resources) and a model are blocks; a
    scalar, a list and free data (a body, headers, path_seed) are values,
    marked as a whole.

    Args:
        key:     The key as written in config.yaml.
        value:   Its value as the run used it.
        written: Its value as written, or _NOT_WRITTEN.
        field:   Its field in the model.
        path:    Keys from the root, this one included.
        depth:   Indentation level.
        lines:   Output lines, appended to.
    """
    pad = _INDENT * depth
    entry_model = mapping_entry_model(field.annotation)
    if isinstance(value, dict) and entry_model is not None:
        written_entries = written if isinstance(written, Mapping) else {}
        if not value:
            lines.append(f"{pad}{_key(key)}: {{}}  # {_mark(written)}")
            return
        lines.append(f"{pad}{_key(key)}:")
        for name, entry in value.items():
            lines.append(f"{pad}{_INDENT}{_key(name)}:")
            _emit_model(
                entry,
                written_entries.get(name, _NOT_WRITTEN),
                entry_model,
                path + (name,),
                depth + 2,
                lines,
            )
        return
    block_model = model_in_annotation(field.annotation)
    if isinstance(value, dict) and block_model is not None and block_model.model_fields:
        lines.append(f"{pad}{_key(key)}:")
        _emit_model(value, written, block_model, path, depth + 1, lines)
        return

    shown, generated = _shown_value(value, written, has_marker(field, SECRET_VALUE), path)
    mark = _mark(written)
    if generated:
        mark += "; " + _IN_CLEAR_NOTE.format(name=", ".join(generated))
    _emit_value(key, shown, mark, depth, lines)


def _mark(written: object) -> str:
    """The mark of a value: specified when the user's file has its key."""
    return DEFAULT_MARK if written is _NOT_WRITTEN else SPECIFIED_MARK


# ---------------------------------------------------------------------------
# The value written for a key
# ---------------------------------------------------------------------------


def _shown_value(
    value: object, written: object, secret: bool, path: tuple[str, ...]
) -> tuple[object, list[str]]:
    """
    Return the value to write for a key, and the generated variable names.

    Args:
        value:   The value the run used.
        written: The value as written, or _NOT_WRITTEN.
        secret:  Whether the field is marked SECRET_VALUE.
        path:    Keys from the root.

    Returns:
        The written form when it has a placeholder; for a secret written in
        clear, a generated placeholder (each value of a mapping on its own);
        otherwise the value used.
    """
    if written is not _NOT_WRITTEN and _has_placeholder(written):
        if not (secret and isinstance(written, Mapping)):
            return written, []
    if not secret or value is None:
        return value, []
    if isinstance(value, Mapping):
        written_values = written if isinstance(written, Mapping) else {}
        shown: dict[str, object] = {}
        generated: list[str] = []
        for name in value:
            as_written = written_values.get(name, _NOT_WRITTEN)
            if as_written is not _NOT_WRITTEN and _has_placeholder(as_written):
                shown[name] = as_written
            else:
                variable = _generated_variable(path + (str(name),))
                shown[name] = f"${{{variable}}}"
                generated.append(variable)
        return shown, generated
    variable = _generated_variable(path)
    return f"${{{variable}}}", [variable]


def _has_placeholder(value: object) -> bool:
    """True when a written value, or anything inside it, contains a ${VAR} placeholder."""
    if isinstance(value, str):
        return ENV_VAR_PATTERN.search(value) is not None
    if isinstance(value, Mapping):
        return any(_has_placeholder(item) for item in value.values())
    if isinstance(value, list):
        return any(_has_placeholder(item) for item in value)
    return False


def _generated_variable(path: tuple[str, ...]) -> str:
    """The variable named after a key: APIGUARD_CREDENTIALS_ADMIN_PASSWORD."""
    parts = [re.sub(r"[^A-Za-z0-9]", "_", part).upper() for part in path]
    return "_".join([GENERATED_VARIABLE_PREFIX, *parts])


# ---------------------------------------------------------------------------
# YAML text
# ---------------------------------------------------------------------------


def _emit_value(key: str, value: object, mark: str, depth: int, lines: list[str]) -> None:
    """
    Write a key and its value, with its mark as a comment.

    A scalar or a list of scalars goes on the key's line; a mapping or a list
    holding mappings goes in a block under it.

    Args:
        key:   The key.
        value: The value to write.
        mark:  The comment.
        depth: Indentation level.
        lines: Output lines, appended to.
    """
    pad = _INDENT * depth
    if _is_inline(value):
        lines.append(f"{pad}{_key(key)}: {_inline(value)}  # {mark}")
        return
    lines.append(f"{pad}{_key(key)}:  # {mark}")
    _emit_block(value, depth + 1, lines)


def _emit_block(value: object, depth: int, lines: list[str]) -> None:
    """Write a mapping or a list as a YAML block, one item per line."""
    pad = _INDENT * depth
    if isinstance(value, Mapping):
        items = [(f"{pad}{_key(str(name))}:", item) for name, item in value.items()]
    elif isinstance(value, list):
        items = [(f"{pad}-", item) for item in value]
    else:
        items = []
    for lead, item in items:
        if _is_inline(item):
            lines.append(f"{lead} {_inline(item)}")
        else:
            lines.append(lead)
            _emit_block(item, depth + 1, lines)


def _is_inline(value: object) -> bool:
    """True for a value written on one line: a scalar, an empty mapping, a list of scalars."""
    if isinstance(value, Mapping):
        return not value
    if isinstance(value, list):
        return all(not isinstance(item, Mapping | list) for item in value)
    return True


def _inline(value: object) -> str:
    """The YAML text of a value written on one line."""
    if isinstance(value, Mapping):
        return "{}"
    if isinstance(value, list):
        return "[" + ", ".join(_scalar(item) for item in value) + "]"
    return _scalar(value)


def _scalar(value: object) -> str:
    """
    The YAML text of a scalar, read back as the same value.

    An unquoted placeholder stays unquoted (it takes the type of its value);
    any other string is double-quoted (JSON's form, valid YAML); a float
    keeps a decimal point, which PyYAML needs to read an exponent as a float.

    Args:
        value: The scalar.

    Returns:
        Its text.
    """
    if isinstance(value, UnquotedPlaceholder):
        return str(value)
    if isinstance(value, float):
        text = repr(value)
        mantissa, exponent_mark, exponent = text.partition("e")
        if exponent_mark and "." not in mantissa:
            return f"{mantissa}.0e{exponent}"
        return text
    return json.dumps(value, ensure_ascii=False)


def _key(key: str) -> str:
    """A key as written: plain when YAML reads it back as the same string, else quoted."""
    if _PLAIN_KEY.match(key) and key.lower() not in _YAML_SPECIAL_WORDS:
        return key
    return json.dumps(key, ensure_ascii=False)
