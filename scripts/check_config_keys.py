"""
scripts/check_config_keys.py

Check that config.example.yaml lists every configuration key, and nothing else,
and that it loads as written.

config.example.yaml is the one complete configuration of the repository: every
key of the schema, with its description. The lab configurations hold only
what each lab needs. This script walks the configuration schema (ToolConfig,
with its tests section built from the parameter models the tests declare,
src/config/tests_section.py) and the YAML keys of
the example, and fails when a schema key is missing from the example or the
example has a key the schema does not know. Run by `hatch run dev:check`.

Keys are compared as written in config.yaml (a field's alias when it has one,
e.g. 'in' for credentials.send_as). A field whose value is a free mapping
(path_seed, gateway.admin.headers, url_accepting_endpoint.body) is a leaf: its keys
belong to the user. A mapping of names to a model (resources) is checked
field by field: the names are the user's and count as '*', so every field of
the model must appear in at least one entry (e.g. resources.*.create.path).

A section with no key (the tests section of a test without parameters) need
not be listed. A key may be listed commented out, for the alternatives that cannot be active
together in a valid file (specification.url or specification.path, tokens or
passwords): a line '<indent># <key>: ...' whose key is lowercase snake_case
counts as the key '<key>' at that indentation. Prose comments start with an
uppercase letter or have no 'key:' form, so they are not taken for keys.

The file is then loaded as written, as a user would copy it: the loader
(src/config/loader.py) and the tests section check (engine.check_tests), with
no contact with the target. A ${VAR} placeholder whose variable is not set gets
a stand-in value in this process only.

Usage:
    python scripts/check_config_keys.py [path]   (default: config.example.yaml)

Exit codes: 0 aligned and loadable, 1 not aligned, 2 file unreadable, 3 does not load.
"""

from __future__ import annotations

import logging
import os
import re
import sys
import types
import typing
from pathlib import Path

import structlog
import yaml
from pydantic import BaseModel
from src.config.loader import ENV_VAR_PATTERN, load_config
from src.config.tests_section import config_model
from src.core.exceptions import ToolBaseError
from src.engine import check_tests, test_parameter_models

_DEFAULT_PATH: Path = Path("config.example.yaml")
_EXIT_ALIGNED: int = 0
_EXIT_NOT_ALIGNED: int = 1
_EXIT_UNREADABLE: int = 2
_EXIT_NOT_LOADABLE: int = 3
# Value of a placeholder whose variable is not set, for the load check only.
_STAND_IN_VALUE: str = "stand-in"
# Stands for the user's names in a mapping of names to a model (resources.*.create).
_ANY_NAME: str = "*"
# A commented-out key: '<indent># <key>:' followed by a space or the end of line.
_COMMENTED_KEY: re.Pattern[str] = re.compile(r"^(\s*)# ([a-z_][a-z0-9_]*):(\s|$)")


def uncomment_keys(text: str) -> str:
    """Turn every commented-out key line into an active one, keeping its indentation."""
    return "\n".join(_COMMENTED_KEY.sub(r"\1\2:\3", line) for line in text.splitlines())


def _model_in(annotation: object) -> type[BaseModel] | None:
    """The Pydantic model inside an annotation (Model, Model | None, Annotated[...])."""
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    origin = typing.get_origin(annotation)
    if origin is typing.Annotated or origin in (typing.Union, types.UnionType):
        for argument in typing.get_args(annotation):
            model = _model_in(argument)
            if model is not None:
                return model
    return None


def _entry_model(annotation: object) -> type[BaseModel] | None:
    """The model of the values of a dict[str, Model] annotation (wrappers included)."""
    if typing.get_origin(annotation) is dict:
        arguments = typing.get_args(annotation)
        return _model_in(arguments[-1]) if arguments else None
    for argument in typing.get_args(annotation):
        model = _entry_model(argument)
        if model is not None:
            return model
    return None


def schema_keys(model: type[BaseModel], prefix: str = "") -> set[str]:
    """
    Every dotted key of a model, nested models included.

    Args:
        model:  The model to walk.
        prefix: Dotted key of the model itself ('' for the root).

    Returns:
        The keys, as written in config.yaml.
    """
    keys: set[str] = set()
    for name, field in model.model_fields.items():
        key = f"{prefix}{field.alias or name}"
        nested = _model_in(field.annotation)
        if nested is not None and not nested.model_fields:
            continue  # a section with no key (a test without parameters): nothing to list
        keys.add(key)
        entry = _entry_model(field.annotation)
        if entry is not None:
            keys |= schema_keys(entry, f"{key}.{_ANY_NAME}.")
            continue
        if nested is not None:
            keys |= schema_keys(nested, f"{key}.")
    return keys


def file_keys(data: object, model: type[BaseModel], prefix: str = "") -> set[str]:
    """
    Every dotted key written in a YAML mapping, following the schema.

    The mapping of a field that is not a model (a free mapping) is not
    descended into.

    Args:
        data:   The parsed YAML at this level.
        model:  The model this level is validated with.
        prefix: Dotted key of this level.

    Returns:
        The keys found.
    """
    keys: set[str] = set()
    if not isinstance(data, dict):
        return keys
    fields = {field.alias or name: field for name, field in model.model_fields.items()}
    for raw_key, value in data.items():
        key = f"{prefix}{raw_key}"
        field = fields.get(str(raw_key))
        keyless = _model_in(field.annotation) if field is not None else None
        if keyless is not None and not keyless.model_fields:
            continue  # a section with no key, written empty: allowed, not listed
        keys.add(key)
        entry = _entry_model(field.annotation) if field is not None else None
        if entry is not None:
            if isinstance(value, dict):
                for item in value.values():
                    keys |= file_keys(item, entry, f"{key}.{_ANY_NAME}.")
            continue
        nested = _model_in(field.annotation) if field is not None else None
        if nested is not None:
            keys |= file_keys(value, nested, f"{key}.")
    return keys


def complete_schema() -> type[BaseModel]:
    """ToolConfig with its tests section as the tool checks it (one model per test)."""
    return config_model(test_parameter_models())


def main(argv: list[str]) -> int:
    """
    Compare the keys of a configuration file with the schema.

    Args:
        argv: Command-line arguments (an optional path).

    Returns:
        The exit code.
    """
    # The test discovery logs each test at debug level: keep the output to the result.
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING))
    path = Path(argv[1]) if len(argv) > 1 else _DEFAULT_PATH
    try:
        data = yaml.safe_load(uncomment_keys(path.read_text(encoding="utf-8")))
    except (OSError, yaml.YAMLError) as exc:
        sys.stderr.write(f"{path}: cannot read: {exc}\n")
        return _EXIT_UNREADABLE
    schema = complete_schema()
    expected = schema_keys(schema)
    found = file_keys(data, schema)
    missing = sorted(expected - found)
    unknown = sorted(found - expected)
    for key in missing:
        sys.stderr.write(f"{path}: missing key {key}\n")
    for key in unknown:
        sys.stderr.write(f"{path}: unknown key {key}\n")
    if missing or unknown:
        sys.stderr.write(
            f"{path}: not aligned with the configuration schema "
            f"({len(missing)} missing, {len(unknown)} unknown).\n"
        )
        return _EXIT_NOT_ALIGNED
    sys.stdout.write(f"{path}: all {len(expected)} configuration keys listed.\n")
    return _check_loads(path)


def _check_loads(path: Path) -> int:
    """
    Load the file as written, with the loader and the tests section check.

    Args:
        path: The configuration file.

    Returns:
        _EXIT_ALIGNED when it loads, _EXIT_NOT_LOADABLE otherwise (the error
        on stderr).
    """
    for name in ENV_VAR_PATTERN.findall(path.read_text(encoding="utf-8")):
        os.environ.setdefault(name, _STAND_IN_VALUE)
    try:
        check_tests(load_config(path))
    except ToolBaseError as exc:
        sys.stderr.write(f"{path}: does not load as written: {exc}\n")
        return _EXIT_NOT_LOADABLE
    sys.stdout.write(f"{path}: loads as written.\n")
    return _EXIT_ALIGNED


if __name__ == "__main__":
    sys.exit(main(sys.argv))
