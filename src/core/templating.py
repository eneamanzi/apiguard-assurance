"""
src/core/templating.py

Placeholders: the values the tool fills in configuration strings.

One syntax for every place (docs/architecture/design-decisions.md, D6):
a name between braces, '{owner}', in a path or in a string of a JSON body.
Names are identifiers (letters, digits, underscore); '{{' and '}}' are literal
braces. Python's other format forms are rejected: '{a.b}', '{a[0]}',
'{a:>8}', '{a!r}', '{}', a single '{' or '}'.

Functions:
    placeholder_names(text)            names in one string
    names_in(value)                    names in a body (nested dicts and lists)
    occurrences(value, name)           how many times a name appears in a body
    unquoted_placeholders(value, names)
        names written without quotes in YAML: 'email: {username}' is read as
        the mapping {"username": None}, which would be sent as an object
    render(value, values)              a copy with every placeholder filled

Rendering never calls str.format: format strings can read attributes
('{x.__class__}'); the text is rebuilt piece by piece instead.

Where the names are checked: the models of src/core/models (resources) and
the configuration schema (src/config/schema, which also checks the test
parameters: src/test_config cannot import src.core).

TemplateError is a ValueError, so that inside a Pydantic validator it becomes
a validation error, and the run stops with exit 10 (ConfigurationError).

Dependency rule: imports only from the stdlib.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from string import Formatter

# A placeholder name: a Python identifier, ASCII only.
_NAME_PATTERN: re.Pattern[str] = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

_FORMATTER: Formatter = Formatter()


class TemplateError(ValueError):
    """A string with a malformed or unknown placeholder."""


def placeholder_names(text: str) -> frozenset[str]:
    """
    Return the placeholder names in a string.

    Args:
        text: The string, e.g. '/api/v1/repos/{owner}/{repo}'.

    Returns:
        The names, e.g. frozenset({'owner', 'repo'}); empty when there are none.

    Raises:
        TemplateError: On a malformed placeholder or an unmatched brace.
    """
    return frozenset(name for _, name in _pieces(text) if name is not None)


def names_in(value: object) -> frozenset[str]:
    """
    Return the placeholder names in every string of a value.

    Args:
        value: A string, or dicts and lists holding strings at any depth;
               other leaves (numbers, booleans, None) have no placeholders.

    Returns:
        The names found.

    Raises:
        TemplateError: On a malformed placeholder.
    """
    if isinstance(value, str):
        return placeholder_names(value)
    found: frozenset[str] = frozenset()
    for item in _children(value):
        found |= names_in(item)
    return found


def occurrences(value: object, name: str) -> int:
    """
    Return how many times a placeholder appears in every string of a value.

    Args:
        value: A string, or dicts and lists holding strings at any depth.
        name:  The placeholder name, e.g. 'ssrf_url'.

    Returns:
        The count (0 when absent).

    Raises:
        TemplateError: On a malformed placeholder.
    """
    if isinstance(value, str):
        return sum(1 for _, found in _pieces(value) if found == name)
    return sum(occurrences(item, name) for item in _children(value))


def unquoted_placeholders(value: object, names: frozenset[str]) -> frozenset[str]:
    """
    Return the names written as a placeholder without quotes in YAML.

    YAML reads 'email: {username}' as 'email: {"username": None}': a mapping
    with one key, a known name, and no value. The tool would send it as a JSON
    object instead of the value. 'email: "{username}"' is the intended form.

    Args:
        value: A body, as loaded from YAML.
        names: The placeholder names allowed at this place.

    Returns:
        The names found in that form.
    """
    found: frozenset[str] = frozenset()
    if isinstance(value, Mapping) and len(value) == 1:
        ((key, item),) = value.items()
        if item is None and key in names:
            found |= {key}
    for item in _children(value):
        found |= unquoted_placeholders(item, names)
    return found


def render(value: object, values: Mapping[str, str]) -> object:
    """
    Return a copy of a value with every placeholder filled.

    Args:
        value:  A string, or dicts and lists holding strings at any depth.
        values: Placeholder name -> value.

    Returns:
        The same structure with the strings filled; other leaves unchanged.

    Raises:
        TemplateError: On a malformed placeholder, or a name without a value.
    """
    if isinstance(value, str):
        return _render_text(value, values)
    if isinstance(value, Mapping):
        return {key: render(item, values) for key, item in value.items()}
    if isinstance(value, list):
        return [render(item, values) for item in value]
    return value


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _pieces(text: str) -> list[tuple[str, str | None]]:
    """
    Split a string into (literal text, placeholder name or None) pieces.

    Formatter.parse already turns '{{' and '}}' into literal braces and
    rejects unmatched ones; the forms it accepts beyond a plain name are
    rejected here.
    """
    try:
        parsed = list(_FORMATTER.parse(text))
    except ValueError as exc:
        raise TemplateError(f"Malformed placeholder in {text!r}: {exc}.") from exc
    pieces: list[tuple[str, str | None]] = []
    for literal, name, spec, conversion in parsed:
        if name is None:
            pieces.append((literal, None))
            continue
        if spec or conversion or not _NAME_PATTERN.fullmatch(name):
            written = "{" + name + (f"!{conversion}" if conversion else "")
            written += (f":{spec}" if spec else "") + "}"
            raise TemplateError(
                f"Malformed placeholder {written} in {text!r}: write a name between braces, "
                "e.g. {owner}; write literal braces as {{ and }}."
            )
        pieces.append((literal, name))
    return pieces


def _render_text(text: str, values: Mapping[str, str]) -> str:
    """Fill the placeholders of one string."""
    parts: list[str] = []
    for literal, name in _pieces(text):
        parts.append(literal)
        if name is None:
            continue
        if name not in values:
            raise TemplateError(
                f"Placeholder {{{name}}} in {text!r} has no value here; "
                f"known: {', '.join(sorted(values)) or 'none'}."
            )
        parts.append(values[name])
    return "".join(parts)


def _children(value: object) -> list[object]:
    """The direct items of a mapping or a list; nothing for other values."""
    if isinstance(value, Mapping):
        return list(value.values())
    if isinstance(value, list):
        return list(value)
    return []
