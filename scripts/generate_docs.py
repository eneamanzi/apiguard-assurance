"""
scripts/generate_docs.py

The parts of the documentation that repeat the code, built from the test declarations.

Each test declares who it is (``info = TestInfo(...)``) and its parameters
(``BaseTest[Test21Params]``) once, in its module (docs/04-architecture/05-design-decisions.md,
D8). The documentation shows the same facts in several places; these
functions build those parts, and Cog (cogapp, a development tool) writes them
into the files between markers, leaving everything else as written:

    <!-- [[[cog import generate_docs as g; cog.out(g.catalogue()) ]]] -->
    ... generated ...
    <!-- [[[end]]] -->

    python scripts/generate_docs.py           writes every generated part (hatch run dev:gen)
    python scripts/generate_docs.py --check   fails when a part is out of date, showing the
                                              difference (in hatch run dev:check)

The files with generated parts are listed once, in GENERATED_FILES.

Generated parts:

    catalogue()             docs/05-tests/README.md, one row per test, by domain
    test_header(*ids, page) the table at the top of each test page
    strategy_matrix()       docs/04-architecture/03-assessment-model.md, tests by
                            strategy and priority
    configuration_tests()   docs/03-reference/01-configuration.md, the tests chapter:
                            one table per test with every parameter
    example_tests()         config.example.yaml, the tests section: every
                            parameter with its default and the first sentence
                            of its description

A test page is found by its header marker (``test_header("2.1", ...)``): a test
without a page stops the generation, so ``dev:check`` fails until it has one.

This file lives in scripts/ (development only), like check_config_keys.py.
"""

from __future__ import annotations

import argparse
import ast
import importlib
import inspect
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import typing
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

import structlog
import typer.main
import yaml
from annotated_types import Ge, Gt, Le, Lt
from pydantic import AnyHttpUrl, BaseModel, JsonValue
from pydantic.fields import FieldInfo
from pydantic_core import PydanticUndefined
from src.cli import app as cli_app
from src.config.loader import mapping_entry_model, model_in_annotation
from src.config.schema import ToolConfig
from src.core.assessment_test import NEEDED_TO_RUN, AssessmentTest, has_marker
from src.core.models import (
    STANDARD_FORMATS,
    DerivedFact,
    EvidenceFile,
    EvidenceRecord,
    Finding,
    InfoNote,
    NotRunEntry,
    Reference,
    SubTestResult,
    TestStrategy,
    TlsSettings,
    TransactionSummary,
)
from src.core.models.enums import EXIT_CODES
from src.core.references import CalibrationPoint, Fingerprint, PositiveControl
from src.core.test_metadata import (
    EFFECT_RANK,
    PRIORITY_MAX,
    PRIORITY_MIN,
    Effect,
    Need,
    TestInfo,
    section_keys,
)
from src.external_tests.registry import ExternalTestRegistry
from src.report.builder import (
    DOMAIN_NAMES,
    ConnectionTrust,
    DomainSummary,
    ExecutiveSummary,
    ReferencesSummary,
    ReportData,
    TestResultRow,
)
from src.tests.registry import TestRegistry
from typer.core import TyperArgument, TyperCommand, TyperOption

# Discovery logs every test at debug level: keep Cog's output to the generated text.
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING))

_ROOT: Path = Path(__file__).resolve().parent.parent
# The files with generated parts, relative to the repository root (glob patterns).
GENERATED_FILES: tuple[str, ...] = (
    "docs/05-tests/README.md",
    "docs/05-tests/*/*.md",
    "docs/05-tests/external/*/*.md",
    "docs/04-architecture/03-assessment-model.md",
    "docs/02-guides/01-usage/01-configure-a-target.md",
    "docs/03-reference/06-compatibility.md",
    "docs/06-knowledge/03-guarantees.md",
    "docs/06-knowledge/02-methodology.md",
    "docs/03-reference/01-configuration.md",
    "docs/03-reference/02-cli.md",
    "docs/03-reference/04-report-schema.md",
    "docs/03-reference/03-exit-codes.md",
    "docs/03-reference/05-evidence-format.md",
    "docs/02-guides/03-extending/02-add-a-native-test.md",
    "docs/02-guides/03-extending/03-add-an-external-test.md",
    "docs/02-guides/03-extending/04-add-a-gateway-adapter.md",
    "docs/04-architecture/01-overview.md",
    "config.example.yaml",
)
_EXIT_OUT_OF_DATE: int = 1
_TEST_PAGES: Path = _ROOT / "docs" / "05-tests"
_CONFIGURATION_PAGE: Path = _ROOT / "docs" / "03-reference" / "01-configuration.md"
_PORTABILITY: str = "../03-reference/06-compatibility.md#test-portability"
_HEADER_MARKER: re.Pattern[str] = re.compile(r"test_header\(([^)]*)\)")
_QUOTED: re.Pattern[str] = re.compile(r"""["']([^"']+)["']""")
# The first sentence of a description ends at a period followed by a space and
# an uppercase letter, a digit, a quote or an opening parenthesis; not after
# the abbreviations below ("e.g. 'x'", "NIST SP 800-131A Rev. 2").
_SENTENCE_END: re.Pattern[str] = re.compile(
    r"(?<!\be\.g\.)(?<!\bi\.e\.)(?<!\bRev\.)(?<!\bvs\.)(?<=[.!?])\s+(?=[A-Z0-9('\"])"
)
# Sequences longer than this are shown by their size and first values.
_INLINE_ITEMS: int = 3
_YAML_INDENT: str = "  "
_COMMENT_WIDTH: int = 100
_PAGE_ANCHOR_CHARS: re.Pattern[str] = re.compile(r"[^a-z0-9 _-]")


@dataclass(frozen=True)
class _Test:
    """What the documentation needs of a test."""

    info: TestInfo
    params: type[BaseModel] | None


def _tests() -> list[_Test]:
    """Every test, native then external, by ID within each."""
    found: list[AssessmentTest[Any]] = [
        *TestRegistry().list_tests(),
        *ExternalTestRegistry().list_tests(),
    ]
    tests = [_Test(info=t.info, params=type(t).params_model) for t in found]
    return sorted(tests, key=lambda t: (t.info.is_external, _id_key(t.info.id), t.info.id))


def _id_key(test_id: str) -> tuple[int, ...]:
    """Numeric sort key of a test ID ("2.10" after "2.9")."""
    return tuple(int(part) for part in re.findall(r"\d+", test_id))


def _pages() -> dict[str, Path]:
    """Test ID -> the page whose header marker names it."""
    pages: dict[str, Path] = {}
    for page in sorted(_TEST_PAGES.rglob("*.md")):
        for match in _HEADER_MARKER.finditer(page.read_text(encoding="utf-8")):
            for test_id in _QUOTED.findall(match.group(1)):
                pages.setdefault(test_id, page)
    return pages


def _relative(target: Path, page: str | Path) -> str:
    """The link from a page to a file, relative to the page's folder."""
    return os.path.relpath(target, (_ROOT / page).resolve().parent)


def _block(lines: list[str]) -> str:
    """Markdown lines with a blank line before and after, apart from the markers."""
    return "\n" + "\n".join(lines).strip("\n") + "\n\n"


def _id_cell(info: TestInfo) -> str:
    return f"`{info.id}`"


def _priority(info: TestInfo) -> str:
    return f"P{info.priority}"


def _needs(test: _Test) -> str:
    """What a test needs: its needs, its needed parameters, then its optional needs."""
    needs = [f"`{need.value}`" for need in test.info.needs]
    if test.params is not None:
        needs += [
            f"`{name}`"
            for name, field in test.params.model_fields.items()
            if has_marker(field, NEEDED_TO_RUN)
        ]
    needs += [f"`{need.value}` (optional)" for need in test.info.optional_needs]
    return ", ".join(needs) or "-"


def _prerequisites(info: TestInfo) -> str:
    parts = []
    if info.depends_on:
        parts.append("uses data of " + ", ".join(f"`{t}`" for t in info.depends_on))
    if info.requires_pass:
        parts.append("needs PASS of " + ", ".join(f"`{t}`" for t in info.requires_pass))
    return "; ".join(parts) or "none"


def _config_anchor(test: _Test) -> str:
    """The anchor of a test's section in configuration.md (GitHub's rule on its heading)."""
    domain_key, test_key = section_keys(test.info.id)
    heading = f"tests.{domain_key}.{test_key}".lower()
    return _PAGE_ANCHOR_CHARS.sub("", heading).replace(" ", "-")


# ---------------------------------------------------------------------------
# Catalogue and page headers
# ---------------------------------------------------------------------------


def catalogue() -> str:
    """
    The test catalogue of docs/05-tests/README.md: one row per test, by domain.

    Returns:
        A Markdown table.

    Raises:
        ValueError: When a test has no page (no header marker naming it).
    """
    tests = _tests()
    pages = _pages()
    missing = [t.info.id for t in tests if t.info.id not in pages]
    if missing:
        raise ValueError(
            f"tests without a page in docs/05-tests/ (a page with a test_header marker): {missing}"
        )
    readme = _TEST_PAGES / "README.md"
    native = sum(1 for t in tests if not t.info.is_external)
    lines = [
        f"{len(tests)} tests: {native} native, {len(tests) - native} external.",
        "",
        "| ID | Name | Pri. | Strategy | Effect | CWE | Needs | Page |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for domain, name in DOMAIN_NAMES.items():
        lines.append(f"| **Domain {domain} - {name}** | | | | | | | |")
        in_domain = [t for t in tests if t.info.domain == domain]
        if not in_domain:
            lines.append("| - | no test implemented | | | | | | |")
        for test in sorted(in_domain, key=lambda t: _id_key(t.info.id.removeprefix("ext."))):
            info = test.info
            link = _relative(pages[info.id], readme.relative_to(_ROOT))
            lines.append(
                f"| {_id_cell(info)} | {info.name} | {_priority(info)} | {info.strategy.value} "
                f"| {info.effect.value} | {info.cwe or '-'} | {_needs(test)} "
                f"| [{info.id}]({link}) |"
            )
    lines.append("")
    lines.append(
        "Needs: what the test needs from the configuration (credentials of a role, a gateway, a "
        "parameter); without it the engine records SKIP without running the test. An optional need "
        "is used when configured; without it the test runs and the sub-tests that use it are not "
        "applicable. What each test needs from a target, measured on the labs: "
        f"[Test portability]({_PORTABILITY})."
    )
    return _block(lines)


def test_header(*test_ids: str, page: str) -> str:
    """
    The table at the top of a test page.

    Args:
        test_ids: The tests the page describes (one, or several sharing a module).
        page:     The page's path (cog.inFile), for the relative links.

    Returns:
        A Markdown table: one column per test.
    """
    by_id = {t.info.id: t for t in _tests()}
    tests = [by_id[test_id] for test_id in test_ids]
    configuration = _relative(_CONFIGURATION_PAGE, page)

    def parameters(test: _Test) -> str:
        if test.params is None:
            return "none"
        domain_key, test_key = section_keys(test.info.id)
        return f"[`tests.{domain_key}.{test_key}`]({configuration}#{_config_anchor(test)})"

    rows: list[tuple[str, list[str]]] = [
        ("Test ID", [_id_cell(t.info) for t in tests]),
        ("Name", [t.info.name for t in tests]),
        ("Domain", [f"{t.info.domain} - {DOMAIN_NAMES[t.info.domain]}" for t in tests]),
        ("Priority / strategy", [f"{_priority(t.info)} / {t.info.strategy.value}" for t in tests]),
        ("Effect", [t.info.effect.value for t in tests]),
        ("CWE", [t.info.cwe or "none" for t in tests]),
        ("Standards", [_standards(t.info) for t in tests]),
        ("Tags", [", ".join(f"`{tag}`" for tag in t.info.tags) or "none" for t in tests]),
        ("Prerequisites", [_prerequisites(t.info) for t in tests]),
        ("Needs", [_needs(t) for t in tests]),
        ("Parameters", [parameters(t) for t in tests]),
    ]
    if any(t.info.tool for t in tests):
        rows.append(
            (
                "Tool",
                [
                    f"`{t.info.tool}` "
                    f"([`external_tools.{t.info.tool}`]({configuration}#external_tools))"
                    for t in tests
                ],
            )
        )
    lines = ["| " + " | ".join([""] * (len(tests) + 1)) + " |"]
    lines.append("|" + "---|" * (len(tests) + 1))
    for label, cells in rows:
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    return _block(lines)


def strategy_matrix() -> str:
    """
    The tests by strategy and priority (docs/04-architecture/03-assessment-model.md).

    Returns:
        A Markdown table: one row per strategy, one column per priority.
    """
    tests = _tests()
    priorities = range(PRIORITY_MIN, PRIORITY_MAX + 1)
    lines = [
        "| Strategy | " + " | ".join(f"P{p}" for p in priorities) + " |",
        "|---|" + "---|" * len(priorities),
    ]
    for strategy in TestStrategy:
        cells = []
        for priority in priorities:
            ids = [
                _id_cell(t.info)
                for t in tests
                if t.info.strategy is strategy and t.info.priority == priority
            ]
            cells.append(", ".join(ids) or "-")
        lines.append(f"| `{strategy.value}` | " + " | ".join(cells) + " |")
    return _block(lines)


# ---------------------------------------------------------------------------
# Parameters: configuration.md and config.example.yaml
# ---------------------------------------------------------------------------


def _fields(model: type[BaseModel], prefix: str = "") -> Iterable[tuple[str, FieldInfo]]:
    """Every field of a parameter model, then the fields of a nested model as dotted keys."""
    for name, field in model.model_fields.items():
        yield f"{prefix}{name}", field
        nested = _nested_model(field.annotation)
        if nested is not None:
            yield from _fields(nested, f"{prefix}{name}.")


def _nested_model(annotation: object) -> type[BaseModel] | None:
    """The model of a field whose value is a model (Model or Model | None)."""
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    for argument in typing.get_args(annotation):
        if isinstance(argument, type) and issubclass(argument, BaseModel):
            return argument
    return None


def _bound(field: FieldInfo, inclusive: type, exclusive: type, attribute: str) -> object:
    """A numeric bound of a field (Ge/Le first, else Gt/Lt), or None."""
    for kind in (inclusive, exclusive):
        for item in field.metadata:
            if isinstance(item, kind):
                return getattr(item, attribute if kind is inclusive else attribute[0] + "t")
    return None


_TYPE_NAMES: dict[type, str] = {
    bool: "bool",
    int: "int",
    float: "number",
    str: "string",
    tuple: "list",
    list: "list",
    dict: "object",
    Path: "path",
    AnyHttpUrl: "URL",
}
# The section of configuration.md that describes a tls block, linked from each connection.
_TLS_SECTION: str = "[tls block](#tls-certificates-of-a-connection)"


def _type_name(annotation: object) -> str:
    """The type of a value as written in YAML: a name, the values of an enum, a map, a list."""
    if annotation is TlsSettings:
        return _TLS_SECTION
    if annotation is JsonValue:
        return "JSON"
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return " \\| ".join(f"`{member.value}`" for member in annotation)
    if _nested_model(annotation) is not None:
        return "object"
    origin = typing.get_origin(annotation) or annotation
    arguments = typing.get_args(annotation)
    if origin is dict and len(arguments) == 2 and arguments[1] is str:
        return "map string → string"
    if origin in (list, tuple) and arguments and arguments[0] is not Ellipsis:
        item = arguments[0]
        if isinstance(item, type) and issubclass(item, Enum):
            return f"list of {_type_name(item)}"
    return _TYPE_NAMES.get(origin, "string") if isinstance(origin, type) else "string"


def _number(value: object) -> object:
    """A bound as written: 30.0 as 30, 0.5 as 0.5, anything else unchanged."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _type(field: FieldInfo) -> str:
    """The type of a parameter as written in YAML, with its numeric range."""
    arguments = typing.get_args(field.annotation)
    nullable = type(None) in arguments
    base = field.annotation
    if nullable:
        base = next(a for a in arguments if a is not type(None))
    name = _type_name(base)
    low = _number(_bound(field, Ge, Gt, "ge"))
    high = _number(_bound(field, Le, Lt, "le"))
    if low is not None and high is not None:
        name += f" {low}-{high}"
    elif low is not None:
        name += f" ≥{low}"
    elif high is not None:
        name += f" ≤{high}"
    return f"{name} \\| null" if nullable and base is not TlsSettings else name


def _default(field: FieldInfo) -> object:
    """The default value of a parameter."""
    return field.get_default(call_default_factory=True)


def _default_cell(value: object) -> str:
    """A default value for a Markdown table cell."""
    if value is PydanticUndefined:
        return "required"
    if value is None:
        return "none"
    if isinstance(value, bool):
        return f"`{str(value).lower()}`"
    if isinstance(value, str):
        return f"`{value}`" if value else '`""`'
    if isinstance(value, (tuple, list)):
        if not value:
            return "empty"
        items = [f"`{item}`" for item in value]
        if len(items) <= _INLINE_ITEMS:
            return ", ".join(items)
        return f"{len(items)} values ({', '.join(items[:2])}, …)"
    return f"`{value}`"


def _cell(text: str) -> str:
    """Text for a Markdown table cell (pipes escaped, on one line)."""
    return " ".join(text.split()).replace("|", "\\|")


def test_params(*test_ids: str, page: str) -> str:
    """
    The parameter table of a test page (section 11), from the test's model.

    Only for a test that declares parameters: a test without them keeps the
    hand-written sentence saying what the page derives instead.

    Args:
        test_ids: The tests the page describes.
        page:     The page's path (cog.inFile), for the relative link.

    Returns:
        A Markdown table per test: key, type, default, description.
    """
    by_id = {t.info.id: t for t in _tests()}
    configuration = _relative(_CONFIGURATION_PAGE, page)
    parts: list[str] = []
    for test_id in test_ids:
        test = by_id[test_id]
        if test.params is None:
            continue
        domain_key, test_key = section_keys(test.info.id)
        parts.append(
            f"Section [`tests.{domain_key}.{test_key}`]"
            f"({configuration}#{_config_anchor(test)}) of `config.yaml`:\n"
        )
        parts.append("| Key | Type | Default | Description |\n|---|---|---|---|")
        for key, field in _fields(test.params):
            default = _default_cell(_default(field))
            if has_marker(field, NEEDED_TO_RUN):
                default += ", **needed to run**"
            parts.append(
                f"| `{key}` | {_type(field)} | {default} | {_cell(field.description or '')} |"
            )
        parts.append("")
    return _block(parts)


def configuration_tests() -> str:
    """
    The tests chapter of configuration.md: one section and table per test.

    Returns:
        Markdown: a section per test with parameters, in ID order.
    """
    parts: list[str] = []
    pages = _pages()
    for test in _tests():
        if test.params is None:
            continue
        domain_key, test_key = section_keys(test.info.id)
        page = pages.get(test.info.id)
        name = (
            f"[{test.info.id}]({_relative(page, _CONFIGURATION_PAGE.relative_to(_ROOT))})"
            if page
            else test.info.id
        )
        parts.append(f"### `tests.{domain_key}.{test_key}`\n")
        parts.append(f"Test {name}, {test.info.name}.\n")
        parts.append("| Key | Type | Default | Description |\n|---|---|---|---|")
        for key, field in _fields(test.params):
            default = _default_cell(_default(field))
            if has_marker(field, NEEDED_TO_RUN):
                default += ", **needed to run**"
            parts.append(
                f"| `{key}` | {_type(field)} | {default} | {_cell(field.description or '')} |"
            )
        parts.append("")
    return _block(parts)


def _section_model(section: str) -> tuple[type[BaseModel], str]:
    """
    The model of a dotted section of config.yaml, and the prefix of its keys.

    A section that maps names to a block (resources) gives the block's model
    and the prefix <name>.

    Args:
        section: The section's dotted key (target, gateway, resources, ...).

    Returns:
        The model and the key prefix ('' for a plain block).
    """
    model: type[BaseModel] = ToolConfig
    prefix = ""
    for key in section.split("."):
        annotation = model.model_fields[key].annotation
        entry = mapping_entry_model(annotation)
        found = entry or model_in_annotation(annotation)
        if found is None:
            raise ValueError(f"{section}: {key} is not a block of the configuration")
        model, prefix = found, "<name>." if entry is not None else ""
    return model, prefix


def _configuration_rows(
    model: type[BaseModel], prefix: str = "", optional_block: str | None = None
) -> Iterable[tuple[str, FieldInfo, str | None]]:
    """
    Every key of a block, nested blocks flattened as dotted keys.

    A tls block is one row (it has its own section); a block that may be absent
    (Block | None) is a row, then its keys; a mapping of names to a block (resources) gives the keys
    of one entry, as <name>.key.

    Yields:
        The dotted key, its field, and the optional block it is in (None: none).
    """
    for name, field in model.model_fields.items():
        key = f"{prefix}{field.alias or name}"
        entry = mapping_entry_model(field.annotation)
        block = _nested_model(field.annotation)
        if entry is not None:
            yield from _configuration_rows(entry, f"{key}.<name>.", optional_block)
        elif block is not None and block is not TlsSettings:
            if type(None) in typing.get_args(field.annotation):
                yield key, field, optional_block
                yield from _configuration_rows(block, f"{key}.", field.alias or name)
            else:
                yield from _configuration_rows(block, f"{key}.", optional_block)
        else:
            yield key, field, optional_block


def configuration_table(section: str) -> str:
    """
    The table of one section of configuration.md (outside tests): every key of it.

    Args:
        section: The section's dotted key in config.yaml (target, gateway, ...).

    Returns:
        Markdown: one row per key, with type, default and description.
    """
    model, prefix = _section_model(section)
    return _keys_table(model, prefix)


def tls_block_table() -> str:
    """The table of a tls block, the certificate settings every connection may have."""
    return _keys_table(TlsSettings, "")


def _keys_table(model: type[BaseModel], prefix: str) -> str:
    """Markdown: one row per key of a block, with type, default and description."""
    lines = ["| Key | Type | Default | Description |", "|---|---|---|---|"]
    for key, field, optional_block in _configuration_rows(model, prefix):
        default = _default_cell(_default(field))
        if default == "required":
            default = f"required with `{optional_block}`" if optional_block else "**required**"
        lines.append(f"| `{key}` | {_type(field)} | {default} | {_cell(field.description or '')} |")
    return _block(lines)


def _first_sentence(text: str) -> str:
    return _SENTENCE_END.split(" ".join(text.split()), maxsplit=1)[0]


def _comment(text: str, indent: str) -> list[str]:
    """A YAML comment, wrapped."""
    words = text.split()
    lines: list[str] = []
    line = f"{indent}#"
    for word in words:
        if len(line) + 1 + len(word) > _COMMENT_WIDTH and line.strip() != "#":
            lines.append(line)
            line = f"{indent}#"
        line += f" {word}"
    lines.append(line)
    return lines


class _IndentedDumper(yaml.SafeDumper):
    """A YAML dumper that indents a list under its key, as config.example.yaml does."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        """Never write a block sequence at the level of its key."""
        super().increase_indent(flow, False)


def _yaml_value(key: str, value: object, indent: str, commented: bool) -> list[str]:
    """A key and its value as YAML lines, optionally commented out."""
    plain = _plain(value)
    if isinstance(plain, (list, dict)) and plain:
        dumped = yaml.dump(
            {key: plain},
            Dumper=_IndentedDumper,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        )
    else:
        dumped = yaml.safe_dump(
            {key: plain}, default_flow_style=True, sort_keys=False, allow_unicode=True
        )
        dumped = dumped.strip().removeprefix("{").removesuffix("}") + "\n"
    raw = dumped.rstrip("\n").split("\n")
    if commented:
        # The nesting goes before '#', so that every commented key reads as a key at its level.
        return [
            f"{indent}{line[: len(line) - len(line.lstrip())]}# {line.lstrip()}" for line in raw
        ]
    return [indent + line for line in raw]


def _plain(value: object) -> object:
    """A default as plain YAML data (tuples as lists, models as mappings)."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, tuple):
        return [_plain(item) for item in value]
    if isinstance(value, list):
        return [_plain(item) for item in value]
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    return value


def example_tests() -> str:
    """
    The tests section of config.example.yaml.

    Every parameter with its default and the first sentence of its
    description; a parameter without a default but with an example is
    written commented out, with the example.

    Returns:
        YAML text, starting with "tests:".
    """
    indent = _YAML_INDENT
    lines = ["tests:"]
    by_domain: dict[str, list[_Test]] = {}
    for test in _tests():
        by_domain.setdefault(section_keys(test.info.id)[0], []).append(test)
    for domain_key in sorted(by_domain):
        lines.append(f"{indent}{domain_key}:")
        for test in by_domain[domain_key]:
            _, test_key = section_keys(test.info.id)
            if test.params is None:
                if test.info.is_external:
                    continue  # external tests are configured under external_tools
                lines += _comment(f"{test.info.id} {test.info.name}: no parameters.", indent * 2)
                lines.append(f"{indent * 2}{test_key}: {{}}")
                continue
            lines += _comment(f"{test.info.id} {test.info.name}.", indent * 2)
            lines.append(f"{indent * 2}{test_key}:")
            for name, field in test.params.model_fields.items():
                lines += _parameter_lines(name, field, indent * 3)
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def _parameter_lines(name: str, field: FieldInfo, indent: str) -> list[str]:
    """The comment and the YAML of one parameter."""
    lines = _comment(_first_sentence(field.description or name), indent)
    default = _default(field)
    examples: Sequence[object] = field.examples or ()
    if default is None and examples:
        lines += _yaml_value(name, examples[0], indent, commented=True)
        return lines
    lines += _yaml_value(name, default, indent, commented=False)
    if examples and not default:
        lines.append(f"{indent}# Example:")
        lines += _yaml_value(name, examples[0], indent, commented=True)
    return lines


# ---------------------------------------------------------------------------
# Output formats: report-schema.md
# ---------------------------------------------------------------------------

# The models of apiguard_report.json, each with its section in report-schema.md.
_REPORT_MODELS: dict[str, type[BaseModel]] = {
    model.__name__: model
    for model in (
        ReportData,
        ConnectionTrust,
        ExecutiveSummary,
        NotRunEntry,
        DomainSummary,
        TestResultRow,
        SubTestResult,
        Finding,
        InfoNote,
        Reference,
        TransactionSummary,
        DerivedFact,
        ReferencesSummary,
        CalibrationPoint,
        Fingerprint,
        PositiveControl,
    )
}

_JSON_TYPE_NAMES: dict[type, str] = {
    str: "string",
    int: "int",
    float: "number",
    bool: "bool",
    dict: "object",
    datetime: "string, ISO 8601 UTC",
}


def _json_type(annotation: object, models: dict[str, type[BaseModel]]) -> str:
    """The JSON type of a field: a name, a link to a documented model, an array of either."""
    arguments = typing.get_args(annotation)
    if type(None) in arguments:
        inner = next(a for a in arguments if a is not type(None))
        return f"{_json_type(inner, models)} \\| null"
    if typing.get_origin(annotation) is typing.Literal:
        return " \\| ".join(f"`{value}`" for value in arguments)
    if isinstance(annotation, type) and annotation.__name__ in models:
        return f"[`{annotation.__name__}`](#{annotation.__name__.lower()})"
    origin = typing.get_origin(annotation) or annotation
    if origin in (list, tuple) and arguments:
        return f"array of {_json_type(arguments[0], models)}"
    return _JSON_TYPE_NAMES.get(origin, "string") if isinstance(origin, type) else "string"


def _fields_table(model: type[BaseModel], models: dict[str, type[BaseModel]]) -> str:
    """Markdown: one row per field of an output model, with its JSON type and description."""
    lines = ["| Field | Type | Description |", "|---|---|---|"]
    for name, field in model.model_fields.items():
        lines.append(
            f"| `{field.alias or name}` | {_json_type(field.annotation, models)} "
            f"| {_cell(field.description or '')} |"
        )
    for name, computed in model.model_computed_fields.items():
        lines.append(
            f"| `{name}` | {_json_type(computed.return_type, models)} "
            f"| {_cell(computed.description or '')} (computed) |"
        )
    return _block(lines)


def _standards(info: TestInfo) -> str:
    """The test's references as shown to a reader, each in backticks (a text may hold a comma)."""
    return ", ".join(f"`{ref.text}`" for ref in info.references) or "none"


def standards_table() -> str:
    """The format of each standard a reference may cite (report-schema.md): STANDARD_FORMATS."""
    lines = [
        "| `standard` | Standard | `id` example | Section | Shown as |",
        "|---|---|---|---|---|",
    ]
    for standard, spec in STANDARD_FORMATS.items():
        example = Reference(standard=standard, id=spec.example, section=spec.section_example)
        section = f"optional, e.g. `{spec.section_example}`" if spec.section_example else "no"
        lines.append(
            f"| `{standard.value}` | {spec.name} | `{spec.example}` | {section} "
            f"| `{example.text}` |"
        )
    return _block(lines)


def report_table(name: str) -> str:
    """
    The table of one model of apiguard_report.json (report-schema.md).

    Args:
        name: The model's class name (ReportData, TestResultRow, ...).

    Returns:
        Markdown: one row per field; a field holding another model of the
        report links to its section.
    """
    return _fields_table(_REPORT_MODELS[name], _REPORT_MODELS)


# The models of evidence.json, each with its section in evidence-format.md.
_EVIDENCE_MODELS: dict[str, type[BaseModel]] = {
    model.__name__: model for model in (EvidenceFile, EvidenceRecord)
}


def evidence_table(name: str) -> str:
    """One model of evidence.json (evidence-format.md): EvidenceFile or EvidenceRecord."""
    return _fields_table(_EVIDENCE_MODELS[name], _EVIDENCE_MODELS)


def exit_codes_table() -> str:
    """The exit codes of apiguard run (exit-codes.md), from their single definition (EXIT_CODES)."""
    lines = ["| Code | Label | Meaning |", "|---|---|---|"]
    for code, info in EXIT_CODES.items():
        meaning = info.meaning[0].upper() + info.meaning[1:]
        lines.append(f"| `{code}` | {info.label} | {_cell(meaning)}. |")
    return _block(lines)


def _member_docs(enum_class: type[Enum]) -> dict[str, str]:
    """
    The docstring written under each member of a StrEnum, by member name.

    Python keeps no attribute docstrings at runtime, so they are read from the
    class source: that way a table built from them cannot drift from the code.

    Args:
        enum_class: The enum whose members carry a docstring.

    Returns:
        Member name to its docstring, collapsed to one line without the final
        full stop.
    """
    pairs = re.findall(
        r'^    (\w+) = "[^"]*"\n    """(.+?)"""', inspect.getsource(enum_class), re.M | re.S
    )
    return {name: " ".join(doc.split()).rstrip(".") for name, doc in pairs}


# The graph's nodes: src's top-level modules and packages, with core split per
# submodule, which is the granularity a contributor needs to place a new module.
_GRAPH_CORE: str = "core"


def _graph_node(module: str) -> str | None:
    """
    The graph node a src module belongs to.

    Args:
        module: A dotted module name starting with "src".

    Returns:
        The node name, or None when the module is src itself.
    """
    parts = module.split(".")
    if len(parts) < 2:
        return None
    if parts[1] == _GRAPH_CORE and len(parts) > 2:
        return f"{_GRAPH_CORE}/{parts[2]}"
    return parts[1]


def import_graph() -> str:
    """
    The import graph of src, computed from the source (overview.md).

    One line per node, in the order a reader follows the pipeline, with the
    nodes it imports. An import that exists only under `if TYPE_CHECKING` is
    marked, because it does not constrain the runtime dependency direction.

    Returns:
        A fenced code block with the graph.
    """
    edges: dict[str, dict[str, bool]] = {}
    for path in sorted((_ROOT / "src").rglob("*.py")):
        relative = path.relative_to(_ROOT / "src").with_suffix("")
        module = "src." + ".".join(p for p in relative.parts if p != "__init__")
        source_node = _graph_node(module)
        if source_node is None:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        type_only: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.If) and "TYPE_CHECKING" in ast.unparse(node.test):
                type_only.update(id(child) for child in ast.walk(node))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("src"):
                names = [node.module]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names if a.name.startswith("src")]
            for name in names:
                target = _graph_node(name)
                if target is None or target == source_node:
                    continue
                runtime = id(node) not in type_only
                known = edges.setdefault(source_node, {})
                known[target] = known.get(target, False) or runtime
    order = [
        "cli",
        "cli_console",
        "engine",
        "config",
        "discovery",
        "tests",
        "external_tests",
        "connectors",
        "report",
    ]
    nodes = [n for n in order if n in edges] + sorted(n for n in edges if n not in order)
    width = max(len(n) for n in nodes)
    lines: list[str] = []
    for name in nodes:
        targets = [t if edges[name][t] else f"{t} (types only)" for t in sorted(edges[name])]
        lines.append(f"{name:<{width}} -> {', '.join(targets)}")
    return _block(["```", *lines, "```"])


def effects_table() -> str:
    """
    The tests by the effect they declare (configure-a-target.md).

    What a run does to the target, from TestInfo.effect and the Effect enum, in
    the order the engine runs them.

    Returns:
        A Markdown table: one row per effect, with the tests that declare it.
    """
    docs = _member_docs(Effect)
    tests = _tests()
    lines = ["| Effect | What it does to the target | Tests |", "|---|---|---|"]
    for effect in sorted(Effect, key=lambda e: EFFECT_RANK[e]):
        ids = [_id_cell(t.info) for t in tests if t.info.effect is effect]
        lines.append(
            f"| `{effect.name}` | {_cell(docs.get(effect.name, ''))} | {', '.join(ids) or '-'} |"
        )
    return _block(lines)


def guarantee_priorities() -> str:
    """
    The guarantees by the priority their test declares (03-guarantees.md).

    A guarantee with no test keeps the priority the methodology proposes, which
    the catalogue states in its heading; it is listed in its own row.

    Returns:
        A Markdown table: one row per priority, with the guarantee numbers.
    """
    by_guarantee: dict[str, int] = {}
    for test in _tests():
        key = (
            test.info.id
            if not test.info.id.startswith("ext.")
            else ".".join(test.info.id.split(".")[1:3])
        )
        by_guarantee.setdefault(key, test.info.priority)
    lines = ["| Priority | Guarantees |", "|---|---|"]
    for priority in range(PRIORITY_MIN, PRIORITY_MAX + 1):
        ids = sorted(k for k, p in by_guarantee.items() if p == priority)
        lines.append(f"| P{priority} | {', '.join(ids)} |")
    return _block(lines)


def needs_table() -> str:
    """
    The needs a test can declare (docs/04-architecture/03-assessment-model.md).

    The vocabulary comes from the Need enum and each row's meaning from that
    member's docstring, so the table cannot drift from the code; the last two
    columns come from the tests' own declarations.

    Returns:
        A Markdown table: one row per need, with the tests that require it and
        the tests that use it when it is there.
    """
    member_docs = _member_docs(Need)
    tests = _tests()
    lines = [
        "| Need | What the configuration must give | Required by | Used when present by |",
        "|---|---|---|---|",
    ]
    for need in Need:
        required = [_id_cell(t.info) for t in tests if need in t.info.needs]
        optional = [_id_cell(t.info) for t in tests if need in t.info.optional_needs]
        meaning = member_docs.get(need.name, "")
        lines.append(
            f"| `{need.name}` | {_cell(meaning)} | "
            f"{', '.join(required) or '-'} | {', '.join(optional) or '-'} |"
        )
    # A parameter marked NEEDED_TO_RUN is a need too: the engine skips the test
    # naming it, exactly as it does for a Need member.
    by_parameter: dict[str, tuple[str, list[str]]] = {}
    for test in tests:
        if test.params is None:
            continue
        for key, field in _fields(test.params):
            if not has_marker(field, NEEDED_TO_RUN):
                continue
            first = re.split(r"\.\s", field.description or "")[0].rstrip(".")
            meaning, ids = by_parameter.setdefault(key, (first, []))
            ids.append(_id_cell(test.info))
    for key, (meaning, ids) in sorted(by_parameter.items()):
        lines.append(f"| `{key}` | {_cell(meaning)} | {', '.join(ids)} | - |")
    return _block(lines)


def domain_names_table() -> str:
    """The domains of the methodology, as the report names them (DOMAIN_NAMES)."""
    lines = ["| `domain` | `domain_name` |", "|---|---|"]
    lines += [f"| {number} | {name} |" for number, name in sorted(DOMAIN_NAMES.items())]
    return _block(lines)


# ---------------------------------------------------------------------------
# Developer guides: the code a contributor uses
# ---------------------------------------------------------------------------

# The tests' source folders, searched for the tests that call a gateway concept.
_TEST_SOURCES: tuple[Path, ...] = (_ROOT / "src" / "tests", _ROOT / "src" / "external_tests")
_TEST_ID_IN_SOURCE: re.Pattern[str] = re.compile(r'TestInfo\(\s*id="([^"]+)"')
_CONNECTOR_BASE_NAME: str = "BaseConnector"


def _resolve(target: str) -> Any:  # noqa: ANN401 -- a class, a function or a method
    """The object at 'module:Name' or 'module:Class.attribute'."""
    module_name, _, path = target.partition(":")
    found: Any = importlib.import_module(module_name)
    for part in path.split("."):
        found = getattr(found, part)
    return found


def _summary(obj: object) -> str:
    """The first paragraph of an object's docstring, on one line."""
    doc = inspect.getdoc(obj) or ""
    return " ".join(doc.split("\n\n", 1)[0].split())


def _signature(func: Any, typed: bool) -> str:  # noqa: ANN401 -- any callable
    """A call as a contributor writes it: name(arg, key=default); with types when typed."""
    signature = inspect.signature(func)
    parts: list[str] = []
    keyword_only_marked = False
    for parameter in signature.parameters.values():
        if parameter.name == "self":
            continue
        if parameter.kind is parameter.KEYWORD_ONLY and not keyword_only_marked:
            parts.append("*")
            keyword_only_marked = True
        text = parameter.name
        if typed and parameter.annotation is not parameter.empty:
            text += f": {parameter.annotation}"
        if parameter.default is not parameter.empty:
            text += f" = {parameter.default!r}" if typed else f"={parameter.default!r}"
        parts.append(text)
    returned = signature.return_annotation
    suffix = f" -> {returned}" if typed and returned is not signature.empty else ""
    return f"{func.__name__}({', '.join(parts)}){suffix}"


def methods_table(header: Sequence[str], *calls: str | tuple[str, str], typed: bool = False) -> str:
    """
    The table of some methods or functions: their call and the first paragraph of their docstring.

    Args:
        header: The two column titles.
        calls:  'module:Class.method' (or 'module:function'), or (prefix, that) to write the call
                with its receiver, e.g. ('store.', 'src.core.evidence:EvidenceStore.pin_evidence').
        typed:  Whether the calls show the types (for the methods a subclass implements).

    Returns:
        Markdown: one row per call, in the given order.
    """
    lines = [f"| {header[0]} | {header[1]} |", "|---|---|"]
    for call in calls:
        prefix, target = call if isinstance(call, tuple) else ("", call)
        func = _resolve(target)
        lines.append(f"| `{prefix}{_signature(func, typed)}` | {_cell(_summary(func))} |")
    return _block(lines)


def _tests_calling(method: str) -> str:
    """The IDs of the tests whose source calls .method(, sorted."""
    ids: set[str] = set()
    for folder in _TEST_SOURCES:
        for source in folder.rglob("*.py"):
            text = source.read_text(encoding="utf-8")
            if f".{method}(" in text:
                ids.update(_TEST_ID_IN_SOURCE.findall(text))
    return ", ".join(sorted(ids, key=_id_key)) or "-"


def gateway_concepts_table() -> str:
    """The concepts a gateway adapter answers: reader, method to implement, items, users."""
    adapter = _resolve("src.core.gateway.base:BaseGatewayAdapter")
    lines = ["| Reader | Implement | Items | Used by |", "|---|---|---|---|"]
    for name, func in inspect.getmembers(adapter, inspect.isfunction):
        hook = f"_read_{name}"
        if name.startswith("_") or not hasattr(adapter, hook):
            continue
        item = (
            str(inspect.signature(func).return_annotation).removeprefix("ConceptRead[").rstrip("]")
        )
        lines.append(f"| `{name}()` | `{hook}()` | `{item}` | {_tests_calling(name)} |")
    return _block(lines)


def connector_bases_table() -> str:
    """The connector bases: what each is for, the class attributes a connector declares."""
    lines = ["| Base | For | Declares | Optional (default) |", "|---|---|---|---|"]
    for name in ("BaseSubprocessConnector", "BaseLibraryConnector"):
        base = _resolve(f"src.connectors.base:{name}")
        required: list[str] = []
        optional: list[str] = []
        for klass in reversed(base.__mro__):
            if klass.__name__ not in (_CONNECTOR_BASE_NAME, name) and klass is not base:
                continue
            for attribute, annotation in klass.__dict__.get("__annotations__", {}).items():
                if "ClassVar" not in str(annotation):
                    continue
                if attribute in klass.__dict__:
                    optional.append(f"`{attribute}` ({klass.__dict__[attribute]!r})")
                else:
                    required.append(f"`{attribute}`")
        declares = ", ".join(required)
        defaults = ", ".join(optional) or "-"
        lines.append(f"| `{name}` | {_cell(_summary(base))} | {declares} | {defaults} |")
    return _block(lines)


# The exceptions of the tool, by module, in the order of the pipeline.
_EXCEPTIONS: tuple[str, ...] = (
    "src.core.exceptions:ConfigurationError",
    "src.core.exceptions:TestDefinitionError",
    "src.core.exceptions:OpenAPILoadError",
    "src.core.exceptions:DAGCycleError",
    "src.core.exceptions:SecurityClientError",
    "src.core.exceptions:AuthenticationSetupError",
    "src.core.exceptions:ExternalToolError",
    "src.core.gateway.base:GatewayAdapterError",
    "src.core.exceptions:TeardownError",
    "src.discovery.seed_generator:SeedGeneratorFetchError",
    "src.discovery.seed_generator:SeedGeneratorParseError",
)


def exceptions_table() -> str:
    """The tool's exceptions: their fields and when they are raised, with what follows."""
    lines = ["| Exception | Fields | Raised, and what follows |", "|---|---|---|"]
    for target in _EXCEPTIONS:
        exception = _resolve(target)
        fields = [
            f"`{name}`"
            for name in inspect.signature(exception.__init__).parameters
            if name not in ("self", "message")
        ]
        module = target.partition(":")[0].replace(".", "/") + ".py"
        lines.append(
            f"| `{exception.__name__}` (`{module}`) | {', '.join(fields) or '-'} "
            f"| {_cell(_summary(exception))} |"
        )
    return _block(lines)


# ---------------------------------------------------------------------------
# CLI: cli.md
# ---------------------------------------------------------------------------

# The program name, as the user types it.
_PROGRAM: str = "apiguard"


def _command(name: str) -> TyperCommand:
    """A command of the CLI, as Typer builds it from src/cli.py."""
    command = typer.main.get_command(cli_app).commands[name]  # type: ignore[attr-defined]
    if not isinstance(command, TyperCommand):
        raise TypeError(f"{name}: not a Typer command")
    return command


def _parameters(command: TyperCommand) -> list[TyperArgument | TyperOption]:
    """The arguments and options of a command, in declaration order (without --help)."""
    return [
        p for p in command.params if isinstance(p, TyperArgument | TyperOption) and p.name != "help"
    ]


def _value(parameter: TyperArgument | TyperOption, command: TyperCommand) -> str:
    """What a parameter takes: its values, a file, a number range; '' for a flag."""
    if isinstance(parameter, TyperArgument) or (
        isinstance(parameter, TyperOption) and parameter.is_flag
    ):
        return ""
    choices = getattr(parameter.type, "choices", None)
    if choices:
        return " \\| ".join(f"`{choice}`" for choice in choices)
    low, high = getattr(parameter.type, "min", None), getattr(parameter.type, "max", None)
    if low is not None or high is not None:
        kind = "number" if parameter.type.name.startswith("float") else "int"
        return f"{kind} {_number(low)}-{_number(high)}"
    metavar = parameter.make_metavar(
        command.make_context(command.name or "", [], resilient_parsing=True)
    )
    return metavar.strip("<>").upper() if metavar else ""


def _names(parameter: TyperArgument | TyperOption) -> str:
    """The parameter as typed: --config, -c; --banner / --no-banner; SPEC."""
    if isinstance(parameter, TyperArgument):
        return f"`{parameter.human_readable_name.upper()}`"
    names = ", ".join(f"`{name}`" for name in parameter.opts)
    if parameter.secondary_opts:
        names += " / " + ", ".join(f"`{name}`" for name in parameter.secondary_opts)
    return names


def _option_default(parameter: TyperArgument | TyperOption) -> str:
    """The default of a parameter for a table cell (its show_default text when it has one)."""
    if isinstance(parameter, TyperOption) and isinstance(parameter.show_default, str):
        return parameter.show_default
    value = parameter.default
    if isinstance(parameter, TyperOption) and parameter.is_flag:
        if parameter.secondary_opts:
            return f"`{parameter.opts[0] if value else parameter.secondary_opts[0]}`"
        return "off" if not value else "on"
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, Path):
        value = str(value)
    return _default_cell(value)


def cli_synopsis(name: str) -> str:
    """
    The syntax line of a command: every argument and option, as the user types them.

    Args:
        name: The command (run, validate-config, ...).

    Returns:
        Markdown: a code block with the syntax.
    """
    command = _command(name)
    parts = [_PROGRAM, name]
    for parameter in _parameters(command):
        if isinstance(parameter, TyperArgument):
            word = parameter.human_readable_name.upper()
            parts.append(word if parameter.required else f"[{word}]")
            continue
        value = _value(parameter, command)
        flag = parameter.opts[0] + (
            f"|{parameter.secondary_opts[0]}" if parameter.secondary_opts else ""
        )
        value = (
            value.replace("`", "")
            .replace(" \\| ", "|")
            .removeprefix("number ")
            .removeprefix("int ")
        )
        shown = f"{flag} {value}" if value else flag
        parts.append(f"[{shown}]")
    return "\n```\n" + " ".join(parts) + "\n```\n"


def cli_options(name: str) -> str:
    """
    The table of a command's arguments and options, with their help text.

    Args:
        name: The command (run, validate-config, ...).

    Returns:
        Markdown: one row per argument or option.
    """
    command = _command(name)
    lines = ["| Option | Value | Default | Description |", "|---|---|---|---|"]
    for parameter in _parameters(command):
        help_text = (
            parameter.help
            if isinstance(parameter, TyperOption)
            else (getattr(parameter, "help", None) or "")
        )
        lines.append(
            f"| {_names(parameter)} | {_value(parameter, command)} | {_option_default(parameter)} "
            f"| {_cell(help_text or '')} |"
        )
    return _block(lines)


def generated_files() -> list[str]:
    """The files with generated parts, relative to the repository root, sorted."""
    found = {path for pattern in GENERATED_FILES for path in _ROOT.glob(pattern)}
    return sorted(str(path.relative_to(_ROOT)) for path in found)


def main(argv: list[str]) -> int:
    """
    Write the generated parts of the documentation, or check they are up to date.

    Cog runs in its own interpreter with an empty bytecode cache: it imports
    the test modules, and a stale .pyc (a module edited to the same size within
    the same second) would hide the change.

    Args:
        argv: Command-line arguments: --check, or none to write.

    Returns:
        0 when written, or when every part is up to date; 1 when a part is out of
        date (Cog prints the file and the difference).
    """
    parser = argparse.ArgumentParser(description=__doc__.strip().splitlines()[2])
    parser.add_argument(
        "--check", action="store_true", help="fail when a part is out of date, without writing"
    )
    check = parser.parse_args(argv[1:]).check
    files = generated_files()
    mode = ["--check", "--diff"] if check else ["-r"]
    cache = tempfile.mkdtemp(prefix="apiguard-cog-pycache-")
    try:
        result = subprocess.run(  # noqa: S603 -- fixed arguments, the repository's own files
            [sys.executable, "-m", "cogapp", "-I", "scripts", "--verbosity=1", *mode, *files],
            cwd=_ROOT,
            env={**os.environ, "PYTHONPYCACHEPREFIX": cache},
            check=False,
        )
    finally:
        shutil.rmtree(cache, ignore_errors=True)
    if result.returncode != 0:
        if check:
            sys.stderr.write("Generated documentation out of date: run hatch run dev:gen.\n")
        return _EXIT_OUT_OF_DATE if check else result.returncode
    done = "up to date" if check else "written"
    sys.stdout.write(f"Generated documentation {done} ({len(files)} files).\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
