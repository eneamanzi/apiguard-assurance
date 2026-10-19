"""
scripts/generate_docs.py

The parts of the documentation that repeat the code, built from the test declarations.

Each test declares who it is (``info = TestInfo(...)``) and its parameters
(``BaseTest[Test21Params]``) once, in its module (docs/architecture/design-decisions.md,
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

    catalogue()             docs/tests/README.md, one row per test, by domain
    test_header(*ids, page) the table at the top of each test page
    strategy_matrix()       docs/architecture/assessment-model.md, tests by
                            strategy and priority
    configuration_tests()   docs/reference/configuration.md, the tests chapter:
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
from pathlib import Path
from typing import Any

import structlog
import yaml
from annotated_types import Ge, Gt, Le, Lt
from pydantic import BaseModel
from pydantic.fields import FieldInfo
from pydantic_core import PydanticUndefined
from src.core.assessment_test import NEEDED_TO_RUN, AssessmentTest, has_marker
from src.core.models import TestStrategy
from src.core.test_metadata import PRIORITY_MAX, PRIORITY_MIN, TestInfo, section_keys
from src.external_tests.registry import ExternalTestRegistry
from src.report.builder import DOMAIN_NAMES
from src.tests.registry import TestRegistry

# Discovery logs every test at debug level: keep Cog's output to the generated text.
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING))

_ROOT: Path = Path(__file__).resolve().parent.parent
# The files with generated parts, relative to the repository root (glob patterns).
GENERATED_FILES: tuple[str, ...] = (
    "docs/tests/README.md",
    "docs/tests/*/*.md",
    "docs/tests/external/*/*.md",
    "docs/architecture/assessment-model.md",
    "docs/reference/configuration.md",
    "config.example.yaml",
)
_EXIT_OUT_OF_DATE: int = 1
_TEST_PAGES: Path = _ROOT / "docs" / "tests"
_CONFIGURATION_PAGE: Path = _ROOT / "docs" / "reference" / "configuration.md"
_PORTABILITY: str = "../reference/compatibility.md#test-portability"
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
    """What a test needs from the configuration: its needs, then its needed parameters."""
    needs = [f"`{need.value}`" for need in test.info.needs]
    if test.params is not None:
        needs += [
            f"`{name}`"
            for name, field in test.params.model_fields.items()
            if has_marker(field, NEEDED_TO_RUN)
        ]
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
    The test catalogue of docs/tests/README.md: one row per test, by domain.

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
            f"tests without a page in docs/tests/ (a page with a test_header marker): {missing}"
        )
    readme = _TEST_PAGES / "README.md"
    native = sum(1 for t in tests if not t.info.is_external)
    lines = [
        f"{len(tests)} tests: {native} native, {len(tests) - native} external.",
        "",
        "| ID | Name | Pri. | Strategy | CWE | Needs | Page |",
        "|---|---|---|---|---|---|---|",
    ]
    for domain, name in DOMAIN_NAMES.items():
        lines.append(f"| **Domain {domain} - {name}** | | | | | | |")
        in_domain = [t for t in tests if t.info.domain == domain]
        if not in_domain:
            lines.append("| - | no test implemented | | | | | |")
        for test in sorted(in_domain, key=lambda t: _id_key(t.info.id.removeprefix("ext."))):
            info = test.info
            link = _relative(pages[info.id], readme.relative_to(_ROOT))
            lines.append(
                f"| {_id_cell(info)} | {info.name} | {_priority(info)} | {info.strategy.value} "
                f"| {info.cwe} | {_needs(test)} | [{info.id}]({link}) |"
            )
    lines.append("")
    lines.append(
        "Needs: what the test needs from the configuration (credentials of a role, a gateway, a "
        "parameter); without it the engine records SKIP without running the test. What each test "
        f"needs from a target, measured on the labs: [Test portability]({_PORTABILITY})."
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
        ("CWE", [t.info.cwe for t in tests]),
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
    The tests by strategy and priority (docs/architecture/assessment-model.md).

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
}


def _type(field: FieldInfo) -> str:
    """The type of a parameter as written in YAML, with its numeric range."""
    arguments = typing.get_args(field.annotation)
    nullable = type(None) in arguments
    base = field.annotation
    if nullable:
        base = next(a for a in arguments if a is not type(None))
    origin = typing.get_origin(base) or base
    if _nested_model(base) is not None:
        name = "object"
    elif isinstance(origin, type):
        name = _TYPE_NAMES.get(origin, "string")
    else:
        name = "string"
    low = _bound(field, Ge, Gt, "ge")
    high = _bound(field, Le, Lt, "le")
    if low is not None and high is not None:
        name += f" {low}-{high}"
    elif low is not None:
        name += f" ≥{low}"
    elif high is not None:
        name += f" ≤{high}"
    return f"{name} \\| null" if nullable else name


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
