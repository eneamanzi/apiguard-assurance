"""
validation/catalogue.py

The cases of the oracles the tests declare, and the files that say how each is
produced (README.md).

    declared_cases()  every case the code declares, test by test: the rows of
                      each oracle and of the two shared rules, with the
                      sentence that describes it (the same as the test page's);
    CaseFile          validation/cases/<test>.yaml: per case, the fields copied
                      from the code and the fields we write (how it is produced);
    Variant           validation/variants/<lab>.yaml: one temporary change to a lab.

The fields copied from the code (id, sub_test, situation, expected) are checked
against it by check.py in dev:check, so code, test pages and these files cannot
drift apart.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

ROOT: Path = Path(__file__).resolve().parent.parent
HERE: Path = Path(__file__).resolve().parent
CASES_DIR: Path = HERE / "cases"
VARIANTS_DIR: Path = HERE / "variants"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import generate_docs  # noqa: E402 -- the generator's own reading of the tests, reused
from src.core.assessment_test import CONCEPT_NOT_ACCESSIBLE  # noqa: E402
from src.core.models import Outcome  # noqa: E402
from src.core.response_category import UNINFORMATIVE_CATEGORIES  # noqa: E402

LABS: tuple[str, ...] = ("forgejo-kong", "crapi-kong", "forgejo-apisix")
# The variant of a case seen on the lab as built.
AS_BUILT: str = "none"
# The sub-test of a shared answer that says nothing: any of the test's; its
# group's key in a case file.
ANY_SUB_TEST: str = "*"
ANY_SUB_TEST_KEY: str = "any_sub_test"
# The situation of the answers that say nothing (the rule's table on each page).
_SHARED_SITUATION: str = (
    "an answer of this category on any sub-test that does not judge it: {meaning} It says "
    "nothing about the guarantee (one rule for every test)"
)


class Expected(BaseModel):
    """The judgement a case gives: the row of the oracle."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    outcome: Outcome
    detail: str = Field(min_length=1)
    confidence: Literal["CERTAIN", "FIRM", "TENTATIVE"] | None = None


@dataclass(frozen=True)
class DeclaredCase:
    """One case the code declares, with what the case file copies from it."""

    test: str
    id: str
    sub_test: str
    situation: str
    expected: Expected


def case_id(sub_test: str, expected: Expected) -> str:
    """The id of a case: sub-test, outcome, detail and, for a violation, confidence."""
    parts = [sub_test, expected.outcome.value, expected.detail]
    return "/".join([*parts, expected.confidence] if expected.confidence else parts)


def _declared(test: str, sub_test: str, situation: str, expected: Expected) -> DeclaredCase:
    """A declared case, its id computed."""
    return DeclaredCase(test, case_id(sub_test, expected), sub_test, situation, expected)


def declared_cases() -> dict[str, tuple[str, list[DeclaredCase]]]:
    """
    Every case the code declares, by test ID: the test's name and its cases.

    In the order of the page's section 6: sub-test by sub-test as the test
    declares them, in each the oracle's rows (a family one case per member) and
    then CONCEPT_NOT_ACCESSIBLE for a test reading a gateway concept; last, each
    answer that says nothing the test applies the shared rule to.
    """
    concept_readers = generate_docs._ids_calling("_unread_concept")
    rule_users = generate_docs._ids_applying_the_rule()
    meanings = generate_docs._category_meanings()
    found: dict[str, tuple[str, list[DeclaredCase]]] = {}
    for test in generate_docs._tests():
        info = test.info
        cases: list[DeclaredCase] = []
        for sub_test in info.sub_tests:
            for oracle_case in info.oracle:
                if info.case_sub_test(oracle_case) != sub_test:
                    continue
                confidence = oracle_case.confidence.value if oracle_case.confidence else None
                for detail in oracle_case.names():
                    expected = Expected(
                        outcome=oracle_case.outcome, detail=detail, confidence=confidence
                    )
                    cases.append(_declared(info.id, sub_test, oracle_case.when, expected))
            if info.id in concept_readers:
                expected = Expected(outcome=Outcome.NOT_VERIFIABLE, detail=CONCEPT_NOT_ACCESSIBLE)
                cases.append(
                    _declared(
                        info.id, sub_test, generate_docs.CONCEPT_NOT_ACCESSIBLE_CASE, expected
                    )
                )
        if info.id in rule_users:
            for category in UNINFORMATIVE_CATEGORIES:
                if all(info.decides(category, s) for s in info.sub_tests):
                    continue
                situation = _SHARED_SITUATION.format(meaning=meanings.get(category.value, ""))
                expected = Expected(outcome=Outcome.NOT_VERIFIABLE, detail=category.value)
                cases.append(_declared(info.id, ANY_SUB_TEST, situation, expected))
        found[info.id] = (info.name, cases)
    return found


class NotProducible(BaseModel):
    """Why no lab can give a case."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    group: Literal["code", "gateway", "environment", "decision"] = Field(
        description="code: a guard the code cannot reach; gateway: a feature Kong and APISIX "
        "lack; environment: infrastructure the labs do not have; decision: left out by the owner."
    )
    reason: str = Field(min_length=1, description="As the test's page states it.")


class AddedOperation(BaseModel):
    """An operation added to the specification's copy (SpecEdit)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(min_length=1, description="As the specification writes it (after basePath).")
    method: str = Field(min_length=1, description="Lowercase, as in the specification.")
    operation: dict[str, object] = Field(description="The operation object, as written.")


class DroppedOperations(BaseModel):
    """Methods removed from every path whose parameters are exactly these (SpecEdit)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    within_parameters: list[str] = Field(description="The path's parameters, e.g. [owner, repo].")
    methods: list[str] = Field(min_length=1, description="Lowercase, as in the specification.")


class SpecEdit(BaseModel):
    """
    The run reads a local copy of the lab's specification, edited.

    The copy is read before the variant is applied (a variant may stop what
    serves the specification); with no edit, it is the specification as is.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    set: dict[str, object] = Field(
        default_factory=dict, description="Top-level fields set (e.g. basePath)."
    )
    add_operations: list[AddedOperation] = Field(default_factory=list)
    drop_plain_get: bool = Field(
        default=False, description="Remove every GET on a path without parameters."
    )
    drop_operations: list[DroppedOperations] = Field(default_factory=list)
    operations_security: list[dict[str, object]] | None = Field(
        default=None, description="Set as the `security` of every operation (e.g. [] : none)."
    )


class CaseEntry(BaseModel):
    """One case in a case file: the fields copied from the code, then ours."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    sub_test: str
    situation: str
    expected: Expected
    how: str = Field(default="", description="How the situation is produced, in words.")
    lab: str = Field(default="", description="The lab it is produced on.")
    variant: str = Field(
        default="", description="The lab's variant (variants/<lab>.yaml), or 'none': as built."
    )
    config: dict[str, object] = Field(
        default_factory=dict, description="Changes to the lab's tool configuration (dotted keys)."
    )
    spec: SpecEdit | None = Field(
        default=None, description="A local, edited copy of the specification for the run."
    )
    not_producible: NotProducible | None = None
    review: str = Field(
        default="",
        description="Set by sync.py when the code changed the case's situation: check `how`, "
        "then remove it (dev:check fails while it is set).",
    )

    @model_validator(mode="after")
    def produced_or_not(self) -> CaseEntry:
        """A case is left to fill, produced (how, lab, variant), or not producible: never mixed."""
        produced = (self.how, self.lab, self.variant)
        if self.not_producible is not None and (any(produced) or self.config or self.spec):
            raise ValueError(f"case {self.id}: not producible, yet it says how it is produced")
        if any(produced) and not all(produced):
            raise ValueError(f"case {self.id}: how, lab and variant go together")
        if self.lab and self.lab not in LABS:
            raise ValueError(f"case {self.id}: unknown lab {self.lab!r} (one of {LABS})")
        return self

    @property
    def filled(self) -> bool:
        """Whether it says how it is produced, or why it cannot be."""
        return bool(self.variant) or self.not_producible is not None


class CaseFile(BaseModel):
    """
    The cases of one test. In its file (validation/cases/<test>.yaml) they are
    grouped by sub-test, in the order the test declares them, each written
    without its sub-test (its key) and with its id after the sub-test's; the
    answers that say nothing, which hold for any sub-test, come last, under
    ANY_SUB_TEST_KEY. load_case_file() and dump_case_file() convert.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    test: str
    name: str
    cases: list[CaseEntry]


# The kinds of change a variant makes, each applied and undone by run.py:
#   kong_plugin_set     set fields of a plugin of a Kong service or route (kong.yml)
#   kong_plugin_add     add a plugin to a Kong service, route, or globally (kong.yml)
#   kong_entity_add     add an entity to a top-level list of kong.yml (consumers,
#                       routes naming their service, upstreams)
#   kong_entity_set     set fields of an entity of a top-level list, by name
#   apisix_admin        one call to APISIX's Admin API (undone: setup.sh again, and
#                       every object the variant created deleted)
#   stop_container      stop a container of the lab (undone: started again)
#   stand_in_admin_api  a local process answering every request with one fixed
#                       answer, for the run's gateway.admin.url (stopped after)
#   compose_env         recreate a service of the lab with environment variables
#                       added (an extra compose file); undone: recreated without it
ChangeKind = Literal[
    "kong_plugin_set",
    "kong_plugin_add",
    "kong_entity_add",
    "kong_entity_set",
    "apisix_admin",
    "stop_container",
    "compose_env",
    "stand_in_admin_api",
]


class Change(BaseModel):
    """One change of a variant: its kind and its fields (run.py reads them)."""

    model_config = ConfigDict(frozen=True, extra="allow")

    kind: ChangeKind


class Variant(BaseModel):
    """One temporary change to a lab: what it does in words, and the changes."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    what: str = Field(min_length=1, description="The change, one sentence.")
    changes: list[Change] = Field(min_length=1)


def case_file_path(test: str) -> Path:
    """The case file of a test."""
    return CASES_DIR / f"{test}.yaml"


def load_case_file(test: str) -> CaseFile | None:
    """A test's case file, or None when it does not exist yet."""
    path = case_file_path(test)
    if not path.exists():
        return None
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    cases: list[dict[str, object]] = []
    for key, entries in (raw.get("sub_tests") or {}).items():
        sub_test = ANY_SUB_TEST if key == ANY_SUB_TEST_KEY else str(key)
        for entry in entries or []:
            cases.append({**entry, "id": f"{sub_test}/{entry['id']}", "sub_test": sub_test})
    return CaseFile.model_validate({"test": raw["test"], "name": raw["name"], "cases": cases})


def load_variants(lab: str) -> dict[str, Variant]:
    """A lab's variants by name (an empty dict when the file does not exist yet)."""
    path = VARIANTS_DIR / f"{lab}.yaml"
    if not path.exists():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {name: Variant.model_validate(body) for name, body in raw.items()}


def dump_case_file(case_file: CaseFile) -> str:
    """A case file as YAML: by sub-test, empty optional fields left out."""
    groups: dict[str, list[dict[str, object]]] = {}
    for entry in case_file.cases:
        data = entry.model_dump(mode="json", exclude_none=True)
        data["id"] = entry.id.split("/", 1)[1]
        del data["sub_test"]
        data["expected"] = {k: v for k, v in data["expected"].items() if v is not None}
        for optional in ("config", "review"):
            if not data[optional]:
                data.pop(optional)
        key = ANY_SUB_TEST_KEY if entry.sub_test == ANY_SUB_TEST else entry.sub_test
        groups.setdefault(key, []).append(data)
    body = {"test": case_file.test, "name": case_file.name, "sub_tests": groups}
    text = yaml.dump(body, Dumper=_IndentedDumper, sort_keys=False, allow_unicode=True, width=110)
    # A blank line before each sub-test and each case, for the reader.
    lines: list[str] = []
    for line in text.splitlines():
        sub_test_key = line.startswith("  ") and not line.startswith("   ") and line.endswith(":")
        if sub_test_key or line.startswith("    - id: "):
            lines.append("")
        lines.append(line)
    return "\n".join(lines) + "\n"


class _IndentedDumper(yaml.SafeDumper):
    """A YAML dumper that indents a list under its key, so the cases sit inside their sub-test."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:  # noqa: FBT001, FBT002
        """Never write a list flush with its key."""
        super().increase_indent(flow, indentless=False)
