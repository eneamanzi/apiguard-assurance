"""
src/core/models/standards.py

References to security standards: one model, one format per standard.

A reference is a pair: the standard and the identifier the standard itself
prescribes, written exactly as the standard writes it, so a reader of the
report recognises it and a tool can group by it (SARIF names a taxonomy and
the identifier of an entry the same way). Where the standard prescribes no
compact form for a part of a document (RFC, NIST SP), the reference carries
it as a separate section.

    Standard        identifier                      example           source of the format
    CWE             CWE-<number>                    CWE-285           MITRE CWE
    OWASP_API_TOP10 API<n>:<year>                   API5:2023         OWASP API Security Top 10
    OWASP_TOP10     A<nn>:<year>                    A01:2025          OWASP Top 10
    ASVS            v<version>-<ch>.<sec>.<req>     v5.0.0-1.2.5      ASVS 5.0, "What is the ASVS"
    WSTG            WSTG-v<version>-<CAT>-<nn>      WSTG-v42-ATHN-01  WSTG README
    RFC             <number> (+ section)            9110, 15.5.2      RFC 7322 (textual naming)
    NIST_SP         <series>-<number> (+ section)   800-204A, 4.3     NIST publication identifiers

ASVS and WSTG ask documents, reports and tools to always write the version,
since the numbering changes between versions: the identifier is accepted
only with it. The text of a reference (Reference.text) adds the name of the
standard where the identifier alone does not say it: "OWASP ASVS
v5.0.0-1.2.5", "RFC 9110, Section 15.5.2".

The patterns check the form of a reference, not that the cited entry exists
or says what the test claims: that is checked in each test's review.

Dependency rule: this module imports only from pydantic and the stdlib.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator


class Standard(StrEnum):
    """The standards a reference may cite."""

    CWE = "CWE"
    OWASP_API_TOP10 = "OWASP_API_TOP10"
    OWASP_TOP10 = "OWASP_TOP10"
    ASVS = "ASVS"
    WSTG = "WSTG"
    RFC = "RFC"
    NIST_SP = "NIST_SP"


@dataclass(frozen=True)
class StandardFormat:
    """
    How a standard's identifiers are written and shown: the standard's name,
    the identifier pattern and an example, the text put before the identifier
    when shown, and an example section (None: the identifiers take no section).
    """

    name: str
    pattern: re.Pattern[str]
    example: str
    prefix: str
    section_example: str | None


# A section of a document: numbers joined by dots, optionally starting with an
# appendix letter ("15.5.2", "4.3", "A.1").
SECTION_PATTERN: re.Pattern[str] = re.compile(r"^([A-Z]|[1-9][0-9]*)(\.[0-9]+)*$")

CWE_ID_PATTERN: re.Pattern[str] = re.compile(r"^CWE-[1-9][0-9]*$")

STANDARD_FORMATS: dict[Standard, StandardFormat] = {
    Standard.CWE: StandardFormat(
        name="CWE",
        pattern=CWE_ID_PATTERN,
        example="CWE-285",
        prefix="",
        section_example=None,
    ),
    Standard.OWASP_API_TOP10: StandardFormat(
        name="OWASP API Security Top 10",
        pattern=re.compile(r"^API([1-9]|10):20[0-9]{2}$"),
        example="API5:2023",
        prefix="OWASP ",
        section_example=None,
    ),
    Standard.OWASP_TOP10: StandardFormat(
        name="OWASP Top 10",
        pattern=re.compile(r"^A(0[1-9]|10):20[0-9]{2}$"),
        example="A01:2025",
        prefix="OWASP ",
        section_example=None,
    ),
    Standard.ASVS: StandardFormat(
        name="OWASP ASVS",
        pattern=re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+-[1-9][0-9]*\.[1-9][0-9]*\.[1-9][0-9]*$"),
        example="v5.0.0-1.2.5",
        prefix="OWASP ASVS ",
        section_example=None,
    ),
    Standard.WSTG: StandardFormat(
        name="OWASP WSTG",
        pattern=re.compile(r"^WSTG-v[0-9]+-[A-Z]{4}-[0-9]{2}$"),
        example="WSTG-v42-ATHN-01",
        prefix="OWASP ",
        section_example=None,
    ),
    Standard.RFC: StandardFormat(
        name="IETF RFC",
        pattern=re.compile(r"^[1-9][0-9]*$"),
        example="9110",
        prefix="RFC ",
        section_example="15.5.2",
    ),
    Standard.NIST_SP: StandardFormat(
        name="NIST Special Publication",
        pattern=re.compile(r"^[1-9][0-9]*-[1-9][0-9]*[A-Z]?(-[1-9][0-9]*)?(r[1-9][0-9]*)?$"),
        example="800-204A",
        prefix="NIST SP ",
        section_example="4.3",
    ),
}


class Reference(BaseModel):
    """
    One reference to a standard: the standard, its identifier, and for a
    document without compact identifiers (RFC, NIST SP) an optional section.

    Validated on construction: an identifier not in the standard's format, or
    a section on a standard whose identifiers are already precise, is
    rejected with the expected format and an example.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    standard: Standard = Field(description="The standard cited.")
    id: str = Field(
        description=(
            "The identifier as the standard writes it: `CWE-285`, `API5:2023`, `A01:2025`, "
            "`v5.0.0-1.2.5` (ASVS), `WSTG-v42-ATHN-01`, `9110` (RFC), `800-204A` (NIST SP)."
        )
    )
    section: str | None = Field(
        default=None,
        description="RFC and NIST SP only: the section cited, e.g. `15.5.2`.",
    )

    @model_validator(mode="before")
    @classmethod
    def _drop_text(cls, data: object) -> object:
        """Accept back the serialized `text` (computed, output only): the report is re-read."""
        if isinstance(data, dict) and "text" in data:
            return {key: value for key, value in data.items() if key != "text"}
        return data

    @model_validator(mode="after")
    def _in_format(self) -> Reference:
        """Check the identifier and the section against the standard's format."""
        spec = STANDARD_FORMATS[self.standard]
        if not spec.pattern.match(self.id):
            raise ValueError(
                f"{self.standard.value} reference {self.id!r} is not in the format of "
                f"{spec.name}, e.g. {spec.example!r}"
            )
        if self.section is not None:
            if spec.section_example is None:
                raise ValueError(
                    f"{self.standard.value} reference {self.id!r}: {spec.name} identifiers "
                    f"take no section"
                )
            if not SECTION_PATTERN.match(self.section):
                raise ValueError(
                    f"{self.standard.value} reference {self.id!r}: section {self.section!r} "
                    f"must be numbers joined by dots, e.g. {spec.section_example!r}"
                )
        return self

    @computed_field(  # type: ignore[prop-decorator]
        description=(
            "The reference as shown to a reader: `CWE-285`, `OWASP API5:2023`, "
            "`OWASP ASVS v5.0.0-1.2.5`, `RFC 9110, Section 15.5.2`."
        )
    )
    @property
    def text(self) -> str:
        """The identifier, with the name of the standard where it does not say it."""
        text = STANDARD_FORMATS[self.standard].prefix + self.id
        if self.section is not None:
            text += f", Section {self.section}"
        return text


def duplicate_references(references: tuple[Reference, ...] | list[Reference]) -> list[str]:
    """
    The references cited more than once.

    Args:
        references: The references of a declaration, a finding or a note.

    Returns:
        The text of each repeated reference, sorted; empty when there is none.
    """
    return sorted({ref.text for ref in references if references.count(ref) > 1})
