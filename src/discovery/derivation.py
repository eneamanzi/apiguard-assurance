"""
src/discovery/derivation.py

Derived knowledge: what the tool deduces from the specification before any
test runs (docs/project/test-review.md, topic 4: "derive first, configure on
top").

Each rule has a name and a basis (DECLARED: the specification states it;
HEURISTIC: the rule infers it) and turns the specification into DerivedFact
objects; derive_knowledge() runs every rule of RULES in Phase 2 and returns the
AttackSurface with its facts. The tests read them (AttackSurface.derived_facts)
without importing this package; the report lists them. No request is sent:
everything comes from the specification.

A rule is added together with the test that uses it, and proven on the labs
then (the crAPI case of its category, Forgejo as the negative); a rule that
does not hold on them is not adopted.

Rules:
    service_prefixes (HEURISTIC) -- the static prefixes under which the
        operations of the specification live: for each first path segment,
        the longest common prefix of the directories of its paths (the static
        segments before the first parameter, without the last one), cut before
        the first segment shaped as a version (v1, v2, v2.7): the version is
        something to explore (an old version left active), not part of the
        service's root. A prefix that is itself a documented path, or the
        direct parent of a parameter (/users with /users/{id}), is a collection
        of objects, not a service: the API lives at the root, "/". On crAPI
        /identity/api, /community/api, /workshop/api; on Forgejo /api; on an API
        whose resources are at the root, "/". Used to look for undocumented
        paths where the services really are (test 0.1), not only at the root.

    version_siblings (HEURISTIC) -- the API versions next to the documented
        ones that the specification does not document. For each position where
        a path segment is shaped as a version (VERSION_SEGMENT: the part of the
        path before it, e.g. /identity/api/), the major numbers documented there
        (v2, v2.7 and v4.0 give 2 and 4); the candidates are the majors from 1
        to the highest plus one that are not documented, written v<major>. One
        fact per candidate, its value the path of the version (/identity/api/v3),
        its note the documented versions. On Forgejo (/api/v1 only) /api/v2; on
        crAPI /identity/api/v1 and v3, /identity/api/auth/v1 and v5,
        /community/api/v1 and v3. Used to look for an undocumented version that
        still answers (test 0.1).

Dependency rule: imports only from the standard library, structlog and
src.core.models.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

import structlog

from src.core.models import AttackSurface, DerivationBasis, DerivedFact, EndpointRecord

log: structlog.BoundLogger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class DerivationRule:
    """A named rule: its basis and the function that derives its facts."""

    name: str
    basis: DerivationBasis
    derive: Callable[[dict[str, object], Sequence[EndpointRecord]], list[DerivedFact]]


# ---------------------------------------------------------------------------
# Rule: service_prefixes
# ---------------------------------------------------------------------------

SERVICE_PREFIXES: str = "service_prefixes"

# A path segment shaped as an API version: v1, v2, v4.0, v2.7.
VERSION_SEGMENT: re.Pattern[str] = re.compile(r"^v\d+(\.\d+)*$", re.IGNORECASE)


def _directories(path: str) -> list[str]:
    """The static segments of a path before its first parameter, without the last one."""
    segments = [segment for segment in path.split("/") if segment]
    static: list[str] = []
    for segment in segments:
        if "{" in segment:
            return static
        static.append(segment)
    return static[:-1]


def _common_prefix(lists: list[list[str]]) -> list[str]:
    """The longest common prefix of several segment lists, cut before a version segment."""
    common: list[str] = []
    for column in zip(*lists, strict=False):
        if len(set(column)) != 1 or VERSION_SEGMENT.match(column[0]):
            break
        common.append(column[0])
    return common


def _is_collection(prefix: str, paths: set[str]) -> bool:
    """A prefix that is a documented path or the direct parent of a parameter."""
    return prefix in paths or any(
        path.startswith(prefix + "/{") and "/" not in path[len(prefix) + 1 :].split("}", 1)[0]
        for path in paths
    )


def _service_prefixes(
    spec: dict[str, object], endpoints: Sequence[EndpointRecord]
) -> list[DerivedFact]:
    """The service prefixes of the specification (see the module docstring)."""
    paths = {endpoint.path for endpoint in endpoints}
    groups: dict[str, list[list[str]]] = {}
    for path in sorted(paths):
        directories = _directories(path)
        if directories:
            groups.setdefault(directories[0], []).append(directories)
    found: dict[str, str] = {}
    for first, group in groups.items():
        prefix = "/" + "/".join(_common_prefix(group))
        if _is_collection(prefix, paths):
            prefix = "/"
        note = f"common prefix of the {len(group)} path(s) under /{first}"
        if prefix == "/":
            note = f"the paths under /{first} start at the root (a collection or a version)"
        found.setdefault(prefix, note)
    return [
        DerivedFact(rule=SERVICE_PREFIXES, basis=DerivationBasis.HEURISTIC, value=prefix, note=note)
        for prefix, note in found.items()
    ]


# ---------------------------------------------------------------------------
# Rule: version_siblings
# ---------------------------------------------------------------------------

VERSION_SIBLINGS: str = "version_siblings"

# The major number of a version segment: "v2.7" -> 2.
_VERSION_MAJOR: re.Pattern[str] = re.compile(r"^v(\d+)", re.IGNORECASE)

# The first major version a candidate may have.
_FIRST_MAJOR: int = 1


def _version_siblings(
    spec: dict[str, object], endpoints: Sequence[EndpointRecord]
) -> list[DerivedFact]:
    """The undocumented versions next to the documented ones (see the module docstring)."""
    documented: dict[str, set[str]] = {}
    for path in sorted({endpoint.path for endpoint in endpoints}):
        segments = path.split("/")
        for position, segment in enumerate(segments):
            if VERSION_SEGMENT.match(segment):
                base = "/".join(segments[:position])
                documented.setdefault(base, set()).add(segment)
    facts: list[DerivedFact] = []
    for base, versions in documented.items():
        majors: set[int] = set()
        for version in versions:
            match = _VERSION_MAJOR.match(version)
            if match is not None:
                majors.add(int(match.group(1)))
        note = f"documented under {base}/: {', '.join(sorted(versions))}"
        for major in range(_FIRST_MAJOR, max(majors) + 2):
            if major not in majors:
                facts.append(
                    DerivedFact(
                        rule=VERSION_SIBLINGS,
                        basis=DerivationBasis.HEURISTIC,
                        value=f"{base}/v{major}",
                        note=note,
                    )
                )
    return facts


# ---------------------------------------------------------------------------
# Registry and entry point
# ---------------------------------------------------------------------------

RULES: tuple[DerivationRule, ...] = (
    DerivationRule(SERVICE_PREFIXES, DerivationBasis.HEURISTIC, _service_prefixes),
    DerivationRule(VERSION_SIBLINGS, DerivationBasis.HEURISTIC, _version_siblings),
)


def derive_knowledge(spec: dict[str, object], surface: AttackSurface) -> AttackSurface:
    """
    Run every rule on the specification and return the surface with its facts.

    Args:
        spec:    The dereferenced specification (load_openapi_spec).
        surface: The AttackSurface built from it (build_attack_surface).

    Returns:
        A copy of the surface whose `derived` holds every rule's facts.
    """
    facts: list[DerivedFact] = []
    for rule in RULES:
        produced = rule.derive(spec, surface.endpoints)
        facts.extend(produced)
        log.info("derivation_rule_applied", rule=rule.name, basis=rule.basis, facts=len(produced))
    return surface.model_copy(update={"derived": facts})
