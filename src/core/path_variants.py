"""
src/core/path_variants.py

The variants of a path that a target may route to the same operation while a
control attached to the path does not recognise them (a
technique, not a guarantee, so it is written once here and applied by every
test whose control is decided on the path: 1.1 to authentication, 2.1 to the
admin paths).

Each variant is a way of writing the same resource that a router may accept:
an upper-case segment, a trailing slash, a doubled separator, a dot segment, a
percent-encoded separator, a path parameter appended with ';'. Where the
gateway or the application normalises the path before applying its policy, the
variant reaches the same operation and the same control; where it does not, the
control can be missed while the operation still answers.

What the labs answer to these variants, measured 2026-10-22 on the three labs:
no variant was served without a credential. Kong normalises the dot segments
and routes them to the endpoint, which asks for a credential as the canonical
path does; APISIX does not, so the application answers "not found"; on crAPI
the canonical path answers 404 while four variants answer 401. So a variant
that merely answers differently proves nothing: only one that is served
without the control is a finding, and that judgement belongs to the test.

Sources of the list:

    RFC 3986 sections 3.3, 6.2.2 and 6.2.3  the syntax of a path, the
                                            case-sensitivity of its segments,
                                            the removal of dot segments and
                                            the equivalence of an empty
                                            segment;
    RFC 9110 section 4.2.3                  the comparison of URIs;
    OWASP WSTG-v42-ATHZ-01                  directory traversal and path
                                            bypass variants;
    Q-32 (2026-10-14)                       double encoding and "../" seen on
                                            the labs; ';' in the path.

Dependency rule: imports only from the standard library. No test logic: the
module says how to write a path, never what an answer means.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class VariantKind(StrEnum):
    """
    How a variant is written, for the result and the report.

    UPPER_SEGMENT    -- the last segment in upper case.
    TRAILING_SLASH   -- a slash appended.
    DOUBLE_SLASH     -- the leading separator doubled.
    DOT_SEGMENT      -- "/./" before the last segment.
    DOT_DOT_SEGMENT  -- an extra segment removed again with "/../".
    ENCODED_SLASH    -- the separators written as "%2f".
    DOUBLE_ENCODED   -- the separators written as "%252f" (decoded twice).
    PATH_PARAMETER   -- ";" and a parameter appended to the last segment.
    """

    UPPER_SEGMENT = "UPPER_SEGMENT"
    TRAILING_SLASH = "TRAILING_SLASH"
    DOUBLE_SLASH = "DOUBLE_SLASH"
    DOT_SEGMENT = "DOT_SEGMENT"
    DOT_DOT_SEGMENT = "DOT_DOT_SEGMENT"
    ENCODED_SLASH = "ENCODED_SLASH"
    DOUBLE_ENCODED = "DOUBLE_ENCODED"
    PATH_PARAMETER = "PATH_PARAMETER"


@dataclass(frozen=True)
class PathVariant:
    """One way of writing a path, with the kind that says how."""

    kind: VariantKind
    path: str


# The segment inserted and removed again by the dot-dot variant: a name no
# route is expected to match on its own.
_FILLER_SEGMENT: str = "zqxv"

# The parameter appended by the path-parameter variant.
_PATH_PARAMETER: str = ";zqxv=1"


def path_variants(path: str) -> tuple[PathVariant, ...]:
    """
    The variants of one concrete path, in a fixed order.

    Args:
        path: A concrete path (no template parameters left), starting with "/".

    Returns:
        One PathVariant per kind that applies, without duplicates and without
        the path itself. A path of one segment has no dot-segment variants: in
        "/users" there is nothing before the last segment.

    Raises:
        ValueError: The path does not start with "/".
    """
    if not path.startswith("/"):
        raise ValueError(f"path must start with '/': {path!r}")
    body = path.rstrip("/") or "/"
    head, _, last = body.rpartition("/")
    candidates: list[PathVariant] = []
    if last and last != last.upper():
        candidates.append(PathVariant(VariantKind.UPPER_SEGMENT, f"{head}/{last.upper()}"))
    candidates.append(PathVariant(VariantKind.TRAILING_SLASH, f"{body}/"))
    candidates.append(PathVariant(VariantKind.DOUBLE_SLASH, f"/{body}"))
    if head:
        candidates.append(PathVariant(VariantKind.DOT_SEGMENT, f"{head}/./{last}"))
        candidates.append(
            PathVariant(
                VariantKind.DOT_DOT_SEGMENT,
                f"{head}/{_FILLER_SEGMENT}/../{last}",
            )
        )
        # The leading separator stays a real one, so that the result is still a
        # path the client can be asked for; the ones inside it are encoded.
        inside = body[1:]
        candidates.append(PathVariant(VariantKind.ENCODED_SLASH, "/" + inside.replace("/", "%2f")))
        candidates.append(
            PathVariant(VariantKind.DOUBLE_ENCODED, "/" + inside.replace("/", "%252f"))
        )
    candidates.append(PathVariant(VariantKind.PATH_PARAMETER, f"{body}{_PATH_PARAMETER}"))
    seen: set[str] = {path, body}
    kept: list[PathVariant] = []
    for variant in candidates:
        if variant.path in seen:
            continue
        seen.add(variant.path)
        kept.append(variant)
    return tuple(kept)
