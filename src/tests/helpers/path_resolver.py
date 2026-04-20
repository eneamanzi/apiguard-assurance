"""
src/tests/helpers/path_resolver.py

Context-aware path parameter resolver for the APIGuard Assurance tool.

Responsibility
--------------
This module provides the single authoritative implementation for substituting
OpenAPI path template parameters (``{param}``) with real values during test
execution.  It replaces every test-local ``_resolve_path`` function that used
a single global placeholder, enabling a two-level lookup strategy:

    1. Seed lookup    -- If the parameter name is present in the operator-supplied
                         seed dictionary (``target.path_seed``), use the real value.
                         This allows probes to reach authentication middleware
                         instead of being rejected by the backend with 404.

    2. Fallback       -- If the parameter name is NOT in the seed, substitute the
                         caller-supplied fallback string (default ``"1"``).

Why a shared helper instead of per-test functions
--------------------------------------------------
The path resolution pattern recurs in every test that probes parametric paths
(Tests 1.1, 2.1, 2.2, 2.3, ...).  Extracting it here ensures:

    - A single regex pattern handles constrained variants (``{id:[0-9]+}``).
    - The seed lookup logic is maintained in one place.
    - Unit tests for the resolver do not depend on any test domain.
    - Future tests import ``resolve_path_with_seed`` directly without
      duplicating the substitution logic.

Constrained parameter syntax
-----------------------------
Some framework routers extend the OpenAPI ``{param}`` syntax with inline
constraints, such as ``{id:[0-9]+}``.  The resolver extracts the parameter name
as the substring before the first colon inside the braces.  The seed lookup
and fallback substitution use the extracted name, not the full expression.

    Input path:  ``/api/v1/repos/{owner}/{repo}/issues/{index}``
    Seed:        ``{"owner": "mario_rossi", "repo": "test-repo"}``
    Fallback:    ``"1"``
    Result:      ``/api/v1/repos/mario_rossi/test-repo/issues/1``

    Input path:  ``/api/v1/items/{id:[0-9]+}``
    Seed:        ``{"id": "42"}``
    Fallback:    ``"1"``
    Result:      ``/api/v1/items/42``

Non-parametric paths are returned unchanged regardless of the seed content.

Dependency rule
---------------
This module imports only from stdlib and structlog.  It must never import from
src.core, src.config, src.discovery, src.engine, or any other test module.
"""

from __future__ import annotations

import re

import structlog

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default fallback value used when a path parameter name is not found in the
# seed dictionary.  A generic integer string is the most broadly compatible
# placeholder: it satisfies integer-typed path parameters without triggering
# 422 (Unprocessable Entity) validation errors before the auth check fires,
# and is unlikely to match a real resource ID in any database.
PATH_PARAM_FALLBACK_DEFAULT: str = "1"

# Safe fallback for DELETE probes.  A non-numeric, application-specific string
# minimises the probability of matching a real resource ID, bounding the risk
# of accidental deletion to near-zero.
PATH_PARAM_FALLBACK_SAFE_DELETE: str = "apiguard-probe"

# Regex that matches an OpenAPI path template parameter.
# Capture group 1: the full content between braces (e.g. "owner" or "id:[0-9]+").
# The pattern deliberately does NOT use a named group to keep the substitution
# callback lean.
_PARAM_PATTERN: re.Pattern[str] = re.compile(r"\{([^}]+)\}")


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def resolve_path_with_seed(
    path: str,
    seed: dict[str, str],
    fallback: str = PATH_PARAM_FALLBACK_DEFAULT,
) -> str:
    """
    Substitute all OpenAPI path template parameters using the seed dictionary.

    For each ``{param}`` template found in ``path``:

        - If the extracted parameter name is a key in ``seed``, the
          corresponding seed value is used as the substitution.  This produces
          a real, routable path that reaches the backend (and therefore the
          authentication middleware) instead of returning 404 at the routing
          layer.

        - If the extracted parameter name is NOT in ``seed``, the ``fallback``
          string is substituted.  The caller selects the appropriate fallback
          for the probe context (generic ``"1"`` for read probes, the
          ``PATH_PARAM_FALLBACK_SAFE_DELETE`` constant for parametric DELETE
          probes).

    Non-parametric paths (no ``{...}`` segments) are returned unchanged.

    The function logs a DEBUG event for each substitution so that the
    assessment audit trail clearly indicates whether a real seed value or a
    fallback was used for each probe.

    Args:
        path:     OpenAPI path template string, e.g.
                  ``"/api/v1/repos/{owner}/{repo}/issues/{index}"``.
        seed:     Operator-supplied dictionary mapping parameter names to real
                  resource identifiers (e.g. ``{"owner": "mario_rossi"}``).
                  An empty dict causes all parameters to be substituted with
                  the fallback, matching the pre-seed behaviour.
        fallback: String to use when a parameter name is absent from ``seed``.
                  Defaults to ``PATH_PARAM_FALLBACK_DEFAULT`` (``"1"``).

    Returns:
        Path string with all ``{param}`` templates replaced.  For a
        non-parametric path (no template segments) this is the original string.

    Examples:
        >>> resolve_path_with_seed(
        ...     "/api/v1/repos/{owner}/{repo}",
        ...     {"owner": "mario_rossi", "repo": "test-repo"},
        ... )
        "/api/v1/repos/mario_rossi/test-repo"

        >>> resolve_path_with_seed(
        ...     "/api/v1/users/{id}",
        ...     {},
        ...     fallback="apiguard-probe",
        ... )
        "/api/v1/users/apiguard-probe"

        >>> resolve_path_with_seed("/api/v1/version", {})
        "/api/v1/version"
    """
    if "{" not in path:
        # Fast path: non-parametric paths are returned without regex evaluation.
        return path

    def _substitute(match: re.Match[str]) -> str:
        """
        Inner replacement callback for re.sub.

        Extracts the parameter name from the match (splitting on ':' to handle
        constrained variants like ``{id:[0-9]+}``), looks it up in the seed,
        and returns either the seed value or the fallback.
        """
        full_content: str = match.group(1)
        # Strip inline constraint suffix (e.g. "id:[0-9]+" → "id").
        param_name: str = full_content.split(":")[0].strip()

        if param_name in seed:
            log.debug(
                "path_resolver_seed_hit",
                param_name=param_name,
                substituted_with="seed_value",
            )
            return seed[param_name]

        log.debug(
            "path_resolver_seed_miss",
            param_name=param_name,
            substituted_with="fallback",
            fallback=fallback,
        )
        return fallback

    return _PARAM_PATTERN.sub(_substitute, path)


def extract_param_names_from_path(path: str) -> list[str]:
    """
    Extract all unique parameter names declared in an OpenAPI path template.

    Returns the names in the order they appear in the path, deduplicated while
    preserving first-occurrence order.  The same name appearing multiple times
    (unusual but not impossible) is returned only once.

    Constrained variants (``{id:[0-9]+}``) are normalised to the bare name
    (``"id"``) using the same colon-split logic as ``resolve_path_with_seed``.

    Args:
        path: OpenAPI path template string (e.g.
              ``"/api/v1/repos/{owner}/{repo}/issues/{index}"``).

    Returns:
        Ordered, deduplicated list of parameter name strings.  Empty list if
        the path contains no template segments.

    Examples:
        >>> extract_param_names_from_path("/api/v1/repos/{owner}/{repo}/issues/{index}")
        ["owner", "repo", "index"]

        >>> extract_param_names_from_path("/api/v1/version")
        []
    """
    seen: set[str] = set()
    result: list[str] = []

    for match in _PARAM_PATTERN.finditer(path):
        full_content: str = match.group(1)
        param_name: str = full_content.split(":")[0].strip()

        if param_name not in seen:
            seen.add(param_name)
            result.append(param_name)

    return result
