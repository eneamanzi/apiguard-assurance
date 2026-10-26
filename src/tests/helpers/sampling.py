"""
src/tests/helpers/sampling.py

A shared, stated sampling rule (rule 5: a sample by a rule, never "the first N").
A test that checks a property of many responses (security headers, leaked
information) takes one documented operation per service prefix, so the sample
spans the services of the API and can show an inconsistency between them,
without probing every endpoint.

    for method, path, template in sample_by_service(target, _SAFE_METHODS):
        ...

The service prefixes are the Phase-2 `service_prefixes` facts (the static roots
under which the operations live, e.g. /identity/api, /api); the operation chosen
for each is the shortest of the given methods under it. When no prefix is
derived, the shortest operations overall are taken, capped.

Dependency rule: imports from stdlib, src.core and other src.tests.helpers.
"""

from __future__ import annotations

from src.core.context import TargetContext
from src.core.models import EndpointRecord
from src.tests.helpers.path_resolver import resolve_path_with_seed

# The rule name of the service prefixes (src/discovery/derivation.py); written
# here as a string, a test never imports discovery/.
_RULE_SERVICE_PREFIXES: str = "service_prefixes"

# The largest sample when no service prefix is derived.
_FALLBACK_CAP: int = 8


def sample_by_service(
    target: TargetContext,
    methods: frozenset[str],
) -> list[tuple[str, str, str]]:
    """
    One documented operation per service prefix, of the given methods.

    Args:
        target:  The run's target (surface, derived facts, path seed).
        methods: The HTTP methods to sample from (e.g. {'GET', 'HEAD'}).

    Returns:
        (method, concrete path, template path) per service, shortest first; the
        shortest operations overall (capped) when no service prefix is derived.
    """
    surface = target.attack_surface
    if surface is None:
        return []
    candidates = sorted(
        (e for e in surface.endpoints if e.method.upper() in methods),
        key=lambda e: (len(e.path), e.path, e.method),
    )
    if not candidates:
        return []
    prefixes = [fact.value for fact in surface.derived_facts(_RULE_SERVICE_PREFIXES)]
    chosen: list[EndpointRecord] = []
    if prefixes and prefixes != ["/"]:
        for prefix in sorted(prefixes, key=len, reverse=True):
            first = next((e for e in candidates if e.path.startswith(prefix)), None)
            if first is not None and first not in chosen:
                chosen.append(first)
    else:
        chosen = candidates[:_FALLBACK_CAP]
    return [
        (e.method.upper(), resolve_path_with_seed(e.path, target.path_seed), e.path) for e in chosen
    ]
