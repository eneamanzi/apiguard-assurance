"""
src/tests/helpers/owned_object.py

A disposable object owned by a role, for the cross-user and property-level
authorization tests (2.2, 2.5). The object is created through a configured
resource (config.yaml `resources:`) as the role, so the run owns a real object
whose identifiers are known, then its documented by-id operations are found by
resolving their path parameters from the resource's values.

    owned = create_owned_object(target, context, client, "repository", ROLE_USER_A, "2.2")
    for method, path, template in object_operations(target, owned.values, _SAFE):
        ...                       # GET /api/v1/repos/<owner>/<repo>, resolved
    delete_resource(target, context, client, owned, "2.2")   # cleanup

The object is created and deleted by the calling test (effect CHANGES_DATA); the
resource's own teardown entry stays and accepts the 404 after an early delete.

Dependency rule: imports from stdlib, src.core and other src.tests.helpers
(resources, path_resolver). It must never import from src.tests.domain_* or
src.engine.
"""

from __future__ import annotations

import structlog
from src.core.context import TargetContext
from src.core.models import EndpointRecord
from src.tests.helpers.path_resolver import resolve_path_with_seed
from src.tests.helpers.resources import PreparedResource, create_resource

log: structlog.BoundLogger = structlog.get_logger(__name__)

# Re-exported so a test imports the creation and the resolution from one place.
create_owned_object = create_resource

# The methods that change nothing (for the read probes).
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})


def object_operations(
    target: TargetContext,
    values: dict[str, str],
    methods: frozenset[str],
) -> list[tuple[str, str, str]]:
    """
    The documented operations that address the created object, resolved.

    An operation addresses the object when every path parameter of its template
    is a key in `values` (the identifiers the resource read from the create
    response, e.g. `owner`, `repo`): the object's own by-id operations, not a
    collection. Of these, only the ones that use the **most** of the object's
    identifiers are kept, so that a less specific resource sharing one parameter
    (e.g. `/packages/{owner}`, which uses only `owner` while the repository is
    `/repos/{owner}/{repo}`) is not mistaken for the object. The path is then
    resolved from the values (falling back to `path_seed` for a parameter the
    values do not hold).

    Args:
        target:  The run's target (surface, path seed).
        values:  The created resource's values (its identifiers).
        methods: The HTTP methods to keep (e.g. SAFE_METHODS, or the write ones).

    Returns:
        (method, concrete path, template path) per operation, shortest first.
    """
    surface = target.attack_surface
    if surface is None:
        return []
    candidates: list[tuple[int, str, str]] = []
    for endpoint in surface.endpoints:
        if endpoint.method.upper() not in methods:
            continue
        params = _path_parameters(endpoint)
        if not params or not params <= values.keys():
            continue
        candidates.append((len(params), endpoint.method.upper(), endpoint.path))
    if not candidates:
        return []
    most_specific = max(count for count, _method, _path in candidates)
    seed = {**target.path_seed, **values}
    operations = [
        (method, resolve_path_with_seed(path, seed), path)
        for count, method, path in candidates
        if count == most_specific
    ]
    operations.sort(key=lambda item: (len(item[2]), item[2], item[0]))
    return operations


def _path_parameters(endpoint: EndpointRecord) -> set[str]:
    """The names of the endpoint's path parameters."""
    return {p.name for p in endpoint.parameters if p.location == "path"}


__all__ = ["PreparedResource", "SAFE_METHODS", "create_owned_object", "object_operations"]
