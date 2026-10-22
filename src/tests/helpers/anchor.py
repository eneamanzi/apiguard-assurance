"""
src/tests/helpers/anchor.py

Finding an anchor: a documented operation that answers 2xx with the role's
valid credential. Tests 1.2 and 1.4 need one, because their question is whether
a degraded credential (invalid, revoked) is refused, and "refused" means
something only where the genuine credential is accepted. Without an anchor, a
refusal could be the endpoint refusing everyone.

The anchor is derived, not configured (rule 5): the documented read operations
that require authentication are tried in a stated order with the credential,
and the first that answers 2xx is the anchor. A read is used so that finding
the anchor changes nothing on the target.

Dependency rule: imports from stdlib, src.core and other src.tests.helpers.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.core.assessment_test import category_of
from src.core.client import SecurityClient
from src.core.context import TargetContext
from src.core.exceptions import SecurityClientError
from src.core.models import EvidenceRecord, ResponseCategory
from src.tests.helpers.path_resolver import resolve_path_with_seed

# The methods that change nothing: an anchor is looked for only among them.
_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})


@dataclass(frozen=True)
class Anchor:
    """A documented operation that answered 2xx with the role's credential."""

    method: str
    path: str
    record: EvidenceRecord


def find_anchor(
    target: TargetContext,
    client: SecurityClient,
    headers: dict[str, str],
    params: dict[str, str],
    test_id: str,
) -> Anchor | None:
    """
    The first documented read operation that answers 2xx with a given credential.

    Args:
        target:  The run's target (surface, path_seed).
        client:  The run's HTTP client.
        headers: The headers carrying the credential (from a placement).
        params:  The query parameters carrying the credential, if any.
        test_id: The id the probe requests are attributed to.

    Returns:
        The Anchor, or None when no protected read answered 2xx (an API with
        no readable protected operation, or a credential that works nowhere).
    """
    surface = target.attack_surface
    if surface is None:
        return None
    candidates = sorted(
        (e for e in surface.endpoints if e.method.upper() in _SAFE_METHODS and e.requires_auth),
        key=lambda e: (len(e.path), e.path, e.method),
    )
    for endpoint in candidates:
        path = resolve_path_with_seed(endpoint.path, target.path_seed)
        method = endpoint.method.upper()
        with_credential = _ask(client, method, path, headers, params, test_id)
        if with_credential is None or category_of(with_credential) != ResponseCategory.SERVED:
            continue
        # The credential must make the difference: an endpoint that answers 2xx
        # with no credential too (a public one the spec marks protected, such as
        # Forgejo's `/api/v1/orgs`) is no anchor, because then a refusal of a
        # degraded or revoked credential would not be about the credential.
        without = _ask(client, method, path, {}, {}, test_id)
        if without is not None and category_of(without) == ResponseCategory.SERVED:
            continue
        return Anchor(method=method, path=path, record=with_credential)
    return None


def _ask(
    client: SecurityClient,
    method: str,
    path: str,
    headers: dict[str, str],
    params: dict[str, str],
    test_id: str,
) -> EvidenceRecord | None:
    """One request, returning its record or None on a transport failure."""
    try:
        _response, record = client.request(
            method,
            path,
            test_id=test_id,
            headers=dict(headers) or None,
            params=dict(params) or None,
        )
    except SecurityClientError:
        return None
    return record
