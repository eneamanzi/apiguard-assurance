"""
src/tests/helpers/route_limits.py

The limits a gateway states for the routes that may serve one request.

Tests 4.1 and 4.4 read a limit from the gateway (`rate_limits()`,
`body_size_limits()`) to size their probe and, when the probe goes past it
unrefused, to say the limit is configured and not enforced. That claim holds
only for a limit that applies to the probe, so a limit counts for a request
only through the routes that may serve it:

    the routes      every enabled route with a path that matches the
                    request's path (a prefix it starts with, the exact path, a
                    regular expression found in it) and a method list that is
                    empty or holds the request's method. This is a superset of
                    the gateway's own matching: Kong anchors a regular
                    expression at the start of the path, and both gateways also
                    match hosts and headers, which the routes concept does not
                    carry. A route without paths may serve any path.
    their limits    for each route, the enabled limits on every request
                    (GLOBAL), on the route's backend and on the route itself.

Which of them the gateway applies when several do is not decided here (Kong
runs the most specific instance of a plugin, APISIX runs a global rule's
plugin in addition to the route's): a test that needs certainty asks every
limit of every route.

Dependency rule: imports from stdlib and src.core.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Generic, TypeVar
from urllib.parse import urlsplit

from src.core.gateway.base import BaseGatewayAdapter
from src.core.gateway.concepts import (
    BodySizeLimit,
    ConceptRead,
    ConceptScope,
    ConceptStatus,
    GatewayRoute,
    RateLimit,
    RouteMatch,
    RoutePath,
)

LimitT = TypeVar("LimitT", RateLimit, BodySizeLimit)


@dataclass(frozen=True)
class RouteLimits(Generic[LimitT]):
    """A route that may serve the request, with the limits that may apply to it."""

    route: GatewayRoute
    limits: tuple[LimitT, ...]


def limits_for_request(
    gateway: BaseGatewayAdapter,
    limits: ConceptRead[LimitT],
    base_url: str,
    path: str,
    method: str,
) -> tuple[RouteLimits[LimitT], ...] | None:
    """
    The routes that may serve a request, each with the limits that may apply to it.

    Args:
        gateway:  The run's gateway adapter (its routes).
        limits:   The limits concept read from it.
        base_url: The target's base URL: its path, if any, comes before the
                  request path at the gateway.
        path:     The request path, relative to base_url.
        method:   The request method.

    Returns:
        One entry per route that may serve the request (its limits may be
        empty), or None when the routes or the limits could not be read or no
        route may serve the request: then nothing is known of the limits that
        apply.
    """
    routes = gateway.routes()
    if routes.status != ConceptStatus.READ or limits.status != ConceptStatus.READ:
        return None
    full_path = urlsplit(base_url).path.rstrip("/") + path
    serving = [
        route
        for route in routes.items
        if route.enabled and _may_serve(route, full_path, method.upper())
    ]
    if not serving:
        return None
    return tuple(
        RouteLimits(route=route, limits=_applying(limits.items, route)) for route in serving
    )


def _may_serve(route: GatewayRoute, path: str, method: str) -> bool:
    """Whether a route may serve a request (module docstring: a superset of the gateway's)."""
    if route.methods and method not in {m.upper() for m in route.methods}:
        return False
    if not route.paths:
        return True
    return any(_path_matches(route_path, path) for route_path in route.paths)


def _path_matches(route_path: RoutePath, path: str) -> bool:
    """Whether one route path matches a request path; a regex that does not compile may."""
    if route_path.match == RouteMatch.PREFIX:
        return path.startswith(route_path.value)
    if route_path.match == RouteMatch.EXACT:
        return path == route_path.value
    try:
        return re.search(route_path.value, path) is not None
    except re.error:
        return True


def _applying(items: tuple[LimitT, ...], route: GatewayRoute) -> tuple[LimitT, ...]:
    """The enabled limits on every request, on the route's backend and on the route."""
    return tuple(
        item
        for item in items
        if item.enabled
        and (
            item.scope == ConceptScope.GLOBAL
            or (item.scope == ConceptScope.BACKEND and item.name == route.backend)
            or (item.scope == ConceptScope.ROUTE and item.name == route.name)
        )
    )
