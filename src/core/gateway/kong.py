"""
src/core/gateway/kong.py

Kong Gateway adapter for WHITE_BOX configuration audit tests.

Implements BaseGatewayAdapter against the Kong DB-less Admin API (v3.x).
Provides read-only access to routes, services, plugins, and upstreams via
paginated GET requests to the Kong Admin API.

Construction and HTTP reads (direct httpx, not SecurityClient) come from
BaseGatewayAdapter; gateway.health.url is not used: Kong's Admin API
reports the live health of the targets.

Paginated responses
-------------------
Kong returns paginated responses in the format:
    {"data": [...], "next": "/path?offset=..."}

_fetch_paginated() follows the 'next' cursor until exhausted.  In DB-less
mode, all objects are returned in a single page and 'next' is null.

Dependency rule: imports from stdlib, structlog, src.core.gateway.base and
src.core.gateway.concepts. Must never import from src.tests, src.engine,
src.config, or src.discovery.
"""

from __future__ import annotations

from typing import Any

import structlog

from src.core.gateway.base import BaseGatewayAdapter, collect_text_values
from src.core.gateway.concepts import (
    ActiveCheck,
    BackendTimeout,
    CircuitBreaker,
    ConceptRead,
    ConceptScope,
    ConfigValue,
    ConfigValueKind,
    GatewayRoute,
    HealthCheck,
    PassiveCheck,
    SigningPolicy,
    TargetHealth,
    TargetState,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Kong Admin API resource paths
# ---------------------------------------------------------------------------

_PATH_ROUTES: str = "/routes"
_PATH_PLUGINS: str = "/plugins"
_PATH_SERVICES: str = "/services"
_PATH_UPSTREAMS: str = "/upstreams"
_PATH_UPSTREAM_HEALTH: str = "/upstreams/{name}/health"

# Kong milliseconds to the concepts' seconds.
_MS_PER_SECOND: float = 1000.0
# Kong's health values of a target that map to a neutral state (others: unknown).
_KONG_TARGET_STATES: dict[str, TargetState] = {
    "HEALTHY": TargetState.HEALTHY,
    "UNHEALTHY": TargetState.UNHEALTHY,
}
# Kong OSS ships no circuit breaker: these field names of third-party breaker
# plugins are tried in order (moved from test 4.3).
_BREAKER_THRESHOLD_FIELDS: tuple[str, ...] = (
    "failure_threshold",
    "consecutive_errors",
    "error_threshold_percentage",
)
_BREAKER_OPEN_FIELDS: tuple[str, ...] = (
    "timeout",
    "sleep_time",
    "recovery_time",
    "timeout_duration",
)
_GLOBAL_SCOPE_NAME: str = "global"


# ---------------------------------------------------------------------------
# KongGatewayAdapter
# ---------------------------------------------------------------------------


class KongGatewayAdapter(BaseGatewayAdapter):
    """
    Gateway adapter for Kong (DB-less mode) Admin API.

    Targets Kong OSS 3.x with the DB-less Admin API exposed on a dedicated
    port (default: 8001).  All calls are read-only GET requests.

    Instantiated by engine.py Phase 3 when gateway.adapter = 'kong'
    is set in config.yaml.  The instance is stored on TargetContext.gateway
    and shared across all WHITE_BOX tests for the assessment run.

    Built with the arguments of BaseGatewayAdapter; the Admin API base URL
    is e.g. 'http://localhost:8001'.
    """

    @property
    def adapter_name(self) -> str:
        """Return the adapter identifier used in logs and error messages."""
        return "kong"

    # ------------------------------------------------------------------
    # Neutral concepts (docs/architecture/design-decisions.md, D7)
    # ------------------------------------------------------------------

    def _read_backend_timeouts(self) -> ConceptRead[BackendTimeout]:
        """Map each Kong Service to its timeouts (milliseconds to seconds)."""
        items = tuple(
            BackendTimeout(
                scope=ConceptScope.BACKEND,
                name=self._service_name(service),
                connect_seconds=_ms_to_seconds(service.get("connect_timeout")),
                send_seconds=_ms_to_seconds(service.get("write_timeout")),
                read_seconds=_ms_to_seconds(service.get("read_timeout")),
                source=f"service {self._service_name(service)}",
            )
            for service in self._fetch_paginated(_PATH_SERVICES)
        )
        return ConceptRead[BackendTimeout].read(items)

    def _read_health_checks(self) -> ConceptRead[HealthCheck]:
        """Map each Kong Upstream to its passive and active health checks."""
        items: list[HealthCheck] = []
        for upstream in self._fetch_paginated(_PATH_UPSTREAMS):
            name = self._upstream_name(upstream)
            checks: dict[str, Any] = upstream.get("healthchecks") or {}
            passive: dict[str, Any] = checks.get("passive") or {}
            unhealthy: dict[str, Any] = passive.get("unhealthy") or {}
            active: dict[str, Any] = checks.get("active") or {}
            items.append(
                HealthCheck(
                    scope=ConceptScope.BACKEND,
                    name=name,
                    passive=PassiveCheck(
                        http_failures=unhealthy.get("http_failures"),
                        tcp_failures=unhealthy.get("tcp_failures"),
                        timeouts=unhealthy.get("timeouts"),
                        failure_statuses=tuple(unhealthy.get("http_statuses") or ()),
                    )
                    if passive
                    else None,
                    active=ActiveCheck(
                        healthy_interval_seconds=(active.get("healthy") or {}).get("interval"),
                        unhealthy_interval_seconds=(active.get("unhealthy") or {}).get("interval"),
                        http_path=active.get("http_path"),
                    )
                    if active
                    else None,
                    source=f"upstream {name}",
                )
            )
        return ConceptRead[HealthCheck].read(tuple(items))

    def _read_target_health(self) -> ConceptRead[TargetHealth]:
        """Read the live health of the targets of each Kong Upstream."""
        items: list[TargetHealth] = []
        for upstream in self._fetch_paginated(_PATH_UPSTREAMS):
            name = self._upstream_name(upstream)
            health = self._fetch_single(_PATH_UPSTREAM_HEALTH.format(name=name))
            for target in health.get("data") or []:
                items.append(
                    TargetHealth(
                        backend=name,
                        target=str(target.get("target", "")),
                        state=_KONG_TARGET_STATES.get(
                            str(target.get("health", "")), TargetState.UNKNOWN
                        ),
                        counters=None,
                    )
                )
        return ConceptRead[TargetHealth].read(tuple(items))

    def _read_routes(self) -> ConceptRead[GatewayRoute]:
        """Map each Kong Route, with the name of its Service as backend."""
        service_names = {
            str(s["id"]): self._service_name(s)
            for s in self._fetch_paginated(_PATH_SERVICES)
            if "id" in s
        }
        items = tuple(
            GatewayRoute(
                name=str(route.get("name") or route.get("id")),
                paths=tuple(route.get("paths") or ()),
                methods=tuple(route.get("methods") or ()),
                backend=service_names.get(str((route.get("service") or {}).get("id"))),
                enabled=True,
                source=f"route {route.get('name') or route.get('id')}",
            )
            for route in self._fetch_paginated(_PATH_ROUTES)
        )
        return ConceptRead[GatewayRoute].read(items)

    def _read_circuit_breakers(self) -> ConceptRead[CircuitBreaker]:
        """
        Map the plugins named in test 4.3's configuration to circuit breakers.

        Kong OSS has no breaker plugin; third-party ones are recognised by
        name, in the configured priority order, first instance of each name.
        """
        first_by_name: dict[str, dict[str, Any]] = {}
        for plugin in self._fetch_paginated(_PATH_PLUGINS):
            first_by_name.setdefault(str(plugin.get("name", "")), plugin)
        items: list[CircuitBreaker] = []
        for candidate in self._breaker.accepted_cb_plugin_names:
            breaker = first_by_name.get(candidate)
            if breaker is None:
                continue
            config: dict[str, Any] = breaker.get("config") or {}
            scope, name = self._plugin_scope(breaker)
            items.append(
                CircuitBreaker(
                    scope=scope,
                    name=name,
                    enabled=bool(breaker.get("enabled", False)),
                    failure_threshold=_first_number(config, _BREAKER_THRESHOLD_FIELDS),
                    failure_statuses=(),
                    open_seconds=_first_number(config, _BREAKER_OPEN_FIELDS),
                    recovery_successes=None,
                    source=f"plugin {breaker.get('name')} (id: {breaker.get('id')})",
                )
            )
        return ConceptRead[CircuitBreaker].read(tuple(items))

    def _read_signing_policies(self) -> ConceptRead[SigningPolicy]:
        """Map the plugins named in test 3.3's configuration to signing policies."""
        names = {n.lower() for n in self._signing.plugin_names}
        items: list[SigningPolicy] = []
        for plugin in self._fetch_paginated(_PATH_PLUGINS):
            if str(plugin.get("name", "")).lower() not in names:
                continue
            config: dict[str, Any] = plugin.get("config") or {}
            algorithms = config.get(self._signing.field_algorithms)
            skew = config.get(self._signing.field_clock_skew)
            body = config.get(self._signing.field_validate_body)
            scope, name = self._plugin_scope(plugin)
            items.append(
                SigningPolicy(
                    scope=scope,
                    name=name,
                    enabled=bool(plugin.get("enabled", False)),
                    algorithms=tuple(str(a) for a in algorithms)
                    if algorithms is not None
                    else None,
                    replay_window_seconds=float(skew) if skew is not None else None,
                    required_signed_headers=tuple(config.get("enforce_headers") or ()),
                    body_signed=bool(body) if body is not None else None,
                    source=f"plugin {plugin.get('name')} (id: {plugin.get('id', '<unknown>')})",
                )
            )
        return ConceptRead[SigningPolicy].read(tuple(items))

    def _read_config_values(self) -> ConceptRead[ConfigValue]:
        """Collect the Service URLs and every text value of the plugin configurations."""
        items: list[ConfigValue] = []
        for service in self._fetch_paginated(_PATH_SERVICES):
            url = service.get("url")
            if isinstance(url, str) and url:
                items.append(
                    ConfigValue(
                        kind=ConfigValueKind.BACKEND,
                        location=f"service {service.get('name', '<unnamed>')}",
                        key="url",
                        value=url,
                    )
                )
        for plugin in self._fetch_paginated(_PATH_PLUGINS):
            config = plugin.get("config", {})
            if isinstance(config, dict):
                location = (
                    f"plugin {plugin.get('name', '<unnamed>')} (id: {plugin.get('id', '<no-id>')})"
                )
                items.extend(
                    collect_text_values(config, ConfigValueKind.PLUGIN, location, "config")
                )
        return ConceptRead[ConfigValue].read(tuple(items))

    def _plugin_scope(self, plugin: dict[str, Any]) -> tuple[ConceptScope, str]:
        """
        Return the scope of a Kong plugin and the name of the object it is attached to.

        Names are those of the other concepts (a Service's name, a Route's
        name), so that a policy can be related to the routes of its backend;
        an object without a name keeps its id.
        """
        route = plugin.get("route") or {}
        service = plugin.get("service") or {}
        if route.get("id"):
            names = {
                str(r["id"]): str(r.get("name") or r["id"])
                for r in self._fetch_paginated(_PATH_ROUTES)
                if "id" in r
            }
            return ConceptScope.ROUTE, names.get(str(route["id"]), str(route["id"]))
        if service.get("id"):
            names = {
                str(s["id"]): self._service_name(s)
                for s in self._fetch_paginated(_PATH_SERVICES)
                if "id" in s
            }
            return ConceptScope.BACKEND, names.get(str(service["id"]), str(service["id"]))
        return ConceptScope.GLOBAL, _GLOBAL_SCOPE_NAME

    @staticmethod
    def _service_name(service: dict[str, Any]) -> str:
        """Return a Service's name, or its id when unnamed (as test 4.2 did)."""
        return str(service.get("name") or service.get("id", "<unknown>"))

    @staticmethod
    def _upstream_name(upstream: dict[str, Any]) -> str:
        """Return an Upstream's name, or its id when unnamed (as test 4.3 did)."""
        return str(upstream.get("name") or upstream.get("id") or "<unnamed>")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_paginated(self, path: str) -> list[dict[str, Any]]:
        """
        Fetch all items from a paginated Kong Admin API collection endpoint.

        Follows the 'next' cursor until exhausted.  In DB-less mode all
        objects are returned in a single page and 'next' is null.

        Args:
            path: Collection path (e.g. '/routes', '/plugins').

        Returns:
            Flat list of all items across all pages.

        Raises:
            GatewayAdapterError: On transport failure or non-200 response on any page.
        """
        items: list[dict[str, Any]] = []
        next_url: str | None = f"{self._admin_base_url}{path}"

        while next_url is not None:
            response_data = self._get_json_object(next_url, path)
            page_items: list[dict[str, Any]] = response_data.get("data", [])
            items.extend(page_items)

            raw_next: str | None = response_data.get("next")
            if raw_next:
                next_url = f"{self._admin_base_url}{raw_next}"
            else:
                next_url = None

            log.debug(
                "kong_gateway_page_fetched",
                path=path,
                page_count=len(page_items),
                has_next=bool(raw_next),
            )

        log.debug("kong_gateway_collection_fetched", path=path, total=len(items))
        return items

    def _fetch_single(self, path: str) -> dict[str, Any]:
        """
        Fetch a single object from the Kong Admin API.

        Args:
            path: Resource path (e.g. '/status').

        Returns:
            Parsed JSON response as a dict.

        Raises:
            GatewayAdapterError: On transport failure or non-200 response.
        """
        url = f"{self._admin_base_url}{path}"
        return self._get_json_object(url, path)


# ---------------------------------------------------------------------------
# Module helpers for the concept mappings
# ---------------------------------------------------------------------------


def _ms_to_seconds(value: int | float | None) -> float | None:
    """Return a Kong millisecond value in seconds; None stays None (not set)."""
    return None if value is None else float(value) / _MS_PER_SECOND


def _first_number(config: dict[str, Any], fields: tuple[str, ...]) -> int | None:
    """
    Return the integer value of the first field present, or None.

    None both when no field is present and when the value is not numeric:
    the neutral concept has no place for an unreadable value.
    """
    field = next((f for f in fields if f in config), None)
    if field is None:
        return None
    try:
        return int(float(str(config[field])))
    except (ValueError, TypeError):
        return None
