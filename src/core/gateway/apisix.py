"""
src/core/gateway/apisix.py

Apache APISIX adapter for WHITE_BOX configuration audit tests.

Implements BaseGatewayAdapter against the APISIX Admin API (3.x, traditional
deployment with etcd) and, for the live health of the backends, the APISIX
Control API. Mappings: docs/project/gateway-concepts.md.

Interfaces
----------
Admin API (gateway.admin.url, e.g. http://127.0.0.1:9180): the
configuration. Collections are read under /apisix/admin (routes, upstreams,
services, global_rules, plugin_configs, consumers), each answered as
{"total": n, "list": [{"key": ..., "value": {...}}]}; without paging
parameters APISIX returns the whole collection. A key of role viewer is
enough (GET only); it is sent as the X-API-KEY header of
gateway.admin.headers.

Control API (gateway.health.url, e.g. http://127.0.0.1:9090): live health
of the upstream nodes, GET /v1/healthcheck. It has no authentication and is
read without the Admin API headers. APISIX starts checking an upstream only
when it first receives a request, so before that the list is empty.

Default values
--------------
The Admin API returns what was written, not the values APISIX applies to the
fields left out (e.g. hmac-auth without allowed_algorithms allows
hmac-sha1). The adapter fills them from the schemas of the running APISIX:
GET /apisix/admin/plugins/{name} (documented Admin API) for a plugin and
GET /apisix/admin/schema/upstream (served by APISIX 3.19.0, not in its
documentation) for an upstream. A schema that cannot be read leaves the
missing fields empty ("not stated"), and the reason is logged.

Plugins
-------
APISIX's own plugins are read: hmac-auth (request signing policies) and
api-breaker (circuit breakers). The plugin and field names of test 3.3 and
4.3 configuration describe Kong plugins and are not used here. A plugin
applies to a route from the route itself, else from its plugin_config, else
from its service (APISIX merges them in this order, the first wins); a global
rule applies to every request. A plugin on a service is therefore reported
for each route of that service.

Dependency rule: imports from stdlib, structlog, src.core.gateway.base and
src.core.gateway.concepts. Must never import from src.tests, src.engine,
src.config, or src.discovery.
"""

from __future__ import annotations

from copy import deepcopy
from functools import cached_property
from typing import Any

import structlog

from src.core.gateway.base import (
    HEALTH_API_INTERFACE,
    BaseGatewayAdapter,
    GatewayAdapterError,
    collect_text_values,
)
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
    HealthCounters,
    PassiveCheck,
    SigningPolicy,
    TargetHealth,
    TargetState,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# APISIX interfaces
# ---------------------------------------------------------------------------

_ADMIN_PREFIX: str = "/apisix/admin"
_PATH_ROUTES: str = "/routes"
_PATH_UPSTREAMS: str = "/upstreams"
_PATH_SERVICES: str = "/services"
_PATH_GLOBAL_RULES: str = "/global_rules"
_PATH_PLUGIN_CONFIGS: str = "/plugin_configs"
_PATH_CONSUMERS: str = "/consumers"
_PATH_PLUGIN_SCHEMA: str = "/plugins/{name}"
_PATH_UPSTREAM_SCHEMA: str = "/schema/upstream"
_PATH_CONTROL_HEALTHCHECK: str = "/v1/healthcheck"

# Keys under which APISIX stores its objects in etcd: the Control API names a
# health checker by the key of the object holding the upstream.
_ETCD_KEY_UPSTREAM: str = "/apisix/upstreams/{id}"
_ETCD_KEY_ROUTE: str = "/apisix/routes/{id}"
_ETCD_KEY_SERVICE: str = "/apisix/services/{id}"

_PLUGIN_SIGNING: str = "hmac-auth"
_PLUGIN_BREAKER: str = "api-breaker"

# Control API node states (APISIX health check documentation: the "mostly"
# states are still classed as healthy or unhealthy).
_APISIX_TARGET_STATES: dict[str, TargetState] = {
    "healthy": TargetState.HEALTHY,
    "mostly_healthy": TargetState.HEALTHY,
    "unhealthy": TargetState.UNHEALTHY,
    "mostly_unhealthy": TargetState.UNHEALTHY,
}

# Route status: 0 disabled, 1 (default) enabled.
_ROUTE_STATUS_DISABLED: int = 0
_GLOBAL_SCOPE_NAME: str = "global"

_NO_HEALTH_API_REASON: str = (
    "the address of the APISIX Control API is not configured: set gateway.health.url"
)


# ---------------------------------------------------------------------------
# ApisixGatewayAdapter
# ---------------------------------------------------------------------------


class ApisixGatewayAdapter(BaseGatewayAdapter):
    """
    Gateway adapter for Apache APISIX (Admin API and Control API).

    Built with the arguments of BaseGatewayAdapter; admin_base_url is the
    Admin API address without the /apisix/admin path (accepted with it too),
    health_api_url the Control API address. All calls are read-only GETs.
    """

    @property
    def adapter_name(self) -> str:
        """Return the adapter identifier used in logs and error messages."""
        return "apisix"

    # ------------------------------------------------------------------
    # Neutral concepts (docs/project/gateway-concepts.md)
    # ------------------------------------------------------------------

    def _read_backend_timeouts(self) -> ConceptRead[BackendTimeout]:
        """Timeouts of each upstream (backend scope) and of routes that set their own."""
        items: list[BackendTimeout] = []
        for backend in self._backends():
            connect, send, read = _timeout_values(backend.upstream.get("timeout"))
            items.append(
                BackendTimeout(
                    scope=ConceptScope.BACKEND,
                    name=backend.name,
                    connect_seconds=connect,
                    send_seconds=send,
                    read_seconds=read,
                    source=backend.source,
                )
            )
        for route in self._collection(_PATH_ROUTES):
            if isinstance(route.get("timeout"), dict):
                connect, send, read = _timeout_values(route["timeout"])
                items.append(
                    BackendTimeout(
                        scope=ConceptScope.ROUTE,
                        name=_object_name(route),
                        connect_seconds=connect,
                        send_seconds=send,
                        read_seconds=read,
                        source=f"route {route.get('id')}",
                    )
                )
        return ConceptRead[BackendTimeout].read(tuple(items))

    def _read_health_checks(self) -> ConceptRead[HealthCheck]:
        """Passive and active checks of each upstream, with APISIX's defaults."""
        schema = self._upstream_schema()
        items: list[HealthCheck] = []
        for backend in self._backends():
            upstream = _with_defaults(backend.upstream, schema)
            checks = _as_dict(upstream.get("checks"))
            items.append(
                HealthCheck(
                    scope=ConceptScope.BACKEND,
                    name=backend.name,
                    passive=_passive_check(checks.get("passive")),
                    active=_active_check(checks.get("active")),
                    source=backend.source,
                )
            )
        return ConceptRead[HealthCheck].read(tuple(items))

    def _read_target_health(self) -> ConceptRead[TargetHealth]:
        """Live state of every checked node, from the Control API."""
        if self._health_api_url is None:
            return ConceptRead[TargetHealth].not_accessible(_NO_HEALTH_API_REASON)
        checkers = self._get_json_array(
            f"{self._health_api_url}{_PATH_CONTROL_HEALTHCHECK}",
            _PATH_CONTROL_HEALTHCHECK,
            HEALTH_API_INTERFACE,
        )
        backend_by_key = {backend.etcd_key: backend.name for backend in self._backends()}
        items: list[TargetHealth] = []
        for checker in checkers:
            checker_data = _as_dict(checker)
            key = str(checker_data.get("name", ""))
            backend_name = backend_by_key.get(key, key) or "<unknown>"
            for node in checker_data.get("nodes") or []:
                node_data = _as_dict(node)
                counter = _as_dict(node_data.get("counter"))
                items.append(
                    TargetHealth(
                        backend=backend_name,
                        target=f"{node_data.get('ip')}:{node_data.get('port')}",
                        state=_APISIX_TARGET_STATES.get(
                            str(node_data.get("status")), TargetState.UNKNOWN
                        ),
                        counters=HealthCounters(
                            successes=_int_or_none(counter.get("success")),
                            http_failures=_int_or_none(counter.get("http_failure")),
                            tcp_failures=_int_or_none(counter.get("tcp_failure")),
                            timeouts=_int_or_none(counter.get("timeout_failure")),
                        )
                        if counter
                        else None,
                    )
                )
        return ConceptRead[TargetHealth].read(tuple(items))

    def _read_routes(self) -> ConceptRead[GatewayRoute]:
        """Every route with its paths, methods, backend and status."""
        items: list[GatewayRoute] = []
        for route in self._collection(_PATH_ROUTES):
            uris = route.get("uris") or ([route["uri"]] if route.get("uri") else [])
            items.append(
                GatewayRoute(
                    name=_object_name(route),
                    paths=tuple(str(uri) for uri in uris),
                    methods=tuple(str(method) for method in route.get("methods") or ()),
                    backend=self._route_backend(route),
                    enabled=route.get("status") != _ROUTE_STATUS_DISABLED,
                    source=f"route {route.get('id')}",
                )
            )
        return ConceptRead[GatewayRoute].read(tuple(items))

    def _read_circuit_breakers(self) -> ConceptRead[CircuitBreaker]:
        """Every api-breaker instance in effect, with APISIX's defaults."""
        items: list[CircuitBreaker] = []
        for instance in self._plugin_instances(_PLUGIN_BREAKER):
            unhealthy = _as_dict(instance.config.get("unhealthy"))
            healthy = _as_dict(instance.config.get("healthy"))
            items.append(
                CircuitBreaker(
                    scope=instance.scope,
                    name=instance.name,
                    enabled=instance.enabled,
                    failure_threshold=_int_or_none(unhealthy.get("failures")),
                    failure_statuses=_int_tuple(unhealthy.get("http_statuses")),
                    open_seconds=_number_or_none(instance.config.get("max_breaker_sec")),
                    recovery_successes=_int_or_none(healthy.get("successes")),
                    source=instance.source,
                )
            )
        return ConceptRead[CircuitBreaker].read(tuple(items))

    def _read_signing_policies(self) -> ConceptRead[SigningPolicy]:
        """Every hmac-auth instance in effect, with APISIX's defaults."""
        items: list[SigningPolicy] = []
        for instance in self._plugin_instances(_PLUGIN_SIGNING):
            algorithms = instance.config.get("allowed_algorithms")
            body = instance.config.get("validate_request_body")
            items.append(
                SigningPolicy(
                    scope=instance.scope,
                    name=instance.name,
                    enabled=instance.enabled,
                    algorithms=(
                        tuple(str(a) for a in algorithms) if isinstance(algorithms, list) else None
                    ),
                    replay_window_seconds=_number_or_none(instance.config.get("clock_skew")),
                    required_signed_headers=tuple(
                        str(h) for h in instance.config.get("signed_headers") or ()
                    ),
                    body_signed=body if isinstance(body, bool) else None,
                    source=instance.source,
                )
            )
        return ConceptRead[SigningPolicy].read(tuple(items))

    def _read_config_values(self) -> ConceptRead[ConfigValue]:
        """Upstream node addresses, plugin configuration texts, consumer plugin texts."""
        items: list[ConfigValue] = []
        for backend in self._backends():
            for address in _node_addresses(backend.upstream.get("nodes")):
                items.append(
                    ConfigValue(
                        kind=ConfigValueKind.BACKEND,
                        location=backend.source,
                        key="nodes",
                        value=address,
                    )
                )
        holders = (
            (_PATH_ROUTES, "route"),
            (_PATH_SERVICES, "service"),
            (_PATH_GLOBAL_RULES, "global rule"),
            (_PATH_PLUGIN_CONFIGS, "plugin config"),
        )
        for path, label in holders:
            for holder in self._collection(path):
                for name, config in _as_dict(holder.get("plugins")).items():
                    location = f"{label} {holder.get('id')}, plugin {name}"
                    items.extend(
                        collect_text_values(
                            _as_dict(config), ConfigValueKind.PLUGIN, location, "config"
                        )
                    )
        for consumer in self._collection(_PATH_CONSUMERS):
            for name, config in _as_dict(consumer.get("plugins")).items():
                location = f"consumer {consumer.get('username')}, plugin {name}"
                items.extend(
                    collect_text_values(
                        _as_dict(config), ConfigValueKind.CLIENT_CREDENTIAL, location, "config"
                    )
                )
        return ConceptRead[ConfigValue].read(tuple(items))

    # ------------------------------------------------------------------
    # Admin API reads (each collection and schema read once per run)
    # ------------------------------------------------------------------

    @cached_property
    def _admin_url(self) -> str:
        """Admin API base URL ending with /apisix/admin."""
        if self._admin_base_url.endswith(_ADMIN_PREFIX):
            return self._admin_base_url
        return f"{self._admin_base_url}{_ADMIN_PREFIX}"

    @cached_property
    def _collections(self) -> dict[str, list[dict[str, Any]]]:
        """Collections already read in this run, by path."""
        return {}

    @cached_property
    def _schemas(self) -> dict[str, dict[str, Any]]:
        """Schemas already read (or found unreadable: empty) in this run, by path."""
        return {}

    def _collection(self, path: str) -> list[dict[str, Any]]:
        """
        Return the objects of an Admin API collection (the 'value' of each entry).

        Raises:
            GatewayAdapterError: On transport failure, an unexpected status or
                                 body, or a list shorter than its total.
        """
        if path not in self._collections:
            body = self._get_json_object(f"{self._admin_url}{path}", path)
            entries = body.get("list") or []
            if not isinstance(entries, list):
                raise GatewayAdapterError(
                    message=f"apisix Admin API answered GET {path} without a list.", path=path
                )
            total = body.get("total")
            if isinstance(total, int) and total > len(entries):
                raise GatewayAdapterError(
                    message=(
                        f"apisix Admin API answered GET {path} with {len(entries)} of "
                        f"{total} objects."
                    ),
                    path=path,
                )
            objects = [_as_dict(_as_dict(entry).get("value")) for entry in entries]
            self._collections[path] = [obj for obj in objects if obj]
            log.debug("apisix_gateway_collection_fetched", path=path, total=len(objects))
        return self._collections[path]

    def _schema(self, path: str) -> dict[str, Any]:
        """Return a schema of the running APISIX, or {} when it cannot be read."""
        if path not in self._schemas:
            try:
                self._schemas[path] = self._get_json_object(f"{self._admin_url}{path}", path)
            except GatewayAdapterError as exc:
                log.warning("apisix_gateway_schema_not_read", path=path, reason=exc.message)
                self._schemas[path] = {}
        return self._schemas[path]

    def _upstream_schema(self) -> dict[str, Any]:
        """Schema of an upstream object (defaults of its health checks)."""
        return self._schema(_PATH_UPSTREAM_SCHEMA)

    def _plugin_config_with_defaults(self, name: str, config: object) -> dict[str, Any]:
        """A plugin configuration completed with the defaults of the plugin's schema."""
        return _with_defaults(_as_dict(config), self._schema(_PATH_PLUGIN_SCHEMA.format(name=name)))

    # ------------------------------------------------------------------
    # Backends and plugin instances
    # ------------------------------------------------------------------

    def _backends(self) -> list[_Backend]:
        """
        Every upstream: the Upstream objects, then those written inline in a
        service or a route. An unnamed upstream is named by its id, an inline
        one by its holder ('service <name>', 'route <name>').
        """
        backends: list[_Backend] = []
        for upstream in self._collection(_PATH_UPSTREAMS):
            upstream_id = str(upstream.get("id"))
            backends.append(
                _Backend(
                    name=str(upstream.get("name") or upstream_id),
                    upstream=upstream,
                    source=f"upstream {upstream_id}",
                    etcd_key=_ETCD_KEY_UPSTREAM.format(id=upstream_id),
                )
            )
        for path, label, key in (
            (_PATH_SERVICES, "service", _ETCD_KEY_SERVICE),
            (_PATH_ROUTES, "route", _ETCD_KEY_ROUTE),
        ):
            for holder in self._collection(path):
                inline = holder.get("upstream")
                if isinstance(inline, dict):
                    backends.append(
                        _Backend(
                            name=str(inline.get("name") or f"{label} {_object_name(holder)}"),
                            upstream=inline,
                            source=f"{label} {holder.get('id')}",
                            etcd_key=key.format(id=holder.get("id")),
                        )
                    )
        return backends

    def _route_backend(self, route: dict[str, Any]) -> str | None:
        """Name of the backend a route sends to: its own upstream, else its service's."""
        names_by_source = {backend.source: backend.name for backend in self._backends()}
        if isinstance(route.get("upstream"), dict):
            return names_by_source.get(f"route {route.get('id')}")
        if route.get("upstream_id") is not None:
            return names_by_source.get(f"upstream {route['upstream_id']}")
        service_id = route.get("service_id")
        if service_id is None:
            return None
        for service in self._collection(_PATH_SERVICES):
            if str(service.get("id")) != str(service_id):
                continue
            if isinstance(service.get("upstream"), dict):
                return names_by_source.get(f"service {service_id}")
            if service.get("upstream_id") is not None:
                return names_by_source.get(f"upstream {service['upstream_id']}")
        return None

    def _plugin_instances(self, plugin: str) -> list[_PluginInstance]:
        """
        Every instance of a plugin in effect: global rules, then for each
        route the instance from the route, its plugin_config or its service.
        """
        instances: list[_PluginInstance] = []
        for rule in self._collection(_PATH_GLOBAL_RULES):
            config = _as_dict(rule.get("plugins")).get(plugin)
            if config is not None:
                instances.append(
                    self._instance(
                        plugin,
                        config,
                        ConceptScope.GLOBAL,
                        _GLOBAL_SCOPE_NAME,
                        f"global rule {rule.get('id')}",
                    )
                )
        plugin_configs = {
            str(pc.get("id")): _as_dict(pc.get("plugins"))
            for pc in self._collection(_PATH_PLUGIN_CONFIGS)
        }
        services = {
            str(svc.get("id")): _as_dict(svc.get("plugins"))
            for svc in self._collection(_PATH_SERVICES)
        }
        for route in self._collection(_PATH_ROUTES):
            pc_id = str(route.get("plugin_config_id"))
            svc_id = str(route.get("service_id"))
            for holder_plugins, source in (
                (_as_dict(route.get("plugins")), f"route {route.get('id')}"),
                (plugin_configs.get(pc_id, {}), f"plugin config {pc_id}"),
                (services.get(svc_id, {}), f"service {svc_id}"),
            ):
                if plugin in holder_plugins:
                    instances.append(
                        self._instance(
                            plugin,
                            holder_plugins[plugin],
                            ConceptScope.ROUTE,
                            _object_name(route),
                            source,
                        )
                    )
                    break
        return instances

    def _instance(
        self, plugin: str, config: object, scope: ConceptScope, name: str, holder: str
    ) -> _PluginInstance:
        """Build a plugin instance with its configuration completed by the schema defaults."""
        full = self._plugin_config_with_defaults(plugin, config)
        return _PluginInstance(
            scope=scope,
            name=name,
            enabled=not bool(_as_dict(full.get("_meta")).get("disable", False)),
            config=full,
            source=f"{holder}, plugin {plugin}",
        )


# ---------------------------------------------------------------------------
# Internal records
# ---------------------------------------------------------------------------


class _Backend:
    """An upstream with the name, evidence source and etcd key it is known by."""

    __slots__ = ("etcd_key", "name", "source", "upstream")

    def __init__(self, name: str, upstream: dict[str, Any], source: str, etcd_key: str) -> None:
        """Store the backend fields."""
        self.name: str = name
        self.upstream: dict[str, Any] = upstream
        self.source: str = source
        self.etcd_key: str = etcd_key


class _PluginInstance:
    """A plugin in effect on a scope, with its configuration completed by defaults."""

    __slots__ = ("config", "enabled", "name", "scope", "source")

    def __init__(
        self, scope: ConceptScope, name: str, enabled: bool, config: dict[str, Any], source: str
    ) -> None:
        """Store the instance fields."""
        self.scope: ConceptScope = scope
        self.name: str = name
        self.enabled: bool = enabled
        self.config: dict[str, Any] = config
        self.source: str = source


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def _as_dict(value: object) -> dict[str, Any]:
    """The value when it is a JSON object, else an empty dict."""
    return value if isinstance(value, dict) else {}


def _object_name(obj: dict[str, Any]) -> str:
    """An APISIX object's name, else its id."""
    return str(obj.get("name") or obj.get("id"))


def _int_or_none(value: object) -> int | None:
    """An integer value, else None."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _number_or_none(value: object) -> float | None:
    """A numeric value as float, else None."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return float(value)
    return None


def _int_tuple(value: object) -> tuple[int, ...]:
    """The integers of a JSON array (empty when absent)."""
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, int) and not isinstance(item, bool))


def _timeout_values(value: object) -> tuple[float | None, float | None, float | None]:
    """Connect, send and read seconds of an APISIX timeout object (None when absent)."""
    timeout = _as_dict(value)
    return (
        _number_or_none(timeout.get("connect")),
        _number_or_none(timeout.get("send")),
        _number_or_none(timeout.get("read")),
    )


def _passive_check(value: object) -> PassiveCheck | None:
    """Passive check thresholds (checks.passive.unhealthy), or None when not configured."""
    if not isinstance(value, dict):
        return None
    unhealthy = _as_dict(value.get("unhealthy"))
    return PassiveCheck(
        http_failures=_int_or_none(unhealthy.get("http_failures")),
        tcp_failures=_int_or_none(unhealthy.get("tcp_failures")),
        timeouts=_int_or_none(unhealthy.get("timeouts")),
        failure_statuses=_int_tuple(unhealthy.get("http_statuses")),
    )


def _active_check(value: object) -> ActiveCheck | None:
    """Active check intervals and path (checks.active), or None when not configured."""
    if not isinstance(value, dict):
        return None
    path = value.get("http_path")
    return ActiveCheck(
        healthy_interval_seconds=_number_or_none(_as_dict(value.get("healthy")).get("interval")),
        unhealthy_interval_seconds=_number_or_none(
            _as_dict(value.get("unhealthy")).get("interval")
        ),
        http_path=path if isinstance(path, str) else None,
    )


def _node_addresses(nodes: object) -> list[str]:
    """Node addresses of an upstream: keys of the {"host:port": weight} form, or host:port."""
    if isinstance(nodes, dict):
        return [str(address) for address in nodes]
    if isinstance(nodes, list):
        return [
            f"{node.get('host')}:{node.get('port')}" if node.get("port") else str(node.get("host"))
            for node in nodes
            if isinstance(node, dict) and node.get("host")
        ]
    return []


def _with_defaults(value: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    """
    Complete a JSON object with the defaults of its JSON schema.

    For each property of the schema: a missing field takes the property's
    default; a present object is completed with its own property schema. The
    same rule APISIX applies when it loads a configuration; with an empty
    schema the object is returned as it is.
    """
    properties = _as_dict(schema.get("properties"))
    result = dict(value)
    for key, prop in properties.items():
        prop_schema = _as_dict(prop)
        if key in result:
            if isinstance(result[key], dict):
                result[key] = _with_defaults(result[key], prop_schema)
        elif "default" in prop_schema:
            default = deepcopy(prop_schema["default"])
            if isinstance(default, dict):
                default = _with_defaults(default, prop_schema)
            result[key] = default
    return result
