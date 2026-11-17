"""
src/core/gateway/apisix.py

Apache APISIX adapter for WHITE_BOX configuration audit tests.

Implements BaseGatewayAdapter against the APISIX Admin API (3.x, traditional
deployment with etcd) and, for the live health of the backends, the APISIX
Control API. Concepts: docs/04-architecture/05-design-decisions.md, D7.

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
APISIX's own plugins are read: hmac-auth (request signing policies),
api-breaker (circuit breakers), limit-count and limit-req (rate limits),
client-control (body-size limits) and the log shippers. The plugin and field names of test 3.3 and
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
    sorted_config_values,
)
from src.core.gateway.concepts import (
    REQUEST_PART_COOKIE,
    REQUEST_PART_EVERY,
    REQUEST_PART_HEADER,
    REQUEST_PART_QUERY,
    ActiveCheck,
    BackendTimeout,
    BodySizeLimit,
    CircuitBreaker,
    ConceptRead,
    ConceptScope,
    ConfigValue,
    ConfigValueKind,
    GatewayRoute,
    HealthCheck,
    HealthCounters,
    LogShipper,
    PassiveCheck,
    RateLimit,
    RateWindow,
    RouteMatch,
    RoutePath,
    ShippedRequest,
    SigningPolicy,
    TargetHealth,
    TargetState,
    http_status,
    request_part,
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
_PATH_PLUGIN_METADATA: str = "/plugin_metadata"
_PATH_UPSTREAM_SCHEMA: str = "/schema/upstream"
_PATH_CONTROL_HEALTHCHECK: str = "/v1/healthcheck"

# Keys under which APISIX stores its objects in etcd: the Control API names a
# health checker by the key of the object holding the upstream.
_ETCD_KEY_UPSTREAM: str = "/apisix/upstreams/{id}"
_ETCD_KEY_ROUTE: str = "/apisix/routes/{id}"
_ETCD_KEY_SERVICE: str = "/apisix/services/{id}"

_PLUGIN_SIGNING: str = "hmac-auth"
# The plugins that send request logs over the network (APISIX 3.12,
# conf/config.yaml.example, read 2026-11-04). file-logger writes on the gateway's
# own host: not a separate system (ASVS v5.0.0-16.4.3). syslog sends to a
# configured host.
_LOG_SHIPPING_PLUGINS: frozenset[str] = frozenset(
    {
        "clickhouse-logger",
        "elasticsearch-logger",
        "google-cloud-logging",
        "http-logger",
        "kafka-logger",
        "loggly",
        "loki-logger",
        "rocketmq-logger",
        "skywalking-logger",
        "sls-logger",
        "splunk-hec-logging",
        "syslog",
        "tcp-logger",
        "tencent-cloud-cls",
        "udp-logger",
    }
)
# What a logger's record carries of the request (apisix/utils/log-util.lua,
# get_log_entry, 3.19.0, read in the lab's container 2026-11-17). Each part
# with whether a data-mask (log phase, priority 1500, before every logger) and
# a hide_credentials (access phase) take it out of the record:
#   the default record (get_full_log): every header, read after both; the query
#     string in `uri` and `url`, the URI as received, which data-mask rewrites
#     and hide_credentials does not;
#   kafka-logger and rocketmq-logger with meta_format "origin"
#     (get_req_original): the raw request line ($request), which neither
#     rewrites, and every header as above;
#   google-cloud-logging without a log_format: the URL and the User-Agent only;
#   a log_format (the plugin's own, else its plugin metadata): only the
#     variables it names; log_format_extra adds its variables to a default
#     record.
# A header variable ($http_<name>) is cached on the request: hide_credentials
# clears the cache under the name with its dashes, data-mask under the one
# with underscores (core/request.lua, plugins/data-mask.lua), so a hidden
# header may stay in a log_format record: not taken as removed.
_LOG_FORMAT: str = "log_format"
_LOG_FORMAT_EXTRA: str = "log_format_extra"
_LOG_META_FORMAT: str = "meta_format"
_LOG_META_ORIGIN: str = "origin"
_LOG_ORIGIN_PLUGINS: frozenset[str] = frozenset({"kafka-logger", "rocketmq-logger"})
_LOG_URL_ONLY_PLUGINS: frozenset[str] = frozenset({"google-cloud-logging"})
_LOG_VARIABLE_PREFIX: str = "$"
_VAR_HEADER_PREFIX: str = "http_"
_VAR_COOKIE_PREFIX: str = "cookie_"
_VAR_ARG_PREFIX: str = "arg_"
# The variables holding the whole query string: data-mask rewrites all of
# them but $request, hide_credentials only $args and $query_string.
# Whether (data-mask, hide_credentials) take a part out of the record: True,
# False, or None when it may stay (a cached header variable).
_Removable = tuple[bool | None, bool | None]
_VARS_QUERY: dict[str, _Removable] = {
    "args": (True, True),
    "query_string": (None, None),
    "request_uri": (True, False),
    "request_line": (True, False),
    "request": (False, False),
}
_HEADER_USER_AGENT: str = "user-agent"
# The plugins taking a request part out of the record, and their fields.
_PLUGIN_DATA_MASK: str = "data-mask"
_MASK_ACTION_PATTERN: str = "regex"
_HIDE_FIELD: str = "hide_credentials"
# Plugins whose hide_credentials clears the header and query argument their
# config names (key-auth, jwt-auth), or Authorization (the others).
_HIDE_NAMED_PLUGINS: frozenset[str] = frozenset({"key-auth", "jwt-auth"})
_HIDE_AUTHORIZATION_PLUGINS: frozenset[str] = frozenset({"basic-auth", "hmac-auth", "ldap-auth"})
_HEADER_AUTHORIZATION: str = "authorization"
_HEADER_COOKIE: str = "cookie"
_PLUGIN_JWT: str = "jwt-auth"
# A plugin's `_meta.filter` runs it for part of the traffic only, and
# `_meta.priority` moves it in the order: a remover with either, or a logger
# with a priority of its own, removes in part only.
_META: str = "_meta"
_META_FILTER: str = "filter"
_META_PRIORITY: str = "priority"
# hmac-auth checks the request's date only when clock_skew > 0
# (apisix/plugins/hmac-auth.lua: "if conf.clock_skew and conf.clock_skew > 0");
# 3.13.0 rejects 0 in its schema (minimum = 1), earlier versions allowed it.
_SIGNING_NO_DATE_CHECK: float = 0.0
# hmac-auth's signed_headers default, and the date header it checks.
_SIGNING_DEFAULT_HEADERS: tuple[str, ...] = ("date",)
_SIGNING_DATE: str = "date"
_SIGNING_DIGEST: str = "digest"
_SIGNING_TARGET: str = "@request-target"
_PLUGIN_BREAKER: str = "api-breaker"
# Rate limits (https://apisix.apache.org/docs/apisix/plugins/limit-count/ and
# limit-req/, read 2026-11-15). limit-count allows `count` requests every
# `time_window` seconds; both may be strings taken from the request, and in
# `rules` mode a rule is skipped when its key resolves nothing, so only a plain
# count and window are stated. Its counters are shared by every node with a
# Redis policy (redis, redis-cluster, redis-sentinel), updated on each request
# with sync_interval -1; `local` keeps them per node. limit-req is a leaky
# bucket that delays requests above `rate` within `burst`: not a count per
# window.
_PLUGIN_RATE_COUNT: str = "limit-count"
_PLUGIN_RATE_BUCKET: str = "limit-req"
_RATE_SHARED_POLICY_PREFIX: str = "redis"
_RATE_SYNC_EVERY_REQUEST: float = -1.0
# The status of a refused request, for both plugins: `rejected_code` (default 503).
_RATE_REFUSAL_DEFAULT: int = 503
# Body-size limits (https://apisix.apache.org/docs/apisix/plugins/client-control/,
# apisix/plugins/client-control.lua 3.19, read 2026-11-15): max_body_size in
# bytes, compared with the request's Content-Length (413 above it); 0 means no
# restriction.
_PLUGIN_BODY_SIZE: str = "client-control"

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

# ---------------------------------------------------------------------------
# ApisixGatewayAdapter
# ---------------------------------------------------------------------------


# APISIX's own path syntax: a uri ending with "*" is a prefix, any other is
# matched exactly (https://apisix.apache.org/docs/apisix/admin-api/).
_APISIX_WILDCARD_SUFFIX: str = "*"


def _route_path(uri: str) -> RoutePath:
    """
    One APISIX route uri in the neutral vocabulary of the concept.

    Args:
        uri: The uri as APISIX states it.

    Returns:
        Its value without APISIX's syntax, and how APISIX matches it.
    """
    if uri.endswith(_APISIX_WILDCARD_SUFFIX):
        return RoutePath(value=uri.removesuffix(_APISIX_WILDCARD_SUFFIX), match=RouteMatch.PREFIX)
    return RoutePath(value=uri, match=RouteMatch.EXACT)


# nginx's default proxy timeout, which applies where APISIX sets none
# (_backend_timeout), and the concept fields it fills, in APISIX's order.
_NGINX_DEFAULT_TIMEOUT_SECONDS: float = 60.0
_TIMEOUT_FIELDS: tuple[str, str, str] = ("connect_seconds", "send_seconds", "read_seconds")


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

    @property
    def secret_reference_prefixes(self) -> tuple[str, ...]:
        """APISIX's secret and environment references, by their start."""
        # "$secret://vault/1/jack/auth-key" and "$ENV://JACK_AUTH_KEY", also
        # written "$env://" (apisix.apache.org/docs/apisix/terminology/secret,
        # read 2026-11-05).
        return ("$secret://", "$env://")

    # ------------------------------------------------------------------
    # Neutral concepts (docs/04-architecture/05-design-decisions.md, D7)
    # ------------------------------------------------------------------

    def _read_backend_timeouts(self) -> ConceptRead[BackendTimeout]:
        """Timeouts of each upstream (backend scope) and of routes that set their own."""
        items: list[BackendTimeout] = []
        for backend in self._backends():
            items.append(
                _backend_timeout(
                    ConceptScope.BACKEND,
                    backend.name,
                    backend.upstream.get("timeout"),
                    backend.source,
                )
            )
        for route in self._collection(_PATH_ROUTES):
            if isinstance(route.get("timeout"), dict):
                items.append(
                    _backend_timeout(
                        ConceptScope.ROUTE,
                        _object_name(route),
                        route["timeout"],
                        f"route {route.get('id')}",
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
        """
        Live state of every checked node, from the Control API, and every other
        node of an upstream, from the Admin API, as UNKNOWN.

        An upstream without `checks` is absent from the Control API (until
        2026-11-16 its nodes were left out, so test 0.4 never tried them); without
        a Control API every node is UNKNOWN.
        """
        backends = self._backends()
        checkers = (
            self._get_json_array(
                f"{self._health_api_url}{_PATH_CONTROL_HEALTHCHECK}",
                _PATH_CONTROL_HEALTHCHECK,
                HEALTH_API_INTERFACE,
            )
            if self._health_api_url is not None
            else []
        )
        backend_by_key = {backend.etcd_key: backend.name for backend in backends}
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
        # A checked upstream's nodes are in the Control API under the address
        # they resolved to ("172.24.0.4:3000" for "forgejo:3000"): added again
        # by name, they read as unchecked (2026-11-16 to 2026-11-17).
        checked = {item.backend for item in items}
        for backend in backends:
            if backend.name in checked:
                continue
            for address in _node_addresses(backend.upstream.get("nodes")):
                items.append(
                    TargetHealth(
                        backend=backend.name,
                        target=address,
                        state=TargetState.UNKNOWN,
                        counters=None,
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
                    paths=tuple(_route_path(str(uri)) for uri in uris),
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
            window = _number_or_none(instance.config.get("clock_skew"))
            unlimited = window is not None and window <= _SIGNING_NO_DATE_CHECK
            listed = instance.config.get("signed_headers")
            signed = (
                _SIGNING_DEFAULT_HEADERS
                if listed is None
                else tuple(str(h) for h in listed if isinstance(listed, list))
            )
            lowered = {h.lower() for h in signed}
            items.append(
                SigningPolicy(
                    scope=instance.scope,
                    name=instance.name,
                    enabled=instance.enabled,
                    algorithms=(
                        tuple(str(a) for a in algorithms) if isinstance(algorithms, list) else None
                    ),
                    replay_window_seconds=None if unlimited else window,
                    replay_unlimited=unlimited,
                    required_signed_headers=signed,
                    # The signing string holds the headers of signed_headers
                    # (hmac-auth.lua 3.x): the body counts only with `digest`
                    # among them, the target with `@request-target`.
                    body_signed=(body and _SIGNING_DIGEST in lowered)
                    if isinstance(body, bool)
                    else None,
                    target_signed=_SIGNING_TARGET in lowered,
                    # APISIX checks the clock skew on Date only, and requires
                    # every header of signed_headers (default ["date"]) in the
                    # signature (hmac-auth.lua 3.x).
                    date_signed=_SIGNING_DATE in lowered,
                    optional=bool(instance.config.get("anonymous_consumer")),
                    source=instance.source,
                )
            )
        return ConceptRead[SigningPolicy].read(tuple(items))

    def _read_log_shipping(self) -> ConceptRead[LogShipper]:
        """Every instance in effect of a log-shipping plugin (_LOG_SHIPPING_PLUGINS)."""
        items: list[LogShipper] = []
        metadata = self._plugin_metadata()
        removers = self._removers()
        for plugin in sorted(_LOG_SHIPPING_PLUGINS):
            for instance in self._plugin_instances(plugin):
                parts = _record_parts(plugin, instance.config, metadata.get(plugin, {}))
                items.append(
                    LogShipper(
                        scope=instance.scope,
                        name=instance.name,
                        plugin=plugin,
                        enabled=instance.enabled,
                        request=_shipped_request(parts, instance, removers),
                        source=instance.source,
                    )
                )
        return ConceptRead[LogShipper].read(tuple(items))

    def _plugin_metadata(self) -> dict[str, dict[str, Any]]:
        """
        The plugin metadata objects, by plugin name (a logger's shared log_format).

        Raises:
            GatewayAdapterError: When the Admin API cannot be read.
        """
        body = self._get_json_object(
            f"{self._admin_url}{_PATH_PLUGIN_METADATA}", _PATH_PLUGIN_METADATA
        )
        found: dict[str, dict[str, Any]] = {}
        for entry in body.get("list") or []:
            value = _as_dict(_as_dict(entry).get("value"))
            name = value.get("id") or str(_as_dict(entry).get("key", "")).rsplit("/", 1)[-1]
            if name:
                found[str(name)] = value
        return found

    def _removers(self) -> list[_Remover]:
        """Every enabled data-mask item and hide_credentials, with its scope."""
        removers: list[_Remover] = []
        for instance in self._plugin_instances(_PLUGIN_DATA_MASK):
            if not instance.enabled:
                continue
            for item in instance.config.get("request") or []:
                item = _as_dict(item)
                kind = str(item.get("type", ""))
                if kind not in (REQUEST_PART_HEADER, REQUEST_PART_QUERY) or not item.get("name"):
                    continue
                removers.append(
                    _Remover(
                        instance,
                        request_part(kind, str(item["name"])),
                        masks=True,
                        pattern=item.get("action") == _MASK_ACTION_PATTERN,
                    )
                )
        for plugin in sorted(_HIDE_NAMED_PLUGINS | _HIDE_AUTHORIZATION_PLUGINS):
            for instance in self._plugin_instances(plugin):
                if not instance.enabled or not instance.config.get(_HIDE_FIELD):
                    continue
                if plugin in _HIDE_AUTHORIZATION_PLUGINS:
                    parts = [request_part(REQUEST_PART_HEADER, _HEADER_AUTHORIZATION)]
                else:
                    # jwt-auth also takes its cookie out of the Cookie header.
                    parts = [
                        request_part(kind, str(instance.config[kind]))
                        for kind in (REQUEST_PART_HEADER, REQUEST_PART_QUERY, REQUEST_PART_COOKIE)
                        if instance.config.get(kind)
                        and (kind != REQUEST_PART_COOKIE or plugin == _PLUGIN_JWT)
                    ]
                removers.extend(_Remover(instance, part, masks=False) for part in parts)
        return removers

    def _read_rate_limits(self) -> ConceptRead[RateLimit]:
        """Every limit-count and limit-req instance in effect, with APISIX's defaults."""
        items: list[RateLimit] = []
        for instance in self._plugin_instances(_PLUGIN_RATE_COUNT):
            items.append(
                RateLimit(
                    scope=instance.scope,
                    name=instance.name,
                    enabled=instance.enabled,
                    windows=_count_windows(instance.config),
                    shared_counter=_count_shared(instance.config),
                    refusal_status=_rate_refusal(instance.config),
                    source=instance.source,
                )
            )
        for instance in self._plugin_instances(_PLUGIN_RATE_BUCKET):
            items.append(
                RateLimit(
                    scope=instance.scope,
                    name=instance.name,
                    enabled=instance.enabled,
                    windows=(),
                    shared_counter=None,
                    refusal_status=_rate_refusal(instance.config),
                    source=instance.source,
                )
            )
        return ConceptRead[RateLimit].read(tuple(items))

    def _read_body_size_limits(self) -> ConceptRead[BodySizeLimit]:
        """Every client-control instance in effect with a size above 0 (0: no restriction)."""
        items: list[BodySizeLimit] = []
        for instance in self._plugin_instances(_PLUGIN_BODY_SIZE):
            size = _int_or_none(instance.config.get("max_body_size"))
            if size is None or size <= 0:
                continue
            items.append(
                BodySizeLimit(
                    scope=instance.scope,
                    name=instance.name,
                    enabled=instance.enabled,
                    max_bytes=size,
                    source=instance.source,
                )
            )
        return ConceptRead[BodySizeLimit].read(tuple(items))

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
                            _as_dict(config),
                            ConfigValueKind.PLUGIN,
                            location,
                            "config",
                            enabled=not _plugin_disabled(config),
                        )
                    )
        for consumer in self._collection(_PATH_CONSUMERS):
            for name, config in _as_dict(consumer.get("plugins")).items():
                location = f"consumer {consumer.get('username')}, plugin {name}"
                items.extend(
                    collect_text_values(
                        _as_dict(config),
                        ConfigValueKind.CLIENT_CREDENTIAL,
                        location,
                        "config",
                        enabled=not _plugin_disabled(config),
                    )
                )
        return ConceptRead[ConfigValue].read(sorted_config_values(items))

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
        """Schemas already read in this run, by path."""
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
        """
        Return a schema of the running APISIX.

        Raises:
            GatewayAdapterError: When it cannot be read. Without its schema a
                configuration lacks the defaults APISIX applies, so a replay window
                or a health check it does apply would read as absent: the concept
                is then not accessible, never read without them.
        """
        if path not in self._schemas:
            self._schemas[path] = self._get_json_object(f"{self._admin_url}{path}", path)
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
        rules = [
            rule
            for rule in self._collection(_PATH_GLOBAL_RULES)
            if _as_dict(rule.get("plugins")).get(plugin) is not None
        ]
        # A plugin in more than one global rule runs from none of them
        # (apisix/plugin.lua, merge_global_rules: "configured across different
        # global rules. Removing it from execution list").
        for rule in rules if len(rules) == 1 else []:
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
                            key=f"route {route.get('id')}",
                        )
                    )
                    break
        return instances

    def _instance(
        self,
        plugin: str,
        config: object,
        scope: ConceptScope,
        name: str,
        holder: str,
        key: str = _GLOBAL_SCOPE_NAME,
    ) -> _PluginInstance:
        """Build a plugin instance with its configuration completed by the schema defaults."""
        full = self._plugin_config_with_defaults(plugin, config)
        return _PluginInstance(
            scope=scope,
            name=name,
            enabled=not bool(_as_dict(full.get("_meta")).get("disable", False)),
            config=full,
            source=f"{holder}, plugin {plugin}",
            key=key,
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


class _Remover:
    """A request part a plugin takes out of the log record (data-mask, hide_credentials)."""

    __slots__ = ("instance", "masks", "part", "pattern")

    def __init__(
        self, instance: _PluginInstance, part: str, masks: bool, pattern: bool = False
    ) -> None:
        """Store the remover fields (masks: data-mask in the log phase, else hide_credentials)."""
        self.instance: _PluginInstance = instance
        self.part: str = part
        self.masks: bool = masks
        self.pattern: bool = pattern


class _PluginInstance:
    """A plugin in effect on a scope, with its configuration completed by defaults."""

    __slots__ = ("config", "enabled", "key", "name", "scope", "source")

    def __init__(
        self,
        scope: ConceptScope,
        name: str,
        enabled: bool,
        config: dict[str, Any],
        source: str,
        key: str = _GLOBAL_SCOPE_NAME,
    ) -> None:
        """Store the instance fields (key: the route's id, names are not unique)."""
        self.scope: ConceptScope = scope
        self.name: str = name
        self.enabled: bool = enabled
        self.config: dict[str, Any] = config
        self.source: str = source
        self.key: str = key


# ---------------------------------------------------------------------------
# Module helpers
# ---------------------------------------------------------------------------


def _record_parts(
    plugin: str, config: dict[str, Any], metadata: dict[str, Any]
) -> dict[str, _Removable] | None:
    """
    The request parts a logger's record carries, each with (data-mask removes it,
    hide_credentials removes it), as described at _LOG_FORMAT.

    Returns:
        The parts, or None when a log_format names something other than variables.
    """
    every_header = request_part(REQUEST_PART_HEADER, REQUEST_PART_EVERY)
    every_query = request_part(REQUEST_PART_QUERY, REQUEST_PART_EVERY)
    # meta_format "origin" ignores log_format and its metadata
    # (kafka-logger.lua, rocketmq-logger.lua: get_req_original first).
    if plugin in _LOG_ORIGIN_PLUGINS and config.get(_LOG_META_FORMAT) == _LOG_META_ORIGIN:
        return {every_header: (True, True), every_query: (False, False)}
    # The plugin's own log_format counts even empty (a Lua table is true),
    # the metadata's only with keys (get_log_entry, has_meta_log_format).
    log_format = config.get(_LOG_FORMAT)
    if log_format is None:
        log_format = _as_dict(metadata).get(_LOG_FORMAT) or None
    if log_format is not None:
        return _format_parts(log_format)
    parts: dict[str, _Removable]
    if plugin in _LOG_URL_ONLY_PLUGINS:
        parts = {
            request_part(REQUEST_PART_HEADER, _HEADER_USER_AGENT): (True, True),
            every_query: (True, False),
        }
    else:
        parts = {every_header: (True, True), every_query: (True, False)}
    extra = config.get(_LOG_FORMAT_EXTRA)
    if extra is None:
        extra = _as_dict(metadata).get(_LOG_FORMAT_EXTRA)
    if extra:
        extra_parts = _format_parts(extra)
        if extra_parts is None:
            return None
        for part, removable in extra_parts.items():
            parts[part] = _both(parts.get(part), removable)
    return parts


def _format_parts(log_format: object) -> dict[str, _Removable] | None:
    """
    The request parts the variables of a log_format carry, nested objects and
    arrays included (do_gen_log_format recurses into any Lua table).
    """
    if isinstance(log_format, dict):
        values = list(log_format.values())
    elif isinstance(log_format, list):
        values = log_format
    else:
        return None
    parts: dict[str, _Removable] = {}
    for value in values:
        if isinstance(value, dict | list):
            nested = _format_parts(value)
            if nested is None:
                return None
            for part, removable in nested.items():
                parts[part] = _both(parts.get(part), removable)
            continue
        text = str(value)
        if not text.startswith(_LOG_VARIABLE_PREFIX):
            continue
        found = _variable_part(text[len(_LOG_VARIABLE_PREFIX) :].lower())
        if found is not None:
            part, removable = found
            parts[part] = _both(parts.get(part), removable)
    return parts


def _both(first: _Removable | None, second: _Removable) -> _Removable:
    """Two fields carrying one part: removed only where both are (False wins, then None)."""
    if first is None:
        return second
    return (_and(first[0], second[0]), _and(first[1], second[1]))


def _and(first: bool | None, second: bool | None) -> bool | None:
    """Three-valued 'and': False if either is False, None if either is None, else True."""
    if first is False or second is False:
        return False
    if first is None or second is None:
        return None
    return True


def _variable_part(variable: str) -> tuple[str, _Removable] | None:
    """The request part an NGINX/APISIX variable holds, with how it can be removed."""
    if variable in _VARS_QUERY:
        return request_part(REQUEST_PART_QUERY, REQUEST_PART_EVERY), _VARS_QUERY[variable]
    if variable.startswith(_VAR_HEADER_PREFIX):
        name = variable[len(_VAR_HEADER_PREFIX) :].replace("_", "-")
        return request_part(REQUEST_PART_HEADER, name), (True, None)
    if variable.startswith(_VAR_COOKIE_PREFIX):
        return request_part(REQUEST_PART_COOKIE, variable[len(_VAR_COOKIE_PREFIX) :]), (
            False,
            False,
        )
    if variable.startswith(_VAR_ARG_PREFIX):
        return request_part(REQUEST_PART_QUERY, variable[len(_VAR_ARG_PREFIX) :]), (None, None)
    return None


def _shipped_request(
    parts: dict[str, _Removable] | None,
    shipper: _PluginInstance,
    removers: list[_Remover],
) -> ShippedRequest | None:
    """
    Relate the removers to one logger's record.

    APISIX runs the global rules' plugins first, then the route's
    (apisix/init.lua common_phase): a data-mask of the shipper's route, or a
    global one, runs before the logger; a route's data-mask after a global
    logger. hide_credentials acts before any log: on the logger's route or
    globally for all its traffic, on another route for part of a global
    logger's. A part a remover cannot take out of every field carrying it
    (the URI as received) stays shipped; a pattern, or a header variable
    hide_credentials may leave cached, is removed in part.

    Returns:
        The record's parts, or None when its log_format is not read.
    """
    if parts is None:
        return None
    removed: set[str] = set()
    in_part: set[str] = set()
    shipper_moved = _META_PRIORITY in _as_dict(shipper.config.get(_META))
    for remover in removers:
        scope = remover.instance.scope
        same = scope == shipper.scope and remover.instance.key == shipper.key
        if scope == ConceptScope.GLOBAL or same:
            full = True
        elif shipper.scope == ConceptScope.GLOBAL and not remover.masks:
            full = False
        else:
            continue
        meta = _as_dict(remover.instance.config.get(_META))
        if _META_FILTER in meta or (remover.masks and (shipper_moved or _META_PRIORITY in meta)):
            full = False
        kind = remover.part.split(":", 1)[0]
        # A cookie taken out of the Cookie header leaves the header's other cookies.
        targets = {remover.part, request_part(kind, REQUEST_PART_EVERY)}
        if kind == REQUEST_PART_COOKIE:
            targets = {
                remover.part,
                request_part(REQUEST_PART_HEADER, _HEADER_COOKIE),
                request_part(REQUEST_PART_HEADER, REQUEST_PART_EVERY),
            }
        carrying = [
            removable[0] if remover.masks else removable[1]
            for part, removable in parts.items()
            if part in targets
        ]
        if not carrying or False in carrying:
            continue
        certain = full and not remover.pattern and None not in carrying
        (removed if certain else in_part).add(remover.part)
    return ShippedRequest(
        carries=tuple(sorted(parts)),
        removed=tuple(sorted(removed)),
        removed_in_part=tuple(sorted(in_part - removed)),
    )


def _as_dict(value: object) -> dict[str, Any]:
    """The value when it is a JSON object, else an empty dict."""
    return value if isinstance(value, dict) else {}


def _plugin_disabled(config: object) -> bool:
    """Whether a plugin configuration switches itself off (APISIX's common `_meta.disable`)."""
    return _as_dict(_as_dict(config).get("_meta")).get("disable") is True


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


def _count_windows(config: dict[str, Any]) -> tuple[RateWindow, ...]:
    """The window of a limit-count configuration, when its count and window are plain numbers."""
    if config.get("rules"):
        return ()
    count = _int_or_none(config.get("count"))
    window = _number_or_none(config.get("time_window"))
    if count is None or count < 1 or window is None or window <= 0:
        return ()
    return (RateWindow(requests=count, seconds=window),)


def _rate_refusal(config: dict[str, Any]) -> int | None:
    """The status a limit-count or limit-req refuses with (`rejected_code`)."""
    return http_status(config.get("rejected_code", _RATE_REFUSAL_DEFAULT))


def _count_shared(config: dict[str, Any]) -> bool | None:
    """Whether a limit-count counter is shared by every node and updated on each request."""
    policy = str(config.get("policy") or "").lower()
    if not policy.startswith(_RATE_SHARED_POLICY_PREFIX):
        return False
    sync = _number_or_none(config.get("sync_interval"))
    if sync is None:
        return None
    return sync == _RATE_SYNC_EVERY_REQUEST


def _backend_timeout(scope: ConceptScope, name: str, value: object, source: str) -> BackendTimeout:
    """
    One APISIX timeout object as the concept, with nginx's default for an unset field.

    APISIX sets the upstream timeouts only when the route or the upstream has a
    `timeout` (apisix/balancer.lua, read in the lab's 3.x container 2026-11-05);
    otherwise nginx's own proxy timeouts apply, which APISIX's nginx.conf leaves
    at their default of 60 s (nginx.org, ngx_http_proxy_module:
    proxy_connect_timeout, proxy_send_timeout, proxy_read_timeout). The Admin API
    omits the field, so the default is stated here and named in `defaulted`
    (the test read the omission as "no bound").
    """
    values = dict(zip(_TIMEOUT_FIELDS, _timeout_values(value), strict=True))
    defaulted = tuple(field for field, seconds in values.items() if seconds is None)
    for field in defaulted:
        values[field] = _NGINX_DEFAULT_TIMEOUT_SECONDS
    return BackendTimeout(
        scope=scope,
        name=name,
        connect_seconds=values["connect_seconds"],
        send_seconds=values["send_seconds"],
        read_seconds=values["read_seconds"],
        defaulted=defaulted,
        source=source,
    )


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
