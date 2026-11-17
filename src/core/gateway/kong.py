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

import re
from typing import Any, TypeGuard

import structlog

from src.core.gateway.base import (
    BaseGatewayAdapter,
    collect_text_values,
    sorted_config_values,
)
from src.core.gateway.concepts import (
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
# Request signing: Kong's own hmac-auth plugin and the fields of its schema
# (https://developer.konghq.com/plugins/hmac-auth/reference/; source:
# kong/plugins/hmac-auth/schema.lua). Kong requires clock_skew > 0 (gt = 0), so
# a Kong policy always has a replay window.
_SIGNING_PLUGINS: frozenset[str] = frozenset({"hmac-auth"})
# The bundled plugins that send request logs over the network (Kong 3.9.0,
# kong/constants.lua, read 2026-11-04). file-log writes a file and syslog the
# syslog of the gateway's own host: not a separate system (ASVS v5.0.0-16.4.3).
_LOG_SHIPPING_PLUGINS: frozenset[str] = frozenset({"http-log", "tcp-log", "udp-log", "loggly"})
# What their record carries (kong/pdk/log.lua, serialize, 3.9.3, read in the
# lab's container 2026-11-17): every request header, with authorization and
# proxy-authorization replaced by "REDACTED", and the query string, both as
# `querystring` and inside `uri` and `url` (the request URI as received).
_LOG_RECORD_CARRIES: tuple[str, ...] = (
    request_part(REQUEST_PART_HEADER, REQUEST_PART_EVERY),
    request_part(REQUEST_PART_QUERY, REQUEST_PART_EVERY),
)
_LOG_RECORD_REDACTED: tuple[str, ...] = (
    request_part(REQUEST_PART_HEADER, "authorization"),
    request_part(REQUEST_PART_HEADER, "proxy-authorization"),
)
# A shipper's custom_fields_by_lua sets record fields from Lua code: one on the
# request part of the record (these fields, or below them) leaves its content
# to code the adapter does not run.
_LOG_FIELD_CUSTOM: str = "custom_fields_by_lua"
_LOG_REQUEST_FIELDS: tuple[str, ...] = ("request", "upstream_uri")
# key-auth with hide_credentials clears the headers of key_names from the
# request before the log phase (kong/plugins/key-auth/handler.lua 3.9.3), so
# the record no longer has them; it clears the query argument too, but the
# record's `uri` keeps the URI as received, so a key in the query is shipped
# anyway. The other plugins with hide_credentials hide Authorization, which the
# record redacts already.
_PLUGIN_KEY_AUTH: str = "key-auth"
_KEY_AUTH_HIDE: str = "hide_credentials"
_KEY_AUTH_NAMES: str = "key_names"
_SIGNING_FIELD_ALGORITHMS: str = "algorithms"
_SIGNING_FIELD_REPLAY_WINDOW: str = "clock_skew"
_SIGNING_FIELD_BODY: str = "validate_request_body"
_SIGNING_FIELD_HEADERS: str = "enforce_headers"
# Kong OSS ships no circuit breaker (its documented circuit breakers are the
# passive health checks): the third-party breaker plugins recognised, in
# priority order, and their field names, tried in order. A new plugin is added
# here, its name together with its fields (docs/04-architecture/05-design-decisions.md, D8).
#
# The one plugin recognised is dream11/kong-circuit-breaker, whose plugin name
# is `circuit-breaker` (https://github.com/dream11/kong-circuit-breaker, read
# 2026-10-28). Its own field names come first in each tuple: without them the
# concept answered "not stated" for a threshold the plugin does state, and the
# note of test 4.3 printed "threshold None". The other names stay for a plugin
# that uses them.
_BREAKER_PLUGINS: tuple[str, ...] = ("circuit-breaker",)
_BREAKER_THRESHOLD_FIELDS: tuple[str, ...] = (
    "failure_percent_threshold",
    "failure_threshold",
    "consecutive_errors",
    "error_threshold_percentage",
)
_BREAKER_OPEN_FIELDS: tuple[str, ...] = (
    "wait_duration_in_open_state",
    "timeout",
    "sleep_time",
    "recovery_time",
    "timeout_duration",
)
_GLOBAL_SCOPE_NAME: str = "global"

# Rate limits: Kong's own rate-limiting plugin
# (https://developer.konghq.com/plugins/rate-limiting/reference/, read 2026-11-15).
# Each field is a number of requests per period; the periods are calendar
# periods (kong/tools/timestamp.lua 3.9.0: the current time floored to the
# second, minute, hour, day, month, year), so a month and a year take their
# shortest length.
_RATE_LIMIT_PLUGINS: frozenset[str] = frozenset({"rate-limiting"})
_SECONDS_PER_DAY: float = 86400.0
_RATE_PERIOD_SECONDS: dict[str, float] = {
    "second": 1.0,
    "minute": 60.0,
    "hour": 3600.0,
    "day": _SECONDS_PER_DAY,
    "month": 28 * _SECONDS_PER_DAY,
    "year": 365 * _SECONDS_PER_DAY,
}
# The policies whose counters every node shares: cluster (the data store) and
# redis; local keeps them "in-memory on the node". They are updated on each
# request only with sync_rate -1 (SYNC_RATE_REALTIME in
# kong/plugins/rate-limiting/handler.lua 3.9.0); another value syncs them
# periodically.
_RATE_SHARED_POLICIES: frozenset[str] = frozenset({"cluster", "redis"})
# The status of a refused request: `error_code` (schema.lua 3.9.0: default 429).
_RATE_REFUSAL_DEFAULT: int = 429
_RATE_SYNC_REALTIME: float = -1.0
# Body-size limits: Kong's own request-size-limiting plugin, its limit in the
# unit of size_unit (megabytes by default), with the factors of its handler
# (kong/plugins/request-size-limiting/handler.lua 3.9.0, read 2026-11-15).
_BODY_SIZE_PLUGINS: frozenset[str] = frozenset({"request-size-limiting"})
_BODY_SIZE_UNIT_DEFAULT: str = "megabytes"
_BODY_SIZE_UNIT_BYTES: dict[str, int] = {
    "bytes": 1,
    "kilobytes": 1024,
    "megabytes": 1048576,
}
# The HTTP protocols of a plugin's `protocols` field: a plugin listing only
# one of them applies to part of the HTTP traffic, a plugin listing neither
# (gRPC only) to none of it.
_HTTP_PROTOCOLS: frozenset[str] = frozenset({"http", "https"})


# ---------------------------------------------------------------------------
# KongGatewayAdapter
# ---------------------------------------------------------------------------


# Kong's own path syntax: a path starting with "~" is a regular expression, any
# other is a prefix (https://developer.konghq.com/gateway/routing/traditional/).
_KONG_REGEX_PREFIX: str = "~"


# The date headers Kong's hmac-auth checks the clock skew on, either one.
_SIGNED_DATES: frozenset[str] = frozenset({"date", "x-date"})
# The digest header, and the pseudo-headers that put the method and path in the
# signature (hmac-auth/access.lua 3.9.3).
_DIGEST: str = "digest"
_SIGNED_TARGETS: frozenset[str] = frozenset({"request-line", "@request-target"})
# A PCRE named group "(?<name>" (not a lookbehind "(?<=", "(?<!").
_PCRE_NAMED_GROUP: re.Pattern[str] = re.compile(r"\(\?<(?![=!])")


def _route_path(path: str) -> RoutePath:
    """
    One Kong route path in the neutral vocabulary of the concept.

    Args:
        path: The path as Kong states it.

    Returns:
        Its value without Kong's syntax, and how Kong matches it.
    """
    if path.startswith(_KONG_REGEX_PREFIX):
        # Kong anchors the expression at the start of the path and accepts the
        # PCRE named group "(?<name>", which Python writes "(?P<name>"
        # (kong/router/transform.lua 3.9.3); until 2026-11-16 the value was
        # given as written, and a named group did not compile.
        expression = _PCRE_NAMED_GROUP.sub("(?P<", path.removeprefix(_KONG_REGEX_PREFIX))
        if not expression.startswith("^"):
            expression = "^" + expression
        return RoutePath(value=expression, match=RouteMatch.REGEX)
    return RoutePath(value=path, match=RouteMatch.PREFIX)


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

    @property
    def secret_reference_prefixes(self) -> tuple[str, ...]:
        """Kong vault references, by their start."""
        # "{vault://env/my-secret-postgres-password}"
        # (developer.konghq.com/gateway/secrets-management, read 2026-11-05).
        return ("{vault://",)

    # ------------------------------------------------------------------
    # Neutral concepts (docs/04-architecture/05-design-decisions.md, D7)
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
        """
        Read the live health of the targets of each Kong Upstream, and the enabled
        Services that point straight at a host (no Upstream), as UNKNOWN.

        A Service whose `host` is not an Upstream's name is a backend Kong routes
        to without health checks (until 2026-11-16 it was left out, so test 0.4
        never tried the most common Kong setup).
        """
        items: list[TargetHealth] = []
        upstreams = self._fetch_paginated(_PATH_UPSTREAMS)
        upstream_names = {self._upstream_name(upstream) for upstream in upstreams}
        for service in self._fetch_paginated(_PATH_SERVICES):
            host = str(service.get("host") or "")
            if not host or host in upstream_names or service.get("enabled") is False:
                continue
            port = service.get("port")
            items.append(
                TargetHealth(
                    backend=self._service_name(service),
                    target=f"{host}:{port}" if port else host,
                    state=TargetState.UNKNOWN,
                    counters=None,
                )
            )
        for upstream in upstreams:
            name = self._upstream_name(upstream)
            health = self._fetch_single(_PATH_UPSTREAM_HEALTH.format(name=name))
            for target in health.get("data") or []:
                items.append(
                    TargetHealth(
                        backend=name,
                        target=str(target.get("target", "")),
                        resolved=_resolved_addresses(target),
                        state=_KONG_TARGET_STATES.get(
                            str(target.get("health", "")), TargetState.UNKNOWN
                        ),
                        counters=None,
                    )
                )
        return ConceptRead[TargetHealth].read(tuple(items))

    def _read_routes(self) -> ConceptRead[GatewayRoute]:
        """Map each Kong Route, with the name of its Service as backend."""
        services = {str(s["id"]): s for s in self._fetch_paginated(_PATH_SERVICES) if "id" in s}
        service_names = {sid: self._service_name(s) for sid, s in services.items()}
        items = tuple(
            GatewayRoute(
                name=str(route.get("name") or route.get("id")),
                paths=tuple(_route_path(str(path)) for path in route.get("paths") or ()),
                methods=tuple(route.get("methods") or ()),
                backend=service_names.get(str((route.get("service") or {}).get("id"))),
                # Kong keeps the routes of a disabled Service out of its router
                # (kong/runloop/handler.lua 3.9.3); until 2026-11-16 always True.
                enabled=(
                    services.get(str((route.get("service") or {}).get("id")), {}).get("enabled")
                    is not False
                ),
                source=f"route {route.get('name') or route.get('id')}",
            )
            for route in self._fetch_paginated(_PATH_ROUTES)
        )
        return ConceptRead[GatewayRoute].read(items)

    def _read_circuit_breakers(self) -> ConceptRead[CircuitBreaker]:
        """
        Map the third-party breaker plugins Kong is known to run to circuit breakers.

        Kong OSS has no breaker plugin; third-party ones are recognised by
        name (_BREAKER_PLUGINS, in priority order). Every instance is
        reported, enabled or not: keeping only the first of each name read a
        disabled one in front of an enabled one as no breaker.
        """
        plugins = self._fetch_paginated(_PATH_PLUGINS)
        items: list[CircuitBreaker] = []
        for candidate in _BREAKER_PLUGINS:
            for breaker in (p for p in plugins if str(p.get("name", "")) == candidate):
                items.append(self._breaker(breaker))
        return ConceptRead[CircuitBreaker].read(tuple(items))

    def _breaker(self, breaker: dict[str, Any]) -> CircuitBreaker:
        """One breaker plugin instance as a circuit breaker."""
        config: dict[str, Any] = breaker.get("config") or {}
        scope, name = self._plugin_scope(breaker)
        return CircuitBreaker(
            scope=scope,
            name=name,
            enabled=bool(breaker.get("enabled", False)),
            failure_threshold=_first_number(config, _BREAKER_THRESHOLD_FIELDS),
            failure_statuses=(),
            open_seconds=_first_number(config, _BREAKER_OPEN_FIELDS),
            recovery_successes=None,
            source=f"plugin {breaker.get('name')} (id: {breaker.get('id')})",
        )

    def _read_signing_policies(self) -> ConceptRead[SigningPolicy]:
        """Map every hmac-auth plugin to a signing policy."""
        items: list[SigningPolicy] = []
        for plugin in self._fetch_paginated(_PATH_PLUGINS):
            if str(plugin.get("name", "")).lower() not in _SIGNING_PLUGINS:
                continue
            config: dict[str, Any] = plugin.get("config") or {}
            required = {str(h).lower() for h in config.get(_SIGNING_FIELD_HEADERS) or ()}
            algorithms = config.get(_SIGNING_FIELD_ALGORITHMS)
            skew = config.get(_SIGNING_FIELD_REPLAY_WINDOW)
            body = config.get(_SIGNING_FIELD_BODY)
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
                    replay_unlimited=False,
                    required_signed_headers=tuple(config.get(_SIGNING_FIELD_HEADERS) or ()),
                    # The signature covers the headers the client lists; Kong
                    # requires those of enforce_headers (access.lua 3.9.3): the
                    # body counts only when its Digest must be signed, the
                    # target when request-line or @request-target must be.
                    body_signed=(bool(body) and _DIGEST in required) if body is not None else None,
                    target_signed=bool(_SIGNED_TARGETS & required),
                    # Kong checks the clock skew on X-Date or else Date
                    # (hmac-auth/access.lua 3.9.3), each unsigned unless listed
                    # in enforce_headers (default empty).
                    date_signed=_SIGNED_DATES <= required,
                    optional=bool(config.get("anonymous")),
                    source=f"plugin {plugin.get('name')} (id: {plugin.get('id', '<unknown>')})",
                )
            )
        return ConceptRead[SigningPolicy].read(tuple(items))

    def _read_log_shipping(self) -> ConceptRead[LogShipper]:
        """
        Map every log-shipping plugin (_LOG_SHIPPING_PLUGINS) that logs every client.

        One bound to a consumer or a consumer group logs that client's requests
        only, and _plugin_scope would report it GLOBAL: it is left out, as for
        the limits (until 2026-11-16 it made test 5.1 pass).
        """
        items: list[LogShipper] = []
        hidden = self._hidden_keys()
        # A value custom_fields_by_lua sets is kept on the request and applied
        # by every later serialize() (kong/pdk/log.lua, set_serialize_value,
        # ctx.serialize_values): any log plugin's field on the request part
        # leaves every shipper's record not stated.
        rewritten = any(
            _rewrites_request(plugin)
            for plugin in self._fetch_paginated(_PATH_PLUGINS)
            if plugin.get("enabled", False)
        )
        for plugin in self._limit_plugins(_LOG_SHIPPING_PLUGINS):
            name = str(plugin.get("name", "")).lower()
            scope, owner = self._plugin_scope(plugin)
            items.append(
                LogShipper(
                    scope=scope,
                    name=owner,
                    plugin=name,
                    enabled=bool(plugin.get("enabled", False)),
                    request=None if rewritten else _shipped_request((scope, owner), hidden),
                    source=f"plugin {plugin.get('name')} (id: {plugin.get('id', '<unknown>')})",
                )
            )
        return ConceptRead[LogShipper].read(tuple(items))

    def _hidden_keys(self) -> list[tuple[tuple[ConceptScope, str] | None, tuple[str, ...]]]:
        """
        The headers each enabled key-auth with hide_credentials clears, with its scope.

        Kong runs one instance of a plugin per request, the most specific
        (kong/runloop/plugins_iterator.lua, lookup_cfg): when another key-auth
        does not hide, a hiding one may be replaced on part of the traffic, and
        its scope is returned as None (removed in part only).

        Returns:
            (scope, name) of the plugin, or None, and the header parts it removes.
        """
        hidden: list[tuple[tuple[ConceptScope, str] | None, tuple[str, ...]]] = []
        key_auths = [
            plugin
            for plugin in self._fetch_paginated(_PATH_PLUGINS)
            if str(plugin.get("name", "")).lower() == _PLUGIN_KEY_AUTH
            and plugin.get("enabled", False)
        ]
        overridable = any(not (p.get("config") or {}).get(_KEY_AUTH_HIDE) for p in key_auths)
        for plugin in key_auths:
            config = plugin.get("config") or {}
            if not config.get(_KEY_AUTH_HIDE):
                continue
            names = config.get(_KEY_AUTH_NAMES) or []
            hidden.append(
                (
                    None if overridable else self._plugin_scope(plugin),
                    tuple(request_part(REQUEST_PART_HEADER, str(key)) for key in names),
                )
            )
        return hidden

    def _read_config_values(self) -> ConceptRead[ConfigValue]:
        """Collect the Service addresses and every text value of the plugin configurations."""
        items: list[ConfigValue] = []
        for service in self._fetch_paginated(_PATH_SERVICES):
            address = _service_address(service)
            if address is not None:
                items.append(
                    ConfigValue(
                        kind=ConfigValueKind.BACKEND,
                        location=f"service {service.get('name', '<unnamed>')}",
                        key="url",
                        value=address,
                    )
                )
        for plugin in self._fetch_paginated(_PATH_PLUGINS):
            config = plugin.get("config", {})
            if isinstance(config, dict):
                location = (
                    f"plugin {plugin.get('name', '<unnamed>')} (id: {plugin.get('id', '<no-id>')})"
                )
                items.extend(
                    collect_text_values(
                        config,
                        ConfigValueKind.PLUGIN,
                        location,
                        "config",
                        enabled=bool(plugin.get("enabled", True)),
                    )
                )
        return ConceptRead[ConfigValue].read(sorted_config_values(items))

    def _read_rate_limits(self) -> ConceptRead[RateLimit]:
        """
        Map every rate-limiting plugin that applies to every client.

        A plugin bound to a consumer or a consumer group applies only to the
        requests of that client (kong/runloop/plugins_iterator.lua 3.9.0: the
        consumer combinations are tried only for an authenticated consumer) and
        is left out; so is one for gRPC only. One that covers HTTP or HTTPS
        alone is reported without windows: which of the two a request uses is
        not the concept's.
        """
        items: list[RateLimit] = []
        for plugin in self._limit_plugins(_RATE_LIMIT_PLUGINS):
            config: dict[str, Any] = plugin.get("config") or {}
            windows: tuple[RateWindow, ...] = ()
            if _covers_http(plugin):
                # Kong refuses the request that takes the count past the
                # number, so a fractional number allows its whole part.
                windows = tuple(
                    RateWindow(requests=int(config[period]), seconds=seconds)
                    for period, seconds in _RATE_PERIOD_SECONDS.items()
                    if _positive_number(config.get(period)) and int(config[period]) >= 1
                )
            policy = str(config.get("policy") or "").lower()
            sync_rate = config.get("sync_rate")
            scope, name = self._plugin_scope(plugin)
            items.append(
                RateLimit(
                    scope=scope,
                    name=name,
                    enabled=bool(plugin.get("enabled", False)),
                    windows=windows,
                    shared_counter=policy in _RATE_SHARED_POLICIES
                    and isinstance(sync_rate, int | float)
                    and float(sync_rate) == _RATE_SYNC_REALTIME,
                    refusal_status=http_status(config.get("error_code", _RATE_REFUSAL_DEFAULT)),
                    source=f"plugin {plugin.get('name')} (id: {plugin.get('id', '<unknown>')})",
                )
            )
        return ConceptRead[RateLimit].read(tuple(items))

    def _read_body_size_limits(self) -> ConceptRead[BodySizeLimit]:
        """
        Map every request-size-limiting plugin that applies to every client.

        The limit is allowed_payload_size in the unit of size_unit, converted
        to bytes; the plugins left out, and the one stated without a size, are
        those of _read_rate_limits.
        """
        items: list[BodySizeLimit] = []
        for plugin in self._limit_plugins(_BODY_SIZE_PLUGINS):
            config: dict[str, Any] = plugin.get("config") or {}
            size = config.get("allowed_payload_size")
            unit = str(config.get("size_unit") or _BODY_SIZE_UNIT_DEFAULT).lower()
            factor = _BODY_SIZE_UNIT_BYTES.get(unit)
            max_bytes: int | None = None
            if _covers_http(plugin) and _positive_number(size) and factor is not None:
                max_bytes = int(size) * factor
            scope, name = self._plugin_scope(plugin)
            items.append(
                BodySizeLimit(
                    scope=scope,
                    name=name,
                    enabled=bool(plugin.get("enabled", False)),
                    max_bytes=max_bytes,
                    source=f"plugin {plugin.get('name')} (id: {plugin.get('id', '<unknown>')})",
                )
            )
        return ConceptRead[BodySizeLimit].read(tuple(items))

    def _limit_plugins(self, names: frozenset[str]) -> list[dict[str, Any]]:
        """The plugins of these names that apply to every client of their scope over HTTP."""
        return [
            plugin
            for plugin in self._fetch_paginated(_PATH_PLUGINS)
            if str(plugin.get("name", "")).lower() in names
            and not (plugin.get("consumer") or {}).get("id")
            and not (plugin.get("consumer_group") or {}).get("id")
            and _HTTP_PROTOCOLS & _protocols(plugin)
        ]

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


def _service_address(service: dict[str, Any]) -> str | None:
    """
    The address of a Kong Service, assembled from the fields Kong stores.

    Kong accepts `url` when a Service is written but never answers with it: the
    Admin API holds `protocol`, `host`, `port` and `path` (GET /schemas/services
    declares no `url` field), so reading `service["url"]` collected nothing at
    all. The address is rebuilt from those fields, so that a credential written
    into a backend address is a value test 6.4 can scan.

    Args:
        service: One Service object of the Admin API.

    Returns:
        The address, or None when the Service states no host.
    """
    host = service.get("host")
    if not isinstance(host, str) or not host:
        return None
    protocol = service.get("protocol")
    port = service.get("port")
    path = service.get("path")
    scheme = f"{protocol}://" if isinstance(protocol, str) and protocol else ""
    authority = f"{host}:{port}" if isinstance(port, int) else host
    tail = path if isinstance(path, str) and path else ""
    return f"{scheme}{authority}{tail}"


def _rewrites_request(plugin: dict[str, Any]) -> bool:
    """Whether a plugin's custom_fields_by_lua sets a field on the request part of the record."""
    custom = (plugin.get("config") or {}).get(_LOG_FIELD_CUSTOM) or {}
    return isinstance(custom, dict) and any(
        str(key) == f or str(key).startswith(f"{f}.") for key in custom for f in _LOG_REQUEST_FIELDS
    )


def _shipped_request(
    where: tuple[ConceptScope, str],
    hidden: list[tuple[tuple[ConceptScope, str] | None, tuple[str, ...]]],
) -> ShippedRequest:
    """
    What of the request a Kong log shipper's record carries (_LOG_RECORD_CARRIES).

    A key-auth hiding its keys on the shipper's own scope, or globally, removes
    them for all its traffic; one on another scope only for part of it (Kong
    plugins on a Service and on one of its Routes are not related here).

    Args:
        where:  The shipper's scope and the name of the object it is attached to.
        hidden: _hidden_keys() of the gateway.

    Returns:
        The record's request parts.
    """
    removed: list[str] = list(_LOG_RECORD_REDACTED)
    in_part: list[str] = []
    for scope, parts in hidden:
        covers = scope is not None and (scope == where or scope[0] == ConceptScope.GLOBAL)
        (removed if covers else in_part).extend(parts)
    return ShippedRequest(
        carries=_LOG_RECORD_CARRIES,
        removed=tuple(sorted(set(removed))),
        removed_in_part=tuple(sorted(set(in_part) - set(removed))),
    )


def _protocols(plugin: dict[str, Any]) -> frozenset[str]:
    """The protocols a plugin runs on; Kong's default, every protocol, when not stated."""
    protocols = plugin.get("protocols")
    if not isinstance(protocols, list):
        return _HTTP_PROTOCOLS
    return frozenset(str(protocol).lower() for protocol in protocols)


def _covers_http(plugin: dict[str, Any]) -> bool:
    """Whether a plugin runs on both HTTP and HTTPS."""
    return _HTTP_PROTOCOLS <= _protocols(plugin)


def _positive_number(value: object) -> TypeGuard[int | float]:
    """Whether a configuration value is a number above zero (not a boolean)."""
    return isinstance(value, int | float) and not isinstance(value, bool) and value > 0


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


def _resolved_addresses(target: dict[str, Any]) -> tuple[str, ...]:
    """
    The addresses Kong states it resolved a target to (its health endpoint).

    Kong's /upstreams/{name}/health gives each target as written
    ("forgejo:3000") and, under data.addresses, the IP and port it resolved it
    to (measured on the Forgejo lab 2026-11-04: 172.22.0.3, 3000), which test 0.4
    asks when the name does not resolve where the tool runs (owner decision
    2026-11-04).

    Args:
        target: One entry of the health endpoint's data.

    Returns:
        "ip:port" per address ("[ip]:port" for IPv6), in Kong's order.
    """
    data = target.get("data")
    addresses = data.get("addresses") if isinstance(data, dict) else None
    resolved: list[str] = []
    for address in addresses if isinstance(addresses, list) else []:
        if not isinstance(address, dict) or not address.get("ip") or not address.get("port"):
            continue
        ip, port = str(address["ip"]), address["port"]
        resolved.append(f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}")
    return tuple(resolved)
