"""
src/tests/helpers/kong_admin.py

Kong Admin API reader for WHITE_BOX (P3) configuration audit tests.

Responsibility
--------------
Provides read-only access to the Kong Admin API for configuration audit tests
(4.2, 4.3, 6.4, 1.6).  Every function in this module performs a single GET
request to the Kong Admin API and returns the parsed response body.

Design decision: direct httpx, not SecurityClient
--------------------------------------------------
This module uses httpx directly rather than SecurityClient for a deliberate
architectural reason: calls to the Kong Admin API are configuration audits,
not security test traffic against the target API.  They must NOT appear in
the EvidenceStore (which records test evidence for the report), must NOT be
retried with the same policy as target API calls, and must NOT be coupled to
the test's EvidenceRecord chain.

The Admin API is a separate trust boundary from the proxy.  Using a dedicated
lightweight httpx client with its own timeout keeps the two boundaries
explicit.

Timeout propagation
-------------------
All public functions accept ``connect_timeout`` and ``read_timeout`` keyword
arguments.  Callers read these values from ``target.admin_connect_timeout_seconds``
and ``target.admin_read_timeout_seconds`` (both populated from config.yaml via
TargetConfig -> TargetContext).  This replaces the previous module-level
constants ``_ADMIN_CONNECT_TIMEOUT_SECONDS`` / ``_ADMIN_READ_TIMEOUT_SECONDS``,
which violated the Config-Driven rule (Rule F in LLM_rules.md): no parameter
that governs observable behaviour may be a hardcoded literal in a .py file.

Module-level defaults (``_DEFAULT_CONNECT_TIMEOUT``, ``_DEFAULT_READ_TIMEOUT``)
are kept so the functions are still callable in isolation (CLI utilities,
manual probes) without a TargetContext.  They mirror the defaults in
TargetConfig so the observable behaviour is identical in both call paths.

All functions accept admin_base_url as a plain string rather than TargetContext
to keep the scope narrow: callers extract the URL from target.admin_endpoint_base_url()
and pass it in.  This makes the functions testable in isolation without a full
TargetContext.

Dependency rule
---------------
This module imports from:
    - stdlib: only implicitly via httpx
    - httpx (direct, intentional exception to the SecurityClient rule)
    - structlog
It must never import from src.tests, src.engine, src.config, or src.discovery.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog
from src.core.exceptions import ToolBaseError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Kong Admin API paths.
_KONG_ROUTES_PATH: str = "/routes"
_KONG_PLUGINS_PATH: str = "/plugins"
_KONG_SERVICES_PATH: str = "/services"
_KONG_UPSTREAMS_PATH: str = "/upstreams"
_KONG_STATUS_PATH: str = "/status"

# Expected success status for all Admin API reads.
_OK_STATUS: int = 200

# Default timeouts used when callers do not supply explicit overrides.
# These match TargetConfig.admin_connect_timeout_seconds /
# admin_read_timeout_seconds defaults so that standalone usage (e.g. CLI
# utilities) behaves identically to pipeline usage.
_DEFAULT_CONNECT_TIMEOUT: float = 5.0
_DEFAULT_READ_TIMEOUT: float = 10.0


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class KongAdminError(ToolBaseError):
    """
    Raised when a Kong Admin API request fails or returns an unexpected status.

    Covers both transport failures (connection refused, timeout) and
    application-level errors (404, 500) from the Admin API itself.

    WHITE_BOX tests that call kong_admin helpers must catch this and return
    TestResult(status=ERROR) or TestResult(status=SKIP) depending on whether
    the Admin API is simply unavailable or erroring unexpectedly.
    """

    def __init__(
        self,
        message: str,
        path: str | None = None,
        status_code: int | None = None,
    ) -> None:
        """
        Initialize a Kong Admin API error.

        Args:
            message:     Human-readable description of the failure.
            path:        Admin API path that was being called.
            status_code: HTTP status code received, or None for transport errors.
        """
        super().__init__(message)
        self.path: str | None = path
        self.status_code: int | None = status_code

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"path={self.path!r}, "
            f"status_code={self.status_code!r})"
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_routes(
    admin_base_url: str,
    connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = _DEFAULT_READ_TIMEOUT,
) -> list[dict[str, Any]]:
    """
    Fetch all routes registered in Kong and return them as a list.

    Used by test 0.1 (shadow API discovery via documentation drift) to compare
    the set of active Kong routes against the OpenAPI spec.

    Args:
        admin_base_url:  Base URL of the Kong Admin API, without trailing slash.
                         Example: 'http://localhost:8001'
        connect_timeout: TCP connection timeout in seconds.
                         Read from target.admin_connect_timeout_seconds.
        read_timeout:    HTTP read timeout in seconds.
                         Read from target.admin_read_timeout_seconds.

    Returns:
        List of Kong route objects.  Each dict contains at minimum:
            'id' (str), 'paths' (list[str] | None), 'methods' (list[str] | None),
            'service' (dict with 'id').
        Empty list if no routes are configured.

    Raises:
        KongAdminError: On transport failure or non-200 response.
    """
    return _fetch_paginated(admin_base_url, _KONG_ROUTES_PATH, connect_timeout, read_timeout)


def get_plugins(
    admin_base_url: str,
    connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = _DEFAULT_READ_TIMEOUT,
) -> list[dict[str, Any]]:
    """
    Fetch all plugins installed on Kong and return them as a list.

    Used by tests 4.3 (circuit breaker audit) and 6.3 (layer-7 hardening)
    to verify that expected plugins are present and correctly configured.

    Args:
        admin_base_url:  Base URL of the Kong Admin API.
        connect_timeout: TCP connection timeout in seconds.
        read_timeout:    HTTP read timeout in seconds.

    Returns:
        List of Kong plugin objects.  Each dict contains at minimum:
            'id' (str), 'name' (str), 'enabled' (bool), 'config' (dict).

    Raises:
        KongAdminError: On transport failure or non-200 response.
    """
    return _fetch_paginated(admin_base_url, _KONG_PLUGINS_PATH, connect_timeout, read_timeout)


def get_services(
    admin_base_url: str,
    connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = _DEFAULT_READ_TIMEOUT,
) -> list[dict[str, Any]]:
    """
    Fetch all services registered in Kong and return them as a list.

    Used by test 4.2 (timeout audit) to read connect_timeout, read_timeout,
    and write_timeout values configured on each upstream service.

    Args:
        admin_base_url:  Base URL of the Kong Admin API.
        connect_timeout: TCP connection timeout in seconds.
        read_timeout:    HTTP read timeout in seconds.

    Returns:
        List of Kong service objects.  Each dict contains at minimum:
            'id' (str), 'name' (str | None),
            'connect_timeout' (int), 'read_timeout' (int), 'write_timeout' (int).

    Raises:
        KongAdminError: On transport failure or non-200 response.
    """
    return _fetch_paginated(admin_base_url, _KONG_SERVICES_PATH, connect_timeout, read_timeout)


def get_upstreams(
    admin_base_url: str,
    connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = _DEFAULT_READ_TIMEOUT,
) -> list[dict[str, Any]]:
    """
    Fetch all upstreams registered in Kong and return them as a list.

    Args:
        admin_base_url:  Base URL of the Kong Admin API.
        connect_timeout: TCP connection timeout in seconds.
        read_timeout:    HTTP read timeout in seconds.

    Returns:
        List of Kong upstream objects.

    Raises:
        KongAdminError: On transport failure or non-200 response.
    """
    return _fetch_paginated(admin_base_url, _KONG_UPSTREAMS_PATH, connect_timeout, read_timeout)


def get_plugin_by_name(
    admin_base_url: str,
    plugin_name: str,
    connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = _DEFAULT_READ_TIMEOUT,
) -> dict[str, Any] | None:
    """
    Return the first plugin matching plugin_name, or None.

    Fetches all plugins and filters by name.  If no matching plugin is found
    (either because the plugin is not installed or is disabled), returns None.
    The caller decides whether the absence of a plugin is a FAIL or a SKIP.

    Args:
        admin_base_url:  Base URL of the Kong Admin API.
        plugin_name:     Exact Kong plugin name (e.g. 'rate-limiting',
                         'circuit-breaker', 'jwt').
        connect_timeout: TCP connection timeout in seconds.
        read_timeout:    HTTP read timeout in seconds.

    Returns:
        First matching plugin dict (enabled or disabled), or None if no plugin
        with that name is registered.

    Raises:
        KongAdminError: On transport failure or non-200 response.
    """
    plugins = get_plugins(admin_base_url, connect_timeout, read_timeout)
    for plugin in plugins:
        if plugin.get("name") == plugin_name:
            log.debug(
                "kong_admin_plugin_found",
                plugin_name=plugin_name,
                plugin_id=plugin.get("id"),
                enabled=plugin.get("enabled"),
            )
            return plugin

    log.debug("kong_admin_plugin_not_found", plugin_name=plugin_name)
    return None


def get_status(
    admin_base_url: str,
    connect_timeout: float = _DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = _DEFAULT_READ_TIMEOUT,
) -> dict[str, Any]:
    """
    Fetch the Kong node status endpoint and return the response.

    Used as a connectivity check before WHITE_BOX tests begin.  If this call
    succeeds, the Admin API is reachable and the other functions will work.

    Args:
        admin_base_url:  Base URL of the Kong Admin API.
        connect_timeout: TCP connection timeout in seconds.
        read_timeout:    HTTP read timeout in seconds.

    Returns:
        Kong status dict containing node information and database connectivity.

    Raises:
        KongAdminError: On transport failure or non-200 response.
    """
    return _fetch_single(admin_base_url, _KONG_STATUS_PATH, connect_timeout, read_timeout)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _fetch_paginated(
    admin_base_url: str,
    path: str,
    connect_timeout: float,
    read_timeout: float,
) -> list[dict[str, Any]]:
    """
    Fetch all items from a paginated Kong Admin API collection endpoint.

    Kong returns paginated responses in the format:
        {"data": [...], "next": "/path?offset=..."}

    Follows the 'next' cursor until exhausted.  In DB-less mode, all objects
    are returned in a single page and 'next' is null.

    Args:
        admin_base_url:  Base URL of the Kong Admin API.
        path:            Collection path (e.g. '/routes', '/plugins').
        connect_timeout: TCP connection timeout in seconds.
        read_timeout:    HTTP read timeout in seconds.

    Returns:
        Flat list of all items across all pages.

    Raises:
        KongAdminError: On transport failure or non-200 response on any page.
    """
    items: list[dict[str, Any]] = []
    next_url: str | None = f"{admin_base_url.rstrip('/')}{path}"

    while next_url is not None:
        response_data = _get_json(next_url, path, connect_timeout, read_timeout)
        page_items: list[dict[str, Any]] = response_data.get("data", [])
        items.extend(page_items)

        raw_next: str | None = response_data.get("next")
        if raw_next:
            # Kong returns an absolute path for 'next', e.g. '/routes?offset=abc'.
            # Reconstruct the full URL by prepending the admin base.
            next_url = f"{admin_base_url.rstrip('/')}{raw_next}"
        else:
            next_url = None

        log.debug(
            "kong_admin_page_fetched",
            path=path,
            page_count=len(page_items),
            has_next=bool(raw_next),
        )

    log.debug("kong_admin_collection_fetched", path=path, total=len(items))
    return items


def _fetch_single(
    admin_base_url: str,
    path: str,
    connect_timeout: float,
    read_timeout: float,
) -> dict[str, Any]:
    """
    Fetch a single object from the Kong Admin API.

    Args:
        admin_base_url:  Base URL of the Kong Admin API.
        path:            Resource path (e.g. '/status').
        connect_timeout: TCP connection timeout in seconds.
        read_timeout:    HTTP read timeout in seconds.

    Returns:
        Parsed JSON response as a dict.

    Raises:
        KongAdminError: On transport failure or non-200 response.
    """
    url = f"{admin_base_url.rstrip('/')}{path}"
    return _get_json(url, path, connect_timeout, read_timeout)


def _get_json(
    url: str,
    path: str,
    connect_timeout: float,
    read_timeout: float,
) -> dict[str, Any]:
    """
    Perform a GET request to the given URL and return the parsed JSON body.

    Args:
        url:             Full URL to request.
        path:            Original path (used only for error messages and logging).
        connect_timeout: TCP connection timeout in seconds.
        read_timeout:    HTTP read timeout in seconds.

    Returns:
        Parsed JSON response body as a dict.

    Raises:
        KongAdminError: On connection error, timeout, or non-200 response.
    """
    timeout = httpx.Timeout(
        connect=connect_timeout,
        read=read_timeout,
        write=connect_timeout,
        pool=connect_timeout,
    )

    try:
        with httpx.Client(timeout=timeout, follow_redirects=False) as http:
            response = http.get(url)
    except httpx.TransportError as exc:
        raise KongAdminError(
            message=(
                f"Kong Admin API transport error on GET {path}: {exc}. "
                f"Verify that admin_api_url is correct and the Admin API is reachable."
            ),
            path=path,
            status_code=None,
        ) from exc

    if response.status_code != _OK_STATUS:
        raise KongAdminError(
            message=(
                f"Kong Admin API returned HTTP {response.status_code} on GET {path}. "
                f"Expected {_OK_STATUS}. Response: {response.text[:200]}"
            ),
            path=path,
            status_code=response.status_code,
        )

    result: dict[str, Any] = response.json()
    return result
