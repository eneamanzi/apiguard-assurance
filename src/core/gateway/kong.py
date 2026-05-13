"""
src/core/gateway/kong.py

Kong Gateway adapter for WHITE_BOX configuration audit tests.

Implements BaseGatewayAdapter against the Kong DB-less Admin API (v3.x).
Provides read-only access to routes, services, plugins, and upstreams via
paginated GET requests to the Kong Admin API.

Design decision: direct httpx, not SecurityClient
-------------------------------------------------
This adapter uses httpx directly rather than SecurityClient for a deliberate
architectural reason: calls to the Kong Admin API are configuration audits,
not security test traffic against the target API.  They must NOT appear in
the EvidenceStore, must NOT be retried with the same policy as target API
calls, and must NOT be coupled to the test's EvidenceRecord chain.

The Admin API is a separate trust boundary from the proxy.  Using a dedicated
lightweight httpx client with its own timeout keeps the two boundaries explicit.

Paginated responses
-------------------
Kong returns paginated responses in the format:
    {"data": [...], "next": "/path?offset=..."}

_fetch_paginated() follows the 'next' cursor until exhausted.  In DB-less
mode, all objects are returned in a single page and 'next' is null.

Dependency rule: imports from stdlib, httpx, structlog, and src.core.gateway.base.
Must never import from src.tests, src.engine, src.config, or src.discovery.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from src.core.gateway.base import BaseGatewayAdapter, GatewayAdapterError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Kong Admin API resource paths
# ---------------------------------------------------------------------------

_PATH_ROUTES: str = "/routes"
_PATH_PLUGINS: str = "/plugins"
_PATH_SERVICES: str = "/services"
_PATH_UPSTREAMS: str = "/upstreams"
_PATH_STATUS: str = "/status"

_OK_STATUS: int = 200


# ---------------------------------------------------------------------------
# KongGatewayAdapter
# ---------------------------------------------------------------------------


class KongGatewayAdapter(BaseGatewayAdapter):
    """
    Gateway adapter for Kong (DB-less mode) Admin API.

    Targets Kong OSS 3.x with the DB-less Admin API exposed on a dedicated
    port (default: 8001).  All calls are read-only GET requests.

    Instantiated by engine.py Phase 3 when target.gateway_adapter = 'kong'
    is set in config.yaml.  The instance is stored on TargetContext.gateway
    and shared across all WHITE_BOX tests for the assessment run.

    Args:
        admin_base_url:  Base URL of the Kong Admin API, without trailing slash.
                         Example: 'http://localhost:8001'
        connect_timeout: TCP connection timeout in seconds.
                         Read from target.admin_connect_timeout_seconds.
        read_timeout:    HTTP read timeout in seconds.
                         Read from target.admin_read_timeout_seconds.
    """

    def __init__(
        self,
        admin_base_url: str,
        connect_timeout: float,
        read_timeout: float,
    ) -> None:
        """
        Store admin API coordinates.  No I/O at construction time.

        Args:
            admin_base_url:  Kong Admin API base URL (no trailing slash).
            connect_timeout: TCP connection timeout in seconds.
            read_timeout:    HTTP read timeout in seconds.
        """
        self._admin_base_url: str = admin_base_url.rstrip("/")
        self._connect_timeout: float = connect_timeout
        self._read_timeout: float = read_timeout

    @property
    def adapter_name(self) -> str:
        """Return the adapter identifier used in logs and error messages."""
        return "kong"

    def check_connectivity(self) -> bool:
        """
        Verify that the Kong Admin API is reachable via GET /status.

        Returns:
            True if the status endpoint responds with HTTP 200.
            False on connection refused, timeout, or any other error.
        """
        try:
            self._fetch_single(_PATH_STATUS)
            return True
        except GatewayAdapterError:
            return False
        except Exception:  # noqa: BLE001
            return False

    def get_routes(self) -> list[dict[str, Any]]:
        """
        Fetch all routes registered in Kong.

        Each returned dict contains at minimum:
            'id' (str), 'paths' (list[str] | None), 'methods' (list[str] | None),
            'service' (dict with 'id').

        Returns:
            List of Kong route objects, empty if none are configured.

        Raises:
            GatewayAdapterError: On transport failure or non-200 response.
        """
        return self._fetch_paginated(_PATH_ROUTES)

    def get_plugins(self) -> list[dict[str, Any]]:
        """
        Fetch all plugins installed on Kong.

        Each returned dict contains at minimum:
            'id' (str), 'name' (str), 'enabled' (bool), 'config' (dict).

        Returns:
            List of Kong plugin objects, empty if none are installed.

        Raises:
            GatewayAdapterError: On transport failure or non-200 response.
        """
        return self._fetch_paginated(_PATH_PLUGINS)

    def get_services(self) -> list[dict[str, Any]]:
        """
        Fetch all services registered in Kong.

        Each returned dict contains at minimum:
            'id' (str), 'name' (str | None),
            'connect_timeout' (int), 'read_timeout' (int), 'write_timeout' (int).

        Returns:
            List of Kong service objects, empty if none are configured.

        Raises:
            GatewayAdapterError: On transport failure or non-200 response.
        """
        return self._fetch_paginated(_PATH_SERVICES)

    def get_upstreams(self) -> list[dict[str, Any]]:
        """
        Fetch all upstreams registered in Kong.

        Returns:
            List of Kong upstream objects, empty if none are configured.

        Raises:
            GatewayAdapterError: On transport failure or non-200 response.
        """
        return self._fetch_paginated(_PATH_UPSTREAMS)

    def get_status(self) -> dict[str, Any]:
        """
        Fetch the Kong Admin API /status endpoint.

        Returns:
            Kong status dict with node information and worker statistics.

        Raises:
            GatewayAdapterError: On transport failure or non-200 response.
        """
        return self._fetch_single(_PATH_STATUS)

    def get_plugin_by_name(self, plugin_name: str) -> dict[str, Any] | None:
        """
        Return the first plugin matching plugin_name, or None.

        Fetches all plugins and filters by name.  Returns None if no plugin
        with that name is registered (enabled or disabled).

        Args:
            plugin_name: Exact Kong plugin name (e.g. 'rate-limiting',
                         'circuit-breaker', 'hmac-auth').

        Returns:
            First matching plugin dict, or None if absent.

        Raises:
            GatewayAdapterError: On transport failure or non-200 response.
        """
        plugins = self.get_plugins()
        for plugin in plugins:
            if plugin.get("name") == plugin_name:
                log.debug(
                    "kong_gateway_plugin_found",
                    plugin_name=plugin_name,
                    plugin_id=plugin.get("id"),
                    enabled=plugin.get("enabled"),
                )
                return plugin

        log.debug("kong_gateway_plugin_not_found", plugin_name=plugin_name)
        return None

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
            response_data = self._get_json(next_url, path)
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
        return self._get_json(url, path)

    def _get_json(self, url: str, path: str) -> dict[str, Any]:
        """
        Perform a GET request and return the parsed JSON body.

        Args:
            url:  Full URL to request.
            path: Original path (used in error messages and logging).

        Returns:
            Parsed JSON response body as a dict.

        Raises:
            GatewayAdapterError: On connection error, timeout, or non-200 status.
        """
        timeout = httpx.Timeout(
            connect=self._connect_timeout,
            read=self._read_timeout,
            write=self._connect_timeout,
            pool=self._connect_timeout,
        )

        try:
            with httpx.Client(timeout=timeout, follow_redirects=False) as http:
                response = http.get(url)
        except httpx.TransportError as exc:
            raise GatewayAdapterError(
                message=(
                    f"Kong Admin API transport error on GET {path}: {exc}. "
                    "Verify that admin_api_url is correct and the Admin API is reachable."
                ),
                path=path,
                status_code=None,
            ) from exc

        if response.status_code != _OK_STATUS:
            raise GatewayAdapterError(
                message=(
                    f"Kong Admin API returned HTTP {response.status_code} on GET {path}. "
                    f"Expected {_OK_STATUS}. Response: {response.text[:200]}"
                ),
                path=path,
                status_code=response.status_code,
            )

        result: dict[str, Any] = response.json()
        return result
