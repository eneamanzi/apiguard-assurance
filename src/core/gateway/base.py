"""
src/core/gateway/base.py

Abstract base for gateway adapter implementations.

A gateway adapter provides read-only access to the API Gateway's admin
plane for WHITE_BOX configuration audit tests.  The adapter abstracts the
gateway-specific admin API behind a uniform interface so that tests like
3.3, 4.2, 4.3, 6.4 remain gateway-agnostic: they call
``target.gateway.get_services()`` without knowing whether the underlying
gateway is Kong, Traefik, nginx, or another implementation.

Architecture position
---------------------
BaseGatewayAdapter lives in core/ so that TargetContext (also in core/)
can reference it without violating the unidirectional dependency rule
(core/ ← connectors/ ← tests/ ← engine.py).

Concrete adapter implementations live in src/gateways/ (e.g.
KongGatewayAdapter in src/gateways/kong.py) and are instantiated by
engine.py Phase 3 based on the target.gateway_adapter config field.

Tests that require gateway access guard with::

    if target.gateway is None:
        return self._make_skip(
            "Admin API not configured "
            "(target.gateway_adapter missing from config.yaml)."
        )
    services = target.gateway.get_services()

Dependency rule: this module imports only from stdlib and src.core.exceptions.
It must never import from config/, tests/, external_tests/, connectors/, or
report/.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from src.core.exceptions import ToolBaseError

# ---------------------------------------------------------------------------
# GatewayAdapterError
# ---------------------------------------------------------------------------


class GatewayAdapterError(ToolBaseError):
    """
    Raised when a gateway admin API request fails or returns an unexpected status.

    Covers transport failures (connection refused, timeout) and application-level
    errors (non-200 responses) from the gateway admin endpoint.

    WHITE_BOX tests that call gateway adapter methods must catch this and
    return TestResult(status=ERROR) or TestResult(status=SKIP) depending on
    whether the admin API is simply unavailable or erroring unexpectedly.
    """

    def __init__(
        self,
        message: str,
        path: str | None = None,
        status_code: int | None = None,
    ) -> None:
        """
        Initialize a gateway adapter error.

        Args:
            message:     Human-readable description of the failure.
            path:        Admin API path that was being called, or None.
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
# BaseGatewayAdapter
# ---------------------------------------------------------------------------


class BaseGatewayAdapter(ABC):
    """
    Abstract base class for gateway admin API adapters.

    Provides a uniform read-only interface to the gateway's admin plane.
    Concrete subclasses implement each method against the gateway-specific
    admin API (e.g. Kong DB-less Admin API, Traefik API, nginx Plus API).

    Lifecycle
    ---------
    Instantiated once by engine.py Phase 3 with the admin endpoint URL and
    timeouts read from TargetConfig.  The instance is stored on TargetContext
    as ``target.gateway`` and shared across all tests for the entire run.
    No connection is established at construction; each method call creates
    a short-lived HTTP connection.

    Error contract
    --------------
    All methods raise GatewayAdapterError on transport failures or unexpected
    HTTP status codes from the admin endpoint.  Tests are expected to catch
    GatewayAdapterError and return TestResult(ERROR) with the exception message.
    """

    @property
    @abstractmethod
    def adapter_name(self) -> str:
        """
        Return a short lowercase identifier for this adapter (e.g. 'kong').

        Used in log keys and error messages to identify the gateway type.
        """

    @abstractmethod
    def check_connectivity(self) -> bool:
        """
        Verify that the gateway admin endpoint is reachable.

        Makes a lightweight request to the admin status/health endpoint.
        Returns True if the endpoint responds with a 2xx status.
        Returns False on connection refusal or timeout (does not raise).

        Returns:
            bool: True if the admin API is reachable.
        """

    @abstractmethod
    def get_routes(self) -> list[dict[str, Any]]:
        """
        Fetch all routes registered in the gateway.

        Returns:
            List of route objects.  Each dict structure is gateway-specific;
            see the concrete adapter's docstring for field documentation.
            Empty list if no routes are configured.

        Raises:
            GatewayAdapterError: On transport failure or non-2xx response.
        """

    @abstractmethod
    def get_plugins(self) -> list[dict[str, Any]]:
        """
        Fetch all plugins (middleware) installed on the gateway.

        Returns:
            List of plugin objects.  Each dict structure is gateway-specific.
            Empty list if no plugins are installed.

        Raises:
            GatewayAdapterError: On transport failure or non-2xx response.
        """

    @abstractmethod
    def get_services(self) -> list[dict[str, Any]]:
        """
        Fetch all upstream services registered in the gateway.

        Returns:
            List of service objects.  Each dict structure is gateway-specific.
            Empty list if no services are configured.

        Raises:
            GatewayAdapterError: On transport failure or non-2xx response.
        """

    @abstractmethod
    def get_upstreams(self) -> list[dict[str, Any]]:
        """
        Fetch all upstream (load balancer) objects registered in the gateway.

        Returns:
            List of upstream objects.  Each dict structure is gateway-specific.
            Empty list if no upstreams are configured.

        Raises:
            GatewayAdapterError: On transport failure or non-2xx response.
        """

    @abstractmethod
    def get_plugin_by_name(self, plugin_name: str) -> dict[str, Any] | None:
        """
        Return the first plugin matching plugin_name, or None.

        Fetches all plugins and filters by name.  Returns None if no plugin
        with the given name is registered (absent or disabled).  The caller
        decides whether absence is a FAIL or a SKIP.

        Args:
            plugin_name: Exact plugin identifier (e.g. 'rate-limiting',
                         'hmac-auth', 'circuit-breaker').

        Returns:
            First matching plugin dict, or None.

        Raises:
            GatewayAdapterError: On transport failure or non-2xx response.
        """

    @abstractmethod
    def get_status(self) -> dict[str, Any]:
        """
        Fetch the gateway node status / health endpoint.

        Used as a connectivity check and to inspect runtime diagnostics
        (e.g. whether circuit-breaker metrics are exposed on the status page).

        Returns:
            Status dict.  Structure is gateway-specific.

        Raises:
            GatewayAdapterError: On transport failure or non-2xx response.
        """
