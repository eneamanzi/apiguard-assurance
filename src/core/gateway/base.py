"""
src/core/gateway/base.py

Abstract base for gateway adapter implementations.

A gateway adapter provides read-only access to the API Gateway's admin
plane for WHITE_BOX configuration audit tests.  The adapter abstracts the
gateway-specific admin API behind neutral concepts so that tests like
3.3, 4.2, 4.3, 6.4 remain gateway-agnostic: they call
``target.gateway.backend_timeouts()`` without knowing whether the underlying
gateway is Kong, APISIX, or another implementation.

Architecture position
---------------------
BaseGatewayAdapter lives in core/ so that TargetContext (also in core/)
can reference it without violating the unidirectional dependency rule
(core/ ← connectors/ ← tests/ ← engine.py).

Concrete adapter implementations live in src/core/gateway/ (e.g.
KongGatewayAdapter in src/core/gateway/kong.py) and are instantiated by
engine.py Phase 3 based on the gateway.adapter config field.

Tests that require gateway access declare it, and the engine records SKIP
without a gateway::

    info = TestInfo(..., needs=(Need.GATEWAY,))
    ...
    timeouts = target.gateway.backend_timeouts()

Neutral concepts
----------------
The tests read the gateway through one reader per concept (backend_timeouts(),
circuit_breakers(), health_checks(), signing_policies(), routes(),
config_values(), target_health()), each answering with a ConceptRead
(src/core/gateway/concepts.py): read, not supported, or not accessible. The
public readers are written once, here: the first call runs the adapter's
_read_<concept>() method, later calls in the same run return the same answer
(one adapter per run, so a concept is read once per run), and a
GatewayAdapterError becomes "not accessible" with its message. A concrete
adapter overrides the _read_<concept>() methods it can serve; the others answer
"not supported by this adapter". Design: docs/architecture/design-decisions.md, D7.

Construction and transport
--------------------------
Every adapter is built by engine.py Phase 3 with the same keyword arguments
(the constructor below): the Admin API address, timeouts and headers, the
address of a separate health interface, and the configuration of tests 3.3
and 4.3. Each adapter uses the ones its gateway needs. _get_json_object() and
_get_json_array() perform one read-only GET with those timeouts.

Design decision: direct httpx, not SecurityClient. Reads of the gateway's
interfaces are configuration audits, not security test traffic against the
target API: they must not appear in the EvidenceStore nor follow the retry
policy of target API calls. The interfaces are a separate trust boundary from
the proxy, and a dedicated short-lived httpx client keeps the two explicit.

Dependency rule: this module imports only from stdlib, httpx, structlog,
src.core.exceptions, src.core.gateway.concepts and src.core.tls. It must
never import from config/, tests/, external_tests/, connectors/, or report/.
"""

from __future__ import annotations

import re
import ssl
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from typing import Any, TypeVar, cast

import httpx
import structlog

from src.core.exceptions import ToolBaseError
from src.core.gateway.concepts import (
    BackendTimeout,
    CircuitBreaker,
    ConceptRead,
    ConfigValue,
    ConfigValueKind,
    GatewayRoute,
    HealthCheck,
    SigningPolicy,
    TargetHealth,
)
from src.core.tls import (
    GATEWAY_ADMIN_TLS,
    GATEWAY_HEALTH_TLS,
    build_ssl_context,
    certificate_answer,
    certificate_failure,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# Names of the concepts: keys of the per-run memory and words of the reasons.
CONCEPT_BACKEND_TIMEOUTS: str = "backend timeouts"
CONCEPT_CIRCUIT_BREAKERS: str = "circuit breakers"
CONCEPT_HEALTH_CHECKS: str = "health checks"
CONCEPT_SIGNING_POLICIES: str = "request signing policies"
CONCEPT_ROUTES: str = "routes"
CONCEPT_CONFIG_VALUES: str = "configuration values"
CONCEPT_TARGET_HEALTH: str = "live target health"

# Interfaces of a gateway, for error messages: name and the setting holding its address.
ADMIN_API_INTERFACE: tuple[str, str] = ("Admin API", "gateway.admin.url")
HEALTH_API_INTERFACE: tuple[str, str] = ("health API", "gateway.health.url")

_OK_STATUS: int = 200
# Characters of an unexpected answer quoted in an error message.
_ERROR_BODY_PREVIEW_CHARS: int = 200
# The title of an HTML error page, quoted instead of its markup.
_HTML_TITLE: re.Pattern[str] = re.compile(r"<title>\s*(.*?)\s*</title>", re.IGNORECASE | re.DOTALL)
# Depth limit when collecting the text values of a configuration (the same
# limit test 6.4 applied to the raw configuration).
_CONFIG_VALUES_MAX_DEPTH: int = 10

ItemT = TypeVar(
    "ItemT",
    BackendTimeout,
    CircuitBreaker,
    HealthCheck,
    SigningPolicy,
    GatewayRoute,
    ConfigValue,
    TargetHealth,
)

# ---------------------------------------------------------------------------
# GatewayAdapterError
# ---------------------------------------------------------------------------


class GatewayAdapterError(ToolBaseError):
    """
    A request to the gateway's Admin API or health interface failed (transport error or
    unexpected status). Caught by the adapter's concept readers, which answer "not
    accessible": the audits then SKIP or add a note.

    Covers transport failures (connection refused, timeout) and application-level
    errors (non-200 responses) from the gateway admin endpoint.

    Tests never see it: the concept readers (backend_timeouts(), ...) catch it
    and return a ConceptRead that is not accessible, with the reason.
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
    Instantiated once by engine.py Phase 3 with the settings read from
    TargetConfig.  The instance is stored on TargetContext as
    ``target.gateway`` and shared across all tests for the entire run.
    No connection is established at construction; each read creates a
    short-lived HTTP connection.

    Error contract
    --------------
    The _read_<concept>() methods raise GatewayAdapterError on transport
    failures or unexpected answers; the public readers turn it into a
    "not accessible" answer, so tests never see the exception.
    """

    def __init__(
        self,
        admin_base_url: str,
        connect_timeout: float,
        read_timeout: float,
        admin_headers: Mapping[str, str] | None = None,
        health_api_url: str | None = None,
        admin_tls_context: ssl.SSLContext | None = None,
        health_tls_context: ssl.SSLContext | None = None,
    ) -> None:
        """
        Store the gateway settings.  No I/O at construction time.

        Args:
            admin_base_url:  Admin API base URL (trailing slash removed).
            connect_timeout: TCP connection timeout in seconds, for every read.
            read_timeout:    HTTP read timeout in seconds, for every read.
            admin_headers:   Headers sent on every Admin API request (e.g. an
                             API key); none by default.
            health_api_url:  Base URL of the interface reporting the live
                             health of the backends, for a gateway that keeps
                             it outside the Admin API; None when not set.
            admin_tls_context:  TLS context of gateway.admin.tls (src/core/tls.py);
                                None for the default trust.
            health_tls_context: TLS context of gateway.health.tls; None for the
                                default trust.
        """
        self._admin_base_url: str = admin_base_url.rstrip("/")
        self._connect_timeout: float = connect_timeout
        self._read_timeout: float = read_timeout
        self._admin_headers: dict[str, str] = dict(admin_headers or {})
        self._health_api_url: str | None = (
            health_api_url.rstrip("/") if health_api_url is not None else None
        )
        self._admin_tls: ssl.SSLContext = admin_tls_context or build_ssl_context(
            None, GATEWAY_ADMIN_TLS
        )
        self._health_tls: ssl.SSLContext = health_tls_context or build_ssl_context(
            None, GATEWAY_HEALTH_TLS
        )
        # Answers already read in this run, by concept name.
        self._concept_memory: dict[str, Any] = {}

    @property
    @abstractmethod
    def adapter_name(self) -> str:
        """
        Return a short lowercase identifier for this adapter (e.g. 'kong').

        Used in log keys and error messages to identify the gateway type.
        """

    # ------------------------------------------------------------------
    # Neutral concepts: public readers (read once per run)
    # ------------------------------------------------------------------

    def backend_timeouts(self) -> ConceptRead[BackendTimeout]:
        """Return the timeouts towards the backends (and route overrides)."""
        return self._read_once(
            CONCEPT_BACKEND_TIMEOUTS, BackendTimeout, self._read_backend_timeouts
        )

    def circuit_breakers(self) -> ConceptRead[CircuitBreaker]:
        """Return the circuit breakers configured on the gateway."""
        return self._read_once(
            CONCEPT_CIRCUIT_BREAKERS, CircuitBreaker, self._read_circuit_breakers
        )

    def health_checks(self) -> ConceptRead[HealthCheck]:
        """Return the health checks of each backend."""
        return self._read_once(CONCEPT_HEALTH_CHECKS, HealthCheck, self._read_health_checks)

    def signing_policies(self) -> ConceptRead[SigningPolicy]:
        """Return the request signing (HMAC) policies."""
        return self._read_once(CONCEPT_SIGNING_POLICIES, SigningPolicy, self._read_signing_policies)

    def routes(self) -> ConceptRead[GatewayRoute]:
        """Return the routes the gateway exposes."""
        return self._read_once(CONCEPT_ROUTES, GatewayRoute, self._read_routes)

    def config_values(self) -> ConceptRead[ConfigValue]:
        """Return the configuration text values, secrets masked unless asked for."""
        return self._read_once(CONCEPT_CONFIG_VALUES, ConfigValue, self._read_config_values)

    def target_health(self) -> ConceptRead[TargetHealth]:
        """Return the live health of each target of each backend."""
        return self._read_once(CONCEPT_TARGET_HEALTH, TargetHealth, self._read_target_health)

    # ------------------------------------------------------------------
    # Neutral concepts: adapter-specific reads (override the ones served)
    # ------------------------------------------------------------------

    def _read_backend_timeouts(self) -> ConceptRead[BackendTimeout]:
        """Read the backend timeouts; default: not supported by this adapter."""
        return ConceptRead[BackendTimeout].not_supported(self._not_read(CONCEPT_BACKEND_TIMEOUTS))

    def _read_circuit_breakers(self) -> ConceptRead[CircuitBreaker]:
        """Read the circuit breakers; default: not supported by this adapter."""
        return ConceptRead[CircuitBreaker].not_supported(self._not_read(CONCEPT_CIRCUIT_BREAKERS))

    def _read_health_checks(self) -> ConceptRead[HealthCheck]:
        """Read the health checks; default: not supported by this adapter."""
        return ConceptRead[HealthCheck].not_supported(self._not_read(CONCEPT_HEALTH_CHECKS))

    def _read_signing_policies(self) -> ConceptRead[SigningPolicy]:
        """Read the signing policies; default: not supported by this adapter."""
        return ConceptRead[SigningPolicy].not_supported(self._not_read(CONCEPT_SIGNING_POLICIES))

    def _read_routes(self) -> ConceptRead[GatewayRoute]:
        """Read the routes; default: not supported by this adapter."""
        return ConceptRead[GatewayRoute].not_supported(self._not_read(CONCEPT_ROUTES))

    def _read_config_values(self) -> ConceptRead[ConfigValue]:
        """Read the configuration values; default: not supported by this adapter."""
        return ConceptRead[ConfigValue].not_supported(self._not_read(CONCEPT_CONFIG_VALUES))

    def _read_target_health(self) -> ConceptRead[TargetHealth]:
        """Read the live target health; default: not supported by this adapter."""
        return ConceptRead[TargetHealth].not_supported(self._not_read(CONCEPT_TARGET_HEALTH))

    # ------------------------------------------------------------------
    # Neutral concepts: helpers
    # ------------------------------------------------------------------

    def _not_read(self, concept: str) -> str:
        """Return the reason for a concept this adapter does not read."""
        return f"the {self.adapter_name} adapter does not read {concept}"

    def _read_once(
        self,
        concept: str,
        item_type: type[ItemT],
        reader: Callable[[], ConceptRead[ItemT]],
    ) -> ConceptRead[ItemT]:
        """
        Return the answer for a concept, reading the gateway only the first time.

        A GatewayAdapterError raised by the reader (transport failure, refused
        or unexpected answer of the gateway's interface) becomes a "not
        accessible" answer with its message; the answer, whatever it is, is
        kept for the rest of the run.

        Args:
            concept:   Name of the concept (CONCEPT_* constant).
            item_type: Model of the concept's items.
            reader:    The adapter's _read_<concept>() method.

        Returns:
            The answer for the concept.
        """
        memory = self._concept_memory
        if concept not in memory:
            try:
                answer = reader()
            except GatewayAdapterError as exc:
                answer = ConceptRead[item_type].not_accessible(  # type: ignore[valid-type]
                    f"{self.adapter_name}: {concept} could not be read: {exc.message}"
                )
            memory[concept] = answer
            log.info(
                "gateway_concept_read",
                adapter=self.adapter_name,
                concept=concept,
                status=answer.status.value,
                items=len(answer.items),
                reason=answer.reason,
            )
        return cast("ConceptRead[ItemT]", memory[concept])

    # ------------------------------------------------------------------
    # Transport
    # ------------------------------------------------------------------

    def _get_json_object(
        self,
        url: str,
        path: str,
        interface: tuple[str, str] = ADMIN_API_INTERFACE,
    ) -> dict[str, Any]:
        """
        GET a URL of the gateway's interfaces and return its JSON object body.

        Args:
            url:       Full URL to request.
            path:      Path, for error messages and logs.
            interface: ADMIN_API_INTERFACE (sends the Admin API headers) or
                       HEALTH_API_INTERFACE (sends none).

        Returns:
            The parsed body.

        Raises:
            GatewayAdapterError: On transport failure, a status other than 200,
                                 or a body that is not a JSON object.
        """
        body = self._get_json(url, path, interface)
        if not isinstance(body, dict):
            raise GatewayAdapterError(
                message=f"{self._interface_label(interface)} answered GET {path} "
                "with JSON that is not an object.",
                path=path,
                status_code=_OK_STATUS,
            )
        return body

    def _get_json_array(
        self,
        url: str,
        path: str,
        interface: tuple[str, str] = ADMIN_API_INTERFACE,
    ) -> list[Any]:
        """
        GET a URL of the gateway's interfaces and return its JSON array body.

        Args:
            url:       Full URL to request.
            path:      Path, for error messages and logs.
            interface: ADMIN_API_INTERFACE or HEALTH_API_INTERFACE.

        Returns:
            The parsed body.

        Raises:
            GatewayAdapterError: On transport failure, a status other than 200,
                                 or a body that is not a JSON array.
        """
        body = self._get_json(url, path, interface)
        if not isinstance(body, list):
            raise GatewayAdapterError(
                message=f"{self._interface_label(interface)} answered GET {path} "
                "with JSON that is not an array.",
                path=path,
                status_code=_OK_STATUS,
            )
        return body

    def _get_json(self, url: str, path: str, interface: tuple[str, str]) -> object:
        """
        Perform one GET, no redirects, and return the parsed JSON body.

        The Admin API headers are sent only to the Admin API.

        A TLS problem, whether the connection is refused or the server answers
        with one of nginx's TLS pages (src/core/tls.py), gives a message naming
        the key to set.

        Raises:
            GatewayAdapterError: On transport failure, a status other than 200,
                                 or a body that is not JSON.
        """
        label = self._interface_label(interface)
        setting = interface[1]
        is_admin = interface == ADMIN_API_INTERFACE
        headers = self._admin_headers if is_admin else {}
        tls_context = self._admin_tls if is_admin else self._health_tls
        timeout = httpx.Timeout(
            connect=self._connect_timeout,
            read=self._read_timeout,
            write=self._connect_timeout,
            pool=self._connect_timeout,
        )
        try:
            with httpx.Client(timeout=timeout, follow_redirects=False, verify=tls_context) as http:
                response = http.get(url, headers=headers)
        except httpx.TransportError as exc:
            tls_reason = certificate_failure(
                exc, GATEWAY_ADMIN_TLS if is_admin else GATEWAY_HEALTH_TLS
            )
            if tls_reason is not None:
                raise GatewayAdapterError(
                    message=f"{label}: {tls_reason}",
                    path=path,
                    status_code=None,
                ) from exc
            raise GatewayAdapterError(
                message=(
                    f"{label} transport error on GET {path}: {exc}. "
                    f"Verify that {setting} is correct and the interface is reachable."
                ),
                path=path,
                status_code=None,
            ) from exc

        if response.status_code != _OK_STATUS:
            tls_reason = certificate_answer(
                response.status_code,
                response.text,
                GATEWAY_ADMIN_TLS if is_admin else GATEWAY_HEALTH_TLS,
            )
            if tls_reason is not None:
                raise GatewayAdapterError(
                    message=f"{label}: {tls_reason}",
                    path=path,
                    status_code=response.status_code,
                )
            raise GatewayAdapterError(
                message=(
                    f"{label} returned HTTP {response.status_code} on GET {path}. "
                    f"Expected {_OK_STATUS}. Response: {_answer_preview(response.text)}"
                ),
                path=path,
                status_code=response.status_code,
            )
        try:
            body: object = response.json()
        except ValueError as exc:
            raise GatewayAdapterError(
                message=f"{label} answered GET {path} with a body that is not JSON.",
                path=path,
                status_code=response.status_code,
            ) from exc
        return body

    def _interface_label(self, interface: tuple[str, str]) -> str:
        """Return e.g. 'kong Admin API', for error messages."""
        return f"{self.adapter_name} {interface[0]}"


def _answer_preview(text: str) -> str:
    """The start of an unexpected answer for a message; the title alone for an HTML page."""
    title = _HTML_TITLE.search(text)
    if title is not None:
        return title.group(1)[:_ERROR_BODY_PREVIEW_CHARS]
    return text[:_ERROR_BODY_PREVIEW_CHARS]


# ---------------------------------------------------------------------------
# Helpers for the adapters
# ---------------------------------------------------------------------------


def collect_text_values(
    data: dict[str, Any],
    kind: ConfigValueKind,
    location: str,
    prefix: str,
    depth: int = 0,
) -> list[ConfigValue]:
    """
    Collect the text values of a gateway configuration, with their dotted keys.

    Descends into objects and into objects inside arrays, up to
    _CONFIG_VALUES_MAX_DEPTH levels; only strings are collected (the rules
    test 6.4 applied to the raw configuration). Used by the adapters for the
    configuration values concept.

    Args:
        data:     The configuration object (e.g. a plugin configuration).
        kind:     Type of object holding the values.
        location: Which object, e.g. 'route 5, plugin http-logger'.
        prefix:   Dotted key of data itself, e.g. 'config'.
        depth:    Current depth (0 for the caller).

    Returns:
        One ConfigValue per string found.
    """
    if depth > _CONFIG_VALUES_MAX_DEPTH:
        log.warning("gateway_config_values_max_depth", location=location, key=prefix)
        return []
    values: list[ConfigValue] = []
    for key, value in data.items():
        path = f"{prefix}.{key}"
        if isinstance(value, dict):
            values.extend(collect_text_values(value, kind, location, path, depth + 1))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, dict):
                    values.extend(
                        collect_text_values(item, kind, location, f"{path}[{index}]", depth + 1)
                    )
        elif isinstance(value, str):
            values.append(ConfigValue(kind=kind, location=location, key=path, value=value))
    return values
