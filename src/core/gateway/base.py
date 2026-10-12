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
engine.py Phase 3 based on the target.gateway_adapter config field.

Tests that require gateway access guard with::

    guard = self._requires_admin_api(target)  # SKIP when target.gateway is None
    if guard is not None:
        return guard
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
"not supported by this adapter". Design: docs/project/gateway-concepts.md.

Dependency rule: this module imports only from stdlib, structlog,
src.core.exceptions and src.core.gateway.concepts. It must never import from
config/, tests/, external_tests/, connectors/, or report/.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import Any, TypeVar, cast

import structlog

from src.core.exceptions import ToolBaseError
from src.core.gateway.concepts import (
    BackendTimeout,
    CircuitBreaker,
    ConceptRead,
    ConfigValue,
    GatewayRoute,
    HealthCheck,
    SigningPolicy,
    TargetHealth,
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

# Instance attribute holding the answers already read in this run.
_CONCEPT_MEMORY_ATTRIBUTE: str = "_concept_memory"

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
        memory: dict[str, Any] = self.__dict__.setdefault(_CONCEPT_MEMORY_ATTRIBUTE, {})
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
