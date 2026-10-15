"""
src/core/gateway/concepts.py

Neutral gateway concepts: the shapes in which every gateway adapter answers the
tests that audit the gateway configuration.

A test asks an adapter for one concept at a time (backend timeouts, circuit
breakers, health checks, request signing policies, routes, configuration text
values, live health of the targets). The adapter reads the gateway in its own
way (Admin API, Control API, configuration file) and answers with a
ConceptRead:

    read            the items found; an empty tuple means "read, nothing
                    configured";
    not_supported   the gateway has no such concept;
    not_accessible  the concept exists but cannot be read (permissions, an
                    interface not configured or not exposed).

The tests never see a gateway's own objects or field names, so the same test
runs on any gateway that has an adapter. The fields, and how Kong and APISIX
map onto them, are decided in docs/architecture/design-decisions.md, D7.

Configuration values hold secrets as SecretStr: printed, logged or serialized
they show as '**********'; a test that scans them asks for the value
explicitly (get_secret_value()).

Dependency rule: this module imports only from the standard library and
pydantic.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Generic, TypeVar

from pydantic import BaseModel, Field, SecretStr, computed_field, model_validator

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ConceptStatus(StrEnum):
    """Outcome of reading a concept from a gateway."""

    READ = "read"
    NOT_SUPPORTED = "not_supported"
    NOT_ACCESSIBLE = "not_accessible"


class ConceptScope(StrEnum):
    """What a setting applies to."""

    GLOBAL = "global"
    BACKEND = "backend"
    ROUTE = "route"


class ConfigValueKind(StrEnum):
    """Type of gateway object that holds a configuration text value."""

    BACKEND = "backend"
    PLUGIN = "plugin"
    CLIENT_CREDENTIAL = "client_credential"


class TargetState(StrEnum):
    """Live health state of one target of a backend."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    PARTIALLY_HEALTHY = "partially_healthy"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Outcome of a reader
# ---------------------------------------------------------------------------

ItemT = TypeVar("ItemT", bound=BaseModel)


class ConceptRead(BaseModel, Generic[ItemT]):
    """
    Answer of an adapter reader for one concept.

    Build it with read(), not_supported() or not_accessible(): a status other
    than READ needs a reason and carries no items; READ carries no reason.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    status: ConceptStatus = Field(description="Outcome of the read.")
    items: tuple[ItemT, ...] = Field(
        default=(),
        description="Items found (status READ only); empty means nothing configured.",
    )
    reason: str | None = Field(
        default=None,
        description="Why the concept was not read (status other than READ only).",
    )

    @model_validator(mode="after")
    def _status_matches_content(self) -> ConceptRead[ItemT]:
        """Reject a reason on READ, or a missing reason or any item otherwise."""
        if self.status == ConceptStatus.READ:
            if self.reason is not None:
                raise ValueError("a concept read carries no reason")
        else:
            if not self.reason or not self.reason.strip():
                raise ValueError(f"status '{self.status.value}' requires a reason")
            if self.items:
                raise ValueError(f"status '{self.status.value}' carries no items")
        return self

    @classmethod
    def read(cls, items: tuple[ItemT, ...]) -> ConceptRead[ItemT]:
        """
        Build the answer for a concept that was read.

        Args:
            items: The items found (empty when nothing is configured).

        Returns:
            A ConceptRead with status READ.
        """
        return cls(status=ConceptStatus.READ, items=items)

    @classmethod
    def not_supported(cls, reason: str) -> ConceptRead[ItemT]:
        """
        Build the answer for a concept the gateway does not have.

        Args:
            reason: Why the gateway has no such concept.

        Returns:
            A ConceptRead with status NOT_SUPPORTED.
        """
        return cls(status=ConceptStatus.NOT_SUPPORTED, reason=reason)

    @classmethod
    def not_accessible(cls, reason: str) -> ConceptRead[ItemT]:
        """
        Build the answer for a concept that exists but cannot be read.

        Args:
            reason: What is missing (permission, address of an interface, ...).

        Returns:
            A ConceptRead with status NOT_ACCESSIBLE.
        """
        return cls(status=ConceptStatus.NOT_ACCESSIBLE, reason=reason)


# ---------------------------------------------------------------------------
# Concepts
# ---------------------------------------------------------------------------

_SOURCE_DESCRIPTION: str = "Reference to the gateway's own object, for the evidence."


class BackendTimeout(BaseModel):
    """Timeouts towards a backend, or towards a backend from one route."""

    model_config = {"frozen": True, "extra": "forbid"}

    scope: ConceptScope = Field(
        description="BACKEND (all requests to it) or ROUTE (that route only)."
    )
    name: str = Field(min_length=1, description="Backend or route name.")
    connect_seconds: float | None = Field(
        ge=0, description="Maximum time to open the connection; None: the gateway default applies."
    )
    send_seconds: float | None = Field(
        ge=0, description="Maximum time between two writes; None: the gateway default applies."
    )
    read_seconds: float | None = Field(
        ge=0, description="Maximum time between two reads; None: the gateway default applies."
    )
    source: str = Field(min_length=1, description=_SOURCE_DESCRIPTION)


class CircuitBreaker(BaseModel):
    """A circuit breaker: stops sending requests to a failing backend for a time."""

    model_config = {"frozen": True, "extra": "forbid"}

    scope: ConceptScope = Field(description="Where the breaker applies.")
    name: str = Field(min_length=1, description="Backend or route name.")
    enabled: bool = Field(description="Whether the breaker is active.")
    failure_threshold: int | None = Field(
        ge=0, description="Failures before the circuit opens; None: not stated by the gateway."
    )
    failure_statuses: tuple[int, ...] = Field(description="HTTP statuses counted as failures.")
    open_seconds: float | None = Field(
        ge=0, description="How long the circuit stays open (at most); None: not stated."
    )
    recovery_successes: int | None = Field(
        ge=0, description="Successes needed to close the circuit; None: not stated."
    )
    source: str = Field(min_length=1, description=_SOURCE_DESCRIPTION)


class PassiveCheck(BaseModel):
    """Failure thresholds a gateway observes on real traffic to exclude a target."""

    model_config = {"frozen": True, "extra": "forbid"}

    http_failures: int | None = Field(ge=0, description="HTTP failures before exclusion.")
    tcp_failures: int | None = Field(ge=0, description="TCP failures before exclusion.")
    timeouts: int | None = Field(ge=0, description="Timeouts before exclusion.")
    failure_statuses: tuple[int, ...] = Field(description="HTTP statuses counted as failures.")


class ActiveCheck(BaseModel):
    """Periodic probe a gateway sends to the targets of a backend."""

    model_config = {"frozen": True, "extra": "forbid"}

    healthy_interval_seconds: float | None = Field(
        ge=0, description="Probe interval for healthy targets; 0 or None: not probed."
    )
    unhealthy_interval_seconds: float | None = Field(
        ge=0, description="Probe interval for unhealthy targets; 0 or None: not probed."
    )
    http_path: str | None = Field(description="Path of the probe request.")


class HealthCheck(BaseModel):
    """Health checks of one backend."""

    model_config = {"frozen": True, "extra": "forbid"}

    scope: ConceptScope = Field(description="BACKEND.")
    name: str = Field(min_length=1, description="Backend name.")
    passive: PassiveCheck | None = Field(description="Passive checks; None: not configured.")
    active: ActiveCheck | None = Field(description="Active checks; None: not configured.")
    source: str = Field(min_length=1, description=_SOURCE_DESCRIPTION)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def recovers_automatically(self) -> bool:
        """
        Whether an excluded target comes back by itself.

        Only active checks on unhealthy targets re-enable a target: passive
        checks alone never do (Kong and APISIX documentation).
        """
        interval = self.active.unhealthy_interval_seconds if self.active is not None else None
        return interval is not None and interval > 0


class SigningPolicy(BaseModel):
    """A request signing (HMAC) policy."""

    model_config = {"frozen": True, "extra": "forbid"}

    scope: ConceptScope = Field(description="GLOBAL, BACKEND or ROUTE.")
    name: str = Field(min_length=1, description="Backend or route name; 'global' for GLOBAL.")
    enabled: bool = Field(description="Whether the policy is active.")
    algorithms: tuple[str, ...] | None = Field(
        description=(
            "Allowed algorithms, standard names such as 'hmac-sha256'; None: not stated by "
            "the gateway (an empty tuple means none allowed)."
        )
    )
    replay_window_seconds: float | None = Field(
        ge=0, description="Allowed clock difference against replay; None: not stated."
    )
    required_signed_headers: tuple[str, ...] = Field(
        description="Headers the client must include in the signature."
    )
    body_signed: bool | None = Field(
        description="Whether the body is covered by the signature; None: not stated."
    )
    source: str = Field(min_length=1, description=_SOURCE_DESCRIPTION)


class GatewayRoute(BaseModel):
    """A route exposed by the gateway (minimal form)."""

    model_config = {"frozen": True, "extra": "forbid"}

    name: str = Field(min_length=1, description="Route name, or its id when unnamed.")
    paths: tuple[str, ...] = Field(description="Paths the route exposes.")
    methods: tuple[str, ...] = Field(description="Allowed methods; empty means all.")
    backend: str | None = Field(
        description="Name of the backend the route sends to (same names as the other concepts)."
    )
    enabled: bool = Field(description="Whether the route is active.")
    source: str = Field(min_length=1, description=_SOURCE_DESCRIPTION)


class ConfigValue(BaseModel):
    """A text value of the gateway configuration, scanned for credentials."""

    model_config = {"frozen": True, "extra": "forbid"}

    kind: ConfigValueKind = Field(description="Type of object that holds the value.")
    location: str = Field(min_length=1, description="Which object, e.g. 'service forgejo-service'.")
    key: str = Field(min_length=1, description="Where the value is inside the object, e.g. 'url'.")
    value: SecretStr = Field(description="The text; shown masked unless asked for explicitly.")


class HealthCounters(BaseModel):
    """Successes and failures a gateway has observed for one target."""

    model_config = {"frozen": True, "extra": "forbid"}

    successes: int | None = Field(ge=0, description="Successful responses.")
    http_failures: int | None = Field(ge=0, description="HTTP failures.")
    tcp_failures: int | None = Field(ge=0, description="TCP failures.")
    timeouts: int | None = Field(ge=0, description="Timeouts.")


class TargetHealth(BaseModel):
    """Live health of one target of a backend."""

    model_config = {"frozen": True, "extra": "forbid"}

    backend: str = Field(min_length=1, description="Backend name.")
    target: str = Field(min_length=1, description="Target address, e.g. 'forgejo:3000'.")
    state: TargetState = Field(description="Current state.")
    counters: HealthCounters | None = Field(
        description="Observed counters, when the gateway gives them."
    )
