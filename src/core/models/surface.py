"""
src/core/models/surface.py

Attack surface models for the APIGuard Assurance tool.

Contains the OpenAPI-derived map of the target's exposed endpoints,
built during Phase 2 (OpenAPI Discovery) and stored immutably in
TargetContext for the entire pipeline run.

    ParameterInfo   -- Descriptor for a single declared parameter of an API operation.
    EndpointRecord  -- Structured descriptor for a single HTTP operation (path + method).
    AttackSurface   -- Structured map of all HTTP operations exposed by the target API.

Dependency rule: this module imports only from pydantic, the stdlib, and
sibling modules within src.core.models. It must never import from any other
src/ package.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from src.core.models.enums import SpecDialect

# ---------------------------------------------------------------------------
# ParameterInfo — single declared parameter of an API operation
# ---------------------------------------------------------------------------


class ParameterInfo(BaseModel):
    """Descriptor for a single declared parameter of an API operation."""

    model_config = {"frozen": True}

    name: str = Field(description="Parameter name as declared in the OpenAPI spec.")
    location: str = Field(description="'path', 'query', 'header', or 'cookie'. Stored lowercase.")
    required: bool = Field(default=False)
    schema_type: str | None = Field(default=None)
    schema_format: str | None = Field(default=None)


# ---------------------------------------------------------------------------
# EndpointRecord — single HTTP operation (path + method pair)
# ---------------------------------------------------------------------------


class EndpointRecord(BaseModel):
    """Structured descriptor for a single HTTP operation (path + method pair)."""

    model_config = {"frozen": True}

    path: str = Field(description="API path with template params, e.g. '/api/v1/users/{id}'.")
    method: str = Field(description="HTTP method, uppercase.")
    operation_id: str | None = Field(default=None)
    tags: list[str] = Field(default_factory=list)
    requires_auth: bool = Field(default=True)
    is_deprecated: bool = Field(default=False)
    parameters: list[ParameterInfo] = Field(default_factory=list)
    request_body_required: bool = Field(default=False)
    request_body_content_types: list[str] = Field(default_factory=list)

    @field_validator("method")
    @classmethod
    def method_must_be_uppercase(cls, value: str) -> str:
        """Normalize HTTP method to uppercase for consistent access."""
        return value.strip().upper()

    @field_validator("path")
    @classmethod
    def path_must_start_with_slash(cls, value: str) -> str:
        """Enforce absolute path format consistent with SecurityClient contract."""
        stripped = value.strip()
        if not stripped.startswith("/"):
            raise ValueError(f"EndpointRecord path must start with '/'. Got: '{stripped}'.")
        return stripped


# ---------------------------------------------------------------------------
# AttackSurface — OpenAPI-derived map of the target's exposed endpoints
# ---------------------------------------------------------------------------


class AttackSurface(BaseModel):
    """
    Structured map of all HTTP operations exposed by the target API.

    Built once during Phase 2 (OpenAPI Discovery) by discovery/surface.py
    and stored immutably in TargetContext for the entire pipeline run.
    Filter methods return new lists (copies), never internal views.
    """

    model_config = {"frozen": True}

    spec_title: str = Field(default="Unknown")
    spec_version: str = Field(default="Unknown")
    dialect: SpecDialect = Field(default=SpecDialect.OPENAPI_3)
    endpoints: list[EndpointRecord] = Field(default_factory=list)

    @property
    def total_endpoint_count(self) -> int:
        """Total number of (path, method) operations in the surface."""
        return len(self.endpoints)

    @property
    def unique_path_count(self) -> int:
        """Number of distinct paths, regardless of HTTP method."""
        return len({ep.path for ep in self.endpoints})

    @property
    def deprecated_count(self) -> int:
        """Number of operations marked deprecated in the spec."""
        return sum(1 for ep in self.endpoints if ep.is_deprecated)

    def get_authenticated_endpoints(self) -> list[EndpointRecord]:
        """Return all endpoints with at least one security requirement."""
        return [ep for ep in self.endpoints if ep.requires_auth]

    def get_public_endpoints(self) -> list[EndpointRecord]:
        """Return all publicly accessible endpoints."""
        return [ep for ep in self.endpoints if not ep.requires_auth]

    def get_deprecated_endpoints(self) -> list[EndpointRecord]:
        """Return all endpoints marked deprecated."""
        return [ep for ep in self.endpoints if ep.is_deprecated]

    def get_endpoints_by_method(self, method: str) -> list[EndpointRecord]:
        """Return all endpoints accepting a specific HTTP method."""
        return [ep for ep in self.endpoints if ep.method == method.strip().upper()]

    def get_endpoints_by_tag(self, tag: str) -> list[EndpointRecord]:
        """Return all endpoints annotated with a specific OpenAPI tag."""
        return [ep for ep in self.endpoints if tag in ep.tags]

    def get_endpoints_with_path_parameters(self) -> list[EndpointRecord]:
        """Return all endpoints with at least one path parameter."""
        return [ep for ep in self.endpoints if any(p.location == "path" for p in ep.parameters)]

    def find_endpoint(self, path: str, method: str) -> EndpointRecord | None:
        """Find a specific endpoint by exact path and method."""
        method_upper = method.strip().upper()
        for ep in self.endpoints:
            if ep.path == path and ep.method == method_upper:
                return ep
        return None
