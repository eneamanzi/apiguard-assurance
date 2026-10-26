"""
src/core/models/surface.py

Attack surface models for the APIGuard Assurance tool.

Contains the OpenAPI-derived map of the target's exposed endpoints,
built during Phase 2 (OpenAPI Discovery) and stored immutably in
TargetContext for the entire pipeline run.

    ParameterInfo        -- Descriptor for a single declared parameter of an API operation.
    EndpointRecord       -- Structured descriptor for a single HTTP operation (path + method).
    SecuritySchemeRecord -- One authentication scheme declared by the specification.
    AttackSurface        -- Structured map of all HTTP operations exposed by the target API.

Dependency rule: this module imports only from pydantic, the stdlib, and
sibling modules within src.core.models. It must never import from any other
src/ package.
"""

from __future__ import annotations

from enum import StrEnum

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
    required: bool = Field(
        default=False, description="True if the parameter is marked required in the spec."
    )
    schema_type: str | None = Field(
        default=None,
        description="JSON schema type (e.g. 'string', 'integer'); None if unspecified.",
    )
    schema_format: str | None = Field(
        default=None,
        description="JSON schema format (e.g. 'uuid', 'date-time'); None if unspecified.",
    )


# ---------------------------------------------------------------------------
# EndpointRecord — single HTTP operation (path + method pair)
# ---------------------------------------------------------------------------


class AuthDeclaration(StrEnum):
    """
    Where an operation's security requirement is declared.

    The OpenAPI inheritance rule is the same in both dialects: an operation
    that declares `security` (even `[]`) states its own requirement, and one
    that does not inherits the document's. The two are not worth the same to a
    test: the first is a statement about that operation, the second is a
    default that may never have been thought about (test 1.1 sets the
    confidence of its findings from it; measured 2026-10-22: crAPI declares
    per operation, Forgejo declares only globally for all 473 of them).

    OPERATION -- the operation declares `security` itself.
    DOCUMENT  -- it inherits the document's global `security`.
    """

    OPERATION = "OPERATION"
    DOCUMENT = "DOCUMENT"


class EndpointRecord(BaseModel):
    """Structured descriptor for a single HTTP operation (path + method pair)."""

    model_config = {"frozen": True}

    path: str = Field(description="API path with template params, e.g. '/api/v1/users/{id}'.")
    method: str = Field(description="HTTP method, uppercase.")
    operation_id: str | None = Field(
        default=None,
        description="Spec-declared operationId; None if the spec omits it.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="OpenAPI tags assigned to the operation; used for grouping.",
    )
    requires_auth: bool = Field(
        default=True,
        description="True if a security requirement applies to the operation.",
    )
    auth_declaration: AuthDeclaration = Field(
        default=AuthDeclaration.DOCUMENT,
        description=(
            "Where that requirement is declared: `OPERATION` when the operation declares "
            "`security` itself (even `[]`), `DOCUMENT` when it inherits the global one."
        ),
    )
    is_deprecated: bool = Field(
        default=False,
        description="True if the operation is marked 'deprecated: true' in the spec.",
    )
    parameters: list[ParameterInfo] = Field(
        default_factory=list,
        description="All declared parameters (path, query, header, cookie).",
    )
    request_body_required: bool = Field(
        default=False,
        description="True if requestBody.required is true in the spec.",
    )
    request_body_content_types: list[str] = Field(
        default_factory=list,
        description="MIME types declared in requestBody.content (e.g. 'application/json').",
    )

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
# SecuritySchemeRecord - authentication scheme declared by the specification
# ---------------------------------------------------------------------------


class SecuritySchemeType(StrEnum):
    """
    Type of a declared security scheme, with the OpenAPI 3 names.

    Swagger 2.0 'basic' is recorded as HTTP with http_scheme 'basic'.
    """

    API_KEY = "apiKey"
    HTTP = "http"
    OAUTH2 = "oauth2"
    OPENID_CONNECT = "openIdConnect"
    MUTUAL_TLS = "mutualTLS"


class SecuritySchemeRecord(BaseModel):
    """
    One authentication scheme declared by the specification.

    Read from components.securitySchemes (OpenAPI 3) or securityDefinitions
    (Swagger 2.0). It tells where and how a credential is sent: an apiKey in
    a header, query parameter or cookie with a given name; an HTTP scheme
    (basic, bearer) in the Authorization header; OAuth 2.0 and OpenID Connect
    as a bearer token.
    """

    model_config = {"frozen": True}

    name: str = Field(description="Name of the scheme in the specification, e.g. 'bearerAuth'.")
    scheme_type: SecuritySchemeType = Field(description="Type of the scheme.")
    location: str | None = Field(
        default=None,
        description="apiKey only: 'header', 'query' or 'cookie'. Stored lowercase.",
    )
    parameter_name: str | None = Field(
        default=None,
        description="apiKey only: name of the header, query parameter or cookie.",
    )
    http_scheme: str | None = Field(
        default=None,
        description="HTTP only: the scheme, e.g. 'basic' or 'bearer'. Stored lowercase.",
    )
    description: str | None = Field(
        default=None,
        description="Free text of the specification (may describe a prefix in words).",
    )


# ---------------------------------------------------------------------------
# AttackSurface — OpenAPI-derived map of the target's exposed endpoints
# ---------------------------------------------------------------------------


class DerivationBasis(StrEnum):
    """
    How a derived fact was obtained from the specification (topic 4, precedence).

    DECLARED  -- the specification states it (`deprecated: true`, `format: uri`,
                 a request schema, an `example`).
    HEURISTIC -- a named rule infers it (an `admin` path segment, version
                 siblings): a finding resting on it is at most TENTATIVE.
    """

    DECLARED = "DECLARED"
    HEURISTIC = "HEURISTIC"


class DerivedFact(BaseModel):
    """
    One thing the tool derived from the specification, before any test ran.

    Produced by the named rules of src/discovery/derivation.py in Phase 2; the
    tests read them from AttackSurface.derived; the report lists them, so that
    a reader sees what was derived and can correct it in the configuration
    (which always prevails, topic 4).
    """

    model_config = {"frozen": True}

    rule: str = Field(description="The rule that produced the fact, e.g. `service_prefixes`.")
    basis: DerivationBasis = Field(description="`DECLARED` or `HEURISTIC`.")
    method: str | None = Field(
        default=None, description="The endpoint's method; null for a fact about the whole API."
    )
    path: str | None = Field(
        default=None, description="The endpoint's path; null for a fact about the whole API."
    )
    value: str = Field(description="What was derived, e.g. `/identity/api`.")
    note: str = Field(default="", description="Why, in a few words (the evidence in the spec).")


class AttackSurface(BaseModel):
    """
    Structured map of all HTTP operations exposed by the target API.

    Built once during Phase 2 (OpenAPI Discovery) by discovery/surface.py
    and stored immutably in TargetContext for the entire pipeline run.
    Filter methods return new lists (copies), never internal views.
    """

    model_config = {"frozen": True}

    spec_title: str = Field(
        default="Unknown",
        description="OpenAPI 'info.title' field; 'Unknown' if spec lacked it.",
    )
    spec_version: str = Field(
        default="Unknown",
        description="OpenAPI 'info.version' field; 'Unknown' if spec lacked it.",
    )
    dialect: SpecDialect = Field(
        default=SpecDialect.OPENAPI_3,
        description="OpenAPI dialect detected from the spec (OAS 3.0.x / 3.1.x / Swagger 2.0).",
    )
    endpoints: list[EndpointRecord] = Field(
        default_factory=list,
        description="All (path, method) operations declared in the spec.",
    )
    security_schemes: list[SecuritySchemeRecord] = Field(
        default_factory=list,
        description="Authentication schemes declared by the spec, in declaration order.",
    )
    derived: list[DerivedFact] = Field(
        default_factory=list,
        description=(
            "What the tool derived from the specification by its named rules (Phase 2): "
            "facts about endpoints or about the whole API, each with its rule and basis."
        ),
    )

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

    def derived_facts(self, rule: str | None = None) -> list[DerivedFact]:
        """
        The facts derived from the specification (Phase 2, src/discovery/derivation.py).

        Args:
            rule: Only the facts of this rule; None for all.

        Returns:
            The facts, in the order the rules produced them.
        """
        return [fact for fact in self.derived if rule is None or fact.rule == rule]

    def derived_for(self, method: str, path: str) -> list[DerivedFact]:
        """The facts derived about one endpoint (method and template path)."""
        return [f for f in self.derived if f.method == method.upper() and f.path == path]

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
