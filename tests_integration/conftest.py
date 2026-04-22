"""
tests_integration/conftest.py

Shared pytest fixtures for the APIGuard Assurance integration test suite.

Design rationale
----------------
This suite follows the "Executable Documentation" pattern: every test is also
a precise specification of the contract that a component must honour. Fixtures
here represent canonical, well-understood states of the system — they are the
baselines against which assertions are made.

No network connections are opened in this suite. Components that ultimately
require a live target (SecurityClient, full pipeline runs) are tested by
constructing the minimal in-memory state they depend on, bypassing the
transport layer.

Fixture scoping strategy
------------------------
- ``session`` scope: objects that are expensive to build and identical across
  all tests (e.g. the canonical AttackSurface derived from the reference spec).
- ``function`` scope (default): objects that tests might mutate (e.g. TestContext,
  temporary config files).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import AnyHttpUrl, TypeAdapter
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import AttackSurface, SpecDialect
from src.discovery.surface import build_attack_surface

# ---------------------------------------------------------------------------
# URL construction helper
# ---------------------------------------------------------------------------
# Pydantic v2 AnyHttpUrl is a Url object, not a str subclass.  Passing a
# bare string literal to an AnyHttpUrl parameter is valid at runtime
# (Pydantic coerces it) but fails static analysis (Pylance / mypy).
# Use _url() wherever a fixture or test needs to build an AnyHttpUrl from
# a string literal.

_URL_ADAPTER: TypeAdapter[AnyHttpUrl] = TypeAdapter(AnyHttpUrl)


def _url(raw: str) -> AnyHttpUrl:
    """Parse a raw URL string into a validated AnyHttpUrl for type-safe fixtures.

    Wraps TypeAdapter.validate_python so that callers do not need to
    instantiate the adapter themselves, and so that the type checker
    correctly infers the return type as AnyHttpUrl rather than str.
    """
    return _URL_ADAPTER.validate_python(raw)


# ---------------------------------------------------------------------------
# Canonical inline OpenAPI 3.0 spec
# ---------------------------------------------------------------------------
# This dict represents a minimal but structurally complete OpenAPI 3.0 spec.
# It is used as the ground-truth fixture for all AttackSurface and Discovery
# tests. Every field that is inspected by any test must be present here.
#
# Design constraints:
#   - One public endpoint (no security requirement):    GET /health
#   - One authenticated endpoint (bearer JWT):         GET /api/v1/users/me
#   - One deprecated endpoint (with Sunset in spec):   DELETE /api/v1/users/{id}
#   - One endpoint with a path parameter:              DELETE /api/v1/users/{id}
#   - One POST endpoint with request body:             POST /api/v1/users
#
# This set is deliberately minimal: it exercises every filter method on
# AttackSurface without inflating the fixture with irrelevant operations.

REFERENCE_SPEC: dict[str, object] = {
    "openapi": "3.0.3",
    "info": {
        "title": "APIGuard Reference API",
        "version": "1.0.0",
    },
    "paths": {
        "/health": {
            "get": {
                "operationId": "health_check",
                "summary": "Public health check endpoint",
                "tags": ["health"],
                "responses": {"200": {"description": "Service is healthy"}},
            }
        },
        "/api/v1/users/me": {
            "get": {
                "operationId": "get_current_user",
                "summary": "Retrieve the authenticated user's profile",
                "tags": ["users"],
                "security": [{"bearerAuth": []}],
                "responses": {
                    "200": {"description": "User profile"},
                    "401": {"description": "Unauthorized"},
                },
            }
        },
        "/api/v1/users": {
            "post": {
                "operationId": "create_user",
                "summary": "Create a new user account",
                "tags": ["users"],
                "security": [{"bearerAuth": []}],
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["username", "email"],
                                "properties": {
                                    "username": {"type": "string"},
                                    "email": {"type": "string", "format": "email"},
                                },
                            }
                        }
                    },
                },
                "responses": {"201": {"description": "User created"}},
            }
        },
        "/api/v1/users/{id}": {
            "delete": {
                "operationId": "delete_user",
                "summary": "Delete a user account (deprecated — use /api/v2/users/{id})",
                "deprecated": True,
                "tags": ["users"],
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string", "format": "uuid"},
                    }
                ],
                "responses": {
                    "204": {"description": "User deleted"},
                    "410": {"description": "Endpoint deprecated and removed"},
                },
            }
        },
    },
    "components": {
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            }
        }
    },
}

# Expected counts derived from REFERENCE_SPEC — used as constants in assertions
# so that a change to the fixture triggers a clear, localized test failure rather
# than a cryptic assertion mismatch buried in a test body.
EXPECTED_TOTAL_ENDPOINTS: int = 4
EXPECTED_AUTHENTICATED_ENDPOINTS: int = 3  # /me, /users POST, /users/{id} DELETE
EXPECTED_PUBLIC_ENDPOINTS: int = 1  # /health
EXPECTED_DEPRECATED_ENDPOINTS: int = 1  # DELETE /api/v1/users/{id}
EXPECTED_SPEC_TITLE: str = "APIGuard Reference API"
EXPECTED_SPEC_VERSION: str = "1.0.0"


# ---------------------------------------------------------------------------
# AttackSurface fixture (session scope)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def reference_surface() -> AttackSurface:
    """
    Build an AttackSurface from the canonical REFERENCE_SPEC.

    Session-scoped because the surface is immutable (frozen Pydantic model):
    sharing a single instance across all tests is both correct and efficient.

    This fixture exercises the full build_attack_surface() code path, making
    it a dependency test in its own right: if this fixture fails to construct,
    all tests that depend on it are collected as errors, immediately surfacing
    a regression in the discovery layer.
    """
    return build_attack_surface(spec=REFERENCE_SPEC, dialect=SpecDialect.OPENAPI_3)


# ---------------------------------------------------------------------------
# TargetContext fixture (function scope)
# ---------------------------------------------------------------------------


@pytest.fixture
def reference_target(reference_surface: AttackSurface) -> TargetContext:
    """
    Construct a TargetContext backed by the reference AttackSurface.

    Function-scoped because TargetContext holds URLs that tests might want
    to vary between test cases (e.g. with/without admin_api_url).

    The admin_api_url is intentionally omitted here: tests that need WHITE_BOX
    capability should build their own TargetContext with admin_api_url set.
    This fixture represents the most common assessment configuration:
    Black + Grey Box, no Admin API access.
    """
    return TargetContext(
        base_url=_url("http://localhost:8000"),
        openapi_spec_url=_url("http://localhost:3000/swagger.v1.json"),
        admin_api_url=None,
        attack_surface=reference_surface,
    )


# ---------------------------------------------------------------------------
# TestContext fixture (function scope)
# ---------------------------------------------------------------------------


@pytest.fixture
def empty_test_context() -> TestContext:
    """
    Return a freshly initialised, empty TestContext.

    Always function-scoped: TestContext accumulates JWT tokens and resource
    registry entries as tests run. Sharing a context between tests would
    cause phantom token availability and resource leak false-negatives.
    """
    return TestContext()


# ---------------------------------------------------------------------------
# EvidenceStore fixture (function scope)
# ---------------------------------------------------------------------------


@pytest.fixture
def evidence_store(tmp_path: Path) -> EvidenceStore:
    """
    Return a fresh EvidenceStore backed by a temporary directory.

    Uses pytest's built-in tmp_path fixture so each test gets an isolated
    directory that is removed automatically after the test completes.
    Function-scoped for the same reason as TestContext: test isolation
    requires that one test's evidence does not bleed into another's store.
    """
    return EvidenceStore(tmp_dir=tmp_path / "evidence_tmp")


# ---------------------------------------------------------------------------
# Temporary config file factory
# ---------------------------------------------------------------------------


@pytest.fixture
def minimal_config_file(tmp_path: Path) -> Path:
    """
    Write a minimal valid config.yaml to a temporary directory and return its path.

    This fixture deliberately avoids ${VAR_NAME} placeholders so that tests
    can call load_config() without setting up environment variables. Tests
    that specifically exercise env-var interpolation should write their own
    config content using tmp_path directly.

    The returned config uses localhost URLs and default execution parameters.
    It is a valid ToolConfig in every dimension checked by Pydantic validation.
    """
    config_content = """\
target:
  base_url: "http://localhost:8000"
  openapi_spec_url: "http://localhost:3000/swagger.v1.json"

execution:
  min_priority: 3
  strategies:
    - BLACK_BOX
  fail_fast: false

output:
  directory: "outputs"
"""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(config_content, encoding="utf-8")
    return config_path
