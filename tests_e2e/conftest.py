"""
tests_e2e/conftest.py

Shared fixtures for the APIGuard Assurance End-to-End test suite.

Design principles
-----------------
Every fixture in this file represents a real system state — no mocks, no
in-memory fakes. When a fixture requires a live network connection (e.g.,
to fetch the Forgejo OpenAPI spec), it will skip the test automatically if
the target is unreachable rather than failing with a confusing connection error.

The "skip on unavailability" pattern is implemented via a dedicated
connectivity check fixture (_assert_target_reachable) that every test which
requires a live target depends on. This separates the concern of "is the
infrastructure up?" from the concern of "does the tool behave correctly?".

Fixture scoping
---------------
- ``session`` scope: objects that are expensive to build (real HTTP fetch,
  real spec parsing) and safe to share because they are read-only after
  construction (ToolConfig, AttackSurface).
- ``function`` scope (default): objects that accumulate mutable state during
  test execution (SecurityClient, EvidenceStore) and must be fresh per test.

Environment requirements
------------------------
The target Docker stack must be running before executing this suite:
    docker compose up -d
    # Wait for all services to be healthy before running tests.

Credentials are loaded from .env in the project root via python-dotenv.
The .env file must define:
    ADMIN_USERNAME, ADMIN_PASSWORD
    USER_A_USERNAME, USER_A_PASSWORD
    USER_B_USERNAME, USER_B_PASSWORD
"""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import httpx
import pytest
import structlog
from dotenv import load_dotenv
from src.config.loader import load_config
from src.config.schema import ToolConfig
from src.core.client import SecurityClient
from src.core.context import TargetContext
from src.core.evidence import EvidenceStore
from src.core.models import AttackSurface
from src.discovery.openapi import load_openapi_spec
from src.discovery.surface import build_attack_surface

load_dotenv()
log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Absolute path to config.yaml at the project root.
# Resolved relative to this file's location (tests_e2e/ -> project root).
_PROJECT_ROOT: Path = Path(__file__).parent.parent
CONFIG_YAML_PATH: Path = _PROJECT_ROOT / "config.yaml"

# Connectivity check timeout: if Kong does not respond within this interval,
# the target infrastructure is considered unavailable and all E2E tests are
# skipped with a clear message.
CONNECTIVITY_CHECK_TIMEOUT_SECONDS: float = 5.0


# ---------------------------------------------------------------------------
# Infrastructure availability guard
# ---------------------------------------------------------------------------


def _is_target_reachable(base_url: str) -> bool:
    """
    Perform a lightweight HTTP HEAD request to verify target reachability.

    Uses the root path ("/") rather than a specific API endpoint to avoid
    triggering any authentication logic or side effects. We only care whether
    the TCP connection can be established and a response received.

    Args:
        base_url: The base URL to probe (e.g. "http://localhost:8000").

    Returns:
        True if the target responds to any HTTP method within the timeout.
        False on any connection error or timeout.
    """
    probe_url = base_url.rstrip("/") + "/"
    try:
        with httpx.Client(timeout=CONNECTIVITY_CHECK_TIMEOUT_SECONDS) as client:
            client.get(probe_url)
        return True
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Session-scoped fixtures (built once per test session)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def e2e_config() -> ToolConfig:
    """
    Load the real ToolConfig from config.yaml and the .env file.

    Session-scoped because ToolConfig is frozen and identical across all
    tests in the session. Loading it once avoids redundant file I/O.

    Skips the entire session if config.yaml is not found, producing a clear
    diagnostic message rather than a confusing FileNotFoundError cascade.
    """
    if not CONFIG_YAML_PATH.exists():
        pytest.skip(
            f"config.yaml not found at '{CONFIG_YAML_PATH}'. "
            "Create it from the project root before running E2E tests."
        )

    config = load_config(CONFIG_YAML_PATH)
    log.info(
        "e2e_config_loaded",
        base_url=str(config.target.base_url),
        openapi_spec_url=str(config.target.openapi_spec_url),
    )
    return config


@pytest.fixture(scope="session")
def e2e_target_reachable(e2e_config: ToolConfig) -> None:
    """
    Guard fixture: skip all dependent tests if the target is unreachable.

    This fixture is a prerequisite for every E2E test that requires a live
    network connection. It checks Kong proxy reachability once per session
    and skips if the infrastructure is not running.

    Usage in a test:

        def test_something(e2e_target_reachable, e2e_config):
            ...

    The fixture has no return value: its sole purpose is to gate access.
    """
    base_url = str(e2e_config.target.base_url).rstrip("/")

    if not _is_target_reachable(base_url):
        pytest.skip(
            f"Target is unreachable at '{base_url}'. "
            "Start the Docker stack with 'docker compose up -d' and wait "
            "for all services to reach the 'healthy' state before retrying."
        )

    log.info("e2e_target_reachability_confirmed", base_url=base_url)


@pytest.fixture(scope="session")
def e2e_attack_surface(
    e2e_config: ToolConfig,
    e2e_target_reachable: None,
) -> AttackSurface:
    """
    Fetch and parse the real OpenAPI specification from the live target.

    This is the most expensive E2E fixture: it performs a real HTTP fetch
    of the Forgejo Swagger spec and runs the full prance dereferencing and
    surface-building pipeline. Session-scoped so the fetch happens once.

    The result is a real AttackSurface populated with Forgejo's actual
    endpoints — used by tests to verify that the discovery pipeline produces
    meaningful, non-trivial output.

    Skips if the spec URL is unreachable (separate from Kong reachability:
    the spec is fetched from Forgejo directly on port 3000).
    """
    spec_url = str(e2e_config.target.openapi_spec_url)
    log.info("e2e_fetching_openapi_spec", spec_url=spec_url)

    spec, dialect = load_openapi_spec(spec_url)
    surface = build_attack_surface(spec, dialect)

    log.info(
        "e2e_attack_surface_built",
        spec_title=surface.spec_title,
        spec_version=surface.spec_version,
        dialect=surface.dialect,
        total_endpoints=surface.total_endpoint_count,
        unique_paths=surface.unique_path_count,
    )
    return surface


@pytest.fixture(scope="session")
def e2e_target_context(
    e2e_config: ToolConfig,
    e2e_attack_surface: AttackSurface,
) -> TargetContext:
    """
    Build a real TargetContext from the live configuration and attack surface.

    Session-scoped because TargetContext is frozen and shared safely.
    """
    return TargetContext(
        base_url=e2e_config.target.base_url,
        openapi_spec_url=e2e_config.target.openapi_spec_url,
        admin_api_url=e2e_config.target.admin_api_url,
        attack_surface=e2e_attack_surface,
    )


# ---------------------------------------------------------------------------
# Function-scoped fixtures (fresh per test)
# ---------------------------------------------------------------------------


@pytest.fixture
def e2e_evidence_store() -> EvidenceStore:
    """Return a fresh EvidenceStore for each test."""
    return EvidenceStore()


@pytest.fixture
def e2e_client(
    e2e_config: ToolConfig, e2e_target_reachable: None
) -> Generator[SecurityClient, None, None]:
    """
    Return an open SecurityClient configured for the real target.

    Function-scoped because SecurityClient maintains a sequence counter
    and an open httpx connection pool. Using a single instance across
    multiple tests would cause record_id collisions.

    The client is NOT used as a context manager here: the fixture yields
    inside a context manager block so that the httpx session is properly
    closed after the test completes, even on failure.

    Usage in a test:

        def test_something(e2e_client):
            response, record = e2e_client.request("GET", "/api/v1/repos/search", test_id="e2e")
    """
    base_url = str(e2e_config.target.base_url).rstrip("/")
    with SecurityClient(
        base_url=base_url,
        connect_timeout=e2e_config.execution.connect_timeout,
        read_timeout=e2e_config.execution.read_timeout,
        max_retry_attempts=e2e_config.execution.max_retry_attempts,
    ) as client:
        yield client
