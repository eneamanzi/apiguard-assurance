"""
src/core/context.py

Execution contexts for the APIGuard Assurance tool.

Two objects serve as the coordination axes for the entire assessment:

    TargetContext -- Immutable knowledge about the target API.
                     Created once during bootstrap from ToolConfig and AttackSurface.
                     Frozen: a test reading TargetContext has an absolute guarantee
                     that the data is identical to what every other test saw.
                     Answers the question: "What is the target?"

    TestContext   -- Mutable state accumulated during assessment execution.
                     Created empty at bootstrap and populated by tests as they run.
                     Holds JWT tokens acquired by authentication tests and the
                     registry of resources created during the assessment that must
                     be cleaned up during Phase 6 (Teardown).
                     Answers the question: "What have I discovered or done so far?"

The separation between these two contexts is the architectural guarantee that
a test cannot accidentally corrupt the base information read by all other tests
(TargetContext is frozen) while still being able to share discovered state with
dependent tests (TestContext is mutable via explicit typed interfaces).

Dependency rule: this module imports only from pydantic, stdlib, structlog, and
src.core.models. It must never import from config/, discovery/, tests/, or
report/ to avoid circular dependencies.
"""

from __future__ import annotations

import structlog
from pydantic import AnyHttpUrl, BaseModel, Field, PrivateAttr, computed_field

from src.core.models import AttackSurface

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Token role names used as keys in TestContext._tokens.
# Defined as constants to avoid magic strings scattered across test files.
ROLE_ADMIN: str = "admin"
ROLE_USER_A: str = "user_a"
ROLE_USER_B: str = "user_b"


# ---------------------------------------------------------------------------
# TargetContext — immutable knowledge about the target API
# ---------------------------------------------------------------------------


class TargetContext(BaseModel):
    """
    Immutable snapshot of all statically-known information about the target API.

    TargetContext is constructed once by engine.py during Phase 3 (Context
    Construction) and passed unchanged to every BaseTest.execute() call for
    the entire duration of the pipeline. The frozen configuration enforces
    this immutability at the type level: any attempt to set an attribute after
    construction raises a ValidationError.

    The admin_api_available computed field centralizes the check for WHITE_BOX
    test eligibility. A test that checks target.admin_api_available instead of
    target.admin_api_url is not None is more readable and semantically precise:
    it expresses capability, not implementation detail.
    """

    model_config = {"frozen": True}

    base_url: AnyHttpUrl = Field(
        description=(
            "Base URL of the target API as exposed through the Kong proxy. "
            "All test HTTP requests are constructed relative to this URL. "
            "Example: http://localhost:8000. "
            "Typed as AnyHttpUrl so that Pydantic validates the URL format at "
            "construction time. A malformed base_url is caught in Phase 1/3, "
            "not silently propagated to every test."
        )
    )
    openapi_spec_url: AnyHttpUrl = Field(
        description=(
            "URL from which the OpenAPI specification was fetched. "
            "Stored for traceability in the HTML report and evidence.json metadata. "
            "Example: http://localhost:8000/api/swagger"
        )
    )
    admin_api_url: AnyHttpUrl | None = Field(
        default=None,
        description=(
            "URL of the Kong Admin API, required for WHITE_BOX tests (P3). "
            "If None, all WHITE_BOX tests return SKIP with the reason: "
            "'Admin API not configured (target.admin_api_url missing from config.yaml)'. "
            "Example: http://localhost:8001"
        ),
    )
    attack_surface: AttackSurface | None = Field(
        default=None,
        description=(
            "AttackSurface instance built by discovery/surface.py from the "
            "dereferenced OpenAPI spec. None only during the brief window "
            "between TargetContext construction and the completion of Phase 2. "
            "Every test that calls execute() is guaranteed to receive a "
            "TargetContext where attack_surface is fully populated."
        ),
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def admin_api_available(self) -> bool:
        """
        True if the Kong Admin API URL is configured.

        WHITE_BOX tests check this property before attempting any Admin API
        call. A False value causes the test to return SKIP immediately,
        which is semantically correct: the capability is absent, not broken.
        """
        return self.admin_api_url is not None

    def endpoint_base_url(self) -> str:
        """
        Return base_url as a plain string suitable for URL construction.

        Pydantic v2's AnyHttpUrl is a Url object, not a str. Tests must use
        this method when building request URLs via string concatenation or
        f-strings to avoid double-slash artifacts:

            url = f"{target.endpoint_base_url()}/api/v1/users/me"

        Returns:
            str: The base URL without trailing slash.
        """
        return str(self.base_url).rstrip("/")

    def admin_endpoint_base_url(self) -> str | None:
        """
        Return admin_api_url as a plain string, or None if not configured.

        WHITE_BOX tests use this method to construct Admin API request URLs.
        Returns None rather than raising so that callers can guard with a
        simple None check instead of catching an exception.

        Returns:
            str: The admin API base URL without trailing slash, or None.
        """
        if self.admin_api_url is None:
            return None
        return str(self.admin_api_url).rstrip("/")


# ---------------------------------------------------------------------------
# TestContext — mutable state accumulated during assessment
# ---------------------------------------------------------------------------


class TestContext(BaseModel):
    """
    Mutable state container for data discovered or produced during execution.

    TestContext is created empty at bootstrap (Phase 3) and lives for the
    entire duration of the pipeline. It accumulates two categories of state:

    1. JWT tokens acquired by authentication tests (Domain 1).
       These tokens are consumed by subsequent Domain 2, 3, 4, 5, 6, 7 tests
       that require an authenticated context. The token store uses role-based
       keys (ROLE_ADMIN, ROLE_USER_A, ROLE_USER_B) rather than test IDs,
       because multiple tests may consume the same token.

    2. Resources created during test execution (e.g., POST /api/v1/repos).
       Each resource is registered with its cleanup endpoint at creation time.
       The engine drains this registry during Phase 6 (Teardown) in LIFO order.

    Both categories are stored in PrivateAttr fields, which Pydantic v2
    excludes from serialization, validation, and the public model interface.
    Tests interact exclusively through the typed methods below.
    """

    _tokens: dict[str, str] = PrivateAttr(default_factory=dict)
    _resources: list[tuple[str, str]] = PrivateAttr(default_factory=list)

    # ------------------------------------------------------------------
    # Token interface
    # ------------------------------------------------------------------

    def set_token(self, role: str, token: str) -> None:
        """
        Store a JWT token for the given role.

        Called by Domain 1 authentication tests after a successful login.
        Overwrites any previously stored token for the same role, which is
        the correct behavior for token rotation scenarios (test 1.4).

        The token value is stored as a raw string WITHOUT the 'Bearer ' prefix.
        Tests that construct Authorization headers must add the prefix:
            headers = {"Authorization": f"Bearer {context.get_token(ROLE_ADMIN)}"}

        Args:
            role: Role identifier. Use ROLE_* constants from this module.
            token: Raw JWT token string. Must not be empty.

        Raises:
            ValueError: If role or token is empty after stripping whitespace.
        """
        role_stripped = role.strip()
        token_stripped = token.strip()

        if not role_stripped:
            raise ValueError("Token role must not be empty or whitespace-only.")
        if not token_stripped:
            raise ValueError(
                f"Token value for role '{role_stripped}' must not be empty. "
                "Storing an empty token would cause subsequent tests to send "
                "invalid Authorization headers silently."
            )

        self._tokens[role_stripped] = token_stripped
        log.debug("token_stored", role=role_stripped, token_preview="[REDACTED]")  # noqa: S106

    def get_token(self, role: str) -> str | None:
        """
        Retrieve the JWT token stored for the given role.

        Returns None if no token has been stored for the role. This is the
        expected condition when a prerequisite test has not run or has returned
        SKIP/ERROR. Callers must handle the None case explicitly and return
        a TestResult(status=SKIP) with a descriptive skip_reason.

        Args:
            role: Role identifier matching the key used in set_token().

        Returns:
            Raw JWT token string, or None if not present.
        """
        return self._tokens.get(role.strip())

    def has_token(self, role: str) -> bool:
        """
        Check whether a token is available for the given role.

        Args:
            role: Role identifier to check.

        Returns:
            True if a non-empty token is stored for this role.
        """
        return role.strip() in self._tokens

    def stored_roles(self) -> list[str]:
        """
        Return the list of role names for which tokens are currently stored.

        Used by the engine and report builder for diagnostic logging.
        Does not expose token values.

        Returns:
            List of role name strings in insertion order.
        """
        return list(self._tokens.keys())

    # ------------------------------------------------------------------
    # Teardown resource interface
    # ------------------------------------------------------------------

    def register_resource_for_teardown(self, method: str, path: str) -> None:
        """
        Register a resource for cleanup during Phase 6 (Teardown).

        Must be called immediately after successfully creating a persistent
        resource. Registration must happen before any subsequent assertions
        in the same test, so that cleanup is guaranteed even if a later
        assertion raises an exception that causes execute() to return ERROR.

        Args:
            method: HTTP method for the cleanup request, uppercase.
                    Typically 'DELETE'. Stored uppercase regardless of input.
            path:   Absolute API path including the resource ID.
                    Example: '/api/v1/repos/user-a/test-repo-1234'.
                    Must start with '/'.

        Raises:
            ValueError: If method or path is empty, or path does not start with '/'.
        """
        method_upper = method.strip().upper()
        path_stripped = path.strip()

        if not method_upper:
            raise ValueError("Teardown method must not be empty.")
        if not path_stripped:
            raise ValueError("Teardown resource path must not be empty.")
        if not path_stripped.startswith("/"):
            raise ValueError(f"Teardown resource path must start with '/'. Got: '{path_stripped}'.")

        self._resources.append((method_upper, path_stripped))
        log.debug(
            "resource_registered_for_teardown",
            method=method_upper,
            path=path_stripped,
            total_registered=len(self._resources),
        )

    def drain_resources(self) -> list[tuple[str, str]]:
        """
        Return all registered resources in LIFO order and clear the registry.

        Called once by the engine at the start of Phase 6 (Teardown).
        LIFO ordering ensures that resources with implicit creation dependencies
        are deleted in the correct reverse order (e.g., repository before user).

        The internal list is cleared after draining, so that a second call
        returns an empty list rather than attempting to delete already-cleaned
        resources.

        Returns:
            List of (method, path) tuples in LIFO order.
            Empty list if no resources were registered.
        """
        if not self._resources:
            log.debug("teardown_drain_called_with_empty_registry")
            return []

        lifo_ordered = list(reversed(self._resources))
        resource_count = len(lifo_ordered)
        self._resources.clear()

        log.info(
            "teardown_registry_drained",
            resource_count=resource_count,
            order="LIFO",
        )
        return lifo_ordered

    def registered_resource_count(self) -> int:
        """
        Return the number of resources currently pending teardown.

        Returns:
            int: Count of pending teardown registrations.
        """
        return len(self._resources)
