"""
src/tests/helpers/forgejo_resources.py

Forgejo resource creation helper for GREY_BOX tests that require persistent
objects (repositories, issues) to exist before the test logic runs.

Responsibility
--------------
Each function in this module creates a single Forgejo resource via the
Forgejo API, registers it for Phase 6 teardown in the TestContext, and
returns the full response body as a typed dict so the calling test can
extract identifiers (full_name, number, id) for subsequent requests.

Contract
--------
Every create_* function follows the same contract:

    1. Build the Authorization header from context.get_token(role).
    2. POST to the appropriate Forgejo API endpoint.
    3. Raise ForgejoResourceError on unexpected HTTP status codes.
    4. Call context.register_resource_for_teardown() immediately after a
       successful creation, before any further logic that could raise.
    5. Return the response body dict to the caller.

The teardown path for Forgejo resources (repos, issues) uses the Bearer
token stored in the TestContext — not Basic Auth — because the Gateway
forwards the Bearer token to the Forgejo backend, which applies ownership
authorization internally.  This is why repository and issue teardown
registrations do NOT include explicit headers (unlike token deletion in
auth.py).

Naming convention
-----------------
All created resources use a name prefixed with 'apiguard-' followed by a
secrets.token_hex(4) suffix to avoid collisions across assessment runs.

Dependency rule
---------------
This module imports from:
    - stdlib: secrets
    - src.core.client, src.core.context, src.core.exceptions, src.core.models
It must never import from src.tests.domain_* or src.engine.
"""

from __future__ import annotations

import secrets
from typing import Any

import structlog
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.exceptions import ToolBaseError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Resource name prefix for all objects created by this helper.
_RESOURCE_NAME_PREFIX: str = "apiguard"

# Number of random bytes for the name suffix (4 bytes = 8 hex chars).
_NAME_SUFFIX_BYTES: int = 4

# Forgejo API paths.
_FORGEJO_USER_REPOS_PATH: str = "/api/v1/user/repos"
_FORGEJO_REPO_PATH_TEMPLATE: str = "/api/v1/repos/{owner}/{repo}"
_FORGEJO_ISSUES_PATH_TEMPLATE: str = "/api/v1/repos/{owner}/{repo}/issues"
_FORGEJO_ISSUE_PATH_TEMPLATE: str = "/api/v1/repos/{owner}/{repo}/issues/{index}"
_FORGEJO_USER_INFO_PATH: str = "/api/v1/user"
_FORGEJO_REPOS_SEARCH_PATH: str = "/api/v1/repos/search"

# Expected HTTP status codes.
_CREATED_STATUS: int = 201
_OK_STATUS: int = 200
_ACCEPTED_STATUSES: frozenset[int] = frozenset({_OK_STATUS, _CREATED_STATUS})


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------


class ForgejoResourceError(ToolBaseError):
    """
    Raised when a Forgejo resource creation request returns an unexpected
    HTTP status code.

    Distinct from SecurityClientError (transport failure) and
    AuthenticationSetupError (credential rejection).  This exception covers
    cases where the HTTP connection succeeded and a response was received,
    but the response indicates an application-level error (e.g. 422 Unprocessable
    Entity when a repository name already exists, or 404 when a user does not
    exist).

    The calling test must catch this and return TestResult(status=ERROR).
    """

    def __init__(
        self,
        message: str,
        path: str | None = None,
        status_code: int | None = None,
    ) -> None:
        """
        Initialize a Forgejo resource error.

        Args:
            message:     Human-readable description of the failure.
            path:        API path that returned the unexpected status.
            status_code: HTTP status code received.
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
# Public API
# ---------------------------------------------------------------------------


def get_authenticated_user(
    target: TargetContext,
    context: TestContext,
    client: SecurityClient,
    role: str,
) -> dict[str, Any]:
    """
    Fetch and return the Forgejo user record for the given role.

    Calls GET /api/v1/user with the Bearer token stored in the TestContext
    for the specified role.  Used by tests that need to know the username
    associated with a role before constructing resource paths.

    Args:
        target:  Immutable target context carrying base_url.
        context: Mutable test context providing the Bearer token for the role.
        client:  Centralized HTTP client.
        role:    Role identifier (e.g. ROLE_USER_A).  Must have a token stored
                 in context.

    Returns:
        Forgejo user dict including at minimum: 'id' (int), 'login' (str).

    Raises:
        ForgejoResourceError: If the API returns a non-200 status.
        SecurityClientError:  On transport failure.
    """
    token = _require_token(context, role)
    headers = _bearer_headers(token)

    response, _ = client.request(
        method="GET",
        path=_FORGEJO_USER_INFO_PATH,
        test_id="helper_get_user",
        headers=headers,
    )

    if response.status_code != _OK_STATUS:
        raise ForgejoResourceError(
            message=(
                f"GET {_FORGEJO_USER_INFO_PATH} returned HTTP {response.status_code} "
                f"for role '{role}'. Expected {_OK_STATUS}."
            ),
            path=_FORGEJO_USER_INFO_PATH,
            status_code=response.status_code,
        )

    user_data: dict[str, Any] = response.json()
    log.debug(
        "forgejo_helper_user_fetched",
        role=role,
        username=user_data.get("login"),
        user_id=user_data.get("id"),
    )
    return user_data


def create_repository(
    target: TargetContext,
    context: TestContext,
    client: SecurityClient,
    role: str,
    description: str = "APIGuard assessment test repository",
    private: bool = False,
) -> dict[str, Any]:
    """
    Create a Forgejo repository owned by the user of the given role.

    The repository is named 'apiguard-{8-char hex}' and registered for
    Phase 6 teardown via DELETE /api/v1/repos/{owner}/{repo}.

    Args:
        target:      Immutable target context.
        context:     Mutable test context.
        client:      Centralized HTTP client.
        role:        Role whose token is used to create the repository.
                     The repository owner is the user associated with this role.
        description: Repository description string.
        private:     If True, creates a private repository.

    Returns:
        Forgejo repository dict including at minimum:
            'id' (int), 'name' (str), 'full_name' (str),
            'owner' (dict with 'login' str).

    Raises:
        ForgejoResourceError: If the API returns an unexpected status code.
        SecurityClientError:  On transport failure.
    """
    token = _require_token(context, role)
    repo_name = _unique_name("repo")
    headers = _bearer_headers(token)

    response, _ = client.request(
        method="POST",
        path=_FORGEJO_USER_REPOS_PATH,
        test_id="helper_create_repo",
        headers=headers,
        json={
            "name": repo_name,
            "description": description,
            "private": private,
            "auto_init": True,
        },
    )

    if response.status_code != _CREATED_STATUS:
        raise ForgejoResourceError(
            message=(
                f"Repository creation returned HTTP {response.status_code} "
                f"for role '{role}', repo name '{repo_name}'. "
                f"Expected {_CREATED_STATUS}. "
                f"Response: {response.text[:200]}"
            ),
            path=_FORGEJO_USER_REPOS_PATH,
            status_code=response.status_code,
        )

    repo_data: dict[str, Any] = response.json()
    owner_login: str = repo_data["owner"]["login"]
    teardown_path = _FORGEJO_REPO_PATH_TEMPLATE.format(
        owner=owner_login,
        repo=repo_name,
    )

    # Register teardown before any further logic that could raise.
    # Repository deletion uses Bearer auth forwarded by the Gateway.
    context.register_resource_for_teardown(
        method="DELETE",
        path=teardown_path,
        headers=_bearer_auth_header(token),
    )

    log.info(
        "forgejo_helper_repository_created",
        role=role,
        owner=owner_login,
        repo_name=repo_name,
        full_name=repo_data.get("full_name"),
        teardown_path=teardown_path,
    )
    return repo_data


def create_issue(
    target: TargetContext,
    context: TestContext,
    client: SecurityClient,
    role: str,
    repo_owner: str,
    repo_name: str,
    title: str | None = None,
    body: str = "Created by APIGuard security assessment.",
) -> dict[str, Any]:
    """
    Create an issue in an existing Forgejo repository.

    The issue title defaults to 'apiguard-{8-char hex}' if not provided.
    Issues are automatically closed (state=closed) when the parent repository
    is deleted during teardown, so no separate issue teardown registration
    is needed.

    Args:
        target:     Immutable target context.
        context:    Mutable test context.
        client:     Centralized HTTP client.
        role:       Role whose token is used to create the issue.
        repo_owner: Username of the repository owner.
        repo_name:  Name of the repository in which to create the issue.
        title:      Issue title. Defaults to 'apiguard-{8-char hex}'.
        body:       Issue body text.

    Returns:
        Forgejo issue dict including at minimum:
            'id' (int), 'number' (int), 'title' (str), 'html_url' (str).

    Raises:
        ForgejoResourceError: If the API returns an unexpected status code.
        SecurityClientError:  On transport failure.
    """
    token = _require_token(context, role)
    issue_title = title or _unique_name("issue")
    headers = _bearer_headers(token)
    issues_path = _FORGEJO_ISSUES_PATH_TEMPLATE.format(
        owner=repo_owner,
        repo=repo_name,
    )

    response, _ = client.request(
        method="POST",
        path=issues_path,
        test_id="helper_create_issue",
        headers=headers,
        json={"title": issue_title, "body": body},
    )

    if response.status_code != _CREATED_STATUS:
        raise ForgejoResourceError(
            message=(
                f"Issue creation in '{repo_owner}/{repo_name}' returned "
                f"HTTP {response.status_code} for role '{role}'. "
                f"Expected {_CREATED_STATUS}. "
                f"Response: {response.text[:200]}"
            ),
            path=issues_path,
            status_code=response.status_code,
        )

    issue_data: dict[str, Any] = response.json()

    log.info(
        "forgejo_helper_issue_created",
        role=role,
        repo=f"{repo_owner}/{repo_name}",
        issue_number=issue_data.get("number"),
        title=issue_title,
    )
    return issue_data


def list_repositories(
    target: TargetContext,
    context: TestContext,
    client: SecurityClient,
    role: str,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """
    Return a list of repositories visible to the given role's user.

    Uses GET /api/v1/repos/search with the authenticated user's token.
    Useful for tests that need to discover existing resources before
    operating on them.

    Args:
        target:  Immutable target context.
        context: Mutable test context.
        client:  Centralized HTTP client.
        role:    Role whose token is used for the search.
        limit:   Maximum number of repositories to return (default 10).

    Returns:
        List of Forgejo repository dicts. May be empty if no repositories
        are visible to the authenticated user.

    Raises:
        ForgejoResourceError: If the API returns a non-200 status.
        SecurityClientError:  On transport failure.
    """
    token = _require_token(context, role)
    headers = _bearer_headers(token)

    response, _ = client.request(
        method="GET",
        path=_FORGEJO_REPOS_SEARCH_PATH,
        test_id="helper_list_repos",
        headers=headers,
        params={"limit": str(limit), "token": ""},
    )

    if response.status_code != _OK_STATUS:
        raise ForgejoResourceError(
            message=(
                f"Repository search returned HTTP {response.status_code} "
                f"for role '{role}'. Expected {_OK_STATUS}."
            ),
            path=_FORGEJO_REPOS_SEARCH_PATH,
            status_code=response.status_code,
        )

    search_result: dict[str, Any] = response.json()
    repos: list[dict[str, Any]] = search_result.get("data", [])

    log.debug(
        "forgejo_helper_repositories_listed",
        role=role,
        count=len(repos),
    )
    return repos


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _unique_name(resource_type: str) -> str:
    """
    Generate a unique resource name for assessment-created objects.

    Args:
        resource_type: Short label used as suffix (e.g. 'repo', 'issue').

    Returns:
        String of the form 'apiguard-{resource_type}-{8-char hex}'.
    """
    return f"{_RESOURCE_NAME_PREFIX}-{resource_type}-{secrets.token_hex(_NAME_SUFFIX_BYTES)}"


def _require_token(context: TestContext, role: str) -> str:
    """
    Retrieve the token for the given role or raise if absent.

    Args:
        context: Mutable test context.
        role:    Role identifier.

    Returns:
        Token string.

    Raises:
        ValueError: If no token is stored for the role.  The caller's
                    execute() method must have called acquire_all_tokens_if_needed
                    before invoking any forgejo_resources function.
    """
    token = context.get_token(role)
    if token is None:
        raise ValueError(
            f"No token available for role '{role}' in TestContext. "
            f"Call acquire_all_tokens_if_needed() before using forgejo_resources helpers."
        )
    return token


def _bearer_headers(token: str) -> dict[str, str]:
    """
    Headers for POST/PUT Forgejo API request with JSON body.
    Args:
        token: Raw token string (without 'Bearer ' prefix).
    Returns:
        Dict suitable for passing as the headers argument to client.request().

    """
    return {
        "Authorization": f"token {token}",
        "Content-Type": "application/json",
    }


def _bearer_auth_header(token: str) -> dict[str, str]:
    """Headers for GET/DELETE requests without body."""
    return {"Authorization": f"token {token}"}
