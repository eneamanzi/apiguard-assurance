"""
src/tests/helpers/auth.py

Forgejo token acquisition helper for GREY_BOX test setup.

Responsibility
--------------
This module contains the single function that GREY_BOX tests call at the
start of their execute() method to ensure that valid API tokens are present
in the TestContext before the test logic begins.

The public API is intentionally narrow:

    acquire_all_tokens_if_needed(target, context, client)
        Iterates over all roles that have credentials configured in
        target.credentials and calls acquire_single_token() for each role
        that does not yet have a token in the TestContext.  Idempotent:
        safe to call multiple times across tests in the same pipeline run.

    acquire_single_token(target, context, client, username, password, role)
        Creates a named API token on Forgejo via POST /api/v1/users/{username}/tokens
        authenticated with HTTP Basic Auth.  Stores the token value in
        TestContext and registers the token deletion endpoint for Phase 6
        teardown with the appropriate Basic Auth header.

Forgejo token model
-------------------
Forgejo (and Gitea) uses opaque tokens, not JWTs.  The token value returned
by the API is the ``sha1`` field of the response body.  The token ID (integer)
is required to construct the teardown DELETE path.

Token naming
------------
Each created token is named ``apiguard-{8-char hex suffix}`` where the suffix
is generated via secrets.token_hex(4).  This guarantees uniqueness across
concurrent or repeated assessment runs on the same Forgejo instance without
requiring a central registry.

Dependency rule
---------------
This module imports from:
    - stdlib only: base64, secrets
    - src.core.client, src.core.context, src.core.exceptions, src.core.models
It must never import from src.tests.domain_* or src.engine.
"""

from __future__ import annotations

import base64
import secrets
from typing import Any

import structlog
from src.core.client import SecurityClient
from src.core.context import ROLE_ADMIN, ROLE_USER_A, ROLE_USER_B, TargetContext, TestContext
from src.core.exceptions import AuthenticationSetupError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Forgejo API path for token management.
# {username} is substituted at runtime with the account username.
_FORGEJO_TOKENS_PATH_TEMPLATE: str = "/api/v1/users/{username}/tokens"

# Token name prefix.  The full name is f"{_TOKEN_NAME_PREFIX}-{hex_suffix}".
# Keeping a consistent prefix makes it easy to identify and manually clean up
# tokens created by the tool if teardown fails.
_TOKEN_NAME_PREFIX: str = "apiguard"  # noqa: S105

# Number of random bytes used to generate the token name suffix.
# 4 bytes = 8 hex characters, providing 2^32 (~4 billion) unique names.
_TOKEN_NAME_SUFFIX_BYTES: int = 4

# HTTP status codes considered successful for token creation.
_TOKEN_CREATION_SUCCESS_CODE: int = 201

# HTTP status codes that indicate rejected credentials.
_AUTH_REJECTION_CODES: frozenset[int] = frozenset({401, 403})

# Ordered list of (role, username_attr, password_attr) for iteration.
# The order determines which role's token is acquired first.  Admin is
# acquired first so that subsequent role-specific tests can use it immediately
# if needed, before user_a and user_b tokens are available.
_ROLE_CREDENTIAL_MAP: list[tuple[str, str, str]] = [
    (ROLE_ADMIN, "admin_username", "admin_password"),
    (ROLE_USER_A, "user_a_username", "user_a_password"),
    (ROLE_USER_B, "user_b_username", "user_b_password"),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def acquire_all_tokens_if_needed(
    target: TargetContext,
    context: TestContext,
    client: SecurityClient,
) -> None:
    """
    Acquire API tokens for all configured roles that do not yet have a token.

    Iterates over the roles defined in target.credentials and calls
    acquire_single_token() for each role whose credentials are present and
    whose token is not yet stored in the TestContext.  Skips roles with
    missing credentials and roles that already have a token, making the
    function safe to call multiple times within the same pipeline run.

    This function is the standard entry point for GREY_BOX tests.  It must
    be called before any test logic that requires an authenticated context.
    Canonical usage pattern inside execute():

        try:
            acquire_all_tokens_if_needed(target, context, client)
        except AuthenticationSetupError as exc:
            return self._make_error(exc)
        except SecurityClientError as exc:
            return self._make_error(exc)

    Args:
        target:  Immutable target context carrying credentials and base_url.
        context: Mutable test context where acquired tokens are stored.
        client:  Centralized HTTP client for all outbound requests.

    Raises:
        AuthenticationSetupError: If Forgejo rejects the credentials for any
            role (HTTP 401 or 403).  The error message identifies the role
            without exposing the credential value.
        SecurityClientError: If a transport-layer error prevents the token
            creation request from completing (connection refused, timeout).
    """
    creds = target.credentials

    for role, username_attr, password_attr in _ROLE_CREDENTIAL_MAP:
        username: str | None = getattr(creds, username_attr, None)
        password: str | None = getattr(creds, password_attr, None)

        if not username or not password:
            log.debug(
                "auth_helper_skipping_role_no_credentials",
                role=role,
            )
            continue

        if context.has_token(role):
            log.debug(
                "auth_helper_skipping_role_token_already_present",
                role=role,
            )
            continue

        acquire_single_token(
            target=target,
            context=context,
            client=client,
            username=username,
            password=password,
            role=role,
        )


def acquire_single_token(
    target: TargetContext,
    context: TestContext,
    client: SecurityClient,
    username: str,
    password: str,
    role: str,
) -> None:
    """
    Create a named API token on Forgejo and store it in the TestContext.

    Makes a single POST request to /api/v1/users/{username}/tokens using
    HTTP Basic Auth.  On success, stores the token value in the TestContext
    and registers the token deletion endpoint for Phase 6 teardown.

    The token name is generated as ``apiguard-{8-char hex}`` using
    secrets.token_hex(4), guaranteeing uniqueness across runs.

    Teardown registration note: Forgejo token deletion requires Basic Auth
    from the token owner.  The registration therefore includes the Basic Auth
    header so that the engine can authenticate the DELETE request without
    needing to re-derive the credentials from the TestContext.

    Args:
        target:   Immutable target context carrying base_url.
        context:  Mutable test context where the token is stored.
        client:   Centralized HTTP client.
        username: Forgejo account username. Used in the URL path and in the
                  Basic Auth header.  Never logged in plain text.
        password: Forgejo account password.  Never logged; always [REDACTED].
        role:     Role identifier for storage in TestContext (e.g. ROLE_USER_A).

    Raises:
        AuthenticationSetupError: If Forgejo returns 401 or 403, indicating
            that the credentials are invalid or the account is locked.
        SecurityClientError: If the HTTP request fails at the transport layer.
        ValueError: If the Forgejo response body is missing the expected
            ``sha1`` or ``id`` fields (malformed API response).
    """
    token_name = f"{_TOKEN_NAME_PREFIX}-{secrets.token_hex(_TOKEN_NAME_SUFFIX_BYTES)}"
    tokens_path = _FORGEJO_TOKENS_PATH_TEMPLATE.format(username=username)
    basic_auth_header = _build_basic_auth_header(username, password)

    log.debug(
        "auth_helper_acquiring_token",
        role=role,
        username=username,
        token_name=token_name,
        path=tokens_path,
    )

    response, _ = client.request(
        method="POST",
        path=tokens_path,
        test_id="auth_setup",
        headers={
            "Authorization": basic_auth_header,
            "Content-Type": "application/json",
        },
        json={"name": token_name},
    )

    if response.status_code in _AUTH_REJECTION_CODES:
        raise AuthenticationSetupError(
            message=(
                f"Forgejo rejected credentials for role '{role}' "
                f"(HTTP {response.status_code}). "
                f"Verify that the username and password configured for this "
                f"role in config.yaml are correct and that the account is active."
            ),
            role=role,
            status_code=response.status_code,
        )

    if response.status_code != _TOKEN_CREATION_SUCCESS_CODE:
        raise AuthenticationSetupError(
            message=(
                f"Forgejo token creation for role '{role}' returned unexpected "
                f"HTTP {response.status_code}. "
                f"Expected {_TOKEN_CREATION_SUCCESS_CODE}. "
                f"Response body: {response.text[:200]}"
            ),
            role=role,
            status_code=response.status_code,
        )

    response_data: dict[str, Any] = response.json()

    token_value: str | None = response_data.get("sha1")
    token_id: int | None = response_data.get("id")

    if not token_value:
        raise ValueError(
            f"Forgejo token creation response for role '{role}' is missing "
            f"the 'sha1' field. Cannot store token. "
            f"Response keys received: {list(response_data.keys())}"
        )

    if token_id is None:
        raise ValueError(
            f"Forgejo token creation response for role '{role}' is missing "
            f"the 'id' field. Cannot register teardown endpoint. "
            f"Response keys received: {list(response_data.keys())}"
        )

    # Store the token value in the TestContext so downstream tests can use it
    # by calling context.get_token(role).
    context.set_token(role, token_value)

    # Register the deletion endpoint for Phase 6 teardown.
    # Basic Auth is required to delete a Forgejo token — the Bearer token
    # mechanism used by the Gateway does not apply to the token management API.
    teardown_path = f"{tokens_path}/{token_id}"
    context.register_resource_for_teardown(
        method="DELETE",
        path=teardown_path,
        headers={"Authorization": basic_auth_header},
    )

    log.info(
        "auth_helper_token_acquired",
        role=role,
        username=username,
        token_name=token_name,
        token_id=token_id,
        teardown_path=teardown_path,
        token_value="[REDACTED]",  # noqa: S106
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_basic_auth_header(username: str, password: str) -> str:
    """
    Build a well-formed HTTP Basic Auth header value.

    Encodes ``username:password`` as Base64 per RFC 7617.  The result is
    suitable for use as the value of an ``Authorization`` header.

    The password is never logged by this function.  Callers must ensure
    that any log message containing the return value of this function
    uses ``[REDACTED]`` as a placeholder.

    Args:
        username: Account username.
        password: Account password.  Not logged anywhere in this function.

    Returns:
        String of the form ``Basic <base64-encoded-credentials>``.
    """
    raw_credentials = f"{username}:{password}"
    encoded = base64.b64encode(raw_credentials.encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"
