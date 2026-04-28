"""
src/tests/helpers/auth_jwt_login.py

JWT login token acquisition for GREY_BOX test setup.

This module implements the "jwt_login" auth_type: it acquires tokens by
sending a POST request to a configurable login endpoint with username and
password as a JSON body, then extracts the token from the response using a
dotted JSONPath expression.

This covers the majority of modern API frameworks that are not Forgejo/Gitea:
    - crAPI  (POST /identity/api/auth/login -> {"token": "..."})
    - Django REST Framework with SimpleJWT (POST /api/token/ -> {"access": "..."})
    - FastAPI with python-jose (POST /auth/token -> {"access_token": "..."})
    - Rails Devise Token Auth (POST /auth/sign_in -> {"data": {"token": "..."}})
    - Any API that follows the pattern: POST {endpoint} + JSON body -> JWT in body

Token extraction
----------------
The token_response_path field in CredentialsConfig uses simple dot-notation
to navigate the JSON response body.  Examples:

    "access_token"          -> response["access_token"]
    "token"                 -> response["token"]
    "data.access_token"     -> response["data"]["access_token"]

Known limitation: array indexing ("tokens[0].value") and keys that contain
literal dots are NOT supported.  If the target uses such a structure, a custom
auth implementation is required.  Document this in the consuming test's
docstring and in config.yaml.

No teardown
-----------
JWT tokens are stateless bearer tokens.  They do not require deletion via the
API when the assessment ends (unlike Forgejo opaque tokens which are created
as persistent server-side objects).  This implementation therefore registers
no teardown entries in TestContext.

If the target requires an explicit logout call to invalidate tokens, implement
a custom auth module and register the logout endpoint for teardown there.

Dependency rule
---------------
This module imports from:
    - stdlib only: typing
    - src.core.client, src.core.context, src.core.exceptions
It must never import from src.tests.domain_* or src.engine.
"""

from __future__ import annotations

from typing import Any

import structlog
from src.core.client import SecurityClient
from src.core.context import ROLE_ADMIN, ROLE_USER_A, ROLE_USER_B, TargetContext, TestContext
from src.core.exceptions import AuthenticationSetupError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Ordered mapping of role -> (username_attr, password_attr) on RuntimeCredentials.
# Admin is attempted first so it is available immediately if needed by the
# first test before user_a and user_b tokens are acquired.
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
    required_roles: frozenset[str] | None = None,
) -> None:
    """
    Acquire JWT tokens for configured roles that do not yet have a token.

    Iterates over the roles defined in target.credentials and calls
    acquire_single_token() for each role whose credentials are present and
    whose token is not yet stored in the TestContext.  Idempotent: safe to
    call multiple times within the same pipeline run.

    Canonical usage pattern inside execute():

        try:
            acquire_all_tokens_if_needed(
                target, context, client,
                required_roles=frozenset({ROLE_USER_A}),
            )
        except AuthenticationSetupError as exc:
            return self._make_error(exc)
        except SecurityClientError as exc:
            return self._make_error(exc)

    Args:
        target:         Immutable target context carrying credentials and base_url.
        context:        Mutable test context where acquired tokens are stored.
        client:         Centralized HTTP client for all outbound requests.
        required_roles: Optional frozenset of role identifiers to acquire.
                        When None, all configured roles are attempted.

    Raises:
        AuthenticationSetupError: If the target rejects the credentials for a
            role in required_roles (non-2xx response or token not found in body).
            Failures for roles not in required_roles are never raised.
        SecurityClientError: If a transport-layer error prevents the login
            request from completing (connection refused, timeout).
    """
    creds = target.credentials

    for role, username_attr, password_attr in _ROLE_CREDENTIAL_MAP:
        if required_roles is not None and role not in required_roles:
            log.debug(
                "jwt_auth_skipping_role_not_required",
                role=role,
                required_roles=sorted(required_roles),
            )
            continue

        username: str | None = getattr(creds, username_attr, None)
        password: str | None = getattr(creds, password_attr, None)

        if not username or not password:
            log.debug("jwt_auth_skipping_role_no_credentials", role=role)
            continue

        if context.has_token(role):
            log.debug("jwt_auth_skipping_role_token_already_present", role=role)
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
    Acquire a JWT token for a single role via the configured login endpoint.

    Sends a POST request to target.credentials.login_endpoint with the
    username and password as a JSON body.  On a 2xx response, extracts the
    token using token_response_path (dotted JSONPath) and stores it in
    TestContext via context.set_token(role, token).

    No teardown is registered: JWT tokens are stateless and do not require
    deletion via API.

    Args:
        target:   Immutable target context.
        context:  Mutable test context where the token is stored on success.
        client:   Centralized HTTP client.
        username: Plaintext username (or email) for this role.
        password: Plaintext password for this role.
        role:     Role identifier (ROLE_ADMIN, ROLE_USER_A, ROLE_USER_B).

    Raises:
        AuthenticationSetupError: If login_endpoint is not configured, if the
            server returns a non-2xx status, or if the token cannot be found
            at token_response_path in the response body.
        SecurityClientError: On transport-layer failure.
    """
    creds = target.credentials

    if not creds.login_endpoint:
        raise AuthenticationSetupError(
            "jwt_login auth_type requires 'login_endpoint' in credentials config, "
            "but it is not set.  Add 'login_endpoint: /your/login/path' under "
            "'credentials' in config.yaml."
        )

    request_body = {
        creds.username_body_field: username,
        creds.password_body_field: password,
    }

    log.debug(
        "jwt_auth_login_attempt",
        role=role,
        path=creds.login_endpoint,
        username_field=creds.username_body_field,
        password_field=creds.password_body_field,
        username="[REDACTED]",
    )

    response, _ = client.request(
        method="POST",
        path=creds.login_endpoint,
        test_id="auth_setup",
        json=request_body,
    )

    if response.status_code < 200 or response.status_code >= 300:
        raise AuthenticationSetupError(
            f"JWT login failed for role '{role}': "
            f"POST {creds.login_endpoint} returned HTTP {response.status_code}. "
            f"Check credentials for {creds.username_body_field}=[REDACTED] in config.yaml."
        )

    try:
        response_json: dict[str, Any] = response.json()
    except Exception as exc:
        raise AuthenticationSetupError(
            f"JWT login for role '{role}': server returned HTTP {response.status_code} "
            "but the response body is not valid JSON. "
            f"Path: {creds.login_endpoint}. Parse error: {exc}"
        ) from exc

    token = _extract_token(response_json, creds.token_response_path, role, creds.login_endpoint)

    context.set_token(role, token)
    log.info(
        "jwt_auth_token_acquired",
        role=role,
        token_response_path=creds.token_response_path,
        token_value="[REDACTED]",  # noqa: S106
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _extract_token(
    response_body: dict[str, Any],
    token_response_path: str,
    role: str,
    login_url: str,
) -> str:
    """
    Walk a dotted JSONPath and extract the token string from the login response.

    Supports simple dot-notation only.  Array indexing and keys containing
    literal dots are not supported.

    Args:
        response_body:       Parsed JSON login response.
        token_response_path: Dot-separated path, e.g. "data.access_token".
        role:                Role label for error messages.
        login_url:           Login URL for error messages.

    Returns:
        The token string extracted at the given path.

    Raises:
        AuthenticationSetupError: If any segment of the path is missing, if the
            final value is not a string, or if the extracted string is empty.
    """
    segments = token_response_path.split(".")
    current: Any = response_body

    for segment in segments:
        if not isinstance(current, dict):
            raise AuthenticationSetupError(
                f"JWT login for role '{role}': token_response_path '{token_response_path}' "
                f"is invalid: segment '{segment}' expected a dict but found "
                f"{type(current).__name__}. "
                f"Response body keys at this level: "
                f"{list(current.keys()) if isinstance(current, dict) else 'N/A'}. "
                f"URL: {login_url}."
            )
        if segment not in current:
            raise AuthenticationSetupError(
                f"JWT login for role '{role}': token_response_path '{token_response_path}' "
                f"not found in response body: key '{segment}' is missing. "
                f"Available keys at this level: {sorted(current.keys())}. "
                f"URL: {login_url}. "
                "Check that token_response_path in config.yaml matches the actual "
                "login response structure."
            )
        current = current[segment]

    if not isinstance(current, str):
        raise AuthenticationSetupError(
            f"JWT login for role '{role}': token_response_path '{token_response_path}' "
            f"resolved to a {type(current).__name__}, expected str. "
            f"URL: {login_url}."
        )

    token = current.strip()
    if not token:
        raise AuthenticationSetupError(
            f"JWT login for role '{role}': token extracted from path "
            f"'{token_response_path}' is an empty string. "
            f"URL: {login_url}."
        )

    return token
