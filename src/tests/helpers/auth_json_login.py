"""
src/tests/helpers/auth_json_login.py

The json_login authentication method (renamed from jwt_login: any token in a
JSON response, not only JWTs).

It obtains a token by sending POST credentials.login_endpoint with the role's
username and password in a JSON body (fields username_body_field and
password_body_field), then reads the token from the response at the dotted
path token_response_path. How the token is sent is decided by the placement
(e.g. 'Authorization: Bearer', from the specification's scheme).

This covers many API frameworks:
    - crAPI  (POST /identity/api/auth/login -> {"token": "..."})
    - Django REST Framework with SimpleJWT (POST /api/token/ -> {"access": "..."})
    - FastAPI with python-jose (POST /auth/token -> {"access_token": "..."})
    - Rails Devise Token Auth (POST /auth/sign_in -> {"data": {"token": "..."}})

Token extraction
----------------
token_response_path uses simple dot-notation on the JSON response body:
    "access_token"          -> response["access_token"]
    "data.access_token"     -> response["data"]["access_token"]
Array indexing ("tokens[0].value") and keys containing literal dots are not
supported.

No teardown, no revocation
--------------------------
A login token is not an object created on the target, so nothing is
registered for teardown. The method cannot revoke a token (no logout is
known for the labs; crAPI has none): test 1.4 SKIPs with this method.

Dependency rule: imports from stdlib, src.core and src.tests.helpers.auth_base.
It must never import from src.tests.domain_* or src.engine.
"""

from __future__ import annotations

from typing import Any

import structlog
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.exceptions import AuthenticationSetupError
from src.core.models import AuthType
from src.tests.helpers.auth_base import AuthMethod, role_account

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUCCESS_MIN: int = 200
_SUCCESS_MAX: int = 300


class JsonLoginAuthMethod(AuthMethod):
    """Token from a JSON login endpoint (POST username and password)."""

    auth_type = AuthType.JSON_LOGIN

    def obtain_credential(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        role: str,
    ) -> None:
        """
        Log in with the role's account and store the token from the response.

        Args:
            target:  The current TargetContext (credentials).
            context: The TestContext where the token is stored.
            client:  The SecurityClient for the login request.
            role:    A ROLE_* constant.

        Raises:
            AuthenticationSetupError: If the role has no account, login_endpoint
                is not set, the server answers non-2xx, or the token is not at
                token_response_path.
            SecurityClientError: On transport-layer failure.
        """
        creds = target.credentials
        account = role_account(target, role)
        if account is None:
            raise AuthenticationSetupError(
                f"auth_type 'json_login': no username and password configured for role '{role}'.",
                role=role,
            )
        if not creds.login_endpoint:
            raise AuthenticationSetupError(
                "auth_type 'json_login' requires credentials.login_endpoint.", role=role
            )
        username, password = account
        request_body = {
            creds.username_body_field: username,
            creds.password_body_field: password,
        }
        log.debug(
            "json_login_attempt",
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
        if not _SUCCESS_MIN <= response.status_code < _SUCCESS_MAX:
            raise AuthenticationSetupError(
                f"JSON login failed for role '{role}': POST {creds.login_endpoint} returned "
                f"HTTP {response.status_code}. Check the credentials of this role in config.yaml.",
                role=role,
                status_code=response.status_code,
            )
        try:
            response_json: dict[str, Any] = response.json()
        except ValueError as exc:
            raise AuthenticationSetupError(
                f"JSON login for role '{role}': server returned HTTP {response.status_code} "
                f"but the response body is not valid JSON. Path: {creds.login_endpoint}.",
                role=role,
                status_code=response.status_code,
            ) from exc
        token = _extract_token(response_json, creds.token_response_path, role, creds.login_endpoint)
        context.set_token(role, token)
        log.info(
            "json_login_token_acquired",
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
                f"JSON login for role '{role}': token_response_path '{token_response_path}' "
                f"is invalid: segment '{segment}' expected a dict but found "
                f"{type(current).__name__}. "
                f"Response body keys at this level: "
                f"{list(current.keys()) if isinstance(current, dict) else 'N/A'}. "
                f"URL: {login_url}."
            )
        if segment not in current:
            raise AuthenticationSetupError(
                f"JSON login for role '{role}': token_response_path '{token_response_path}' "
                f"not found in response body: key '{segment}' is missing. "
                f"Available keys at this level: {sorted(current.keys())}. "
                f"URL: {login_url}. "
                "Check that token_response_path in config.yaml matches the actual "
                "login response structure."
            )
        current = current[segment]

    if not isinstance(current, str):
        raise AuthenticationSetupError(
            f"JSON login for role '{role}': token_response_path '{token_response_path}' "
            f"resolved to a {type(current).__name__}, expected str. "
            f"URL: {login_url}."
        )

    token = current.strip()
    if not token:
        raise AuthenticationSetupError(
            f"JSON login for role '{role}': token extracted from path "
            f"'{token_response_path}' is an empty string. "
            f"URL: {login_url}."
        )

    return token
