"""
src/tests/helpers/auth_forgejo.py

The forgejo_token authentication method: Forgejo/Gitea API tokens.

Obtain: for each role it creates a named API token with
POST /api/v1/users/{username}/tokens, authenticated with HTTP Basic (the token
API accepts only the account's password), stores the token value (the 'sha1'
field of the response) and registers its deletion for Phase 6 teardown.

Revocation (test 1.4): it creates a temporary token under the role's account
and revokes it with DELETE /api/v1/users/{username}/tokens/{name}, both with
HTTP Basic. Before creating it, a token left with the same name by an
interrupted run is deleted (204 or 404, both fine).

Forgejo tokens are opaque, not JWTs; how they are sent is decided by the
placement (on the labs: 'Authorization: token <value>', the scheme
AuthorizationHeaderToken that Forgejo declares).

Token names: 'apiguard-<8 hex>' (secrets.token_hex(4)), unique across runs on
the same Forgejo instance.

Dependency rule: imports from stdlib, src.core and src.tests.helpers.auth_base.
It must never import from src.tests.domain_* or src.engine.
"""

from __future__ import annotations

import base64
import secrets
from typing import Any

import httpx
import structlog
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.exceptions import AuthenticationSetupError
from src.core.models import AuthType
from src.tests.helpers.auth_base import (
    RevocableAuthMethod,
    RevocationOutcome,
    TemporaryCredential,
    role_account,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TOKENS_PATH_TEMPLATE: str = "/api/v1/users/{username}/tokens"  # noqa: S105 -- URL path, not a credential
_TOKEN_BY_NAME_PATH_TEMPLATE: str = "/api/v1/users/{username}/tokens/{name}"  # noqa: S105 -- URL path, not a credential
_TOKEN_BY_ID_PATH_TEMPLATE: str = "{tokens_path}/{token_id}"  # noqa: S105 -- URL path, not a credential

# Name prefix of the tokens the run creates (easy to find and clean up by hand).
_TOKEN_NAME_PREFIX: str = "apiguard"  # noqa: S105 -- a name prefix, not a credential
_TOKEN_NAME_SUFFIX_BYTES: int = 4

_TOKEN_CREATED_STATUS: int = 201
_TOKEN_REVOKED_STATUSES: frozenset[int] = frozenset({200, 204})
_AUTH_REJECTION_CODES: frozenset[int] = frozenset({401, 403})
_RESPONSE_BODY_PREVIEW: int = 200

# Forgejo 1.21+ requires 'scopes'. Only what the tool exercises:
#   write:repository / read:repository -- repositories and webhooks (7.2, 1.1)
#   write:user / read:user             -- tokens and the user profile
_TOKEN_SCOPES: tuple[str, ...] = (
    "read:repository",
    "read:user",
    "write:repository",
    "write:user",
)
# The temporary token of test 1.4 only needs to read the user profile.
_TEMPORARY_TOKEN_SCOPES: tuple[str, ...] = ("read:user",)

_BASIC_SECRET_LABEL: str = "Basic credentials of role"  # noqa: S105 -- a label, not a credential
_TEMPORARY_TOKEN_LABEL: str = "temporary token"  # noqa: S105 -- a label, not a credential
# Last characters of a temporary token kept in its label, as Forgejo's
# token_last_eight, so that its create, revoke and reuse requests correlate.
_TOKEN_FINGERPRINT_LENGTH: int = 8


class ForgejoTokenAuthMethod(RevocableAuthMethod):
    """Forgejo/Gitea API tokens, created with the account's password."""

    auth_type = AuthType.FORGEJO_TOKEN

    # ------------------------------------------------------------------
    # Obtain
    # ------------------------------------------------------------------

    def obtain_credential(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        role: str,
    ) -> None:
        """
        Create an API token for the role, store it and register its deletion.

        Args:
            target:  The current TargetContext (credentials).
            context: The TestContext (token, secrets, teardown).
            client:  The SecurityClient.
            role:    A ROLE_* constant.

        Raises:
            AuthenticationSetupError: If the role has no account, Forgejo rejects
                it (401/403), answers another status, or the response misses
                'sha1' or 'id'.
            SecurityClientError: On transport-layer failure.
        """
        username, basic_value = self._basic_value(target, context, role)
        token_name = f"{_TOKEN_NAME_PREFIX}-{secrets.token_hex(_TOKEN_NAME_SUFFIX_BYTES)}"
        tokens_path = _TOKENS_PATH_TEMPLATE.format(username=username)
        log.debug("forgejo_token_creating", role=role, token_name=token_name, path=tokens_path)

        response, _ = client.request(
            method="POST",
            path=tokens_path,
            test_id="auth_setup",
            headers={"Authorization": basic_value, "Content-Type": "application/json"},
            json={"name": token_name, "scopes": list(_TOKEN_SCOPES)},
        )
        body = self._created_token_body(response, role)
        token_value = str(body.get("sha1") or "")
        token_id = body.get("id")
        if not token_value or token_id is None:
            raise AuthenticationSetupError(
                f"Forgejo token creation for role '{role}': the response misses 'sha1' or "
                f"'id' (keys received: {sorted(body)}).",
                role=role,
                status_code=response.status_code,
            )
        context.set_token(role, token_value)
        teardown_path = _TOKEN_BY_ID_PATH_TEMPLATE.format(
            tokens_path=tokens_path, token_id=token_id
        )
        context.register_resource_for_teardown(
            method="DELETE",
            path=teardown_path,
            headers={"Authorization": basic_value},
        )
        log.info(
            "forgejo_token_acquired",
            role=role,
            token_name=token_name,
            token_id=token_id,
            teardown_path=teardown_path,
            token_value="[REDACTED]",  # noqa: S106
        )

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    def create_temporary_credential(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        role: str,
        name: str,
        test_id: str,
    ) -> TemporaryCredential:
        """
        Create a temporary token named 'name' under the role's account.

        A token left with the same name by an interrupted run is deleted
        first. The new token is registered as a secret (label with its last
        characters) and for teardown, before any further step.

        Args:
            target:  The current TargetContext.
            context: The TestContext (secrets, teardown).
            client:  The SecurityClient.
            role:    A ROLE_* constant.
            name:    Token name (test 1.4: tests.domain_1.test_1_4.token_name).
            test_id: Test the requests are attributed to.

        Returns:
            The created token.

        Raises:
            AuthenticationSetupError: If the role has no account or Forgejo does
                not create the token.
            SecurityClientError: On transport-layer failure.
        """
        username, basic_value = self._basic_value(target, context, role)
        revoke_path = _TOKEN_BY_NAME_PATH_TEMPLATE.format(username=username, name=name)
        # Stale token from an interrupted run: 204 if it existed, 404 otherwise.
        client.request(
            method="DELETE",
            path=revoke_path,
            test_id=test_id,
            headers={"Authorization": basic_value},
        )
        response, record = client.request(
            method="POST",
            path=_TOKENS_PATH_TEMPLATE.format(username=username),
            test_id=test_id,
            headers={"Authorization": basic_value},
            json={"name": name, "scopes": list(_TEMPORARY_TOKEN_SCOPES)},
        )
        body = self._created_token_body(response, role)
        value = str(body.get("sha1") or "")
        if not value:
            raise AuthenticationSetupError(
                f"Forgejo temporary token '{name}': the response has no 'sha1' field.",
                role=role,
                status_code=response.status_code,
            )
        context.register_secret(
            value,
            f"{test_id} {_TEMPORARY_TOKEN_LABEL}, last {_TOKEN_FINGERPRINT_LENGTH}: "
            f"{value[-_TOKEN_FINGERPRINT_LENGTH:]}",
        )
        context.register_resource_for_teardown(
            method="DELETE",
            path=revoke_path,
            headers={"Authorization": basic_value},
        )
        return TemporaryCredential(
            value=value, name=name, revoke_path=revoke_path, create_record=record
        )

    def revoke_credential(
        self,
        target: TargetContext,
        client: SecurityClient,
        credential: TemporaryCredential,
        role: str,
        test_id: str,
    ) -> RevocationOutcome:
        """
        Delete the temporary token (= revocation).

        Args:
            target:     The current TargetContext.
            client:     The SecurityClient.
            credential: The token created by create_temporary_credential().
            role:       The role whose account created it.
            test_id:    Test the request is attributed to.

        Returns:
            Revoked when Forgejo answers 200 or 204.

        Raises:
            AuthenticationSetupError: If the role has no account.
            SecurityClientError: On transport-layer failure.
        """
        account = role_account(target, role)
        if account is None:
            raise AuthenticationSetupError(
                f"auth_type 'forgejo_token': no username and password for role '{role}'.",
                role=role,
            )
        response, record = client.request(
            method="DELETE",
            path=credential.revoke_path,
            test_id=test_id,
            headers={"Authorization": _basic_header(*account)},
        )
        return RevocationOutcome(
            revoked=response.status_code in _TOKEN_REVOKED_STATUSES,
            status_code=response.status_code,
            record=record,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _basic_value(target: TargetContext, context: TestContext, role: str) -> tuple[str, str]:
        """The role's username and its Basic Authorization value, registered as a secret."""
        account = role_account(target, role)
        if account is None:
            raise AuthenticationSetupError(
                f"auth_type 'forgejo_token': no username and password for role '{role}'.",
                role=role,
            )
        basic_value = _basic_header(*account)
        context.register_secret(basic_value, f"{_BASIC_SECRET_LABEL} {role}")
        return account[0], basic_value

    @staticmethod
    def _created_token_body(response: httpx.Response, role: str) -> dict[str, Any]:
        """The JSON body of a token creation, or AuthenticationSetupError."""
        status_code = response.status_code
        text = response.text
        if status_code in _AUTH_REJECTION_CODES:
            raise AuthenticationSetupError(
                f"Forgejo rejected the credentials of role '{role}' (HTTP {status_code}). "
                "Check the username and password of this role in config.yaml.",
                role=role,
                status_code=status_code,
            )
        if status_code != _TOKEN_CREATED_STATUS:
            raise AuthenticationSetupError(
                f"Forgejo token creation for role '{role}' returned HTTP {status_code}, "
                f"expected {_TOKEN_CREATED_STATUS}. Response: {text[:_RESPONSE_BODY_PREVIEW]}",
                role=role,
                status_code=status_code,
            )
        try:
            body = response.json()
        except ValueError as exc:
            raise AuthenticationSetupError(
                f"Forgejo token creation for role '{role}': the response is not JSON.",
                role=role,
                status_code=status_code,
            ) from exc
        if not isinstance(body, dict):
            raise AuthenticationSetupError(
                f"Forgejo token creation for role '{role}': the response is not a JSON object.",
                role=role,
                status_code=status_code,
            )
        return body


def _basic_header(username: str, password: str) -> str:
    """'Basic <base64(username:password)>' (RFC 7617); never logged."""
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    return f"Basic {encoded}"
