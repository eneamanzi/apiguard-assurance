"""
src/tests/helpers/auth_static.py

The two authentication methods that make no request to obtain a credential.

    basic         HTTP Basic (RFC 7617): the credential is base64 of
                  'username:password'; the placement writes 'Basic ' before it.
    static_token  The token configured for the role (credentials.<role>_token),
                  sent as the placement says.

Neither can revoke a credential.

Dependency rule: imports from stdlib, src.core and src.tests.helpers.auth_base.
"""

from __future__ import annotations

import base64

import structlog
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.exceptions import AuthenticationSetupError
from src.core.models import AuthType
from src.tests.helpers.auth_base import ROLE_CREDENTIAL_FIELDS, AuthMethod, role_account

log: structlog.BoundLogger = structlog.get_logger(__name__)


class BasicAuthMethod(AuthMethod):
    """HTTP Basic with the configured username and password."""

    auth_type = AuthType.BASIC

    def obtain_credential(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        role: str,
    ) -> None:
        """
        Store base64('username:password') as the credential of the role.

        Args:
            target:  The current TargetContext.
            context: The TestContext where the credential is stored.
            client:  Unused: no request is made.
            role:    A ROLE_* constant.

        Raises:
            AuthenticationSetupError: When the role has no complete account.
        """
        account = role_account(target, role)
        if account is None:
            raise AuthenticationSetupError(
                f"auth_type 'basic': no username and password configured for role '{role}'.",
                role=role,
            )
        username, password = account
        encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
        context.set_token(role, encoded)
        log.info("auth_basic_credential_ready", role=role, credential="[REDACTED]")


class StaticTokenAuthMethod(AuthMethod):
    """A token given in the configuration (credentials.<role>_token)."""

    auth_type = AuthType.STATIC_TOKEN

    def obtain_credential(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        role: str,
    ) -> None:
        """
        Store the configured token as the credential of the role.

        Args:
            target:  The current TargetContext.
            context: The TestContext where the credential is stored.
            client:  Unused: no request is made.
            role:    A ROLE_* constant.

        Raises:
            AuthenticationSetupError: When the role has no token configured.
        """
        token_field = ROLE_CREDENTIAL_FIELDS[role][2]
        token = getattr(target.credentials, token_field)
        if not token:
            raise AuthenticationSetupError(
                f"auth_type 'static_token': credentials.{token_field} is not configured.",
                role=role,
            )
        context.set_token(role, str(token))
        log.info("auth_static_token_ready", role=role, token="[REDACTED]")  # noqa: S106
