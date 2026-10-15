"""
src/tests/helpers/auth_login.py

The login authentication method: the credential comes from a prepared resource.

credentials.login_resource names a resource of config.yaml (resources:) that
logs in for a role (docs/architecture/design-decisions.md, D6):

    create   the login request, e.g. a JSON login (auth: none, the account in
             the body as "{username}" and "{password}") or a token API
             (auth: basic);
    values   'credential': where the token is in the response;
    delete   optional: deletes the token at teardown.

Obtain: the resource is created for the role (requests attributed to
'auth_setup'), its value 'credential' is stored with context.set_token. How it
is sent is decided by the placement, as for every method.

Revocation (test 1.4): possible when the resource has a delete request. A
temporary credential is a new instance of the resource for the role; revoking
it sends its delete request at once (src/tests/helpers/resources.py).

Errors of the resource (ResourceSetupError) become AuthenticationSetupError:
the calling test returns ERROR with the message.

Dependency rule: imports from stdlib, pydantic, src.core and
src.tests.helpers.auth_base / resources. It must never import from
src.tests.domain_* or src.engine.
"""

from __future__ import annotations

import structlog
from pydantic import Field
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.exceptions import AuthenticationSetupError
from src.core.models import CREDENTIAL_VALUE, AuthType
from src.tests.helpers.auth_base import (
    RevocableAuthMethod,
    RevocationOutcome,
    TemporaryCredential,
)
from src.tests.helpers.resources import (
    PreparedResource,
    ResourceSetupError,
    create_resource,
    delete_resource,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

_AUTH_SETUP_TEST_ID: str = "auth_setup"
_SUCCESS_MIN: int = 200
_SUCCESS_MAX: int = 300


class LoginTemporaryCredential(TemporaryCredential):
    """A temporary credential of the login method: the resource it came from."""

    resource: PreparedResource = Field(
        repr=False, description="The login resource instance; its delete revokes the credential."
    )


class LoginAuthMethod(RevocableAuthMethod):
    """Credential from the prepared resource credentials.login_resource."""

    auth_type = AuthType.LOGIN

    def obtain_credential(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        role: str,
    ) -> None:
        """
        Create the login resource for the role and store its credential.

        Args:
            target:  The current TargetContext (credentials, resources).
            context: The TestContext (token, secrets, teardown).
            client:  The SecurityClient.
            role:    A ROLE_* constant.

        Raises:
            AuthenticationSetupError: If the login fails or its response lacks
                the credential.
            SecurityClientError: On transport failure.
        """
        prepared = self._login(target, context, client, role, _AUTH_SETUP_TEST_ID)
        context.set_token(role, prepared.values[CREDENTIAL_VALUE])
        log.info(
            "login_credential_acquired",
            role=role,
            resource=prepared.name,
            token_value="[REDACTED]",  # noqa: S106
        )

    def can_revoke(self, target: TargetContext) -> bool:
        """True when the login resource has a delete request."""
        name = target.credentials.login_resource
        resource = target.resources.get(name) if name is not None else None
        return resource is not None and resource.delete is not None

    def create_temporary_credential(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        role: str,
        test_id: str,
    ) -> TemporaryCredential:
        """
        Create a new instance of the login resource for the role.

        Its deletion is registered for teardown by the resource, and its
        credential as a secret.

        Args:
            target:  The current TargetContext.
            context: The TestContext.
            client:  The SecurityClient.
            role:    A ROLE_* constant.
            test_id: Test the requests are attributed to.

        Returns:
            The credential, with the resource that revokes it.

        Raises:
            AuthenticationSetupError: If the login fails.
            SecurityClientError: On transport failure.
        """
        prepared = self._login(target, context, client, role, test_id)
        return LoginTemporaryCredential(
            value=prepared.values[CREDENTIAL_VALUE],
            role=role,
            create_record=prepared.create_record,
            resource=prepared,
        )

    def revoke_credential(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        credential: TemporaryCredential,
        test_id: str,
    ) -> RevocationOutcome:
        """
        Send the delete request of the credential's resource now.

        Args:
            target:     The current TargetContext.
            context:    The TestContext.
            client:     The SecurityClient.
            credential: A credential from create_temporary_credential().
            test_id:    Test the request is attributed to.

        Returns:
            Revoked when the target answers 2xx.

        Raises:
            AuthenticationSetupError: If the credential does not come from this
                method or its resource has no delete request.
            SecurityClientError: On transport failure.
        """
        if not isinstance(credential, LoginTemporaryCredential):
            raise AuthenticationSetupError(
                "auth_type 'login' can revoke only a credential it created.",
                role=credential.role,
            )
        try:
            response, record = delete_resource(
                target, context, client, credential.resource, test_id
            )
        except ResourceSetupError as exc:
            raise AuthenticationSetupError(str(exc), role=credential.role) from exc
        return RevocationOutcome(
            revoked=_SUCCESS_MIN <= response.status_code < _SUCCESS_MAX,
            status_code=response.status_code,
            record=record,
        )

    @staticmethod
    def _login(
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        role: str,
        test_id: str,
    ) -> PreparedResource:
        """Create the login resource for a role; resource errors become AuthenticationSetupError."""
        name = target.credentials.login_resource
        if name is None:
            raise AuthenticationSetupError(
                "auth_type 'login' requires credentials.login_resource.", role=role
            )
        try:
            prepared = create_resource(target, context, client, name, role, test_id)
        except ResourceSetupError as exc:
            raise AuthenticationSetupError(
                f"Login of role '{role}' failed: {exc} Check the account of this role and "
                f"the resource '{name}' in config.yaml.",
                role=role,
            ) from exc
        if CREDENTIAL_VALUE not in prepared.values:
            raise AuthenticationSetupError(
                f"Login resource '{name}' has no value '{CREDENTIAL_VALUE}'.", role=role
            )
        return prepared
