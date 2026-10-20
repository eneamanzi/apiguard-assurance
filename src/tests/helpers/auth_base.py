"""
src/tests/helpers/auth_base.py

Common shape of the authentication methods (credentials.auth_type).

A method has one responsibility: obtain a credential for a role and store it
in TestContext (context.set_token), where it is registered as a secret and
reused by every test of the run. Where and how the credential is sent is not
the method's business: TargetContext.credential_placement decides it for every
method (src/core/auth_placement.py), and auth.auth_parts() applies it.

A method may also be able to revoke a credential (RevocableAuthMethod): create
a temporary credential and revoke it, used by test 1.4. Whether it can may
depend on the configuration (login: its resource has a delete request), so
the method answers can_revoke(target); without the capability 1.4 SKIPs.

Design: docs/04-architecture/05-design-decisions.md, D5 and D6.

Dependency rule: imports from stdlib, pydantic, src.core only.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import BaseModel, Field
from src.core.client import SecurityClient
from src.core.context import ROLE_ADMIN, ROLE_USER_A, ROLE_USER_B, TargetContext, TestContext
from src.core.models import AuthType, EvidenceRecord

# Fields of RuntimeCredentials for each role: (username, password, token).
ROLE_CREDENTIAL_FIELDS: dict[str, tuple[str, str, str]] = {
    ROLE_ADMIN: ("admin_username", "admin_password", "admin_token"),
    ROLE_USER_A: ("user_a_username", "user_a_password", "user_a_token"),
    ROLE_USER_B: ("user_b_username", "user_b_password", "user_b_token"),
}


def role_account(target: TargetContext, role: str) -> tuple[str, str] | None:
    """
    Return the (username, password) configured for a role, or None.

    Args:
        target: The current TargetContext.
        role:   A ROLE_* constant.

    Returns:
        The account, or None when the role has no complete account.
    """
    username_field, password_field, _ = ROLE_CREDENTIAL_FIELDS[role]
    username = getattr(target.credentials, username_field)
    password = getattr(target.credentials, password_field)
    if not username or not password:
        return None
    return str(username), str(password)


# ---------------------------------------------------------------------------
# AuthMethod
# ---------------------------------------------------------------------------


class AuthMethod(ABC):
    """
    How the tool obtains a credential for a role.

    Contract of obtain_credential():
        - called only for a role the method can serve
          (target.credentials.has_role(role)) and without a token yet;
        - stores the credential with context.set_token(role, value), the value
          as the placement expects it (a token, or base64 'user:password'
          for HTTP Basic);
        - registers for Phase 6 teardown anything it creates on the target;
        - raises AuthenticationSetupError when the target rejects the account,
          SecurityClientError on a transport failure.
    """

    auth_type: ClassVar[AuthType]

    @abstractmethod
    def obtain_credential(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        role: str,
    ) -> None:
        """
        Obtain the credential of a role and store it in the TestContext.

        Args:
            target:  The current TargetContext (credentials, placement).
            context: The TestContext where the credential is stored.
            client:  The SecurityClient for any request the method makes.
            role:    A ROLE_* constant.
        """


# ---------------------------------------------------------------------------
# Revocation capability
# ---------------------------------------------------------------------------


class TemporaryCredential(BaseModel):
    """
    A credential created to be revoked (test 1.4).

    A method that needs more to revoke it (e.g. the resource it came from)
    returns a subclass of its own.
    """

    model_config = {"frozen": True}

    value: str = Field(
        min_length=1, repr=False, description="The credential; registered as a secret."
    )
    role: str = Field(description="The role whose account created it (a ROLE_* constant).")
    create_record: EvidenceRecord = Field(description="The creation request and response.")


class RevocationOutcome(BaseModel):
    """Result of a revocation request."""

    model_config = {"frozen": True}

    revoked: bool = Field(description="True when the target confirmed the revocation.")
    status_code: int = Field(description="HTTP status of the revocation request.")
    record: EvidenceRecord = Field(description="The revocation request and response.")


class RevocableAuthMethod(AuthMethod):
    """
    A method that can also create a temporary credential and revoke it.

    Both requests are attributed to the calling test (test_id), so that they
    appear in its evidence.
    """

    @abstractmethod
    def can_revoke(self, target: TargetContext) -> bool:
        """
        True when the method, as configured, can revoke a credential.

        Args:
            target: The current TargetContext (configuration).
        """

    @abstractmethod
    def create_temporary_credential(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        role: str,
        test_id: str,
    ) -> TemporaryCredential:
        """
        Create a credential for a role, registered as a secret and for teardown.

        Args:
            target:  The current TargetContext.
            context: The TestContext (secrets, teardown).
            client:  The SecurityClient.
            role:    A ROLE_* constant whose account creates the credential.
            test_id: Test the requests are attributed to.

        Returns:
            The created credential.

        Raises:
            AuthenticationSetupError: When the role has no account or the target
                refuses to create the credential.
            SecurityClientError: On a transport failure.
        """

    @abstractmethod
    def revoke_credential(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        credential: TemporaryCredential,
        test_id: str,
    ) -> RevocationOutcome:
        """
        Revoke a credential created by create_temporary_credential().

        Args:
            target:     The current TargetContext.
            context:    The TestContext (the role's credential, secrets).
            client:     The SecurityClient.
            credential: The credential to revoke (it carries its role).
            test_id:    Test the request is attributed to.

        Returns:
            The outcome, with the request record.

        Raises:
            AuthenticationSetupError: When the credential cannot be revoked as
                configured.
            SecurityClientError: On a transport failure.
        """
