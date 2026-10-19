"""
src/tests/helpers/auth.py

Public entry point of authentication for the tests that log in to the API.

Two separate questions (docs/architecture/design-decisions.md, D5):
    how a credential is obtained   the method of credentials.auth_type
                                   (AUTH_METHODS below; one class per method);
    how it is sent                 TargetContext.credential_placement, resolved
                                   once per run (src/core/auth_placement.py).

Functions for the tests:
    acquire_tokens(target, context, client, required_roles)
        Obtain the credential of each configured role not yet in TestContext.
        Idempotent: a role that already has one is skipped without requests.
    auth_parts(target, context, role)
        The headers and query parameters that carry the role's credential;
        merge them into the request instead of writing 'Bearer' by hand.
    credential_parts(target, credential)
        The same for a credential that is not stored for a role (the
        temporary credential of test 1.4).
    revocation_capability(target)
        The configured method when it can revoke a credential as configured
        (login: its resource has a delete request), else None.

Adding a method: a class implementing AuthMethod (auth_base.py), an AuthType
value (src/core/models/runtime.py, with its checks in validate_credentials)
and an entry in AUTH_METHODS.

Dependency rule: imports from stdlib, src.core and the src.tests.helpers.auth_*
modules. It must never import from src.tests.domain_* or src.engine.
"""

from __future__ import annotations

import structlog
from src.core.auth_placement import RequestAuthParts
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.exceptions import AuthenticationSetupError
from src.core.models import AuthType
from src.tests.helpers.auth_base import ROLE_CREDENTIAL_FIELDS, AuthMethod, RevocableAuthMethod
from src.tests.helpers.auth_login import LoginAuthMethod
from src.tests.helpers.auth_static import BasicAuthMethod, StaticTokenAuthMethod

log: structlog.BoundLogger = structlog.get_logger(__name__)

# One instance per method: the methods keep no state of their own.
AUTH_METHODS: dict[AuthType, AuthMethod] = {
    method.auth_type: method
    for method in (
        BasicAuthMethod(),
        StaticTokenAuthMethod(),
        LoginAuthMethod(),
    )
}

_PASSWORD_SECRET_LABEL: str = "password of role"  # noqa: S105 -- a label, not a credential
_TOKEN_SECRET_LABEL: str = "configured token of role"  # noqa: S105 -- a label, not a credential


def acquire_tokens(
    target: TargetContext,
    context: TestContext,
    client: SecurityClient,
    required_roles: frozenset[str] | None = None,
) -> None:
    """
    Obtain the credential of each configured role that has none yet.

    Roles are taken in the order admin, user_a, user_b. A role without
    credentials is skipped (a test that needs the role declares it: info.needs).
    The role's password and configured token are registered as secrets
    before any request, so they are masked in every output.

    Args:
        target:         TargetContext carrying credentials and auth_type.
        context:        TestContext where the credentials are stored.
        client:         SecurityClient for the method's requests.
        required_roles: Only these roles (e.g. frozenset({ROLE_USER_A}));
                        None for every configured role.

    Raises:
        AuthenticationSetupError: If the method fails for a required role.
        SecurityClientError: On transport-layer failure.
    """
    auth_type = target.credentials.auth_type
    log.debug("auth_acquire_called", auth_type=str(auth_type), required_roles=required_roles)
    if auth_type is None:
        return
    method = AUTH_METHODS[auth_type]
    for role, (_, password_field, token_field) in ROLE_CREDENTIAL_FIELDS.items():
        if required_roles is not None and role not in required_roles:
            continue
        if not target.credentials.has_role(role):
            log.debug("auth_skipping_role_no_credentials", role=role)
            continue
        if context.has_token(role):
            continue
        for field, label in (
            (password_field, _PASSWORD_SECRET_LABEL),
            (token_field, _TOKEN_SECRET_LABEL),
        ):
            value = getattr(target.credentials, field)
            if value:
                context.register_secret(str(value), f"{label} {role}")
        method.obtain_credential(target, context, client, role)


def auth_parts(target: TargetContext, context: TestContext, role: str) -> RequestAuthParts:
    """
    Return the request parts carrying the credential of a role.

    Args:
        target:  The current TargetContext (placement).
        context: The TestContext holding the role's credential.
        role:    A ROLE_* constant.

    Returns:
        Headers and query parameters to merge into the request.

    Raises:
        AuthenticationSetupError: If the role has no credential in TestContext
            (acquire_tokens() not called, or the role is not configured).
    """
    credential = context.get_token(role)
    if credential is None:
        raise AuthenticationSetupError(
            f"No credential for role '{role}': call acquire_tokens() first, and configure "
            "the role's credentials.",
            role=role,
        )
    return credential_parts(target, credential)


def credential_parts(target: TargetContext, credential: str) -> RequestAuthParts:
    """
    Return the request parts carrying a credential, as the placement says.

    Args:
        target:     The current TargetContext (placement).
        credential: The credential value.

    Returns:
        Headers and query parameters to merge into the request.

    Raises:
        AuthenticationSetupError: If no placement was resolved (no credentials
            configured).
    """
    placement = target.credential_placement
    if placement is None:
        raise AuthenticationSetupError(
            "No credential placement: credentials.auth_type is not configured."
        )
    return placement.request_parts(credential)


def revocation_capability(target: TargetContext) -> RevocableAuthMethod | None:
    """
    Return the configured method when it can revoke a credential.

    Args:
        target: The current TargetContext.

    Returns:
        The method, or None when no method is configured or it cannot revoke.
    """
    auth_type = target.credentials.auth_type
    if auth_type is None:
        return None
    method = AUTH_METHODS[auth_type]
    if isinstance(method, RevocableAuthMethod) and method.can_revoke(target):
        return method
    return None
