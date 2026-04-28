"""
src/tests/helpers/auth.py

Public auth dispatcher for GREY_BOX test credential acquisition.

Responsibility
--------------
This module is the single import point that every GREY_BOX test uses to
acquire authentication tokens.  It reads target.credentials.auth_type and
delegates to the appropriate implementation:

    "forgejo_token"  ->  auth_forgejo.acquire_all_tokens_if_needed()
    "jwt_login"      ->  auth_jwt_login.acquire_all_tokens_if_needed()

Adding a new auth_type requires:
    1. Implementing a module src/tests/helpers/auth_{type}.py with the
       function acquire_all_tokens_if_needed() following the same signature
       and contract as the existing implementations.
    2. Adding the new auth_type to the elif chain in acquire_tokens() below.
    3. Adding the new auth_type to the supported values in
       src/config/schema/tool_config.py CredentialsConfig.validate_credentials().
    4. Documenting the new type in the CredentialsConfig docstring.

The dispatcher is intentionally thin (< 40 lines of logic).  It contains no
token-acquisition logic of its own.  Domain knowledge lives in the
implementation modules; the dispatcher only routes.

Idempotency contract
--------------------
Every implementation must be idempotent: calling acquire_all_tokens_if_needed()
multiple times within the same pipeline run is safe.  Roles that already have
a token in TestContext are skipped without making network calls.  This allows
multiple GREY_BOX tests to call acquire_tokens() at the start of execute()
without duplicating HTTP requests or creating redundant teardown entries.

Dependency rule
---------------
This module imports from:
    - stdlib only
    - src.core.client, src.core.context, src.core.exceptions
It must never import from src.tests.domain_* or src.engine.
The implementation modules are imported lazily (inside the elif branches) to
avoid loading all implementations when only one is needed.
"""

from __future__ import annotations

import structlog
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.exceptions import AuthenticationSetupError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Public dispatcher
# ---------------------------------------------------------------------------

_SUPPORTED_AUTH_TYPES: tuple[str, ...] = ("forgejo_token", "jwt_login")


def acquire_tokens(
    target: TargetContext,
    context: TestContext,
    client: SecurityClient,
    required_roles: frozenset[str] | None = None,
) -> None:
    """
    Acquire authentication tokens for all configured roles.

    Reads target.credentials.auth_type and delegates to the corresponding
    implementation module.  Idempotent: roles that already have a token in
    TestContext are skipped.

    Args:
        target:         TargetContext carrying credentials and auth_type.
        context:        TestContext where acquired tokens are stored.
        client:         SecurityClient for HTTP calls.
        required_roles: If provided, acquire only these roles (e.g.
                        frozenset({"admin", "user_a"})). If None, acquire
                        all roles that have credentials configured in
                        target.credentials.

    Raises:
        AuthenticationSetupError: If auth_type is unsupported, or if token
            acquisition fails for any required role.
    """
    auth_type = target.credentials.auth_type

    log.debug("auth_dispatcher_called", auth_type=auth_type, required_roles=required_roles)

    if auth_type == "forgejo_token":
        from src.tests.helpers.auth_forgejo import acquire_all_tokens_if_needed

        acquire_all_tokens_if_needed(target, context, client, required_roles)

    elif auth_type == "jwt_login":
        from src.tests.helpers.auth_jwt_login import acquire_all_tokens_if_needed

        acquire_all_tokens_if_needed(target, context, client, required_roles)

    else:
        raise AuthenticationSetupError(
            f"Unsupported auth_type: '{auth_type}'. "
            f"Supported values: {sorted(_SUPPORTED_AUTH_TYPES)}. "
            "To add a new auth type, see the module docstring in "
            "src/tests/helpers/auth.py."
        )
