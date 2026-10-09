"""
src/core/models/runtime.py

RuntimeCredentials: the immutable credentials propagated into TargetContext
by the engine during Phase 3 and read by the tests through target.credentials.

The per-test parameters are not here: they live in src/test_config/ (one
model per test, the same model that validates config.yaml) and reach the
tests through TargetContext.tests_config (src/test_config/runtime.py).

Dependency rule: this module imports only from pydantic and the stdlib.
It must never import from any other src/ module.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# RuntimeCredentials — immutable credentials propagated to TargetContext
# ---------------------------------------------------------------------------


class RuntimeCredentials(BaseModel):
    """
    Immutable snapshot of credentials propagated into TargetContext.

    Lives in core/ so TargetContext can reference it without importing from
    config/ (unidirectional dependency rule: config/ imports core/, never reverse).

    auth_type mirrors CredentialsConfig.auth_type and is read by the auth
    dispatcher (src/tests/helpers/auth.py) to select the correct token-acquisition
    implementation at runtime. The jwt_login-specific fields are only populated
    when auth_type == 'jwt_login'; they are None otherwise.
    """

    model_config = {"frozen": True}

    # ------------------------------------------------------------------
    # Auth type discriminator -- mirrors CredentialsConfig.auth_type
    # ------------------------------------------------------------------

    auth_type: str = Field(
        default="forgejo_token",
        description=(
            "Token-acquisition strategy. Mirrors CredentialsConfig.auth_type. "
            "Read by the auth dispatcher to select the implementation. "
            "Supported: 'forgejo_token', 'jwt_login'."
        ),
    )

    # ------------------------------------------------------------------
    # Common credential fields
    # ------------------------------------------------------------------

    admin_username: str | None = Field(
        default=None,
        description="Resolved admin username (from ${VAR}); None if not configured. "
        "Sensitive — never logged in plain text.",
    )
    admin_password: str | None = Field(
        default=None,
        description="Resolved admin password (from ${VAR}); None if not configured. "
        "Sensitive — always [REDACTED] in logs.",
    )
    user_a_username: str | None = Field(
        default=None,
        description="Resolved user-A username (from ${VAR}); None if not configured. "
        "Sensitive — never logged in plain text.",
    )
    user_a_password: str | None = Field(
        default=None,
        description="Resolved user-A password (from ${VAR}); None if not configured. "
        "Sensitive — always [REDACTED] in logs.",
    )
    user_b_username: str | None = Field(
        default=None,
        description="Resolved user-B username (from ${VAR}); None if not configured. "
        "Sensitive — never logged in plain text.",
    )
    user_b_password: str | None = Field(
        default=None,
        description="Resolved user-B password (from ${VAR}); None if not configured. "
        "Sensitive — always [REDACTED] in logs.",
    )

    # ------------------------------------------------------------------
    # jwt_login specific fields -- None when auth_type != 'jwt_login'
    # ------------------------------------------------------------------

    login_endpoint: str | None = Field(
        default=None,
        description=(
            "Mirrors CredentialsConfig.login_endpoint. "
            "Absolute path of the login endpoint for jwt_login auth. "
            "None when auth_type is not 'jwt_login'."
        ),
    )
    username_body_field: str = Field(
        default="username",
        description="Mirrors CredentialsConfig.username_body_field.",
    )
    password_body_field: str = Field(
        default="password",
        description="Mirrors CredentialsConfig.password_body_field.",
    )
    token_response_path: str = Field(
        default="access_token",
        description=(
            "Mirrors CredentialsConfig.token_response_path. "
            "Dotted JSONPath to extract the token from the login response."
        ),
    )

    def has_admin(self) -> bool:
        """True if both admin_username and admin_password are present and non-empty."""
        return bool(
            self.admin_username
            and self.admin_username.strip()
            and self.admin_password
            and self.admin_password.strip()
        )

    def has_user_a(self) -> bool:
        """True if both user_a_username and user_a_password are present and non-empty."""
        return bool(
            self.user_a_username
            and self.user_a_username.strip()
            and self.user_a_password
            and self.user_a_password.strip()
        )

    def has_user_b(self) -> bool:
        """True if both user_b_username and user_b_password are present and non-empty."""
        return bool(
            self.user_b_username
            and self.user_b_username.strip()
            and self.user_b_password
            and self.user_b_password.strip()
        )

    def has_any_credentials(self) -> bool:
        """True if at least one role has complete credentials configured."""
        return self.has_admin() or self.has_user_a() or self.has_user_b()

    def available_roles(self) -> list[str]:
        """
        Return the list of role names with complete credentials configured.

        Role name strings match ROLE_* constants in context.py.
        Local import avoided here to prevent a circular dependency.
        """
        roles: list[str] = []
        if self.has_admin():
            roles.append("admin")
        if self.has_user_a():
            roles.append("user_a")
        if self.has_user_b():
            roles.append("user_b")
        return roles
