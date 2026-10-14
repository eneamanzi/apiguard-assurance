"""
src/core/models/runtime.py

RuntimeCredentials: the credentials section of config.yaml. It is the one
model of that section: Phase 1 validates config.yaml with it, and the engine
puts the same object into TargetContext (target.credentials) in Phase 3.

The per-test parameters are not here: they live in src/test_config/ (one
model per test, the same model that validates config.yaml) and reach the
tests through TargetContext.tests_config (src/test_config/runtime.py).

Authentication is decided in two parts (docs/project/auth-survey.md):
    auth_type      how a credential is obtained (the method);
    security_scheme / send_as
                   where and how it is sent; completed with the schemes the
                   specification declares once the specification is loaded.
The checks that need the specification (which scheme, whether a prefix is
allowed) are not made here.

Dependency rule: this module imports only from pydantic and the stdlib.
It must never import from any other src/ module.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AuthType(StrEnum):
    """How the tool obtains a credential for each role."""

    BASIC = "basic"
    STATIC_TOKEN = "static_token"  # noqa: S105 -- a method name, not a secret
    JSON_LOGIN = "json_login"
    FORGEJO_TOKEN = "forgejo_token"  # noqa: S105 -- a method name, not a secret


class CredentialLocation(StrEnum):
    """Where a credential is sent (the OpenAPI apiKey locations)."""

    HEADER = "header"
    QUERY = "query"
    COOKIE = "cookie"


# Previous name of json_login (v0.1.0), rejected with a message naming the new one.
_RENAMED_AUTH_TYPES: dict[str, AuthType] = {"jwt_login": AuthType.JSON_LOGIN}

# Roles, as (role, username field, password field, token field). The role
# names are the ROLE_* constants of src/core/context.py, not imported here to
# keep this module free of src/ imports.
_ROLES: tuple[tuple[str, str, str, str], ...] = (
    ("admin", "admin_username", "admin_password", "admin_token"),
    ("user_a", "user_a_username", "user_a_password", "user_a_token"),
    ("user_b", "user_b_username", "user_b_password", "user_b_token"),
)

_SENSITIVE_DESCRIPTION: str = "From a ${VAR} placeholder; never logged, masked in every output."


# ---------------------------------------------------------------------------
# SendAs - how a credential is sent, completing the specification
# ---------------------------------------------------------------------------


class SendAs(BaseModel):
    """
    Where and how a credential is sent.

    Every field left out is taken from the security scheme the specification
    declares. With no declared scheme, 'location' and 'name' are required.
    'prefix' is written before the credential (e.g. "token " for Forgejo,
    whose apiKey scheme describes the prefix only in words).
    """

    model_config = {"frozen": True, "extra": "forbid", "populate_by_name": True}

    location: CredentialLocation | None = Field(
        default=None,
        alias="in",
        description="'header', 'query' or 'cookie' (key 'in' in config.yaml).",
    )
    name: str | None = Field(
        default=None,
        min_length=1,
        description="Name of the header, query parameter or cookie.",
    )
    prefix: str | None = Field(
        default=None,
        min_length=1,
        description="Text written before the credential, spaces included, e.g. 'token '.",
    )


# ---------------------------------------------------------------------------
# RuntimeCredentials - the credentials section of config.yaml
# ---------------------------------------------------------------------------


class RuntimeCredentials(BaseModel):
    """
    Credentials of the accounts the tests log in with, and how to use them.

    Roles: admin (the API's administrator, WHITE_BOX test 1.4), user_a (an
    ordinary account, GREY_BOX tests), user_b (a second ordinary account).
    Every value comes from a ${VAR} placeholder resolved by the loader: never
    write a credential in clear in config.yaml.

    auth_type, required when an account or a token is configured:
        basic          HTTP Basic with username and password (RFC 7617);
        static_token   a token given in config.yaml (<role>_token);
        json_login     POST login_endpoint with username and password in a
                       JSON body, token read at token_response_path;
        forgejo_token  Forgejo/Gitea token API (POST /api/v1/users/{username}/tokens).
    """

    model_config = {"frozen": True, "extra": "forbid"}

    auth_type: AuthType | None = Field(
        default=None,
        description=(
            "How a credential is obtained: 'basic', 'static_token', 'json_login', "
            "'forgejo_token'. Required when an account or a token is configured."
        ),
    )

    # Accounts (basic, json_login, forgejo_token)
    admin_username: str | None = Field(
        default=None, description="Admin username. " + _SENSITIVE_DESCRIPTION
    )
    admin_password: str | None = Field(
        default=None, description="Admin password. " + _SENSITIVE_DESCRIPTION
    )
    user_a_username: str | None = Field(
        default=None, description="User A username. " + _SENSITIVE_DESCRIPTION
    )
    user_a_password: str | None = Field(
        default=None, description="User A password. " + _SENSITIVE_DESCRIPTION
    )
    user_b_username: str | None = Field(
        default=None, description="User B username. " + _SENSITIVE_DESCRIPTION
    )
    user_b_password: str | None = Field(
        default=None, description="User B password. " + _SENSITIVE_DESCRIPTION
    )

    # Tokens (static_token)
    admin_token: str | None = Field(
        default=None, description="Admin token (static_token). " + _SENSITIVE_DESCRIPTION
    )
    user_a_token: str | None = Field(
        default=None, description="User A token (static_token). " + _SENSITIVE_DESCRIPTION
    )
    user_b_token: str | None = Field(
        default=None, description="User B token (static_token). " + _SENSITIVE_DESCRIPTION
    )

    # json_login
    login_endpoint: str | None = Field(
        default=None,
        description="json_login: path of the login endpoint, e.g. '/identity/api/auth/login'.",
    )
    username_body_field: str = Field(
        default="username",
        description="json_login: JSON body field for the username. Default 'username'.",
    )
    password_body_field: str = Field(
        default="password",
        description="json_login: JSON body field for the password. Default 'password'.",
    )
    token_response_path: str = Field(
        default="access_token",
        description=(
            "json_login: dotted path of the token in the login response, e.g. 'data.token'. "
            "Default 'access_token'."
        ),
    )

    # How the credential is sent
    security_scheme: str | None = Field(
        default=None,
        min_length=1,
        description=(
            "Name of the specification's security scheme to send the credential with; "
            "required when the specification declares more than one usable scheme."
        ),
    )
    send_as: SendAs | None = Field(
        default=None,
        description=(
            "Where and how the credential is sent: completes the declared scheme (e.g. a "
            "prefix), or describes it when the specification declares none."
        ),
    )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @model_validator(mode="before")
    @classmethod
    def reject_renamed_auth_type(cls, data: object) -> object:
        """Reject an auth_type renamed since v0.1.0, naming the new value."""
        if isinstance(data, dict):
            old = data.get("auth_type")
            if isinstance(old, str) and old in _RENAMED_AUTH_TYPES:
                raise ValueError(
                    f"auth_type '{old}' was renamed to '{_RENAMED_AUTH_TYPES[old].value}': "
                    "update credentials.auth_type."
                )
        return data

    @model_validator(mode="after")
    def validate_credentials(self) -> RuntimeCredentials:
        """
        Check the section without the specification.

        1. A configured account or token needs auth_type.
        2. Each method takes its own kind of credential: static_token tokens
           only; the others username and password, given together.
        3. json_login needs login_endpoint.
        4. basic has a fixed format: no security_scheme, no send_as.
        """
        configured = [
            field
            for _, username, password, token in _ROLES
            for field in (username, password, token)
            if _present(getattr(self, field))
        ]
        if self.auth_type is None:
            if configured:
                raise ValueError(
                    f"credentials.auth_type is required when credentials are configured "
                    f"(found: {', '.join(configured)}). Supported values: "
                    f"{', '.join(t.value for t in AuthType)}."
                )
            return self

        for role, username, password, token in _ROLES:
            if self.auth_type is AuthType.STATIC_TOKEN:
                for field in (username, password):
                    if _present(getattr(self, field)):
                        raise ValueError(
                            f"auth_type 'static_token' uses <role>_token: remove "
                            f"credentials.{field} (role '{role}')."
                        )
                continue
            if _present(getattr(self, token)):
                raise ValueError(
                    f"credentials.{token} is used only by auth_type 'static_token' "
                    f"(current: '{self.auth_type.value}')."
                )
            has_username = _present(getattr(self, username))
            has_password = _present(getattr(self, password))
            if has_username != has_password:
                missing = password if has_username else username
                raise ValueError(
                    f"Credential pair incomplete for role '{role}': "
                    f"credentials.{missing} is missing."
                )

        if self.auth_type is AuthType.JSON_LOGIN and not _present(self.login_endpoint):
            raise ValueError("auth_type 'json_login' requires credentials.login_endpoint.")
        if self.auth_type is AuthType.BASIC and (
            self.security_scheme is not None or self.send_as is not None
        ):
            raise ValueError(
                "auth_type 'basic' always sends 'Authorization: Basic ...' (RFC 7617): "
                "remove credentials.security_scheme and credentials.send_as."
            )
        return self

    # ------------------------------------------------------------------
    # Roles
    # ------------------------------------------------------------------

    def has_role(self, role: str) -> bool:
        """
        True if the role has what its method needs: a token for static_token,
        username and password otherwise.

        Args:
            role: 'admin', 'user_a' or 'user_b' (ROLE_* constants).
        """
        for name, username, password, token in _ROLES:
            if name != role:
                continue
            if self.auth_type is AuthType.STATIC_TOKEN:
                return _present(getattr(self, token))
            return _present(getattr(self, username)) and _present(getattr(self, password))
        return False

    def has_admin(self) -> bool:
        """True if the admin role is configured (see has_role)."""
        return self.has_role("admin")

    def has_user_a(self) -> bool:
        """True if the user_a role is configured (see has_role)."""
        return self.has_role("user_a")

    def has_user_b(self) -> bool:
        """True if the user_b role is configured (see has_role)."""
        return self.has_role("user_b")

    def has_any_credentials(self) -> bool:
        """True if at least one role is configured."""
        return any(self.has_role(role) for role, _, _, _ in _ROLES)


def _present(value: object) -> bool:
    """True for a non-empty, non-blank string."""
    return isinstance(value, str) and bool(value.strip())
