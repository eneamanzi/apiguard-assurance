"""
src/core/models/runtime.py

RuntimeCredentials: the credentials section of config.yaml. It is the one
model of that section: Phase 1 validates config.yaml with it, and the engine
puts the same object into TargetContext (target.credentials) in Phase 3.

The per-test parameters are not here: each test declares its own model in
its module (BaseTest[Test21Params]) and reads it with self.params(target).

Authentication is decided in two parts (docs/architecture/design-decisions.md, D5):
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
from pydantic.config import JsonDict

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class AuthType(StrEnum):
    """How the tool obtains a credential for each role."""

    BASIC = "basic"
    STATIC_TOKEN = "static_token"  # noqa: S105 -- a method name, not a secret
    LOGIN = "login"


class CredentialLocation(StrEnum):
    """Where a credential is sent (the OpenAPI apiKey locations)."""

    HEADER = "header"
    QUERY = "query"
    COOKIE = "cookie"


# Roles, as (role, username field, password field, token field). The role
# names are the ROLE_* constants of src/core/context.py, not imported here to
# keep this module free of src/ imports.
_ROLES: tuple[tuple[str, str, str, str], ...] = (
    ("admin", "admin_username", "admin_password", "admin_token"),
    ("user_a", "user_a_username", "user_a_password", "user_a_token"),
    ("user_b", "user_b_username", "user_b_password", "user_b_token"),
)

# Marks a configuration field whose value is a secret (for a mapping: each of its
# values), as Field(json_schema_extra=SECRET_VALUE): the configuration a run used
# (config_used.yaml, src/config/config_used.py) writes it only as a ${VAR} placeholder.
SECRET_VALUE: JsonDict = {"secret_value": True}


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
        description="Where the credential is sent: `header`, `query` or `cookie`.",
    )
    name: str | None = Field(
        default=None,
        min_length=1,
        description="Name of the header, query parameter or cookie.",
    )
    prefix: str | None = Field(
        default=None,
        min_length=1,
        description='Text written before the credential, spaces included (Forgejo: `"token "`).',
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
        login          the prepared resource login_resource (resources: in
                       config.yaml) is created for each role; its value
                       'credential' is the token, its delete request (if
                       any) deletes the token at teardown and revokes it
                       for test 1.4.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    auth_type: AuthType | None = Field(
        default=None,
        description=(
            "How a credential is obtained. **Required** when an account or a token is "
            "configured. `basic` (HTTP Basic with username and password, RFC 7617), "
            "`static_token` (the `<role>_token` values), `login` (the prepared resource "
            "`login_resource` is created for each role: its value `credential` is the "
            "token; its delete request, if any, deletes the token at the end of the run and "
            "lets test 1.4 revoke one)."
        ),
    )

    # Accounts (basic, login)
    admin_username: str | None = Field(
        default=None,
        description=(
            "Username of the administrator role (`basic`, `login`). Not a secret: it may "
            "appear in the outputs (e.g. in a path)."
        ),
    )
    admin_password: str | None = Field(
        default=None,
        description=(
            "Password of the administrator role (`basic`, `login`). Write it as a `${VAR}` "
            "placeholder: never logged, and masked in every output when it has 8 characters "
            "or more."
        ),
        json_schema_extra=SECRET_VALUE,
    )
    user_a_username: str | None = Field(
        default=None,
        description=(
            "Username of the first non-privileged role (`basic`, `login`). Not a secret: it "
            "may appear in the outputs (e.g. in a path)."
        ),
    )
    user_a_password: str | None = Field(
        default=None,
        description=(
            "Password of the first non-privileged role (`basic`, `login`). Write it as a "
            "`${VAR}` placeholder: never logged, and masked in every output when it has 8 "
            "characters or more."
        ),
        json_schema_extra=SECRET_VALUE,
    )
    user_b_username: str | None = Field(
        default=None,
        description=(
            "Username of the second non-privileged role (`basic`, `login`). Not a secret: "
            "it may appear in the outputs (e.g. in a path)."
        ),
    )
    user_b_password: str | None = Field(
        default=None,
        description=(
            "Password of the second non-privileged role (`basic`, `login`). Write it as a "
            "`${VAR}` placeholder: never logged, and masked in every output when it has 8 "
            "characters or more."
        ),
        json_schema_extra=SECRET_VALUE,
    )

    # Tokens (static_token)
    admin_token: str | None = Field(
        default=None,
        description=(
            "`static_token` only: the token of the administrator role. Write it as a "
            "`${VAR}` placeholder: never logged, and masked in every output when it has 8 "
            "characters or more."
        ),
        json_schema_extra=SECRET_VALUE,
    )
    user_a_token: str | None = Field(
        default=None,
        description=(
            "`static_token` only: the token of the first non-privileged role. Write it as a "
            "`${VAR}` placeholder: never logged, and masked in every output when it has 8 "
            "characters or more."
        ),
        json_schema_extra=SECRET_VALUE,
    )
    user_b_token: str | None = Field(
        default=None,
        description=(
            "`static_token` only: the token of the second non-privileged role. Write it as "
            "a `${VAR}` placeholder: never logged, and masked in every output when it has 8 "
            "characters or more."
        ),
        json_schema_extra=SECRET_VALUE,
    )

    # login
    login_resource: str | None = Field(
        default=None,
        min_length=1,
        description=(
            "`login` only, **required** there: the name of a prepared resource "
            "(`resources`) whose create request logs in for a role (`auth: basic` or "
            "`none`) and whose values include `credential`, the dotted path of the token in "
            "the response."
        ),
    )

    # How the credential is sent
    security_scheme: str | None = Field(
        default=None,
        min_length=1,
        description=(
            "Name of the specification's security scheme the credential is sent with. "
            "**Required** when the specification declares more than one scheme that can "
            "carry a token (e.g. Forgejo: `AuthorizationHeaderToken`). Not with `basic`."
        ),
    )
    send_as: SendAs | None = Field(
        default=None,
        description=(
            "Where and how the credential is sent. Every field left out comes from the "
            "specification's scheme; with no usable scheme `in` and `name` are required. "
            "With a declared scheme `in` and `name` may only repeat the scheme's, and a "
            '`prefix` is allowed only for an `apiKey` scheme (Forgejo: `prefix: "token "`). '
            "Not with `basic`."
        ),
    )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @model_validator(mode="after")
    def validate_credentials(self) -> RuntimeCredentials:
        """
        Check the section without the specification.

        1. A configured account or token needs auth_type.
        2. Each method takes its own kind of credential: static_token tokens
           only; the others username and password, given together.
        3. login needs login_resource; only login takes it.
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

        if self.auth_type is AuthType.LOGIN and self.login_resource is None:
            raise ValueError(
                "auth_type 'login' requires credentials.login_resource, the name of a "
                "prepared resource (resources:) that logs in."
            )
        if self.auth_type is not AuthType.LOGIN and self.login_resource is not None:
            raise ValueError(
                f"credentials.login_resource is used only by auth_type 'login' "
                f"(current: '{self.auth_type.value}')."
            )
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
