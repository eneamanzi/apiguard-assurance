"""
src/core/models/resources.py

Prepared resources: the resources section of config.yaml.

A resource is something the tool creates on the target and deletes at the end
of the run (docs/architecture/design-decisions.md, D6): a create request, values taken
from its JSON response, an optional delete request. Tests and the login method
use a resource by its name; the test chooses the role it is created for, the
resource says how each request authenticates.

    resources:
      repository:
        create:
          path: /api/v1/user/repos
          body: {name: "apiguard-{random}", private: true}
        values:
          owner: owner.login
          repo: name
        delete:
          path: /api/v1/repos/{owner}/{repo}

Placeholders (src/core/templating.py):
    create   {username}, {password} (the role's account), {random}
    delete   the same, plus the names of 'values'

The checks here concern one resource alone. Checks across sections (a
resource name used by a test or by credentials, a role without a password)
are made where those keys are defined.

Dependency rule: imports only from pydantic, the stdlib and
src.core.templating (itself stdlib only).
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel, Field, JsonValue, field_validator, model_validator

from src.core.templating import names_in, placeholder_names, unquoted_placeholders

# ---------------------------------------------------------------------------
# Names shared with the code that uses resources
# ---------------------------------------------------------------------------

# The account of the role the resource is created for.
PLACEHOLDER_USERNAME: str = "username"
PLACEHOLDER_PASSWORD: str = "password"  # noqa: S105 -- a placeholder name, not a credential
# 8 hexadecimal characters, the same in the create and delete request of one resource.
PLACEHOLDER_RANDOM: str = "random"

# Placeholders every request of a resource can use.
FIXED_PLACEHOLDERS: frozenset[str] = frozenset(
    {PLACEHOLDER_USERNAME, PLACEHOLDER_PASSWORD, PLACEHOLDER_RANDOM}
)

# The value of a login resource that holds the credential (always a secret).
CREDENTIAL_VALUE: str = "credential"

_ALLOWED_METHODS: frozenset[str] = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
# A value name: a placeholder name (letters, digits, underscore).
_VALUE_NAME_PATTERN: re.Pattern[str] = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_PATH_PREFIX: str = "/"
_DOTTED_SEPARATOR: str = "."


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------


class ResourceAuth(StrEnum):
    """How a request of a resource authenticates, as the role it is created for."""

    CREDENTIAL = "credential"  # the role's credential, sent as the placement says
    BASIC = "basic"  # HTTP Basic with the role's username and password
    NONE = "none"  # nothing (a login request)


class _ResourceRequest(BaseModel):
    """Fields common to the create and the delete request."""

    model_config = {"frozen": True, "extra": "forbid"}

    path: str = Field(
        min_length=1,
        description=(
            "Request path, starting with '/'; may hold placeholders, e.g. '/repos/{owner}'."
        ),
    )
    auth: ResourceAuth = Field(
        default=ResourceAuth.CREDENTIAL,
        description=(
            "How the request authenticates: 'credential' (the role's credential, default), "
            "'basic' (HTTP Basic with the role's username and password), 'none'."
        ),
    )

    @field_validator("method", mode="after", check_fields=False)
    @classmethod
    def method_allowed(cls, value: str) -> str:
        """Accept GET, POST, PUT, PATCH, DELETE, in any case; store uppercase."""
        method = value.upper()
        if method not in _ALLOWED_METHODS:
            raise ValueError(
                f"method '{value}' is not supported: use one of "
                f"{', '.join(sorted(_ALLOWED_METHODS))}."
            )
        return method

    @field_validator("path", mode="after")
    @classmethod
    def path_absolute(cls, value: str) -> str:
        """Require a path starting with '/', with well-formed placeholders."""
        if not value.startswith(_PATH_PREFIX):
            raise ValueError(f"path '{value}' must start with '/'.")
        placeholder_names(value)
        return value

    def json_body(self) -> JsonValue:
        """Return the JSON body of the request; None when it has none."""
        return None

    def placeholders(self) -> frozenset[str]:
        """Return the placeholder names in the path and the body."""
        return placeholder_names(self.path) | names_in(self.json_body())


class CreateRequest(_ResourceRequest):
    """The request that creates the resource."""

    method: str = Field(default="POST", description="HTTP method. Default POST.")
    body: JsonValue = Field(
        default=None,
        description="JSON body, optional; strings may hold placeholders, written in quotes.",
    )

    def json_body(self) -> JsonValue:
        """Return the JSON body of the request; None when it has none."""
        return self.body


class DeleteRequest(_ResourceRequest):
    """
    The request that deletes the resource at teardown.

    No body: the teardown registry keeps method, path and headers only.
    """

    method: str = Field(default="DELETE", description="HTTP method. Default DELETE.")


# ---------------------------------------------------------------------------
# Resource
# ---------------------------------------------------------------------------


class ResourceConfig(BaseModel):
    """
    One prepared resource: create request, values from its response, delete request.

    Checks:
        - create uses only {username}, {password}, {random};
        - delete uses those and the names of 'values';
        - value names are identifiers, not one of the fixed placeholders;
          their response paths are dotted names ('owner.login');
        - no placeholder written without quotes in a body.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    create: CreateRequest = Field(description="The request that creates the resource.")
    values: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Values taken from the JSON response of the create request: name -> dotted "
            "path, e.g. {owner: owner.login}. A login resource needs 'credential'."
        ),
    )
    delete: DeleteRequest | None = Field(
        default=None,
        description="The request that deletes the resource at teardown; none if nothing to delete.",
    )

    @field_validator("values", mode="after")
    @classmethod
    def values_well_formed(cls, value: dict[str, str]) -> dict[str, str]:
        """Require identifier names, not fixed placeholders, and dotted paths."""
        for name, path in value.items():
            if not _VALUE_NAME_PATTERN.fullmatch(name):
                raise ValueError(
                    f"value name '{name}' must be letters, digits and underscores, "
                    "not starting with a digit."
                )
            if name in FIXED_PLACEHOLDERS:
                raise ValueError(
                    f"value name '{name}' is reserved for the role's account or the "
                    f"random value ({', '.join(sorted(FIXED_PLACEHOLDERS))}): choose another."
                )
            if not path or any(not part for part in path.split(_DOTTED_SEPARATOR)):
                raise ValueError(
                    f"value '{name}': '{path}' is not a dotted path of the response, "
                    "e.g. 'owner.login'."
                )
        return value

    @model_validator(mode="after")
    def placeholders_defined(self) -> ResourceConfig:
        """Require every placeholder to be known where it is used, and quoted."""
        self._check_request("create", self.create, FIXED_PLACEHOLDERS)
        if self.delete is not None:
            self._check_request("delete", self.delete, FIXED_PLACEHOLDERS | frozenset(self.values))
        return self

    @staticmethod
    def _check_request(part: str, request: _ResourceRequest, known: frozenset[str]) -> None:
        """Raise ValueError for an unknown or unquoted placeholder of one request."""
        unquoted = unquoted_placeholders(request.json_body(), known)
        if unquoted:
            raise ValueError(
                f"{part}.body: write the placeholders in quotes, e.g. "
                f'"{{{sorted(unquoted)[0]}}}": unquoted, YAML reads them as a mapping.'
            )
        unknown = request.placeholders() - known
        if unknown:
            hint = (
                " The response values exist only after the create request: use them in delete."
                if part == "create"
                else ""
            )
            raise ValueError(
                f"{part}: unknown placeholder(s) {', '.join(f'{{{n}}}' for n in sorted(unknown))}; "
                f"known here: {', '.join(f'{{{n}}}' for n in sorted(known))}.{hint}"
            )
