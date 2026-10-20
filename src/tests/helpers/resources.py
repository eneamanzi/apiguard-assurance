"""
src/tests/helpers/resources.py

Prepared resources: creates a resource of config.yaml (resources:) on the
target, for a role, and registers its deletion for Phase 6 teardown.

    prepared = create_resource(target, context, client, "repository", ROLE_USER_A, "7.2")
    prepared.values["owner"], prepared.values["repo"]

Steps (docs/04-architecture/05-design-decisions.md, D6):
    1. Fill the create request: {username}, {password} from the role's
       account, {random} (8 hexadecimal characters, the same for create and
       delete).
    2. Authenticate it as the resource says: 'credential' (the role's
       credential, sent as the placement says), 'basic' (HTTP Basic with the
       role's account), 'none'.
    3. Send it; any 2xx is success.
    4. Read the values from the JSON response (dotted paths). The value
       'credential' is registered as a secret.
    5. Register the delete request for teardown as soon as it can be built,
       with the same role: teardown runs in reverse creation order, so a
       resource created with a credential is deleted before the credential.

delete_resource() sends the delete request at once (test 1.4 revokes a
credential this way); the teardown entry stays and accepts the 404.

Failures raise ResourceSetupError (a ToolBaseError): the calling test returns
ERROR with its message.

The PreparedResource returned holds the values, the credential among them:
it must never be logged.

Dependency rule: imports from the stdlib, pydantic, src.core and
src.tests.helpers.auth_base. It must never import from src.tests.domain_* or
src.engine.
"""

from __future__ import annotations

import base64
import secrets
from typing import Any
from urllib.parse import urlencode

import httpx
import structlog
from pydantic import BaseModel, Field
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.exceptions import ToolBaseError
from src.core.models import (
    CREDENTIAL_VALUE,
    PLACEHOLDER_PASSWORD,
    PLACEHOLDER_RANDOM,
    PLACEHOLDER_USERNAME,
    EvidenceRecord,
    ResourceAuth,
    ResourceConfig,
)
from src.core.models.resources import CreateRequest, DeleteRequest
from src.core.templating import TemplateError, render
from src.tests.helpers.auth_base import role_account

log: structlog.BoundLogger = structlog.get_logger(__name__)

_RANDOM_BYTES: int = 4  # 8 hexadecimal characters
_SUCCESS_MIN: int = 200
_SUCCESS_MAX: int = 300
_RESPONSE_PREVIEW: int = 200
_AUTHORIZATION_HEADER: str = "Authorization"
_BASIC_PREFIX: str = "Basic "
_DOTTED_SEPARATOR: str = "."
_BASIC_SECRET_LABEL: str = "Basic credentials of role"  # noqa: S105 -- a label, not a credential
_PASSWORD_SECRET_LABEL: str = "password of role"  # noqa: S105 -- a label, not a credential
_CREDENTIAL_SECRET_LABEL: str = "credential from resource"  # noqa: S105 -- a label, not a credential
# Added to an error when the resource exists on the target but no teardown could be registered.
_NOT_DELETED: str = "; it was created and is not deleted automatically"


class ResourceSetupError(ToolBaseError):
    """
    A prepared resource could not be created, or its values could not be read.

    Distinct from SecurityClientError (transport failure): a response was
    received, but it is not a success or lacks a configured value. The
    calling test returns ERROR with this message.
    """


class PreparedResource(BaseModel):
    """A resource created on the target. Never log it: values may hold the credential."""

    model_config = {"frozen": True}

    name: str = Field(description="The resource's name in config.yaml.")
    role: str = Field(description="The role it was created for (a ROLE_* constant).")
    values: dict[str, str] = Field(
        repr=False, description="The values read from the create response."
    )
    create_record: EvidenceRecord = Field(description="The create request and its response.")
    request_values: dict[str, str] = Field(
        repr=False,
        exclude=True,
        description=(
            "Every placeholder value of its requests ({username}, {password}, {random} and "
            "the values), to build the delete request again (delete_resource)."
        ),
    )


def create_resource(
    target: TargetContext,
    context: TestContext,
    client: SecurityClient,
    name: str,
    role: str,
    test_id: str,
) -> PreparedResource:
    """
    Create a prepared resource for a role and register its deletion.

    Args:
        target:  The current TargetContext (resources, credentials, placement).
        context: The TestContext (credentials, secrets, teardown).
        client:  The SecurityClient.
        name:    The resource's name in config.yaml.
        role:    A ROLE_* constant: whose account and credential are used.
        test_id: Test the requests are attributed to (the login: 'auth_setup').

    Returns:
        The created resource and its values.

    Raises:
        ResourceSetupError: Unknown resource, missing account or credential,
            a non-2xx response, or a configured value missing from it.
        SecurityClientError: On transport failure.
    """
    resource = target.resources.get(name)
    if resource is None:
        raise ResourceSetupError(f"Resource '{name}' is not defined in config.yaml (resources).")

    fixed = _fixed_values(target, context, resource, name, role)
    response, record = _send(
        target, context, client, resource.create, fixed, name, role, test_id, "create"
    )
    if not _SUCCESS_MIN <= response.status_code < _SUCCESS_MAX:
        raise ResourceSetupError(
            f"Resource '{name}' (role '{role}'): {resource.create.method} "
            f"{_fill(resource.create.path, fixed, name)} returned HTTP {response.status_code}. "
            f"Response: {response.text[:_RESPONSE_PREVIEW]}"
        )

    body = _json_object(response, resource, name) if resource.values else {}
    # The values the delete request needs come first: teardown is registered
    # before any other value can fail.
    delete_names = _delete_value_names(resource)
    values: dict[str, str] = {}
    for value_name in sorted(delete_names):
        values[value_name] = _read_value(
            body, resource.values[value_name], value_name, name, created_not_deleted=True
        )
    if resource.delete is not None:
        _register_teardown(target, context, resource.delete, {**fixed, **values}, name, role)
    for value_name, path in resource.values.items():
        if value_name not in values:
            values[value_name] = _read_value(
                body, path, value_name, name, created_not_deleted=False
            )

    credential = values.get(CREDENTIAL_VALUE)
    if credential:
        context.register_secret(credential, f"{_CREDENTIAL_SECRET_LABEL} '{name}'")
    log.info(
        "resource_created",
        resource=name,
        role=role,
        test_id=test_id,
        status_code=response.status_code,
        teardown_registered=resource.delete is not None,
    )
    return PreparedResource(
        name=name,
        role=role,
        values=values,
        create_record=record,
        request_values={**fixed, **values},
    )


def delete_resource(
    target: TargetContext,
    context: TestContext,
    client: SecurityClient,
    prepared: PreparedResource,
    test_id: str,
) -> tuple[httpx.Response, EvidenceRecord]:
    """
    Send the delete request of a resource now (test 1.4: revoking a credential).

    The teardown entry registered at creation stays: at teardown the resource
    is already gone, and a 404 there is accepted.

    Args:
        target:   The current TargetContext.
        context:  The TestContext (credential of the role, secrets).
        client:   The SecurityClient.
        prepared: The resource, as create_resource() returned it.
        test_id:  Test the request is attributed to.

    Returns:
        The response and its evidence record; the caller judges the status.

    Raises:
        ResourceSetupError: If the resource has no delete request.
        SecurityClientError: On transport failure.
    """
    resource = target.resources.get(prepared.name)
    if resource is None or resource.delete is None:
        raise ResourceSetupError(f"Resource '{prepared.name}' has no delete request.")
    return _send(
        target,
        context,
        client,
        resource.delete,
        prepared.request_values,
        prepared.name,
        prepared.role,
        test_id,
        "delete",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fixed_values(
    target: TargetContext,
    context: TestContext,
    resource: ResourceConfig,
    name: str,
    role: str,
) -> dict[str, str]:
    """{username}, {password} (only when the role has an account) and {random}."""
    fixed = {PLACEHOLDER_RANDOM: secrets.token_hex(_RANDOM_BYTES)}
    account = role_account(target, role)
    needed = resource.create.placeholders()
    if resource.delete is not None:
        needed |= resource.delete.placeholders()
    if account is not None:
        username, password = account
        fixed[PLACEHOLDER_USERNAME] = username
        fixed[PLACEHOLDER_PASSWORD] = password
        context.register_secret(password, f"{_PASSWORD_SECRET_LABEL} {role}")
    elif needed & {PLACEHOLDER_USERNAME, PLACEHOLDER_PASSWORD}:
        raise ResourceSetupError(
            f"Resource '{name}' uses the account of role '{role}', which has no username and "
            "password in config.yaml (credentials)."
        )
    return fixed


def _send(
    target: TargetContext,
    context: TestContext,
    client: SecurityClient,
    request: CreateRequest | DeleteRequest,
    values: dict[str, str],
    name: str,
    role: str,
    test_id: str,
    part: str,
) -> tuple[httpx.Response, EvidenceRecord]:
    """Fill, authenticate and send one request of a resource."""
    headers, params = _auth_parts(target, context, request.auth, name, role, part)
    body = _fill_body(request.json_body(), values, name)
    response, record = client.request(
        method=request.method,
        path=_fill(request.path, values, name),
        test_id=test_id,
        headers=headers or None,
        params=params or None,
        json=body,
    )
    return response, record


def _auth_parts(
    target: TargetContext,
    context: TestContext,
    auth: ResourceAuth,
    name: str,
    role: str,
    part: str,
) -> tuple[dict[str, str], dict[str, str]]:
    """Headers and query parameters authenticating a request as the role."""
    if auth is ResourceAuth.NONE:
        return {}, {}
    if auth is ResourceAuth.BASIC:
        account = role_account(target, role)
        if account is None:
            raise ResourceSetupError(
                f"Resource '{name}' {part} uses HTTP Basic, but role '{role}' has no username "
                "and password in config.yaml (credentials)."
            )
        encoded = base64.b64encode(f"{account[0]}:{account[1]}".encode()).decode("ascii")
        value = _BASIC_PREFIX + encoded
        context.register_secret(value, f"{_BASIC_SECRET_LABEL} {role}")
        return {_AUTHORIZATION_HEADER: value}, {}
    credential = context.get_token(role)
    placement = target.credential_placement
    if credential is None or placement is None:
        raise ResourceSetupError(
            f"Resource '{name}' {part} uses the credential of role '{role}', which has none "
            "(credentials not configured, or not obtained before the resource)."
        )
    parts = placement.request_parts(credential)
    return dict(parts.headers), dict(parts.params)


def _register_teardown(
    target: TargetContext,
    context: TestContext,
    request: DeleteRequest,
    values: dict[str, str],
    name: str,
    role: str,
) -> None:
    """Register the delete request, authenticated as the role; query parameters go in the path."""
    headers, params = _auth_parts(target, context, request.auth, name, role, "delete")
    path = _fill(request.path, values, name)
    if params:
        path = f"{path}?{urlencode(params)}"
    context.register_resource_for_teardown(method=request.method, path=path, headers=headers)


def _delete_value_names(resource: ResourceConfig) -> frozenset[str]:
    """The names of 'values' the delete request uses."""
    if resource.delete is None:
        return frozenset()
    return resource.delete.placeholders() & frozenset(resource.values)


def _json_object(response: httpx.Response, resource: ResourceConfig, name: str) -> dict[str, Any]:
    """The JSON object of a create response; the resource is then not deleted automatically."""
    try:
        body = response.json()
    except ValueError as exc:
        raise ResourceSetupError(
            f"Resource '{name}': the create response is not JSON, so its values "
            f"({', '.join(sorted(resource.values))}) cannot be read"
            f"{_NOT_DELETED if resource.delete is not None else ''}."
        ) from exc
    if not isinstance(body, dict):
        raise ResourceSetupError(
            f"Resource '{name}': the create response is not a JSON object"
            f"{_NOT_DELETED if resource.delete is not None else ''}."
        )
    return body


def _read_value(
    body: dict[str, Any],
    path: str,
    value_name: str,
    name: str,
    created_not_deleted: bool,
) -> str:
    """A string or number at a dotted path of the response."""
    node: Any = body
    for part in path.split(_DOTTED_SEPARATOR):
        if not isinstance(node, dict) or part not in node:
            node = None
            break
        node = node[part]
    if isinstance(node, bool) or not isinstance(node, str | int | float):
        suffix = _NOT_DELETED if created_not_deleted else ""
        raise ResourceSetupError(
            f"Resource '{name}': value '{value_name}' not found at '{path}' in the create "
            f"response (or not a string or number){suffix}."
        )
    return str(node)


def _fill(text: str, values: dict[str, str], name: str) -> str:
    """Fill the placeholders of a path."""
    filled = _fill_body(text, values, name)
    return str(filled)


def _fill_body(value: object, values: dict[str, str], name: str) -> object:
    """Fill the placeholders of a body (or a path); the startup checks make a failure unlikely."""
    try:
        return render(value, values)
    except TemplateError as exc:
        raise ResourceSetupError(f"Resource '{name}': {exc}") from exc
