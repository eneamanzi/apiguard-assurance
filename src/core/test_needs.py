"""
src/core/test_needs.py

Whether a test's needs are met by the configuration, and why not.

A test declares what it needs to run at all (``TestInfo.needs``, the Need
vocabulary of src/core/test_metadata.py) and which of its parameters it
cannot run without (``Field(json_schema_extra=NEEDED_TO_RUN)``,
src/core/assessment_test.py). Both are known from the configuration alone, so
they are checked in one place (docs/04-architecture/05-design-decisions.md, D8):

    - at startup, to warn which selected tests will SKIP and why (engine);
    - before each test runs, to record its SKIP without running it (engine,
      Phase 5), with the same reason;
    - by ``apiguard validate-config`` and ``apiguard list-tests --config``.

Each need is one entry of _CHECKS: a check of the configuration facts and the
reason given when it fails. A new need is a member of Need and an entry here.

Dependency rule: imports only from the standard library, pydantic and
src.core.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from pydantic import BaseModel

from src.core.assessment_test import NEEDED_TO_RUN, has_marker
from src.core.models import AuthType, ResourceConfig, RuntimeCredentials
from src.core.test_metadata import Need, TestInfo, section_keys


@dataclass(frozen=True)
class ConfigurationFacts:
    """What the needs are checked against: the run's configuration, as the tests see it."""

    credentials: RuntimeCredentials
    gateway_configured: bool
    resources: Mapping[str, ResourceConfig]


def login_can_revoke(
    credentials: RuntimeCredentials, resources: Mapping[str, ResourceConfig]
) -> bool:
    """
    True when the login method can revoke a credential.

    That is ``auth_type: login`` with a login resource that has a delete
    request (the method deletes the token it created; test 1.4).

    Args:
        credentials: The run's credentials.
        resources:   The prepared resources, by name.

    Returns:
        Whether a credential obtained by the method can be revoked.
    """
    if credentials.auth_type is not AuthType.LOGIN or credentials.login_resource is None:
        return False
    resource = resources.get(credentials.login_resource)
    return resource is not None and resource.delete is not None


_CHECKS: dict[Need, tuple[Callable[[ConfigurationFacts], bool], str]] = {
    Need.ADMIN_ACCOUNT: (
        lambda facts: facts.credentials.has_admin(),
        "the credentials of the admin role are not configured (credentials.admin_*)",
    ),
    Need.USER_ACCOUNT: (
        lambda facts: facts.credentials.has_user_a(),
        "the credentials of the user_a role are not configured (credentials.user_a_*)",
    ),
    Need.GATEWAY: (
        lambda facts: facts.gateway_configured,
        "no gateway is configured (gateway.adapter and gateway.admin.url)",
    ),
    Need.REVOCABLE_LOGIN: (
        lambda facts: login_can_revoke(facts.credentials, facts.resources),
        "the authentication method cannot revoke a credential (auth_type login with a login "
        "resource that has a delete request can)",
    ),
}


def unmet_needs(info: TestInfo, params: BaseModel | None, facts: ConfigurationFacts) -> list[str]:
    """
    The reasons a test cannot run with this configuration, one per unmet need.

    Args:
        info:   The test's declaration.
        params: The test's validated parameters (None: it has none).
        facts:  The run's configuration.

    Returns:
        One reason per unmet need, then per needed parameter left unset; empty
        when the test can run.
    """
    reasons = [
        f"Needs {need.value}: {reason}."
        for need in info.needs
        for check, reason in (_CHECKS[need],)
        if not check(facts)
    ]
    if params is not None:
        domain_key, test_key = section_keys(info.id)
        for name, field in type(params).model_fields.items():
            if has_marker(field, NEEDED_TO_RUN) and not getattr(params, name):
                reasons.append(
                    f"Needs tests.{domain_key}.{test_key}.{name}: not set "
                    "(the test cannot run without it)."
                )
    return reasons
