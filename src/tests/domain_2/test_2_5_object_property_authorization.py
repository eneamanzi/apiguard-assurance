"""
src/tests/domain_2/test_2_5_object_property_authorization.py

Test 2.5: guarantee "the API exposes only the properties a user may see, and
accepts only the properties a user may set" (Broken Object Property Level
Authorization, BOPLA, OWASP API3:2023).

Two sub-tests, on a disposable object owned by user_a (created through a
configured resource, as in test 2.2):

    no_sensitive_field  the object's response carries no field whose name is
                        sensitive (`password`, `*hash`, `ssn`, `credit*`,
                        `*secret`, `*token`, `*key`, ...). A sensitive field in
                        the response is excessive data exposure, whatever the
                        role (ASVS v5.0.0-14.2.6). Role-differential filtering is
                        covered here: a field a user must not see is caught by
                        its name, with no need to label an "admin-only" field.
    mass_assignment     an object created with extra ownership fields in the
                        body (`role`, `owner`, `user_id`, ...), each a unique
                        string sentinel, must ignore them. The object is read
                        back; if a sentinel appears, the server bound a
                        client-controlled field (ASVS v5.0.0-8.2.3, CWE-915). Only string
                        sentinels are used, so a legitimately-true boolean is
                        never mistaken for a bound value.

The object is created and deleted by the test (effect CHANGES_DATA); the
mass-assignment object is a second disposable one, also deleted.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field

from src.core.assessment_test import NEEDED_TO_RUN, REFERS_TO_RESOURCE
from src.core.auth_placement import RequestAuthParts
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError, SecurityClientError
from src.core.models import (
    Confidence,
    Finding,
    Outcome,
    Reference,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.auth import auth_parts
from src.tests.helpers.owned_object import (
    SAFE_METHODS,
    PreparedResource,
    create_owned_object,
    object_operations,
)
from src.tests.helpers.resources import ResourceSetupError, delete_resource

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB_SENSITIVE: str = "no_sensitive_field"
_SUB_MASS: str = "mass_assignment"

# A response field whose name matches one of these is sensitive: it should not
# be in an API response (ASVS v5.0.0-14.2.6). Matched against the field name in
# lower case, as a substring.
_SENSITIVE_NAMES: tuple[str, ...] = (
    "password",
    "passwd",
    "pwd",
    "hash",
    "secret",
    "token",
    "apikey",
    "api_key",
    "privatekey",
    "private_key",
    "ssn",
    "creditcard",
    "credit_card",
    "cardnumber",
    "card_number",
    "cvv",
    "salt",
)

# How deep the field-name scan descends into a JSON response.
_SCAN_DEPTH: int = 3

# The privileged or ownership fields injected by the mass-assignment probe, each
# with a unique string sentinel. Only a string sentinel is used: a boolean such
# as `admin: true` reflected in the response cannot be told apart from a field
# that is legitimately true (e.g. the owner's `permissions.admin` on their own
# object), which would be a false positive. A unique string never appears by
# chance, so a field echoing it was bound from the request body.
_MASS_SENTINEL: str = "apiguard-mass-probe"
_MASS_FIELDS: dict[str, object] = {
    "role": _MASS_SENTINEL,
    "owner": _MASS_SENTINEL,
    "user_id": _MASS_SENTINEL,
    "userId": _MASS_SENTINEL,
    "created_by": _MASS_SENTINEL,
    "author": _MASS_SENTINEL,
}

_REFERENCES: tuple[Reference, ...] = (
    # Read on the ASVS v5.0.0 source 2026-10-22: 14.2.6 (no sensitive data in a
    # response beyond what the consumer needs); 8.2.3 (field-level access,
    # which ASVS writes for broken object property level authorization).
    Reference(standard=Standard.OWASP_API_TOP10, id="API3:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-14.2.6"),
    Reference(standard=Standard.ASVS, id="v5.0.0-8.2.3"),
    Reference(standard=Standard.CWE, id="CWE-915"),
    Reference(standard=Standard.NIST_SP, id="800-53r5", section="3.1"),
)


class Test25Params(BaseModel):
    """Parameters of test 2.5."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    owned_object_resources: tuple[str, ...] = Field(
        default=(),
        description=(
            "The config.yaml `resources:` resources that each create a disposable object owned by "
            "user_a (the same as test 2.2); each is checked in turn. Without any the test cannot "
            "run."
        ),
        json_schema_extra={**NEEDED_TO_RUN, **REFERS_TO_RESOURCE},
    )


class Test25ObjectPropertyAuthorization(BaseTest[Test25Params]):
    """
    Test 2.5 -- whether the object leaks fields or accepts a mass assignment.

    The oracle of each sub-test is in the module docstring and on the test
    page.
    """

    info = TestInfo(
        id="2.5",
        name="Object Property-Level Authorization",
        priority=1,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-213",
        references=_REFERENCES,
        tags=("authorization", "excessive-data", "mass-assignment"),
        needs=(Need.USER_ACCOUNT,),
        effect=Effect.CHANGES_DATA,
        sub_tests=(_SUB_SENSITIVE, _SUB_MASS),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Read user_a's object for sensitive fields, and probe mass assignment.

        Args:
            target:  The run's target (surface, resources, path seed).
            context: The run's context (user_a credential, teardown).
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._requires_attack_surface(...), or
            self._error(exc).
        """
        try:
            missing = self._requires_attack_surface(target)
            if missing is not None:
                return missing
            user_a = auth_parts(target, context, ROLE_USER_A)
            for name in self.params(target).owned_object_resources:
                self._run_resource(target, context, client, name, user_a)
            return self._finish()
        except AuthenticationSetupError as exc:
            return self._error(exc)
        except SecurityClientError as exc:
            return self._error(exc)

    def _run_resource(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        name: str,
        user_a: RequestAuthParts,
    ) -> None:
        """Run both property sub-tests on one owned-object resource."""
        try:
            self._sensitive(target, context, client, name, user_a)
        except ResourceSetupError as exc:
            log.warning("test_2_5_object_not_created", resource=name, error=str(exc))
            self._record(_SUB_SENSITIVE, Outcome.NOT_VERIFIABLE, "OBJECT_NOT_CREATED")
        try:
            self._mass_assignment(target, context, client, name, user_a)
        except ResourceSetupError as exc:
            log.warning("test_2_5_object_not_created", resource=name, error=str(exc))
            self._record(_SUB_MASS, Outcome.NOT_VERIFIABLE, "OBJECT_NOT_CREATED")

    def _sensitive(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        resource: str,
        user_a: RequestAuthParts,
    ) -> None:
        """Create the object, read it, and scan its fields for sensitive names."""
        owned = create_owned_object(target, context, client, resource, ROLE_USER_A, self.info.id)
        try:
            response = self._read_object(target, client, owned.values, user_a)
            if response is None:
                self._record(_SUB_SENSITIVE, Outcome.NOT_VERIFIABLE, "OBJECT_NOT_READABLE")
                return
            body = _json(response)
            leaked = sorted(_sensitive_fields(body))
            if leaked:
                self._record(
                    _SUB_SENSITIVE,
                    Outcome.VIOLATION,
                    "SENSITIVE_FIELD",
                    Finding(
                        title=f"Response carries sensitive field(s): {', '.join(leaked)}",
                        detail=(
                            f"The response for user_a's object carries the field(s) "
                            f"{', '.join(leaked)}, whose name is sensitive: the API returns more "
                            "of the stored object than the consumer needs (excessive data "
                            "exposure, OWASP API3:2023, ASVS v5.0.0-14.2.6). Filter the response "
                            "server-side to the fields the consumer may see."
                        ),
                        confidence=Confidence.FIRM,
                    ),
                )
            else:
                self._record(_SUB_SENSITIVE, Outcome.ENFORCED, "NO_SENSITIVE_FIELD")
        finally:
            self._cleanup(target, context, client, owned)

    def _mass_assignment(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        resource: str,
        user_a: RequestAuthParts,
    ) -> None:
        """Create an object with injected privileged fields, read it, check reflection."""
        owned = create_owned_object(
            target, context, client, resource, ROLE_USER_A, self.info.id, extra_body=_MASS_FIELDS
        )
        try:
            response = self._read_object(target, client, owned.values, user_a)
            if response is None:
                self._record(_SUB_MASS, Outcome.NOT_VERIFIABLE, "OBJECT_NOT_READABLE")
                return
            reflected = sorted(_reflected_fields(_json(response)))
            if reflected:
                self._record(
                    _SUB_MASS,
                    Outcome.VIOLATION,
                    "MASS_ASSIGNMENT",
                    Finding(
                        title=f"Object bound client-controlled field(s): {', '.join(reflected)}",
                        detail=(
                            f"An object created by user_a with extra body field(s) "
                            f"{', '.join(reflected)} kept the injected value when read back. The "
                            "server binds a client-controlled privileged or ownership property "
                            "(mass assignment, OWASP API3:2023, ASVS v5.0.0-8.2.3, CWE-915). "
                            "Bind only the fields the consumer may set (an allowlist), never "
                            "the whole body."
                        ),
                        confidence=Confidence.CERTAIN,
                    ),
                )
            else:
                self._record(_SUB_MASS, Outcome.ENFORCED, "NO_MASS_ASSIGNMENT")
        finally:
            self._cleanup(target, context, client, owned)

    def _read_object(
        self,
        target: TargetContext,
        client: SecurityClient,
        values: dict[str, str],
        user_a: RequestAuthParts,
    ) -> httpx.Response | None:
        """GET the created object as user_a; its response, or None if unreadable."""
        reads = object_operations(target, values, SAFE_METHODS)
        if not reads:
            return None
        method, path, _template = reads[0]
        try:
            response, record = client.request(
                method,
                path,
                test_id=self.info.id,
                headers=dict(user_a.headers) or None,
                params=dict(user_a.params) or None,
            )
        except SecurityClientError:
            return None
        self._step(record)
        return response

    def _cleanup(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        owned: PreparedResource,
    ) -> None:
        """Delete the created object now; the teardown entry accepts a 404."""
        resource = target.resources.get(owned.name)
        if resource is None or resource.delete is None:
            # The object type has no delete operation (e.g. a crAPI order): it is
            # not cleaned up by the tool; the lab reset removes it. By design.
            log.info("test_2_5_object_not_deletable", resource=owned.name)
            return
        try:
            _response, record = delete_resource(target, context, client, owned, self.info.id)
            self._step(record)
        except (ResourceSetupError, SecurityClientError) as exc:
            log.warning("test_2_5_cleanup_failed", error=str(exc))


def _json(response: httpx.Response) -> object:
    """The response's JSON, or an empty dict when it is not JSON."""
    try:
        return response.json()
    except ValueError:
        return {}


def _sensitive_fields(node: object, depth: int = 0) -> set[str]:
    """The field names in a JSON value whose name is sensitive, to _SCAN_DEPTH."""
    found: set[str] = set()
    if depth > _SCAN_DEPTH:
        return found
    if isinstance(node, dict):
        for key, value in node.items():
            low = str(key).lower()
            if any(marker in low for marker in _SENSITIVE_NAMES):
                found.add(str(key))
            found |= _sensitive_fields(value, depth + 1)
    elif isinstance(node, list):
        for item in node[:5]:
            found |= _sensitive_fields(item, depth + 1)
    return found


def _reflected_fields(node: object, depth: int = 0) -> set[str]:
    """The injected mass-assignment fields echoed with their sentinel value."""
    found: set[str] = set()
    if depth > _SCAN_DEPTH:
        return found
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _MASS_FIELDS and _matches_sentinel(key, value):
                found.add(str(key))
            found |= _reflected_fields(value, depth + 1)
    elif isinstance(node, list):
        for item in node[:5]:
            found |= _reflected_fields(item, depth + 1)
    return found


def _matches_sentinel(key: str, value: object) -> bool:
    """Whether a read-back value echoes the unique string sentinel injected for that field."""
    del key
    return isinstance(value, str) and _MASS_SENTINEL in value
