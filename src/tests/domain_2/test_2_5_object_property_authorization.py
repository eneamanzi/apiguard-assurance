"""
src/tests/domain_2/test_2_5_object_property_authorization.py

Test 2.5: guarantee "the API exposes only the properties a user may see, and
accepts only the properties a user may set" (Broken Object Property Level
Authorization, BOPLA, OWASP API3:2023).

Two sub-tests, on a disposable object owned by user_a (created through a
configured resource, as in test 2.2):

    no_sensitive_field  the object's response carries no field whose name is
                        sensitive (`password`, `hash`, `secret`, `token`,
                        `apikey`, `privatekey`, `ssn`, `creditcard`, `cvv`, ...:
                        the list is _SENSITIVE_NAMES). A sensitive field in
                        the response is excessive data exposure, whatever the
                        role (ASVS v5.0.0-14.2.6). Role-differential filtering is
                        covered here: a field a user must not see is caught by
                        its name, with no need to label an "admin-only" field.
    mass_assignment     an object created with extra ownership fields in the
                        body (`role`, `owner`, `user_id`, ...), each carrying
                        one string sentinel unlikely to appear by chance, must
                        ignore them. The object is read back; if the sentinel
                        appears in one of those fields, the server bound a
                        client-controlled field (ASVS v5.0.0-8.2.3, CWE-915). Only string
                        sentinels are used, so a legitimately-true boolean is
                        never mistaken for a bound value.

The object is created and deleted by the test (effect CHANGES_DATA); the
mass-assignment object is a second disposable one, also deleted.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import re

import httpx
import structlog
from pydantic import BaseModel, ConfigDict, Field

from src.core.assessment_test import NEEDED_TO_RUN, REFERS_TO_RESOURCE, category_of
from src.core.auth_placement import RequestAuthParts
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError, SecurityClientError
from src.core.models import (
    Confidence,
    EvidenceRecord,
    Finding,
    Outcome,
    Reference,
    ResponseCategory,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.test_metadata import Effect, Need, OracleCase, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.auth import auth_parts
from src.tests.helpers.owned_object import (
    SAFE_METHODS,
    PreparedResource,
    create_owned_object,
    not_deleted_note,
    object_operations,
)
from src.tests.helpers.resources import ResourceSetupError, delete_resource

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB_SENSITIVE: str = "no_sensitive_field"
_SUB_MASS: str = "mass_assignment"

# A response field whose name matches one of these is sensitive: it should not
# be in an API response (ASVS v5.0.0-14.2.6). A marker of up to
# _MAX_WORD_MARKER characters must be a whole word of the field name (split on
# '_', '-' and camelCase, lower case, a plural 's' ignored): as a substring
# 'ssn' matched 'classname' and 'hash' 'hashtag'. A longer marker
# is a substring of the name in lower case without '_' and '-', so that
# 'passwordhash', 'accessToken' and 'API-Key' are all caught.
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

# The words of a field name: a capitalised or lower-case run, an upper-case
# run (an acronym), or digits.
_NAME_WORD: re.Pattern[str] = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")
_MAX_WORD_MARKER: int = 4
# A value made of these characters, with at most _MAX_CLEAR characters left in
# clear, is masked ('XXXXXXXXXXXX0796', '****'): it discloses nothing, as a null
# or empty value does not (crAPI returns its owner's card number masked so).
_MASK_CHARACTERS: frozenset[str] = frozenset("*xX#\u2022")
# Markers whose value may be a number (a card number, an SSN, a CVV); any other
# sensitive name counts only with a string value. A boolean, an object or a list
# under a sensitive name (`has_password: true`, `secret_scanning: {...}`) is not
# a value of it (until 2026-11-16 each was a finding).
_NUMERIC_MARKERS: frozenset[str] = frozenset({"ssn", "creditcard", "cardnumber", "cvv"})
# Suffixes that name something about a credential, not the credential.
_ABOUT_SUFFIXES: tuple[str, ...] = ("_at", "_type", "_count", "_enabled", "_policy", "_expires")
_MIN_MASKED: int = 4
_MAX_CLEAR: int = 4

# How deep the field-name scan descends into a JSON response, and how many items
# of each list it reads (an object's lists repeat one shape).
_SCAN_DEPTH: int = 3
_SCAN_LIST_ITEMS: int = 5

# The privileged or ownership fields injected by the mass-assignment probe, all
# carrying the same string sentinel: what identifies a bound field is its own
# name in the read-back object, so one sentinel value is enough. Only a string
# sentinel is used: a boolean such as `admin: true` reflected in the response
# cannot be told apart from a field that is legitimately true (e.g. the owner's
# `permissions.admin` on their own object), which would be a false positive.
# This string never appears by chance, so a field echoing it was bound from the
# request body.
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
    # Read on the ASVS v5.0.0 source 2026-11-16: 15.3.1 (only the required subset
    # of fields returned), 15.3.3 (mass assignment), 8.2.3 (field-level access).
    # 14.2.6 (L3, minimising sensitive data) was cited until then.
    Reference(standard=Standard.OWASP_API_TOP10, id="API3:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-15.3.1"),
    Reference(standard=Standard.ASVS, id="v5.0.0-15.3.3"),
    Reference(standard=Standard.ASVS, id="v5.0.0-8.2.3"),
    Reference(standard=Standard.CWE, id="CWE-915"),
    Reference(standard=Standard.NIST_SP, id="800-53r5", section="3.1"),
)

_ORACLE: tuple[OracleCase, ...] = (
    OracleCase(
        sub_test=_SUB_SENSITIVE,
        when="a sensitive-named field holds a value: a string not empty or masked, or a number "
        "for a card, SSN or CVV",
        outcome=Outcome.VIOLATION,
        detail="SENSITIVE_FIELD",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_SENSITIVE,
        when="no sensitive field holds a value",
        outcome=Outcome.ENFORCED,
        detail="NO_SENSITIVE_FIELD",
    ),
    OracleCase(
        sub_test=_SUB_SENSITIVE,
        when="no documented read, or the read is not served",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="OBJECT_NOT_READABLE",
    ),
    OracleCase(
        sub_test=_SUB_SENSITIVE,
        when="the prepared resource did not create the object",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="OBJECT_NOT_CREATED",
    ),
    OracleCase(
        sub_test=_SUB_MASS,
        when="an injected field (one the configured body does not set) is read back holding the "
        "sentinel",
        outcome=Outcome.VIOLATION,
        detail="MASS_ASSIGNMENT",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_MASS,
        when="an injected field name is shown without the sentinel",
        outcome=Outcome.ENFORCED,
        detail="NO_MASS_ASSIGNMENT",
    ),
    OracleCase(
        sub_test=_SUB_MASS,
        when="the create with the injected fields is refused as invalid while the plain one "
        "works: unknown fields rejected, or a field bound with a wrong-typed value",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="INJECTED_CREATE_REFUSED",
    ),
    OracleCase(
        sub_test=_SUB_MASS,
        when="the read-back shows none of the injected field names",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="FIELDS_NOT_EXPOSED",
    ),
    OracleCase(
        sub_test=_SUB_MASS,
        when="the resource's create body is not a JSON object",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="FIELDS_NOT_INJECTED",
    ),
    OracleCase(
        sub_test=_SUB_MASS,
        when="no documented read, or the read is not served",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="OBJECT_NOT_READABLE",
    ),
    OracleCase(
        sub_test=_SUB_MASS,
        when="the prepared resource did not create the object",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="OBJECT_NOT_CREATED",
    ),
)


# A read back that is refused or missing: the object's fields cannot be seen. An
# answer that says nothing (unavailable, rate limited, failing, silent) is named
# by the shared rule instead (until 2026-11-16 it was OBJECT_NOT_READABLE too).
_NOT_READ: str = "OBJECT_NOT_READABLE"


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
        oracle=_ORACLE,
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
            left: list[str] = []
            for name in self.params(target).owned_object_resources:
                self._run_resource(target, context, client, store, (name, left), user_a)
            return self._finish(notes=not_deleted_note(left) or None)
        except AuthenticationSetupError as exc:
            return self._error(exc)
        except SecurityClientError as exc:
            return self._error(exc)

    def _run_resource(  # noqa: PLR0913 -- both sub-tests need all of it
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
        resource: tuple[str, list[str]],
        user_a: RequestAuthParts,
    ) -> None:
        """Run both property sub-tests on one owned-object resource (its name, the objects left)."""
        name, left = resource
        created = False
        try:
            self._sensitive(target, context, client, store, (name, left), user_a)
            created = True
        except (ResourceSetupError, SecurityClientError) as exc:
            log.warning("test_2_5_object_not_created", resource=name, error=str(exc))
            self._record(_SUB_SENSITIVE, Outcome.NOT_VERIFIABLE, self._not_created(exc))
        try:
            self._mass_assignment(target, context, client, store, (name, left), user_a)
        except (ResourceSetupError, SecurityClientError) as exc:
            log.warning("test_2_5_object_not_created", resource=name, error=str(exc))
            record = exc.record
            if (
                created
                and record is not None
                and category_of(record) == ResponseCategory.INVALID_REQUEST
            ):
                # The plain create works and the one with the injected fields is
                # refused as invalid: unknown properties rejected, or a bound
                # field given a value of the wrong type (the sentinels are
                # strings): which one is not told (until 2026-11-16
                # OBJECT_NOT_CREATED).
                self._judge(
                    record, store, _SUB_MASS, Outcome.NOT_VERIFIABLE, "INJECTED_CREATE_REFUSED"
                )
            else:
                self._record(_SUB_MASS, Outcome.NOT_VERIFIABLE, self._not_created(exc))

    def _not_created(self, exc: Exception) -> str:
        """Why the object was not created: the shared rule's name, or OBJECT_NOT_CREATED."""
        record = getattr(exc, "record", None)
        reason = self._uninformative(record, _SUB_SENSITIVE) if record is not None else None
        if reason is None and isinstance(exc, SecurityClientError):
            return ResponseCategory.NO_RESPONSE.value
        return reason or "OBJECT_NOT_CREATED"

    def _sensitive(  # noqa: PLR0913 -- the probe needs all of it
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
        resource_and_left: tuple[str, list[str]],
        user_a: RequestAuthParts,
    ) -> None:
        """Create the object, read it, and scan its fields for sensitive names."""
        resource, left = resource_and_left
        owned = create_owned_object(target, context, client, resource, ROLE_USER_A, self.info.id)
        try:
            read = self._read_object(target, client, owned.values, user_a)
            if read is None:
                self._record(_SUB_SENSITIVE, Outcome.NOT_VERIFIABLE, _NOT_READ)
                return
            response, record = read
            if response is None or category_of(record) != ResponseCategory.SERVED:
                # A refused, missing or failing read shows no field at all: it
                # proves neither a leak nor its absence.
                reason = self._uninformative(record, _SUB_SENSITIVE) or _NOT_READ
                self._judge(record, store, _SUB_SENSITIVE, Outcome.NOT_VERIFIABLE, reason)
                return
            body = _json(response)
            leaked = sorted(_sensitive_fields(body))
            if leaked:
                fields = ", ".join(leaked)
                self._judge(
                    record,
                    store,
                    _SUB_SENSITIVE,
                    Outcome.VIOLATION,
                    "SENSITIVE_FIELD",
                    Finding(
                        title=f"Response carries sensitive field(s): {fields}",
                        detail=(
                            f"The response for user_a's object carries the field(s) {fields}, "
                            "whose name is sensitive: the API returns more of the stored object "
                            "than the consumer needs (excessive data exposure, OWASP API3:2023, "
                            "ASVS v5.0.0-15.3.1). Filter the response server-side to the fields "
                            "the consumer may see."
                        ),
                        confidence=Confidence.FIRM,
                    ),
                )
            else:
                self._judge(record, store, _SUB_SENSITIVE, Outcome.ENFORCED, "NO_SENSITIVE_FIELD")
        finally:
            self._cleanup(target, context, client, owned, left)

    def _mass_assignment(  # noqa: PLR0913 -- the probe needs all of it
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
        resource_and_left: tuple[str, list[str]],
        user_a: RequestAuthParts,
    ) -> None:
        """Create an object with injected privileged fields, read it, check reflection."""
        resource, left = resource_and_left
        definition = target.resources.get(resource)
        if definition is None or not isinstance(definition.create.json_body(), dict):
            # The fields are merged only into a JSON object body (helpers/
            # resources.py): with any other body nothing is injected, and a
            # clean read-back would prove nothing.
            self._record(_SUB_MASS, Outcome.NOT_VERIFIABLE, "FIELDS_NOT_INJECTED")
            return
        # A key the configured body already sets is the operator's, not an
        # injection (until 2026-11-16 the sentinel replaced it).
        configured = definition.create.json_body()
        injected = {k: v for k, v in _MASS_FIELDS.items() if not _has_key(configured, k)}
        owned = create_owned_object(
            target, context, client, resource, ROLE_USER_A, self.info.id, extra_body=injected
        )
        try:
            read = self._read_object(target, client, owned.values, user_a)
            if read is None:
                self._record(_SUB_MASS, Outcome.NOT_VERIFIABLE, _NOT_READ)
                return
            response, record = read
            if response is None or category_of(record) != ResponseCategory.SERVED:
                # Not read back: no sentinel can be seen, so no conclusion either way.
                reason = self._uninformative(record, _SUB_MASS) or _NOT_READ
                self._judge(record, store, _SUB_MASS, Outcome.NOT_VERIFIABLE, reason)
                return
            body = _json(response)
            if not _exposed_fields(body):
                # The representation shows none of the injected properties:
                # whether they were bound cannot be seen.
                self._judge(record, store, _SUB_MASS, Outcome.NOT_VERIFIABLE, "FIELDS_NOT_EXPOSED")
                return
            reflected = sorted(_reflected_fields(body) & set(injected))
            if reflected:
                fields = ", ".join(reflected)
                self._judge(
                    record,
                    store,
                    _SUB_MASS,
                    Outcome.VIOLATION,
                    "MASS_ASSIGNMENT",
                    Finding(
                        title=f"Object bound client-controlled field(s): {fields}",
                        detail=(
                            f"An object created by user_a with extra body field(s) {fields} kept "
                            "the injected value when read back. The server binds a "
                            "client-controlled property (mass assignment, OWASP API3:2023, ASVS "
                            "v5.0.0-15.3.3, CWE-915), unless the API documents it as one the "
                            "client may set (a blog's `author`): FIRM. Bind only the fields the "
                            "consumer may set (an allowlist), never the whole body."
                        ),
                        # FIRM: whether the client may set the field is not read
                        # from the specification (until 2026-11-16 CERTAIN).
                        confidence=Confidence.FIRM,
                    ),
                )
            else:
                self._judge(record, store, _SUB_MASS, Outcome.ENFORCED, "NO_MASS_ASSIGNMENT")
        finally:
            self._cleanup(target, context, client, owned, left)

    def _read_object(
        self,
        target: TargetContext,
        client: SecurityClient,
        values: dict[str, str],
        user_a: RequestAuthParts,
    ) -> tuple[httpx.Response | None, EvidenceRecord] | None:
        """
        GET the created object as user_a: its response and record.

        A transport failure returns its record with no response, so that the
        caller judges it NO_RESPONSE (rule 4); None when no read
        is documented or no record exists.
        """
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
        except SecurityClientError as exc:
            return None if exc.record is None else (None, exc.record)
        return response, record

    def _cleanup(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        owned: PreparedResource,
        left: list[str],
    ) -> None:
        """Delete the created object now, or name it in `left` (not_deleted_note)."""
        resource = target.resources.get(owned.name)
        if resource is None or resource.delete is None:
            # The object type has no delete operation (e.g. a crAPI order).
            log.info("test_2_5_object_not_deletable", resource=owned.name)
            left.append(f"{owned.name} {owned.values}")
            return
        try:
            _response, record = delete_resource(target, context, client, owned, self.info.id)
            self._step(record)
        except (ResourceSetupError, SecurityClientError) as exc:
            log.warning("test_2_5_cleanup_failed", error=str(exc))
            left.append(f"{owned.name} {owned.values}")


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
            if _sensitive_name(str(key)) and _discloses(str(key), value):
                found.add(str(key))
            found |= _sensitive_fields(value, depth + 1)
    elif isinstance(node, list):
        for item in node[:_SCAN_LIST_ITEMS]:
            found |= _sensitive_fields(item, depth + 1)
    return found


def _sensitive_name(name: str) -> bool:
    """Whether a field name holds a sensitive marker (_SENSITIVE_NAMES, see there)."""
    words = {word.lower() for word in _NAME_WORD.findall(name)}
    words |= {word.removesuffix("s") for word in words}
    compact = name.lower().replace("_", "").replace("-", "")
    for marker in _SENSITIVE_NAMES:
        bare = marker.replace("_", "")
        if bare in words if len(bare) <= _MAX_WORD_MARKER else bare in compact:
            return True
    return False


def _discloses(name: str, value: object) -> bool:
    """
    Whether a sensitive-named field's value discloses it: a string not empty and
    not masked (_MASK_CHARACTERS), or a number under a numeric marker.
    """
    if name.lower().endswith(_ABOUT_SUFFIXES):
        return False
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, int | float):
        compact = name.lower().replace("_", "").replace("-", "")
        return any(marker in compact for marker in _NUMERIC_MARKERS)
    if not isinstance(value, str) or value == "":
        return False
    masked = sum(character in _MASK_CHARACTERS for character in value)
    return not (masked >= _MIN_MASKED and len(value) - masked <= _MAX_CLEAR)


def _has_key(body: object, key: str) -> bool:
    """Whether a configured JSON body sets a key at its top level."""
    return isinstance(body, dict) and key in body


def _reflected_fields(node: object, depth: int = 0) -> set[str]:
    """The injected mass-assignment fields echoed with their sentinel value."""
    found: set[str] = set()
    if depth > _SCAN_DEPTH:
        return found
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _MASS_FIELDS and _matches_sentinel(value):
                found.add(str(key))
            found |= _reflected_fields(value, depth + 1)
    elif isinstance(node, list):
        for item in node[:_SCAN_LIST_ITEMS]:
            found |= _reflected_fields(item, depth + 1)
    return found


def _exposed_fields(node: object, depth: int = 0) -> set[str]:
    """The injected mass-assignment field names present in a JSON value, any value."""
    found: set[str] = set()
    if depth > _SCAN_DEPTH:
        return found
    if isinstance(node, dict):
        found |= {str(key) for key in node if key in _MASS_FIELDS}
        for value in node.values():
            found |= _exposed_fields(value, depth + 1)
    elif isinstance(node, list):
        for item in node[:_SCAN_LIST_ITEMS]:
            found |= _exposed_fields(item, depth + 1)
    return found


def _matches_sentinel(value: object) -> bool:
    """Whether a read-back value echoes the sentinel the probe injected."""
    return isinstance(value, str) and _MASS_SENTINEL in value
