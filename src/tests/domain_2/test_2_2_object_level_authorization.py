"""
src/tests/domain_2/test_2_2_object_level_authorization.py

Test 2.2: guarantee "users access only their own data" (Broken Object Level
Authorization, BOLA, OWASP API1:2023).

An object must refuse a user who does not own it. The test creates a disposable
object owned by user_a (through a configured resource, config.yaml
`resources:`), confirms user_a is served it, then has user_b read, modify and
delete it: each must be refused. A 2xx to user_b is the violation, proven by
contrast (user_a owns the object, user_b does not).

    cross_user_read    user_b reads user_a's object -> expect non-2xx;
    cross_user_modify  user_b PATCH/PUT user_a's object -> non-2xx, confirmed by
                       a user_a read afterwards (the object was not changed);
    cross_user_delete  user_b DELETE user_a's object -> non-2xx.

The object's own by-id operations are the documented ones whose path parameters
are all identifiers the resource read from the create response
(src/tests/helpers/owned_object.py). The object is created and deleted by the
test (effect CHANGES_DATA); it is user_a's, created and destroyed within the
run, so the destructive cross-user probes act on a disposable object, never on a
shared or pre-existing one.

Mass assignment and excessive data (object property level) are test 2.5; this
test is about the object as a whole (rule 10).

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import structlog
from pydantic import BaseModel, ConfigDict, Field

from src.core.assessment_test import NEEDED_TO_RUN, REFERS_TO_RESOURCE, category_of
from src.core.auth_placement import RequestAuthParts
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, ROLE_USER_B, TargetContext, TestContext
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

# The sub-tests, in the order the test runs them (delete last).
_SUB_READ: str = "cross_user_read"
_SUB_MODIFY: str = "cross_user_modify"
_SUB_DELETE: str = "cross_user_delete"

# The write methods probed by the modify and delete sub-tests.
_MODIFY_METHODS: frozenset[str] = frozenset({"PATCH", "PUT"})
_DELETE_METHOD: str = "DELETE"

# Categories that say nothing about the guarantee (rule 1).
_SPOILING: dict[ResponseCategory, str] = {
    ResponseCategory.UPSTREAM_UNAVAILABLE: "UPSTREAM_UNAVAILABLE",
    ResponseCategory.RATE_LIMITED: "RATE_LIMITED",
    ResponseCategory.NO_RESPONSE: "NO_RESPONSE",
    ResponseCategory.SERVER_ERROR: "SERVER_ERROR",
}

_REFERENCES: tuple[Reference, ...] = (
    # Read on the ASVS v5.0.0 source 2026-10-22: 8.2.2 (data-specific access
    # restricted to consumers with explicit permissions: IDOR/BOLA).
    Reference(standard=Standard.OWASP_API_TOP10, id="API1:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-8.2.2"),
    Reference(standard=Standard.NIST_SP, id="800-162", section="2.3"),
)


class Test22Params(BaseModel):
    """Parameters of test 2.2."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    owned_object_resources: tuple[str, ...] = Field(
        default=(),
        description=(
            "The config.yaml `resources:` resources that each create a disposable object owned by "
            "user_a, whose identifiers (its `values`) name the path parameters of the object's "
            "by-id operations. Each is tested in turn, so several object types are covered. "
            "Without any the test cannot run (BOLA needs an owned object)."
        ),
        json_schema_extra={**NEEDED_TO_RUN, **REFERS_TO_RESOURCE},
    )


class Test22ObjectLevelAuthorization(BaseTest[Test22Params]):
    """
    Test 2.2 -- whether an object refuses a user who does not own it.

    The oracle of each sub-test is in the module docstring and on the test
    page.
    """

    info = TestInfo(
        id="2.2",
        name="Object-Level Authorization",
        priority=0,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-639",
        references=_REFERENCES,
        tags=("authorization", "bola"),
        needs=(Need.USER_ACCOUNT, Need.SECOND_USER_ACCOUNT),
        effect=Effect.CHANGES_DATA,
        sub_tests=(_SUB_READ, _SUB_MODIFY, _SUB_DELETE),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Create user_a's object, then have user_b read, modify and delete it.

        Args:
            target:  The run's target (surface, resources, path seed).
            context: The run's context (the two roles' credentials, teardown).
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._requires_attack_surface(...), self._skip(...),
            or self._error(exc).
        """
        try:
            missing = self._requires_attack_surface(target)
            if missing is not None:
                return missing
            user_b = auth_parts(target, context, ROLE_USER_B)
            for name in self.params(target).owned_object_resources:
                self._run_resource(target, context, client, store, name, user_b)
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
        store: EvidenceStore,
        name: str,
        user_b: RequestAuthParts,
    ) -> None:
        """Create one owned object, run the cross-user sub-tests on it, delete it."""
        try:
            owned = create_owned_object(target, context, client, name, ROLE_USER_A, self.info.id)
        except ResourceSetupError as exc:
            log.warning("test_2_2_object_not_created", resource=name, error=str(exc))
            for sub in (_SUB_READ, _SUB_MODIFY, _SUB_DELETE):
                self._record(sub, Outcome.NOT_VERIFIABLE, "OBJECT_NOT_CREATED")
            return
        try:
            self._probe_object(target, context, client, store, owned.values, user_b)
        finally:
            self._cleanup(target, context, client, owned)

    def _probe_object(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
        values: dict[str, str],
        user_b: RequestAuthParts,
    ) -> None:
        """Run the three cross-user sub-tests on the created object."""
        user_a = auth_parts(target, context, ROLE_USER_A)
        reads = object_operations(target, values, SAFE_METHODS)
        modifies = object_operations(target, values, _MODIFY_METHODS)
        deletes = object_operations(target, values, frozenset({_DELETE_METHOD}))
        read_op = reads[0] if reads else None
        self._cross_read(client, store, read_op, user_a, user_b)
        self._cross_modify(client, store, modifies, read_op, user_a, user_b)
        self._cross_delete(client, store, deletes, user_a, user_b)

    def _cross_read(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        read_op: tuple[str, str, str] | None,
        user_a: RequestAuthParts,
        user_b: RequestAuthParts,
    ) -> None:
        """user_b reads user_a's object; a 2xx is BOLA."""
        if read_op is None:
            self._record(_SUB_READ, Outcome.NOT_APPLICABLE, "NO_READ_OPERATION")
            return
        method, path, template = read_op
        if not self._owner_served(client, method, path, user_a, _SUB_READ):
            return
        record = _send(client, method, path, user_b, self.info.id)
        self._judge_cross(record, store, _SUB_READ, method, path, template, "read", "BOLA_READ")

    def _cross_modify(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        modifies: list[tuple[str, str, str]],
        read_op: tuple[str, str, str] | None,
        user_a: RequestAuthParts,
        user_b: RequestAuthParts,
    ) -> None:
        """user_b modifies user_a's object; a 2xx is BOLA, then user_a re-reads it."""
        if not modifies:
            self._record(_SUB_MODIFY, Outcome.NOT_APPLICABLE, "NO_MODIFY_OPERATION")
            return
        method, path, template = modifies[0]
        record = _send(client, method, path, user_b, self.info.id, json_body={})
        outcome = self._judge_cross(
            record, store, _SUB_MODIFY, method, path, template, "modify", "BOLA_MODIFY"
        )
        if outcome == Outcome.VIOLATION and read_op is not None:
            # Confirm the object really changed owner-side (the modify was not a
            # no-op): a user_a read after the attempt is kept as evidence.
            after = _send(client, read_op[0], read_op[1], user_a, self.info.id)
            if after is not None:
                self._step(after)

    def _cross_delete(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        deletes: list[tuple[str, str, str]],
        user_a: RequestAuthParts,
        user_b: RequestAuthParts,
    ) -> None:
        """user_b deletes user_a's object; a 2xx is BOLA. Runs last (it may remove the object)."""
        del user_a
        if not deletes:
            self._record(_SUB_DELETE, Outcome.NOT_APPLICABLE, "NO_DELETE_OPERATION")
            return
        method, path, template = deletes[0]
        record = _send(client, method, path, user_b, self.info.id)
        self._judge_cross(
            record, store, _SUB_DELETE, method, path, template, "delete", "BOLA_DELETE"
        )

    def _owner_served(
        self,
        client: SecurityClient,
        method: str,
        path: str,
        user_a: RequestAuthParts,
        sub_test: str,
    ) -> bool:
        """
        Confirm user_a is served its own object (the positive control): without
        it a user_b refusal says nothing, so the sub-test is NOT_VERIFIABLE.
        """
        record = _send(client, method, path, user_a, self.info.id)
        if record is not None and category_of(record) == ResponseCategory.SERVED:
            self._step(record)
            return True
        self._record(sub_test, Outcome.NOT_VERIFIABLE, "OWNER_NOT_SERVED")
        if record is not None:
            self._step(record)
        return False

    def _judge_cross(
        self,
        record: EvidenceRecord | None,
        store: EvidenceStore,
        sub_test: str,
        method: str,
        path: str,
        template: str,
        verb: str,
        detail: str,
    ) -> Outcome:
        """Judge user_b's answer on user_a's object; return the recorded outcome."""
        if record is None:
            self._record(sub_test, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return Outcome.NOT_VERIFIABLE
        category = category_of(record)
        if category in _SPOILING:
            self._judge(record, store, sub_test, Outcome.NOT_VERIFIABLE, _SPOILING[category])
            return Outcome.NOT_VERIFIABLE
        if category == ResponseCategory.SERVED:
            self._judge(
                record,
                store,
                sub_test,
                Outcome.VIOLATION,
                detail,
                Finding(
                    title=f"User reached another user's object: {method} {template}",
                    detail=(
                        f"user_b was able to {verb} an object owned by user_a "
                        f"({method} {path}, HTTP {record.response_status_code}). The API does not "
                        "check that the object belongs to the authenticated user (BOLA, OWASP "
                        "API1:2023). Enforce an ownership check at the object level "
                        "(WHERE id = ? AND owner = token-user)."
                    ),
                    confidence=Confidence.CERTAIN,
                ),
            )
            return Outcome.VIOLATION
        self._judge(record, store, sub_test, Outcome.ENFORCED, "REFUSED")
        return Outcome.ENFORCED

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
            log.info("test_2_2_object_not_deletable", resource=owned.name)
            return
        try:
            _response, record = delete_resource(target, context, client, owned, self.info.id)
            self._step(record)
        except (ResourceSetupError, SecurityClientError) as exc:
            log.warning("test_2_2_cleanup_failed", error=str(exc))


def _send(
    client: SecurityClient,
    method: str,
    path: str,
    parts: RequestAuthParts,
    test_id: str,
    json_body: object | None = None,
) -> EvidenceRecord | None:
    """One request carrying the credential parts; its record or None on a transport failure."""
    try:
        _response, record = client.request(
            method,
            path,
            test_id=test_id,
            headers=dict(parts.headers) or None,
            params=dict(parts.params) or None,
            json=json_body,
        )
    except SecurityClientError as exc:
        return exc.record
    return record
