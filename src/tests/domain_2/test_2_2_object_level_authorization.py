"""
src/tests/domain_2/test_2_2_object_level_authorization.py

Test 2.2: guarantee "users access only their own data" (Broken Object Level
Authorization, BOLA, OWASP API1:2023).

An object must refuse a user who does not own it. The test creates a disposable
object owned by user_a (through a configured resource, config.yaml
`resources:`), confirms user_a is served it, then has user_b read, modify and
delete it: each must be refused. A 2xx to user_b is the violation, proven by
contrast (user_a owns the object, user_b does not).

A refusal is 401, 403 or 404 only (a 400 or 422 from body validation, a 405 or
a redirect says nothing about ownership), and only when it differs from what
the object's read answers a forged credential: otherwise user_b's credential
may simply not have been accepted.

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
from src.core.references import fingerprint_of, random_token
from src.core.test_metadata import Effect, Need, OracleCase, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.auth import auth_parts, credential_parts
from src.tests.helpers.owned_object import (
    SAFE_METHODS,
    PreparedResource,
    create_owned_object,
    not_deleted_note,
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

# The answers that refuse the request (RFC 9110 sections 15.5.2, 15.5.4,
# 15.5.5). Any other non-2xx answer (400 or 422 from body validation, 405, a
# redirect) does not say that ownership was checked.
_REFUSALS: frozenset[ResponseCategory] = frozenset(
    {
        ResponseCategory.UNAUTHENTICATED,
        ResponseCategory.FORBIDDEN,
        ResponseCategory.NOT_FOUND,
    }
)

_REFERENCES: tuple[Reference, ...] = (
    # Read on the ASVS v5.0.0 source 2026-10-22: 8.2.2 (data-specific access
    # restricted to consumers with explicit permissions: IDOR/BOLA).
    Reference(standard=Standard.OWASP_API_TOP10, id="API1:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-8.2.2"),
    Reference(standard=Standard.NIST_SP, id="800-162", section="2.3"),
)


def _shared(sub_test: str) -> tuple[OracleCase, ...]:
    """The cases every cross-user sub-test shares."""
    return (
        OracleCase(
            sub_test=sub_test,
            when="user_b is refused (`401`, `403`, `404`) unlike the forged credential",
            outcome=Outcome.ENFORCED,
            detail="REFUSED",
        ),
        OracleCase(
            sub_test=sub_test,
            when="user_b is refused like the forged credential, or `401` when the forged "
            "credential is not refused",
            outcome=Outcome.NOT_VERIFIABLE,
            detail="CREDENTIAL_NOT_CONFIRMED",
        ),
        OracleCase(
            sub_test=sub_test,
            when="user_b's answer is neither `2xx` nor a refusal (a redirect, `400`, `405`)",
            outcome=Outcome.NOT_VERIFIABLE,
            detail="NOT_A_REFUSAL",
        ),
        OracleCase(
            sub_test=sub_test,
            when="the prepared resource did not create the object",
            outcome=Outcome.NOT_VERIFIABLE,
            detail="OBJECT_NOT_CREATED",
        ),
    )


_ORACLE: tuple[OracleCase, ...] = (
    *_shared(_SUB_READ),
    *_shared(_SUB_MODIFY),
    *_shared(_SUB_DELETE),
    OracleCase(
        sub_test=_SUB_READ,
        when="user_b is served (`2xx`) user_a's object with the owner's answer",
        outcome=Outcome.VIOLATION,
        detail="BOLA_READ",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_READ,
        when="user_b is served with another answer (a `200` may carry an error)",
        outcome=Outcome.VIOLATION,
        detail="BOLA_READ",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_READ,
        when="user_b is served a sub-resource read after the object's own read refused user_b",
        outcome=Outcome.VIOLATION,
        detail="BOLA_READ_SUBRESOURCE",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_READ,
        when="user_a is not served its own object's read",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="OWNER_NOT_SERVED",
    ),
    OracleCase(
        sub_test=_SUB_READ,
        when="user_a is not served a sub-resource read either (not unavailable, a real refusal)",
        outcome=Outcome.NOT_APPLICABLE,
        detail="OWNER_NOT_SERVED_HERE",
    ),
    OracleCase(
        sub_test=_SUB_READ,
        when="no documented read addresses the object",
        outcome=Outcome.NOT_APPLICABLE,
        detail="NO_READ_OPERATION",
    ),
    OracleCase(
        sub_test=_SUB_MODIFY,
        when="user_b's empty-bodied `PATCH`/`PUT` on user_a's object is accepted (`2xx`)",
        outcome=Outcome.VIOLATION,
        detail="BOLA_MODIFY",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_MODIFY,
        when="no documented `PATCH`/`PUT` addresses the object",
        outcome=Outcome.NOT_APPLICABLE,
        detail="NO_MODIFY_OPERATION",
    ),
    OracleCase(
        sub_test=_SUB_DELETE,
        when="user_b's `DELETE` is accepted, and the object served to user_a before is gone after",
        outcome=Outcome.VIOLATION,
        detail="BOLA_DELETE",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_DELETE,
        when="user_b's `DELETE` is accepted, and the object is not shown gone",
        outcome=Outcome.VIOLATION,
        detail="BOLA_DELETE",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_DELETE,
        when="user_b's `DELETE` is accepted, and user_a is still served the object: nothing was "
        "deleted",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="DELETE_NOT_APPLIED",
    ),
    OracleCase(
        sub_test=_SUB_DELETE,
        when="no documented `DELETE` addresses the object",
        outcome=Outcome.NOT_APPLICABLE,
        detail="NO_DELETE_OPERATION",
    ),
)


class Test22Params(BaseModel):
    """Parameters of test 2.2."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    owned_object_resources: tuple[str, ...] = Field(
        default=(),
        description=(
            "The config.yaml `resources:` resources that each create a disposable object owned by "
            "user_a, whose identifiers (its `values`) name the path or query parameters of the "
            "object's "
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
            left: list[str] = []
            for name in self.params(target).owned_object_resources:
                self._run_resource(target, context, client, store, (name, left), user_b)
            return self._finish(notes=not_deleted_note(left) or None)
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
        resource: tuple[str, list[str]],
        user_b: RequestAuthParts,
    ) -> None:
        """Create one owned object, run the cross-user sub-tests on it, delete it.

        resource is the resource's name and the list of objects left behind.
        """
        name, left = resource
        try:
            owned = create_owned_object(target, context, client, name, ROLE_USER_A, self.info.id)
        except (ResourceSetupError, SecurityClientError) as exc:
            # A creation without an answer, or one the target did not evaluate,
            # is named by the shared rule; any other is OBJECT_NOT_CREATED (until
            # 2026-11-16 a transport failure ended the whole test in ERROR).
            log.warning("test_2_2_object_not_created", resource=name, error=str(exc))
            record = exc.record
            reason = self._uninformative(record, _SUB_READ) if record is not None else None
            if isinstance(exc, SecurityClientError):
                reason = reason or ResponseCategory.NO_RESPONSE.value
            for sub in (_SUB_READ, _SUB_MODIFY, _SUB_DELETE):
                self._record(sub, Outcome.NOT_VERIFIABLE, reason or "OBJECT_NOT_CREATED")
            return
        try:
            self._probe_object(target, context, client, store, owned.values, user_b)
        finally:
            self._cleanup(target, context, client, owned, left)

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
        self._owner_was_served = False
        reads = object_operations(target, values, SAFE_METHODS)
        modifies = object_operations(target, values, _MODIFY_METHODS)
        deletes = object_operations(target, values, frozenset({_DELETE_METHOD}))
        read_op = reads[0] if reads else None
        forged = self._forged_answer(target, client, read_op)
        refusal = self._cross_read(client, store, read_op, user_a, user_b, forged)
        if refusal is not None:
            self._cross_read_more(target, client, store, reads[1:], (user_a, user_b), refusal)
        self._cross_modify(client, store, modifies, read_op, user_a, user_b, forged)
        self._cross_delete(client, store, deletes, user_a, user_b, forged, read_op)

    def _forged_answer(
        self,
        target: TargetContext,
        client: SecurityClient,
        read_op: tuple[str, str, str] | None,
    ) -> ResponseCategory | None:
        """
        How the object's read answers a credential that cannot be valid.

        user_b's refusal is evidence of an ownership check only if user_b's
        credential was accepted: a refusal in the same category as this answer
        could be a credential the target does not accept (an expired static
        token). The read is safe (a GET), placed as the run's
        credential is.

        Args:
            target:  The run's target (the credential placement).
            client:  The HTTP client.
            read_op: The object's read operation, or None.

        Returns:
            The answer's category when it is a refusal; None without a read,
            without an answer, or when the read does not refuse a forged
            credential (crAPI serves its orders without checking one): then the
            control says nothing about user_b's credential.
        """
        if read_op is None:
            return None
        method, path, _template = read_op
        record = _send(client, method, path, credential_parts(target, random_token()), self.info.id)
        if record is None:
            return None
        self._step(record)
        category = category_of(record)
        return category if category in _REFUSALS else None

    def _cross_read(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        read_op: tuple[str, str, str] | None,
        user_a: RequestAuthParts,
        user_b: RequestAuthParts,
        forged: ResponseCategory | None,
    ) -> EvidenceRecord | None:
        """
        user_b reads user_a's object; a 2xx is BOLA (forged: _forged_answer).

        Returns:
            user_b's refused answer when the read was judged ENFORCED (the
            contrast _cross_read_more rests on); None otherwise.
        """
        if read_op is None:
            self._record(_SUB_READ, Outcome.NOT_APPLICABLE, "NO_READ_OPERATION")
            return None
        method, path, template = read_op
        owner = self._owner_served(client, method, path, user_a, _SUB_READ)
        if owner is None:
            return None
        record = _send(client, method, path, user_b, self.info.id)
        # CERTAIN when user_b got the owner's answer (same shape): a 200 carrying
        # an error envelope is served too (until 2026-11-16 always CERTAIN).
        same = record is not None and fingerprint_of(record) == fingerprint_of(owner)
        outcome = self._judge_cross(
            record,
            store,
            _SUB_READ,
            (method, path, template),
            forged,
            "read",
            "BOLA_READ",
            confidence=Confidence.CERTAIN if same else Confidence.FIRM,
        )
        return record if outcome == Outcome.ENFORCED else None

    def _cross_read_more(
        self,
        target: TargetContext,
        client: SecurityClient,
        store: EvidenceStore,
        reads: list[tuple[str, str, str]],
        users: tuple[RequestAuthParts, RequestAuthParts],
        refusal: EvidenceRecord,
    ) -> None:
        """
        user_b reads the object's other reads, its sub-resources.

        An ownership check applied to the object's own read can be missing on a
        sub-resource (a private repository's branches, hooks, collaborators).
        Asked only once the object's own read refused user_b: that refusal is
        the contrast a 2xx here is read against, cited by the finding, which is
        FIRM because a sub-resource may be public by design. Each read has its
        own controls: user_a served (else there is nothing to protect there:
        NOT_APPLICABLE) and the forged credential's answer.

        Args:
            target:  The run's target (the credential placement).
            client:  The HTTP client.
            store:   The evidence store.
            reads:   The object's reads after its own (object_operations).
            users:   user_a's and user_b's request parts.
            refusal: user_b's refused answer on the object's own read.
        """
        user_a, user_b = users
        for method, path, template in reads:
            owner = _send(client, method, path, user_a, self.info.id)
            silent = self._uninformative(owner, _SUB_READ)
            if silent is not None:
                # Unavailable or throttled is not "not served here" (until
                # 2026-11-16 NOT_APPLICABLE, which hid unverified reads).
                if owner is not None:
                    self._step(owner)
                self._record(_SUB_READ, Outcome.NOT_VERIFIABLE, silent)
                continue
            if owner is None or category_of(owner) != ResponseCategory.SERVED:
                if owner is not None:
                    self._step(owner)
                self._record(_SUB_READ, Outcome.NOT_APPLICABLE, "OWNER_NOT_SERVED_HERE")
                continue
            self._step(owner)
            forged = self._forged_answer(target, client, (method, path, template))
            record = _send(client, method, path, user_b, self.info.id)
            self._judge_cross(
                record,
                store,
                _SUB_READ,
                (method, path, template),
                forged,
                "read",
                "BOLA_READ_SUBRESOURCE",
                confidence=Confidence.FIRM,
                contrast=refusal,
            )

    def _cross_modify(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        modifies: list[tuple[str, str, str]],
        read_op: tuple[str, str, str] | None,
        user_a: RequestAuthParts,
        user_b: RequestAuthParts,
        forged: ResponseCategory | None,
    ) -> None:
        """user_b modifies user_a's object; a 2xx is BOLA, then user_a re-reads it."""
        if not modifies:
            self._record(_SUB_MODIFY, Outcome.NOT_APPLICABLE, "NO_MODIFY_OPERATION")
            return
        method, path, template = modifies[0]
        record = _send(client, method, path, user_b, self.info.id, json_body={})
        # A 2xx says the write was accepted, not that the object changed (the
        # body is empty): FIRM.
        outcome = self._judge_cross(
            record,
            store,
            _SUB_MODIFY,
            (method, path, template),
            forged,
            "modify",
            "BOLA_MODIFY",
            confidence=Confidence.FIRM,
        )
        if outcome == Outcome.VIOLATION and read_op is not None:
            # user_a's read after the attempt, kept as evidence for the reader
            # (what the object holds now); not judged.
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
        forged: ResponseCategory | None,
        read_op: tuple[str, str, str] | None = None,
    ) -> None:
        """
        user_b deletes user_a's object; a 2xx is BOLA. Runs last (it may remove the object).

        After a 2xx, user_a reads the object: gone (404) proves the deletion
        (CERTAIN); otherwise the 2xx is only an accepted request (FIRM).
        """
        if not deletes:
            self._record(_SUB_DELETE, Outcome.NOT_APPLICABLE, "NO_DELETE_OPERATION")
            return
        method, path, template = deletes[0]
        record = _send(client, method, path, user_b, self.info.id)
        confidence = Confidence.FIRM
        if record is not None and category_of(record) == ResponseCategory.SERVED and read_op:
            after = _send(client, read_op[0], read_op[1], user_a, self.info.id)
            if after is not None:
                self._step(after)
                gone = category_of(after) == ResponseCategory.NOT_FOUND
                if gone and self._owner_was_served:
                    # Served to its owner before, gone after: the deletion is
                    # proven (without the read before, a 404 says nothing).
                    confidence = Confidence.CERTAIN
                elif category_of(after) == ResponseCategory.SERVED:
                    # Still there for its owner: an ownership-scoped delete
                    # answering 2xx having deleted nothing (until 2026-11-16 a
                    # FIRM BOLA_DELETE).
                    self._judge(
                        record, store, _SUB_DELETE, Outcome.NOT_VERIFIABLE, "DELETE_NOT_APPLIED"
                    )
                    return
        self._judge_cross(
            record,
            store,
            _SUB_DELETE,
            (method, path, template),
            forged,
            "delete",
            "BOLA_DELETE",
            confidence=confidence,
        )

    def _owner_served(
        self,
        client: SecurityClient,
        method: str,
        path: str,
        user_a: RequestAuthParts,
        sub_test: str,
    ) -> EvidenceRecord | None:
        """
        Confirm user_a is served its own object (the positive control): without
        it a user_b refusal says nothing, so the sub-test is NOT_VERIFIABLE.

        Returns:
            The owner's answer when served, else None (recorded here).
        """
        record = _send(client, method, path, user_a, self.info.id)
        if record is not None and category_of(record) == ResponseCategory.SERVED:
            self._step(record)
            self._owner_was_served = True
            return record
        silent = self._uninformative(record, sub_test)
        self._record(sub_test, Outcome.NOT_VERIFIABLE, silent or "OWNER_NOT_SERVED")
        if record is not None:
            self._step(record)
        return None

    def _judge_cross(
        self,
        record: EvidenceRecord | None,
        store: EvidenceStore,
        sub_test: str,
        operation: tuple[str, str, str],
        forged: ResponseCategory | None,
        verb: str,
        detail: str,
        *,
        confidence: Confidence = Confidence.CERTAIN,
        contrast: EvidenceRecord | None = None,
    ) -> Outcome:
        """
        Judge user_b's answer on user_a's object; return the recorded outcome.

        A 2xx is BOLA. Only 401, 403 and 404 are a refusal (_REFUSALS), and only
        when they differ from the answer to a forged credential (forged, from
        _forged_answer; without it a 401 is not taken as a refusal): otherwise
        user_b's credential may not have been accepted.
        """
        method, path, template = operation
        if record is None:
            self._record(sub_test, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return Outcome.NOT_VERIFIABLE
        category = category_of(record)
        uninformative = self._uninformative(record, sub_test)
        if uninformative is not None:
            self._judge(record, store, sub_test, Outcome.NOT_VERIFIABLE, uninformative)
            return Outcome.NOT_VERIFIABLE
        if category not in _REFUSALS and category != ResponseCategory.SERVED:
            self._judge(record, store, sub_test, Outcome.NOT_VERIFIABLE, "NOT_A_REFUSAL")
            return Outcome.NOT_VERIFIABLE
        if category != ResponseCategory.SERVED and (
            category == forged or (forged is None and category == ResponseCategory.UNAUTHENTICATED)
        ):
            self._judge(record, store, sub_test, Outcome.NOT_VERIFIABLE, "CREDENTIAL_NOT_CONFIRMED")
            return Outcome.NOT_VERIFIABLE
        if category == ResponseCategory.SERVED:
            if contrast is not None:
                store.pin_evidence(contrast)
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
                        f"({method} {path}, HTTP {record.response_status_code})"
                        + (
                            f", a part of it, while the object itself was refused to user_b "
                            f"({contrast.request_method} {contrast.request_url}, HTTP "
                            f"{contrast.response_status_code}): the ownership check is applied "
                            "to the object and missing here, unless this part is public by "
                            "design"
                            if contrast is not None
                            else ""
                        )
                        + ". The API does not check that the object belongs to the "
                        "authenticated user (BOLA, OWASP API1:2023). Enforce an ownership check "
                        "at the object level (WHERE id = ? AND owner = token-user)."
                    ),
                    supporting_refs=[contrast.record_id] if contrast is not None else [],
                    confidence=confidence,
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
        left: list[str],
    ) -> None:
        """Delete the created object now, or name it in `left` (not_deleted_note)."""
        resource = target.resources.get(owned.name)
        if resource is None or resource.delete is None:
            # The object type has no delete operation (e.g. a crAPI order).
            log.info("test_2_2_object_not_deletable", resource=owned.name)
            left.append(f"{owned.name} {owned.values}")
            return
        try:
            _response, record = delete_resource(target, context, client, owned, self.info.id)
            self._step(record)
        except (ResourceSetupError, SecurityClientError) as exc:
            log.warning("test_2_2_cleanup_failed", error=str(exc))
            left.append(f"{owned.name} {owned.values}")


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
