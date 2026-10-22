"""
src/tests/domain_0/test_0_3_deprecated_operations.py

Test 0.3: guarantee "an operation the specification marks deprecated is either
switched off or declares its own sunset"
(docs/project/test-review/group-a.md).

One sub-test, deprecated_operations: each operation with `deprecated: true` is
asked for and judged on what it answers and what its response declares.

    410 Gone (RFC 9110 section 15.5.11)        switched off: the guarantee holds;
    served with a Sunset in the future         the timeline is declared
                                               (RFC 8594): the guarantee holds;
    served with a Sunset in the past           it outlived its own deadline;
    served with no Sunset                      its callers are not told when it
                                               stops working.

RFC 9745 (March 2025) made `Deprecation` a Standards Track header: it carries
the date the resource was or will be deprecated, as a Structured Field item
("Deprecation: @1688169599"). A date in the past is normal there, so the header
is read to say whether the API announces the deprecation at all, while the
deadline is the `Sunset` header's business.

Whether an operation is still served is never read off the status code. The
answer is compared with what a random sibling of the same path gives (the
calibration of src/core/references.py): an answer that differs is the
operation's own, one that matches says only that nothing is there. The old test
used a list of statuses it called active, and treated a 404 as the endpoint
being gone.

What is probed, and what is not (effect READ_ONLY):

    - safe methods only (GET, HEAD). A deprecated operation whose method
      writes is never sent: it is counted NOT_VERIFIABLE and named in a note;
    - a path with parameters is filled from the operator's path_seed
      (src/tests/helpers/path_resolver.py). All four deprecated operations of
      the reference lab have parameters, and the old test skipped every path
      holding "{", which is why the violation it holds was never seen;
    - an operation that refuses an unauthenticated request is asked again with
      the user_a credential when one is configured (optional need
      USER_ACCOUNT); refused both ways, nothing is proven and the case is
      NOT_VERIFIABLE.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import structlog

from src.core.assessment_test import category_of
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError, SecurityClientError
from src.core.models import (
    Confidence,
    EndpointRecord,
    EvidenceRecord,
    Finding,
    InfoNote,
    Outcome,
    Reference,
    ResponseCategory,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.references import CalibrationPoint, Credential, Similarity, sibling_pattern
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.auth import acquire_tokens, auth_parts
from src.tests.helpers.path_resolver import (
    extract_param_names_from_path,
    resolve_path_with_seed,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The single sub-test.
_SUB_DEPRECATED: str = "deprecated_operations"

# The methods that change nothing, so a deprecated operation may be asked for.
_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})

# The status of an operation correctly switched off (RFC 9110 section 15.5.11).
_HTTP_GONE: int = 410

# The headers that declare a deprecation, lowercase as the record holds them.
_SUNSET_HEADER: str = "sunset"
_DEPRECATION_HEADER: str = "deprecation"

# The categories in which the answer refuses the request itself: the target did
# not look at the operation, so nothing about it is proven.
_REFUSING: frozenset[ResponseCategory] = frozenset(
    {ResponseCategory.UNAUTHENTICATED, ResponseCategory.FORBIDDEN}
)

# The answer categories that say nothing about the guarantee (rule 1).
_SPOILING: dict[ResponseCategory, str] = {
    ResponseCategory.UPSTREAM_UNAVAILABLE: "UPSTREAM_UNAVAILABLE",
    ResponseCategory.RATE_LIMITED: "RATE_LIMITED",
    ResponseCategory.NO_RESPONSE: "NO_RESPONSE",
    ResponseCategory.SERVER_ERROR: "SERVER_ERROR",
}

# How many items a note lists by name.
_NOTE_EXAMPLES: int = 12

_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API9:2023"),
    Reference(standard=Standard.RFC, id="9745"),
    Reference(standard=Standard.RFC, id="8594"),
    Reference(standard=Standard.RFC, id="9110", section="15.5.11"),
    Reference(standard=Standard.NIST_SP, id="800-228", section="3.1.1"),
)


class Test03DeprecatedOperations(BaseTest):
    """
    Test 0.3 -- whether a deprecated operation is switched off or declares its sunset.

    No primary CWE: the catalogue holds no entry describing an API operation
    that is still served after being deprecated (checked on CWE 4.20,
    2026-10-22), and the guarantee rests on the standards in references.
    """

    info = TestInfo(
        id="0.3",
        name="Deprecated Operations Still Served",
        priority=0,
        strategy=TestStrategy.BLACK_BOX,
        references=_REFERENCES,
        tags=("inventory", "deprecation"),
        optional_needs=(Need.USER_ACCOUNT,),
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB_DEPRECATED,),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Judge every deprecated operation the specification declares.

        Args:
            target:  The run's target (surface, path_seed, credentials).
            context: The run's context (reference responses, credentials).
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._skip() without an attack surface or without a
            deprecated operation, or self._error(exc).
        """
        try:
            missing = self._requires_attack_surface(target)
            if missing is not None:
                return missing
            surface = target.attack_surface
            deprecated = sorted(
                (e for e in (surface.endpoints if surface is not None else ()) if e.is_deprecated),
                key=lambda e: (e.path, e.method),
            )
            if not deprecated:
                return self._skip(
                    "The specification marks no operation 'deprecated: true'. Nothing says that "
                    "no deprecated functionality is served: an endpoint the specification does "
                    "not document at all is test 0.1's question."
                )
            credential = self._credential(target, context, client)
            not_probed: list[str] = []
            not_fillable: list[str] = []
            for endpoint in deprecated:
                if endpoint.method.upper() not in _SAFE_METHODS:
                    not_probed.append(f"{endpoint.method} {endpoint.path}")
                    self._record(_SUB_DEPRECATED, Outcome.NOT_VERIFIABLE, "WRITE_METHOD_NOT_PROBED")
                    continue
                unknown = [
                    name
                    for name in extract_param_names_from_path(endpoint.path)
                    if name not in target.path_seed
                ]
                if unknown:
                    not_fillable.append(f"{endpoint.method} {endpoint.path} ({', '.join(unknown)})")
                    self._record(_SUB_DEPRECATED, Outcome.NOT_VERIFIABLE, "PATH_NOT_FILLABLE")
                    continue
                self._probe(target, context, client, store, endpoint, credential)
            return self._finish(notes=_notes(not_probed, not_fillable))
        except SecurityClientError as exc:
            return self._error(exc)

    # ------------------------------------------------------------------
    # The credential, when one is configured (optional need)
    # ------------------------------------------------------------------

    def _credential(
        self, target: TargetContext, context: TestContext, client: SecurityClient
    ) -> Credential | None:
        """
        The user_a credential, for a second try on an operation that refuses.

        Args:
            target:  The run's target (credentials, placement).
            context: The run's context (the role's credential).
            client:  The run's HTTP client (the login goes through it).

        Returns:
            The Credential, or None when the role is not configured or its
            login did not work (logged, the test goes on unauthenticated).
        """
        if not target.credentials.has_user_a():
            return None
        try:
            acquire_tokens(target, context, client, required_roles=frozenset({ROLE_USER_A}))
            parts = auth_parts(target, context, ROLE_USER_A)
        except (AuthenticationSetupError, SecurityClientError) as exc:
            log.warning("test_0_3_credential_unavailable", error=str(exc))
            return None
        return Credential(label=ROLE_USER_A, headers=dict(parts.headers), params=dict(parts.params))

    # ------------------------------------------------------------------
    # One deprecated operation
    # ------------------------------------------------------------------

    def _probe(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
        endpoint: EndpointRecord,
        credential: Credential | None,
    ) -> None:
        """
        Ask one deprecated operation and judge its answer.

        Args:
            target:     The run's target (path_seed).
            context:    The run's context (reference responses).
            client:     The run's HTTP client.
            store:      The evidence store.
            endpoint:   The deprecated operation.
            credential: The credential for a second try, if any.
        """
        method = endpoint.method.upper()
        path = resolve_path_with_seed(endpoint.path, target.path_seed)
        record = self._send(client, method, path, None)
        used: Credential | None = None
        if category_of(record) in _REFUSING and credential is not None:
            self._step(record)
            record = self._send(client, method, path, credential)
            used = credential
        category = category_of(record)
        if record.response_status_code == _HTTP_GONE:
            self._judge(record, store, _SUB_DEPRECATED, Outcome.ENFORCED, "SWITCHED_OFF")
            return
        if category in _SPOILING:
            self._judge(record, store, _SUB_DEPRECATED, Outcome.NOT_VERIFIABLE, _SPOILING[category])
            return
        if category in _REFUSING:
            self._judge(
                record, store, _SUB_DEPRECATED, Outcome.NOT_VERIFIABLE, "REFUSED_BEFORE_ANSWER"
            )
            return
        similarity = context.references.same_as_unknown(
            record, endpoint.path, used, endpoint.parameters
        )
        if similarity == Similarity.UNRELIABLE:
            self._judge(
                record, store, _SUB_DEPRECATED, Outcome.NOT_VERIFIABLE, "CALIBRATION_UNRELIABLE"
            )
            return
        point = context.references.calibration(
            sibling_pattern(endpoint.path, endpoint.parameters), method, used
        )
        if similarity == Similarity.SAME_AS_UNKNOWN:
            self._judge(
                record,
                store,
                _SUB_DEPRECATED,
                Outcome.NOT_APPLICABLE,
                "NOT_SERVED",
                reference_responses=(point,),
            )
            return
        self._judge_declaration(record, store, endpoint, path, point)

    def _judge_declaration(
        self,
        record: EvidenceRecord,
        store: EvidenceStore,
        endpoint: EndpointRecord,
        path: str,
        point: CalibrationPoint,
    ) -> None:
        """
        Judge what the answer of a served deprecated operation declares.

        Args:
            record:   The answer, already known to be the operation's own.
            store:    The evidence store.
            endpoint: The deprecated operation.
            path:     The concrete path asked.
            point:    The calibration the existence rests on.
        """
        headers = {name.lower(): value for name, value in record.response_headers.items()}
        sunset_raw = headers.get(_SUNSET_HEADER)
        deprecation_raw = headers.get(_DEPRECATION_HEADER)
        announced = deprecation_raw is not None
        where = f"{endpoint.method.upper()} {path}"
        if sunset_raw is None:
            detail = "DEPRECATION_WITHOUT_SUNSET" if announced else "DEPRECATED_WITHOUT_SUNSET"
            said = (
                "The response carries a Deprecation header (RFC 9745), so the API announces the "
                "deprecation, but no Sunset header (RFC 8594), so it does not say when the "
                "operation stops working."
                if announced
                else "The response carries neither a Deprecation header (RFC 9745) nor a Sunset "
                "header (RFC 8594): a caller of this operation is not told that it is deprecated "
                "at all."
            )
            self._judge(
                record,
                store,
                _SUB_DEPRECATED,
                Outcome.VIOLATION,
                detail,
                Finding(
                    title=f"Deprecated operation still served: {where}",
                    detail=(
                        f"The specification marks {endpoint.method.upper()} {endpoint.path} "
                        f"'deprecated: true', and it answered HTTP {record.response_status_code}, "
                        f"unlike a random sibling of the same path. {said} Either switch the "
                        "operation off and answer 410 Gone, or declare Sunset with a future date "
                        "and a Link to its replacement."
                    ),
                    confidence=Confidence.FIRM,
                ),
                reference_responses=(point,),
            )
            return
        sunset = _http_date(sunset_raw)
        if sunset is None:
            self._judge(record, store, _SUB_DEPRECATED, Outcome.NOT_VERIFIABLE, "SUNSET_NOT_A_DATE")
            return
        if sunset <= datetime.now(UTC):
            self._judge(
                record,
                store,
                _SUB_DEPRECATED,
                Outcome.VIOLATION,
                "PAST_SUNSET_STILL_SERVED",
                Finding(
                    title=f"Operation served after its sunset: {where}",
                    detail=(
                        f"The specification marks {endpoint.method.upper()} {endpoint.path} "
                        f"'deprecated: true' and its response declares Sunset "
                        f"{sunset.isoformat()}, which has passed, yet it answered HTTP "
                        f"{record.response_status_code}. An operation kept alive past its own "
                        "deadline is one nobody is maintaining: answer 410 Gone."
                    ),
                    confidence=Confidence.FIRM,
                ),
                reference_responses=(point,),
            )
            return
        self._judge(
            record,
            store,
            _SUB_DEPRECATED,
            Outcome.ENFORCED,
            "SUNSET_DECLARED",
            reference_responses=(point,),
        )

    def _send(
        self,
        client: SecurityClient,
        method: str,
        path: str,
        credential: Credential | None,
    ) -> EvidenceRecord:
        """
        Send one request, keeping the record of a transport failure.

        Args:
            client:     The run's HTTP client.
            method:     The HTTP method.
            path:       The concrete path.
            credential: The credential to carry, if any.

        Returns:
            The EvidenceRecord of the answer, or of the failure.

        Raises:
            SecurityClientError: A failure with no record at all.
        """
        try:
            _response, record = client.request(
                method,
                path,
                test_id=self.info.id,
                headers=dict(credential.headers) if credential else None,
                params=dict(credential.params) if credential and credential.params else None,
            )
        except SecurityClientError as exc:
            if exc.record is None:
                raise
            return exc.record
        return record


def _http_date(value: str) -> datetime | None:
    """
    The date of a Sunset header, or None when it is not one.

    RFC 8594 carries an HTTP-date (RFC 9110 section 5.6.7). An unparseable
    value is not read as compliant: the caller counts it NOT_VERIFIABLE.

    Args:
        value: The header as sent.

    Returns:
        The date with a time zone, or None.
    """
    try:
        parsed = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _notes(not_probed: list[str], not_fillable: list[str]) -> list[InfoNote]:
    """
    The notes on the deprecated operations left unjudged.

    Args:
        not_probed:   Operations whose method writes.
        not_fillable: Operations with a parameter absent from path_seed.

    Returns:
        One note per group that is not empty.
    """
    notes: list[InfoNote] = []
    if not_probed:
        notes.append(
            InfoNote(
                title="Deprecated operations that write, not probed",
                detail=(
                    f"{len(not_probed)} deprecated operation(s) use a method that changes data, "
                    "so this read-only test did not send them and says nothing about them: "
                    f"{', '.join(not_probed[:_NOTE_EXAMPLES])}. Whether they are still served has "
                    "to be checked by hand."
                ),
            )
        )
    if not_fillable:
        notes.append(
            InfoNote(
                title="Deprecated operations whose path could not be filled",
                detail=(
                    f"{len(not_fillable)} deprecated operation(s) have a path parameter with no "
                    "value in target.path_seed, so no concrete path could be asked for: "
                    f"{', '.join(not_fillable[:_NOTE_EXAMPLES])}. Add the parameter to path_seed "
                    "to have them judged."
                ),
            )
        )
    return notes
