"""
src/tests/domain_1/test_1_1_credential_required.py

Test 1.1: guarantee "only requests carrying a credential reach the operations
the specification declares as protected" (docs/project/test-review/group-b.md).

Three sub-tests:

    no_credential         a documented protected operation answers a request
                          that carries no credential at all;
    malformed_credential  it answers one carrying a credential that cannot be
                          valid (an empty value, an arbitrary string), and the
                          same with the header name written in another case
                          (HTTP header names are case-insensitive, RFC 9110
                          section 5.1);
    path_variants         it answers a variant of its own path that the control
                          may not recognise (src/core/path_variants.py).

What the specification's declaration is worth, and why it sets the confidence.
The OpenAPI inheritance rule makes an operation's `security` its own statement
and the document's global `security` a default (AuthDeclaration). Measured on
the labs (2026-10-22): crAPI declares per operation, 9 of them `security: []`,
and the old test found 2 true violations there; Forgejo's 473 operations all
inherit one global list and none declares anything of its own, so 78 genuinely
public endpoints (`/api/v1/licenses`, `/api/v1/gitignore/templates`,
`/api/v1/orgs`, ...) came out as violations. Both are reported, because the
test's question is whether the target does what the document says (owner,
2026-10-22), and the difference is carried by the confidence: FIRM when the
operation declares its own requirement, TENTATIVE when only the document's
default applies, with the finding saying so. A note states once whether the
document distinguishes the two at all, so that a heap of TENTATIVE findings is
read for what it is.

Nothing is read off the status code alone. An answer is compared with what a
random sibling of the same path gives (the calibration of
src/core/references.py), so that a `404` meaning "no such object" is not taken
for "the operation is not there".

**The test carries no credential of its own** (BLACK_BOX, as the methodology
asks). Its question is what the target does when a request carries none, which
is observed directly, so no positive control is involved. An earlier version
asked one per violation, to rule out "this operation refuses everyone": it
suppressed 24 true cases on Forgejo + Kong (2026-10-22), because the lab's
token is issued with narrower scopes than anonymous access and the operation
refused it while serving an anonymous request. Whether our credential is
accepted somewhere else says nothing about whether a credential is required
here.

Writes (effect CHANGES_DATA, the precedent of 0.1, owner 2026-10-21). An
operation whose method writes is probed too: leaving out half the surface
would leave out its most dangerous half. It is sent on a path whose parameters
are random values of the declared type, never on the operator's resources, so
that a write which gets through finds no object of theirs to act on; anything
it creates (a `2xx` with a `Location`) is deleted at once, and what cannot be
deleted is stated in the result.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import structlog

from src.core.assessment_test import category_of
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
from src.core.models import (
    AuthDeclaration,
    Confidence,
    CredentialLocation,
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
from src.core.path_variants import path_variants
from src.core.references import Similarity, random_sibling_path
from src.core.test_metadata import Effect, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.path_resolver import resolve_path_with_seed

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The sub-tests, in the order the page lists them.
_SUB_NONE: str = "no_credential"
_SUB_MALFORMED: str = "malformed_credential"
_SUB_VARIANTS: str = "path_variants"

# The methods that change nothing: they are probed on the path as the operator
# seeded it, so that the request reaches the control instead of a 404.
_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

# The credential values that cannot be valid, each with the detail it is
# recorded under. They are sent **where and how the target expects a
# credential** (`target.credential_placement`, resolved from the configuration
# and the specification), because a value sent under another scheme is refused
# for being the wrong scheme and proves nothing about whether the content is
# checked: Forgejo expects `Authorization: token <value>`, and `Bearer null`
# would never have reached its check. Where no placement is configured, the
# fallback is `Authorization` with the Bearer scheme.
_MALFORMED_VALUES: tuple[tuple[str, str], ...] = (
    # Nothing after the prefix. A trailing space would be an illegal header
    # value and the HTTP library refuses to send it.
    ("EMPTY_CREDENTIAL", ""),
    ("WORD_NULL", "null"),
    ("ARBITRARY_STRING", "zqxv-not-a-credential"),
)

# The fallback placement, when the configuration declares none.
_FALLBACK_HEADER: str = "Authorization"
_FALLBACK_PREFIX: str = "Bearer "

# The categories in which the answer refuses the request: the control answered.
_REFUSING: frozenset[ResponseCategory] = frozenset(
    {ResponseCategory.UNAUTHENTICATED, ResponseCategory.FORBIDDEN}
)

# The answer categories that say nothing about the guarantee (rule 1). The old
# test counted 14 endpoints answering 503 as a PASS (Q-29).
_SPOILING: dict[ResponseCategory, str] = {
    ResponseCategory.UPSTREAM_UNAVAILABLE: "UPSTREAM_UNAVAILABLE",
    ResponseCategory.RATE_LIMITED: "RATE_LIMITED",
    ResponseCategory.NO_RESPONSE: "NO_RESPONSE",
    ResponseCategory.SERVER_ERROR: "SERVER_ERROR",
}

# The header a created object's address comes in (RFC 9110 section 10.2.2).
_LOCATION_HEADER: str = "location"

# How many items a note lists by name.
_NOTE_EXAMPLES: int = 12

# Each one read on its source, 2026-10-22 (rule 8). ASVS 8.2.1 is the
# function-level access control this test checks; 6.3.4 is the consistency
# across pathways that the path variants ask about; NIST SP 800-228 section
# 3.2.1 holds REC-API-11, "the robust authentication and correct processing of
# authentication credentials", which covers the malformed ones. An earlier
# version cited ASVS 6.2.1, which is the minimum length of a password, and
# NIST SP 800-63B section 3.2.2, which is throttling: both wrong here.
_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API2:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-8.2.1"),
    Reference(standard=Standard.ASVS, id="v5.0.0-6.3.4"),
    Reference(standard=Standard.NIST_SP, id="800-228", section="3.2.1"),
    Reference(standard=Standard.RFC, id="9110", section="5.1"),
)


class Test11CredentialRequired(BaseTest):
    """
    Test 1.1 -- whether a documented protected operation answers without a credential.

    The oracle of each sub-test is in the module docstring and on the test
    page.
    """

    info = TestInfo(
        id="1.1",
        name="Credential Required on Documented Operations",
        priority=0,
        strategy=TestStrategy.BLACK_BOX,
        cwe="CWE-306",
        references=_REFERENCES,
        tags=("authentication", "access-control"),
        effect=Effect.CHANGES_DATA,
        sub_tests=(_SUB_NONE, _SUB_MALFORMED, _SUB_VARIANTS),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Probe every documented operation without a credential, then the variants.

        Args:
            target:  The run's target (surface, path_seed, credentials).
            context: The run's context (reference responses, credentials).
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._skip() without an attack surface, or
            self._error(exc).
        """
        try:
            missing = self._requires_attack_surface(target)
            if missing is not None:
                return missing
            surface = target.attack_surface
            endpoints = sorted(
                (surface.endpoints if surface is not None else ()),
                key=lambda e: (e.path, e.method),
            )
            notes: list[InfoNote] = []
            enforced: list[EndpointRecord] = []
            left_behind: list[str] = []
            undeclared = [e for e in endpoints if e.auth_declaration == AuthDeclaration.OPERATION]
            for endpoint in endpoints:
                self._probe_endpoint(
                    target, context, client, store, endpoint, enforced, left_behind
                )
            notes += self._declaration_note(endpoints, undeclared)
            notes += _cleanup_note(left_behind)
            sample = _sample(enforced)
            for endpoint in sample:
                self._probe_malformed(target, context, client, store, endpoint)
                self._probe_variants(target, context, client, store, endpoint)
            if not sample:
                self._record(_SUB_MALFORMED, Outcome.NOT_VERIFIABLE, "NO_PROVEN_CONTROL")
                self._record(_SUB_VARIANTS, Outcome.NOT_VERIFIABLE, "NO_PROVEN_CONTROL")
            return self._finish(notes=notes)
        except SecurityClientError as exc:
            return self._error(exc)

    # ------------------------------------------------------------------
    # Sub-test 1: no credential at all
    # ------------------------------------------------------------------

    def _probe_endpoint(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
        endpoint: EndpointRecord,
        enforced: list[EndpointRecord],
        left_behind: list[str],
    ) -> None:
        """
        Ask one documented operation with no credential and judge the answer.

        Args:
            target:      The run's target (path_seed).
            context:     The run's context (reference responses).
            client:      The run's HTTP client.
            store:       The evidence store.
            endpoint:    The operation.
            enforced:    Collects the operations proven to require a credential.
            left_behind: Collects what a write created and could not delete.
        """
        method = endpoint.method.upper()
        writes = method not in _SAFE_METHODS
        if not endpoint.requires_auth:
            detail = (
                "DECLARED_PUBLIC"
                if endpoint.auth_declaration == AuthDeclaration.OPERATION
                else "NO_SECURITY_DECLARED"
            )
            self._record(_SUB_NONE, Outcome.NOT_APPLICABLE, detail)
            return
        path = (
            random_sibling_path(endpoint.path, endpoint.parameters)
            if writes
            else resolve_path_with_seed(endpoint.path, target.path_seed)
        )
        record = self._ask(client, method, path, None, endpoint)
        category = category_of(record)
        if category in _REFUSING:
            self._judge(record, store, _SUB_NONE, Outcome.ENFORCED, "CREDENTIAL_REQUIRED")
            enforced.append(endpoint)
            return
        if category in _SPOILING:
            self._judge(record, store, _SUB_NONE, Outcome.NOT_VERIFIABLE, _SPOILING[category])
            return
        if category == ResponseCategory.REDIRECT:
            # Not followed: a redirect may lead to a login page (the control
            # working) or to the resource itself (the control missed).
            self._judge(record, store, _SUB_NONE, Outcome.NOT_VERIFIABLE, "REDIRECTED")
            return
        if category == ResponseCategory.INVALID_REQUEST:
            # The application validated the request without a credential, so
            # validation runs before authentication (NIST SP 800-228
            # REC-API-14 asks for the opposite order). The operation was not
            # served, so this is not an answer to this test's question; it is
            # counted apart and named in the result.
            self._judge(
                record, store, _SUB_NONE, Outcome.NOT_VERIFIABLE, "VALIDATED_WITHOUT_CREDENTIAL"
            )
            return
        if category != ResponseCategory.SERVED:
            similarity = context.references.same_as_unknown(
                record, endpoint.path, None, endpoint.parameters
            )
            detail = (
                "NOT_FOUND_LIKE_UNKNOWN"
                if similarity == Similarity.SAME_AS_UNKNOWN
                else "NOT_FOUND_OWN_ANSWER"
            )
            self._judge(record, store, _SUB_NONE, Outcome.NOT_VERIFIABLE, detail)
            return
        if writes:
            self._clean_up(client, record, path, left_behind)
        own = endpoint.auth_declaration == AuthDeclaration.OPERATION
        self._judge(
            record,
            store,
            _SUB_NONE,
            Outcome.VIOLATION,
            "SERVED_WITHOUT_CREDENTIAL",
            Finding(
                title=f"Served without a credential: {method} {path}",
                detail=(
                    f"{method} {endpoint.path} answered HTTP {record.response_status_code} to a "
                    "request carrying no credential, while the specification declares a security "
                    + (
                        "requirement on the operation itself."
                        if own
                        else "requirement for the whole document, which this operation inherits: "
                        "it may be a public operation the document does not mark as such "
                        "(`security: []`), or a control that is missing. The document and the "
                        "target disagree either way."
                    )
                    + " Enforce the credential at the gateway or in the application, or declare "
                    "the operation public in the specification."
                ),
                confidence=Confidence.FIRM if own else Confidence.TENTATIVE,
            ),
        )

    def _declaration_note(
        self, endpoints: list[EndpointRecord], undeclared: list[EndpointRecord]
    ) -> list[InfoNote]:
        """
        The note saying whether the document declares security per operation.

        Args:
            endpoints:  Every documented operation.
            undeclared: Those declaring their own security requirement.

        Returns:
            One note, or none when there is no operation at all.
        """
        if not endpoints:
            return []
        if undeclared:
            return [
                InfoNote(
                    title="The specification declares security per operation",
                    detail=(
                        f"{len(undeclared)} of {len(endpoints)} documented operations declare "
                        "their own security requirement, so what the document says about an "
                        "operation is a statement about it, and the findings of this test are "
                        "FIRM."
                    ),
                )
            ]
        return [
            InfoNote(
                title="The specification declares security only for the whole document",
                detail=(
                    f"None of the {len(endpoints)} documented operations declares its own "
                    "security requirement: every one inherits the document's global `security`, "
                    "and not one is marked public with `security: []`. The document therefore "
                    "does not distinguish a public operation from a protected one, so every "
                    "finding of this test is TENTATIVE: an operation that answers without a "
                    "credential may be public and undeclared. Declaring `security: []` on the "
                    "public operations makes the result exact."
                ),
            )
        ]

    # ------------------------------------------------------------------
    # Sub-test 2: a credential that cannot be valid
    # ------------------------------------------------------------------

    def _probe_malformed(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
        endpoint: EndpointRecord,
    ) -> None:
        """
        Ask an operation proven to need a credential with ones that cannot be valid.

        Args:
            target:   The run's target (path_seed).
            context:  The run's context (unused; kept for symmetry).
            client:   The run's HTTP client.
            store:    The evidence store.
            endpoint: The operation, already proven to require a credential.
        """
        del context
        method = endpoint.method.upper()
        path = resolve_path_with_seed(endpoint.path, target.path_seed)
        for detail, header, value in _malformed_credentials(target):
            record = self._ask(client, method, path, {header: value}, endpoint)
            category = category_of(record)
            if category in _REFUSING:
                self._judge(record, store, _SUB_MALFORMED, Outcome.ENFORCED, "CREDENTIAL_REFUSED")
                continue
            if category in _SPOILING:
                self._judge(
                    record, store, _SUB_MALFORMED, Outcome.NOT_VERIFIABLE, _SPOILING[category]
                )
                continue
            if category != ResponseCategory.SERVED:
                self._judge(record, store, _SUB_MALFORMED, Outcome.NOT_VERIFIABLE, "NOT_SERVED")
                continue
            self._judge(
                record,
                store,
                _SUB_MALFORMED,
                Outcome.VIOLATION,
                f"ACCEPTED_{detail}",
                Finding(
                    title=f"Credential that cannot be valid accepted: {method} {path}",
                    detail=(
                        f"{method} {endpoint.path} refuses a request with no credential, and "
                        f"answered HTTP {record.response_status_code} to one carrying "
                        f"`{header}: {value}`. The control checks that the header is there, not "
                        "what it holds, so any string passes it."
                    ),
                    confidence=Confidence.CERTAIN,
                ),
            )

    # ------------------------------------------------------------------
    # Sub-test 3: the variants of the path
    # ------------------------------------------------------------------

    def _probe_variants(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
        endpoint: EndpointRecord,
    ) -> None:
        """
        Ask the variants of a protected operation's path with no credential.

        Args:
            target:   The run's target (path_seed).
            context:  The run's context (unused; kept for symmetry).
            client:   The run's HTTP client.
            store:    The evidence store.
            endpoint: The operation, already proven to require a credential.
        """
        del context
        method = endpoint.method.upper()
        path = resolve_path_with_seed(endpoint.path, target.path_seed)
        for variant in path_variants(path):
            record = self._ask(client, method, variant.path, None, endpoint)
            category = category_of(record)
            if category in _SPOILING:
                self._judge(
                    record, store, _SUB_VARIANTS, Outcome.NOT_VERIFIABLE, _SPOILING[category]
                )
                continue
            if category != ResponseCategory.SERVED:
                # Refused, or not routed at all: the control was not missed.
                self._judge(record, store, _SUB_VARIANTS, Outcome.ENFORCED, "VARIANT_NOT_SERVED")
                continue
            self._judge(
                record,
                store,
                _SUB_VARIANTS,
                Outcome.VIOLATION,
                f"SERVED_AS_{variant.kind.value}",
                Finding(
                    title=f"Path variant served without a credential: {method} {variant.path}",
                    detail=(
                        f"{method} {path} refuses a request with no credential, and the variant "
                        f"{variant.path} ({variant.kind.value}) answered HTTP "
                        f"{record.response_status_code} without one. The control is attached to "
                        "the path as written, and the target routes another spelling of it to "
                        "the same operation: normalise the path before applying the control."
                    ),
                    confidence=Confidence.CERTAIN,
                ),
            )

    # ------------------------------------------------------------------
    # Requests and cleanup
    # ------------------------------------------------------------------

    def _ask(
        self,
        client: SecurityClient,
        method: str,
        path: str,
        headers: dict[str, str] | None,
        endpoint: EndpointRecord,
    ) -> EvidenceRecord:
        """
        Send one probe, with an empty body where the method carries one.

        Args:
            client:   The run's HTTP client.
            method:   The HTTP method.
            path:     The concrete path.
            headers:  Headers to add, if any.
            endpoint: The operation (its declared body decides whether one is sent).

        Returns:
            The record of the answer, or of the transport failure.

        Raises:
            SecurityClientError: A failure with no record at all.
        """
        body: dict[str, object] | None = (
            {} if endpoint.request_body_content_types or endpoint.request_body_required else None
        )
        try:
            _response, record = client.request(
                method, path, test_id=self.info.id, headers=headers, json=body
            )
        except SecurityClientError as exc:
            if exc.record is None:
                raise
            return exc.record
        return record

    def _clean_up(
        self,
        client: SecurityClient,
        record: EvidenceRecord,
        path: str,
        left_behind: list[str],
    ) -> None:
        """
        Delete what an accepted write created, or record that it stays.

        Args:
            client:      The run's HTTP client.
            record:      The answer to the write.
            path:        The path written to.
            left_behind: Collects what could not be deleted.
        """
        created = record.response_headers.get(_LOCATION_HEADER)
        target_path = created if created and created.startswith("/") else None
        if target_path is None:
            left_behind.append(path)
            return
        try:
            _response, removal = client.request("DELETE", target_path, test_id=self.info.id)
        except SecurityClientError:
            left_behind.append(target_path)
            return
        self._step(removal)
        if category_of(removal) != ResponseCategory.SERVED:
            left_behind.append(target_path)


def _malformed_credentials(target: TargetContext) -> list[tuple[str, str, str]]:
    """
    The credentials that cannot be valid, as the target expects a credential.

    Each value is put where and how the configuration says a credential goes,
    so that what is tested is whether the content is checked and not whether
    the scheme is recognised. Two more cases write the header's name in lower
    and in upper case: header names are case-insensitive (RFC 9110 section
    5.1), and a control that matches the name as written misses them.

    Args:
        target: The run's target (the credential placement).

    Returns:
        (detail, header name, header value) per case. A placement that puts the
        credential in a query parameter or a cookie yields the header cases
        only through the fallback, since there is no header name to vary.
    """
    placement = target.credential_placement
    cases: list[tuple[str, str, str]] = []
    if placement is not None and placement.location is CredentialLocation.HEADER:
        name, prefix = placement.name, placement.prefix
    elif placement is not None:
        # The credential travels in a query parameter or a cookie: the values
        # are sent there, and the header variants do not apply.
        for detail, value in _MALFORMED_VALUES:
            parts = placement.request_parts(value)
            for header, sent in parts.headers.items():
                cases.append((detail, header, sent))
            for parameter, sent in parts.params.items():
                cases.append((f"{detail}_IN_QUERY", parameter, sent))
        return cases
    else:
        name, prefix = _FALLBACK_HEADER, _FALLBACK_PREFIX
    for detail, value in _MALFORMED_VALUES:
        cases.append((detail, name, f"{prefix}{value}".rstrip()))
    arbitrary = f"{prefix}{_MALFORMED_VALUES[-1][1]}"
    cases.append(("HEADER_LOWERCASE", name.lower(), arbitrary))
    cases.append(("HEADER_UPPERCASE", name.upper(), arbitrary))
    return cases


def _sample(enforced: list[EndpointRecord]) -> list[EndpointRecord]:
    """
    The operations the variants and malformed credentials are tried on.

    Whether a control is attached to the path as written, or to the path after
    normalisation, is a property of the component that applies it, not of each
    operation: one operation per first path segment is enough, and that segment
    is what separates the services behind one gateway (crAPI answers under
    `/identity`, `/community` and `/workshop`, each a different application;
    Forgejo has one). The shortest path of each group is taken, the
    alphabetically first among equals, so that two runs choose the same.

    **Only an operation whose method changes nothing** is taken: these two
    sub-tests send several requests per operation, on paths filled with the
    operator's own seeded values, and a write among them would act on their
    resources.

    Args:
        enforced: The operations proven to require a credential.

    Returns:
        The sample, in a fixed order.
    """
    groups: dict[str, EndpointRecord] = {}
    safe = [e for e in enforced if e.method.upper() in _SAFE_METHODS]
    for endpoint in sorted(safe, key=lambda e: (len(e.path), e.path, e.method)):
        first = endpoint.path.lstrip("/").split("/", 1)[0]
        groups.setdefault(first, endpoint)
    return [groups[key] for key in sorted(groups)]


def _cleanup_note(left_behind: list[str]) -> list[InfoNote]:
    """
    The note of what a write created and the test could not delete.

    Args:
        left_behind: The paths.

    Returns:
        One note, or none.
    """
    if not left_behind:
        return []
    return [
        InfoNote(
            title="Objects a write may have left on the target",
            detail=(
                f"{len(left_behind)} write(s) sent without a credential were accepted and the "
                "test could not delete what they may have created, because the answer carried no "
                f"Location: {', '.join(left_behind[:_NOTE_EXAMPLES])}. The paths were filled with "
                "random values, so no object of the operator's was addressed."
            ),
        )
    ]
