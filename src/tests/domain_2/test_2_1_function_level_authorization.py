"""
src/tests/domain_2/test_2_1_function_level_authorization.py

Test 2.1: guarantee "only authorised users reach privileged functions"
(docs/project/test-review/group-e.md). Broken Function Level Authorization
(BFLA), OWASP API5:2023.

A privileged function (an admin or management operation) must refuse an
ordinary user. The test probes every privileged operation with the user_a
credential and expects a refusal; a 2xx is the violation (an authenticated but
unprivileged user reached a function meant for an administrator).

What counts as privileged is derived from the specification (the Phase-2 rule
`privileged_endpoints`: a path with an `admin` or `management` segment), and the
configuration adds or corrects. The old test took the list from the
configuration and counted a `404` as enforced, which passed a wrong path; here a
`404` is enforced only when the admin positive control proves the operation
exists, otherwise it is NOT_VERIFIABLE.

Only safe methods (GET, HEAD) of a derived privileged operation are sent: a
destructive method on a candidate the configuration has not confirmed is not
probed (rule 5). Where a privileged path documents a destructive method we did
not probe, `method_not_confused` records that the method's authorization was
not verified, so the coverage gap is visible rather than hidden.

Sub-tests:

    privileged_function_refuses_user  each privileged operation refuses user_a;
    method_not_confused               the methods of one privileged path agree
                                      (and the destructive ones not probed are
                                      named).

The admin account is an optional need: when the configuration provides it, the
admin positive control proves the operation exists and is genuinely privileged,
so a refusal is known to be about the role (confidence CERTAIN). Without it the
verdict rests on the path's shape and the specification's `security` (FIRM).

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import structlog

from src.core.assessment_test import category_of
from src.core.auth_placement import RequestAuthParts
from src.core.client import SecurityClient
from src.core.context import ROLE_ADMIN, ROLE_USER_A, TargetContext, TestContext
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
from src.core.references import Credential
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.auth import auth_parts
from src.tests.helpers.path_resolver import resolve_path_with_seed

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The Phase-2 derivation rule whose facts name the privileged operations
# (src/discovery/derivation.py). The name is a plain string here, not an import:
# a test never imports discovery/ (the dependency rule). It must match the rule.
_RULE_PRIVILEGED: str = "privileged_endpoints"

# The sub-tests, in the order the page lists them.
_SUB_REFUSES: str = "privileged_function_refuses_user"
_SUB_METHOD: str = "method_not_confused"

# The methods probed on a derived privileged operation: the safe ones. A
# destructive method (POST, PUT, PATCH, DELETE) on a candidate the configuration
# has not confirmed is not sent (rule 5): it would change the target.
_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})

# Categories that say nothing about the guarantee (rule 1).
_SPOILING: dict[ResponseCategory, str] = {
    ResponseCategory.UPSTREAM_UNAVAILABLE: "UPSTREAM_UNAVAILABLE",
    ResponseCategory.RATE_LIMITED: "RATE_LIMITED",
    ResponseCategory.NO_RESPONSE: "NO_RESPONSE",
    ResponseCategory.SERVER_ERROR: "SERVER_ERROR",
}

# The refusal categories: an authenticated user turned away from a function.
_REFUSED: frozenset[ResponseCategory] = frozenset(
    {ResponseCategory.FORBIDDEN, ResponseCategory.UNAUTHENTICATED}
)

_REFERENCES: tuple[Reference, ...] = (
    # Read on the ASVS v5.0.0 source 2026-10-22: 8.1.1 (a documented and enforced
    # access-control policy), 8.3.1 (function-level access control at the server).
    Reference(standard=Standard.OWASP_API_TOP10, id="API5:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-8.1.1"),
    Reference(standard=Standard.ASVS, id="v5.0.0-8.3.1"),
    Reference(standard=Standard.NIST_SP, id="800-53", section="3"),
)


class Test21FunctionLevelAuthorization(BaseTest):
    """
    Test 2.1 -- whether a privileged function refuses an ordinary user.

    The oracle of each sub-test is in the module docstring and on the test
    page.
    """

    info = TestInfo(
        id="2.1",
        name="Function-Level Authorization",
        priority=1,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-285",
        references=_REFERENCES,
        tags=("authorization", "bfla"),
        needs=(Need.USER_ACCOUNT,),
        optional_needs=(Need.ADMIN_ACCOUNT,),
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB_REFUSES, _SUB_METHOD),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Probe every privileged operation with the user_a credential.

        Args:
            target:  The run's target (surface, derived knowledge, path seed).
            context: The run's context (the roles' credentials, references).
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
            admin = self._admin_credential(target, context)
            privileged = self._privileged_operations(target)
            if not privileged:
                self._record(_SUB_REFUSES, Outcome.NOT_APPLICABLE, "NO_PRIVILEGED_ENDPOINT")
                self._record(_SUB_METHOD, Outcome.NOT_APPLICABLE, "NO_PRIVILEGED_ENDPOINT")
                return self._finish(message="No privileged operation found or configured.")
            served: dict[str, dict[str, bool | None]] = {}
            for method, path, requires_auth in privileged:
                if method not in _SAFE_METHODS:
                    # A destructive method on a derived candidate is not sent
                    # (rule 5), but it is surfaced, not dropped: the analyst sees
                    # a privileged destructive operation whose authorization this
                    # run did not verify (e.g. crAPI's DELETE admin video).
                    self._record(_SUB_REFUSES, Outcome.NOT_VERIFIABLE, "DESTRUCTIVE_NOT_PROBED")
                    served.setdefault(path, {})[method] = None
                    continue
                concrete = resolve_path_with_seed(path, target.path_seed)
                verdict = self._probe(
                    client, store, context, user_a, method, path, concrete, requires_auth, admin
                )
                served.setdefault(path, {})[method] = verdict
            self._judge_methods(target, served)
            return self._finish()
        except AuthenticationSetupError as exc:
            return self._error(exc)
        except SecurityClientError as exc:
            return self._error(exc)

    def _admin_credential(self, target: TargetContext, context: TestContext) -> Credential | None:
        """
        The admin credential as a reference, when the configuration provides it.

        Args:
            target:  The run's target (placement).
            context: The run's context (tokens).

        Returns:
            A Credential labelled "admin", or None when no admin account is set.
        """
        if not context.has_token(ROLE_ADMIN):
            return None
        parts = auth_parts(target, context, ROLE_ADMIN)
        return Credential(label=ROLE_ADMIN, headers=parts.headers, params=parts.params)

    def _privileged_operations(self, target: TargetContext) -> list[tuple[str, str, bool]]:
        """
        The privileged operations to probe: method, path, whether auth is required.

        The derived facts (`privileged_endpoints`), every method; the caller
        sends the safe ones and surfaces the destructive ones without sending
        them (rule 5). `requires_auth` comes from the endpoint record.

        Args:
            target: The run's target (surface, derived facts).

        Returns:
            The operations, each (method, path, requires_auth), unique.
        """
        surface = target.attack_surface
        if surface is None:
            return []
        auth_by_op: dict[tuple[str, str], bool] = {
            (e.method.upper(), e.path): e.requires_auth for e in surface.endpoints
        }
        operations: dict[tuple[str, str], bool] = {}
        for fact in surface.derived_facts(_RULE_PRIVILEGED):
            if fact.method is None or fact.path is None:
                continue
            method = fact.method.upper()
            operations[(method, fact.path)] = auth_by_op.get((method, fact.path), True)
        return [(method, path, auth) for (method, path), auth in operations.items()]

    def _probe(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        context: TestContext,
        user_a: RequestAuthParts,
        method: str,
        template_path: str,
        concrete_path: str,
        requires_auth: bool,
        admin: Credential | None,
    ) -> bool | None:
        """
        Probe one privileged operation with the user_a credential and judge it.

        Returns:
            True when user_a was served (a violation or a public endpoint),
            False when refused, None when the probe could not decide.
        """
        record = _send(client, method, concrete_path, user_a, self.info.id)
        if record is None:
            self._record(_SUB_REFUSES, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return None
        category = category_of(record)
        if category in _SPOILING:
            self._judge(record, store, _SUB_REFUSES, Outcome.NOT_VERIFIABLE, _SPOILING[category])
            return None
        if category == ResponseCategory.SERVED:
            return self._served(
                store, context, method, template_path, concrete_path, requires_auth, admin, record
            )
        if category in _REFUSED:
            self._judge(record, store, _SUB_REFUSES, Outcome.ENFORCED, "REFUSED")
            return False
        if category == ResponseCategory.NOT_FOUND:
            return self._not_found(store, context, method, concrete_path, admin, record)
        # A method not allowed, a redirect, an invalid request: no decision.
        self._judge(record, store, _SUB_REFUSES, Outcome.NOT_VERIFIABLE, category.name)
        return None

    def _served(
        self,
        store: EvidenceStore,
        context: TestContext,
        method: str,
        template_path: str,
        concrete_path: str,
        requires_auth: bool,
        admin: Credential | None,
        record: EvidenceRecord,
    ) -> bool:
        """Judge a 2xx answer to user_a on a privileged operation."""
        if not requires_auth:
            # A public endpoint (whatever its path): whether it should require a
            # credential at all is 1.1's question, not a privilege escalation.
            self._judge(record, store, _SUB_REFUSES, Outcome.NOT_APPLICABLE, "PUBLIC_ENDPOINT")
            return True
        control = _admin_control(context, method, concrete_path, admin)
        certain = control is True
        basis = (
            "confirmed by the admin positive control"
            if certain
            else "an admin/management path in the specification"
        )
        finding = Finding(
            title=f"Ordinary user reached a privileged function: {method} {template_path}",
            detail=(
                f"A request to {method} {concrete_path} with the user_a credential answered "
                f"HTTP {record.response_status_code}. This is a privileged operation ({basis}), so "
                "an authenticated but unprivileged user reached a function meant for an "
                "administrator (BFLA, OWASP API5:2023). Enforce the role at the server for this "
                "operation."
            ),
            confidence=Confidence.CERTAIN if certain else Confidence.FIRM,
        )
        self._judge(record, store, _SUB_REFUSES, Outcome.VIOLATION, "BFLA", finding)
        return True

    def _not_found(
        self,
        store: EvidenceStore,
        context: TestContext,
        method: str,
        concrete_path: str,
        admin: Credential | None,
        record: EvidenceRecord,
    ) -> bool | None:
        """Judge a 404 to user_a: enforced only when admin proves the operation exists."""
        if _admin_control(context, method, concrete_path, admin) is True:
            # The operation exists for admin; user_a gets a 404 that hides it (a
            # gateway may hide a forbidden resource behind 404): a refusal.
            self._judge(record, store, _SUB_REFUSES, Outcome.ENFORCED, "REFUSED_HIDDEN")
            return False
        # No admin control, or admin also got non-2xx: the 404 may be a missing
        # path or an unresolved parameter, not a refusal. Not verifiable (this is
        # the old test's false PASS, now avoided).
        self._judge(record, store, _SUB_REFUSES, Outcome.NOT_VERIFIABLE, "ENDPOINT_NOT_CONFIRMED")
        return None

    def _judge_methods(
        self, target: TargetContext, served: dict[str, dict[str, bool | None]]
    ) -> None:
        """
        Judge whether the safe methods of one privileged path agree for user_a.

        A path whose safe methods give user_a different outcomes (one served, one
        refused) is a method-confusion violation. The destructive methods that
        were not probed are already surfaced per operation
        (DESTRUCTIVE_NOT_PROBED under privileged_function_refuses_user).

        Args:
            target: The run's target (unused; kept for a uniform signature).
            served: Per path, the probed method -> whether user_a was served.
        """
        del target
        any_judged = False
        for path, results in served.items():
            decided = {m: v for m, v in results.items() if v is not None}
            if len(set(decided.values())) > 1:
                any_judged = True
                self._record(
                    _SUB_METHOD,
                    Outcome.VIOLATION,
                    "METHOD_CONFUSION",
                    Finding(
                        title=f"Inconsistent authorization across methods: {path}",
                        detail=(
                            f"On the privileged path {path} the methods did not agree for user_a "
                            f"(served/refused: {decided}). One method enforces the role while "
                            "another does not, so the check is bypassed by changing the method "
                            "(OWASP API5:2023). Apply the same authorization to every method."
                        ),
                        confidence=Confidence.CERTAIN,
                    ),
                )
            elif len(decided) > 1:
                any_judged = True
                self._record(_SUB_METHOD, Outcome.ENFORCED, "METHODS_CONSISTENT")
        if not any_judged:
            self._record(_SUB_METHOD, Outcome.NOT_APPLICABLE, "SINGLE_SAFE_METHOD")


def _send(
    client: SecurityClient,
    method: str,
    path: str,
    parts: RequestAuthParts,
    test_id: str,
) -> EvidenceRecord | None:
    """One request carrying the credential parts, its record or None on a transport failure."""
    try:
        _response, record = client.request(
            method,
            path,
            test_id=test_id,
            headers=dict(parts.headers) or None,
            params=dict(parts.params) or None,
        )
    except SecurityClientError as exc:
        return exc.record
    return record


def _admin_control(
    context: TestContext,
    method: str,
    path: str,
    admin: Credential | None,
) -> bool | None:
    """
    Whether the admin credential is served at this operation (the positive control).

    Args:
        context: The run's context (references).
        method:  The HTTP method.
        path:    The concrete path.
        admin:   The admin credential, or None when no admin account is set.

    Returns:
        True/False when an admin account is available (served or not), None when
        there is no admin account to ask.
    """
    if admin is None:
        return None
    return context.references.positive_control(method, path, admin).works
