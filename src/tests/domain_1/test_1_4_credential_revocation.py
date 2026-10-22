"""
src/tests/domain_1/test_1_4_credential_revocation.py

Test 1.4: guarantee "a credential that has been revoked is refused"
(docs/project/test-review/group-c.md).

One sub-test, rejected_after_revocation. The test creates a credential of its
own through the configured login, confirms it works, revokes it the way the
login method allows (deleting the token it created, which is Forgejo's
mechanism; a logout where the method has one), and sends it again, expecting a
refusal. A `2xx` after revocation is the violation: the credential outlives
the act meant to end it, so a stolen or logged-out token keeps access.

The mechanism is the login method's own, read from the configuration, never
hard-coded to one target: `Need.REVOCABLE_LOGIN` is met only when the login
resource has a delete request (src/tests/helpers/auth_base.py). A target whose
login cannot revoke a credential (crAPI issues a stateless JWT with no logout)
does not meet the need and the engine records the test SKIP before it runs;
revocation by a password change is a separate, target-specific flow and is not
part of this test (its own review may add it where the configuration describes
it).

Rebuilt from the test on `main`, on the new base: the anchor is derived, not a
configured endpoint, and the oracle rests on the credential having worked
before revocation.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import structlog

from src.core.assessment_test import category_of
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError, SecurityClientError
from src.core.models import (
    Confidence,
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
from src.tests.helpers.anchor import Anchor, find_anchor
from src.tests.helpers.auth import revocation_capability

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The single sub-test.
_SUB_REVOKED: str = "rejected_after_revocation"

# The answer categories that say nothing about the guarantee (rule 1).
_SPOILING: dict[ResponseCategory, str] = {
    ResponseCategory.UPSTREAM_UNAVAILABLE: "UPSTREAM_UNAVAILABLE",
    ResponseCategory.RATE_LIMITED: "RATE_LIMITED",
    ResponseCategory.NO_RESPONSE: "NO_RESPONSE",
    ResponseCategory.SERVER_ERROR: "SERVER_ERROR",
}

_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API2:2023"),
    Reference(standard=Standard.RFC, id="7009"),
    Reference(standard=Standard.RFC, id="7519", section="4.1.7"),
    Reference(standard=Standard.ASVS, id="v5.0.0-7.4.1"),
)


class Test14CredentialRevocation(BaseTest):
    """
    Test 1.4 -- whether a revoked credential is refused.

    The oracle is in the module docstring and on the test page.
    """

    info = TestInfo(
        id="1.4",
        name="Credential Revocation",
        priority=2,
        strategy=TestStrategy.WHITE_BOX,
        cwe="CWE-613",
        references=_REFERENCES,
        tags=("authentication", "credential-lifecycle"),
        needs=(Need.USER_ACCOUNT, Need.REVOCABLE_LOGIN),
        effect=Effect.CHANGES_DATA,
        sub_tests=(_SUB_REVOKED,),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Create a credential, confirm it works, revoke it, reuse it.

        Args:
            target:  The run's target (surface, path_seed, login method).
            context: The run's context (secrets, teardown).
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._skip() without an attack surface or a
            revocation capability, or self._error(exc).
        """
        try:
            missing = self._requires_attack_surface(target)
            if missing is not None:
                return missing
            method = revocation_capability(target)
            if method is None:
                return self._skip(
                    "The configured login cannot revoke a credential: `Need.REVOCABLE_LOGIN` is "
                    "not met (auth_type 'login' with a login resource that has a delete request "
                    "can). crAPI issues a stateless JWT with no logout, so there is nothing to "
                    "revoke."
                )
            placement = target.credential_placement
            if placement is None:
                return self._skip(
                    "No credential placement is configured, so the created credential cannot be "
                    "sent (credentials.auth_type is not set)."
                )
            credential = method.create_temporary_credential(
                target, context, client, ROLE_USER_A, self.info.id
            )
            parts = placement.request_parts(credential.value)
            anchor = find_anchor(
                target, client, dict(parts.headers), dict(parts.params), self.info.id
            )
            if anchor is None:
                self._record(_SUB_REVOKED, Outcome.NOT_VERIFIABLE, "NO_WORKING_ANCHOR")
                return self._finish()
            self._step(anchor.record)
            outcome = method.revoke_credential(target, context, client, credential, self.info.id)
            self._step(outcome.record)
            if not outcome.revoked:
                self._record(_SUB_REVOKED, Outcome.NOT_VERIFIABLE, "REVOCATION_NOT_CONFIRMED")
                return self._finish()
            self._reuse(client, store, anchor, dict(parts.headers), dict(parts.params))
            return self._finish()
        except AuthenticationSetupError as exc:
            return self._error(exc)
        except SecurityClientError as exc:
            return self._error(exc)

    def _reuse(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        anchor: Anchor,
        headers: dict[str, str],
        params: dict[str, str],
    ) -> None:
        """
        Send the revoked credential to the anchor and judge the answer.

        Args:
            client:  The run's HTTP client.
            store:   The evidence store.
            anchor:  The operation the credential was accepted on before revocation.
            headers: The headers carrying the revoked credential.
            params:  The query parameters carrying it, if any.
        """
        method = anchor.method
        path = anchor.path
        try:
            _response, record = client.request(
                method,
                path,
                test_id=self.info.id,
                headers=headers or None,
                params=params or None,
            )
        except SecurityClientError as exc:
            if exc.record is None:
                raise
            record = exc.record
        category = category_of(record)
        if category in _SPOILING:
            self._judge(record, store, _SUB_REVOKED, Outcome.NOT_VERIFIABLE, _SPOILING[category])
            return
        if category == ResponseCategory.SERVED:
            self._judge(
                record,
                store,
                _SUB_REVOKED,
                Outcome.VIOLATION,
                "ACCEPTED_AFTER_REVOCATION",
                Finding(
                    title=f"Revoked credential still accepted: {method} {path}",
                    detail=(
                        f"A credential was created, accepted at {method} {path}, then revoked "
                        "through the login's own mechanism (the target confirmed the revocation),"
                        f" and still answered HTTP {record.response_status_code} when sent again. "
                        "The act meant to end the credential does not end it, so a stolen or "
                        "logged-out token keeps access for the rest of its lifetime. Invalidate "
                        "the credential at the server on revocation."
                    ),
                    confidence=Confidence.CERTAIN,
                ),
            )
            return
        self._judge(record, store, _SUB_REVOKED, Outcome.ENFORCED, "REFUSED_AFTER_REVOCATION")
