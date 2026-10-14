"""
src/tests/domain_1/test_1_4_token_revocation.py

Test14TokenRevocation: verifies that an explicitly revoked API token is
immediately rejected by the gateway.

Guarantee covered (docs/knowledge/methodology/methodology.it.md §1.4 — Sub-Test 1):
    After a token is revoked through the API (token deletion or logout), any
    subsequent request authenticated with that token must be rejected with
    401 or 403.  A 2xx response indicates the gateway
    or application is not enforcing token revocation, leaving a window for
    credential abuse after compromise.

Strategy and priority:
    WHITE_BOX / P2.  Requires a valid ADMIN credential (the API's
    administrator account: full access, hence WHITE_BOX) to create and delete
    a temporary test token.  The test does not access the token store
    directly; it verifies the externally observable behaviour only.

Sub-test performed, through the revocation capability of the configured
authentication method (src/tests/helpers/auth_base.py; auth_type login when
its resource has a delete request, any other case gives SKIP "Not
applicable"):
    1. Create a temporary credential under the admin account (registered as
       a secret and for teardown by the method).
    2. Revoke it.
    3. Send tests.domain_1.test_1_4.verify_request with it, as the credential
       placement of the run says (no request configured: SKIP).
    4. Oracle: 401/403 → PASS; 2xx → FAIL.

EvidenceStore policy:
    The re-probe response is the key evidence.
    FAIL:  store.add_fail_evidence(re-probe record) + _log_transaction(is_fail=True).
    PASS:  _log_transaction(re-probe record, oracle_state=_STATE_REVOKED_REJECTED).

DAG placement:
    No prerequisite (depends_on = [], requires_pass = []): the method creates
    the temporary credential with the admin account; a refused creation gives
    ERROR with the reason.

Dependency rule:
    Imports from: stdlib, structlog, src.core, src.tests.base,
                  src.tests.helpers.auth.
    Must never import from: connectors/, external_tests/, config/loader.py,
                             discovery/, report/, engine.py.
"""

from __future__ import annotations

from typing import ClassVar

import structlog

from src.core.auth_placement import RequestAuthParts
from src.core.client import SecurityClient
from src.core.context import ROLE_ADMIN, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError
from src.core.models import TestResult, TestStrategy
from src.tests.base import BaseTest
from src.tests.helpers.auth import credential_parts, revocation_capability

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# HTTP status code sets for oracle evaluation.
_REVOKED_STATUS_CODES: frozenset[int] = frozenset({401, 403})
_BYPASS_STATUS_CODES: frozenset[int] = frozenset(range(200, 300))

# Oracle state labels for the Audit Trail column in the HTML report.
_STATE_TOKEN_CREATED: str = "TEMP_TOKEN_CREATED"  # noqa: S105 -- audit-trail state label, not a credential
_STATE_TOKEN_DELETED: str = "TEMP_TOKEN_DELETED"  # noqa: S105 -- audit-trail state label, not a credential
_STATE_REVOKED_REJECTED: str = "REVOKED_TOKEN_REJECTED"
_STATE_REVOKED_ACCEPTED: str = "REVOKED_TOKEN_ACCEPTED"

# Standards references cited in every Finding this test produces.
_REFERENCES: list[str] = [
    "CWE-613",
    "OWASP-API2:2023",
    "RFC-7009",
    "OWASP-ASVS-v5.0.0-V7.4",
    "NIST-SP-800-63B-4-S5.1",
]


class Test14TokenRevocation(BaseTest):
    """
    Verify that a revoked API token is immediately rejected by the gateway.

    Creates a temporary token under the admin account, revokes it via the
    authentication method (login: the login resource's delete request), then
    sends verify_request with it.
    PASS if the gateway returns 401/403; FAIL if the revoked token is still
    accepted (2xx).

    Demonstrates properties D1.P3 (TestContext token+teardown channels),
    D2.P2-PhaseB (DAG dependency on 1.1), D4.P6 (teardown registration),
    D2.P5 (auth dispatcher).
    """

    test_id: ClassVar[str] = "1.4"
    test_name: ClassVar[str] = "Revoked Token Rejected After Deletion"
    domain: ClassVar[int] = 1
    priority: ClassVar[int] = 2
    strategy: ClassVar[TestStrategy] = TestStrategy.WHITE_BOX
    depends_on: ClassVar[list[str]] = []
    requires_pass: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = [
        "authentication",
        "token-revocation",
        "OWASP-API2:2023",
        "RFC-7009",
        "OWASP-ASVS-V7.4",
    ]
    cwe_id: ClassVar[str] = "CWE-613"

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Orchestrate the revocation test.

        Steps:
            1. create_temporary_credential: a credential for the admin account
               (registered as a secret and for teardown by the method).
            2. revoke_credential: revoke it now.
            3. _verify_revocation: send verify_request with it, apply the oracle.

        Returns:
            TestResult: PASS if the revoked token gets 401/403; FAIL if 2xx;
            SKIP if credentials, the revocation capability or verify_request
            are missing; ERROR on unexpected exception.
        """
        try:
            guard = self._requires_credentials(target)
            if guard is not None:
                return guard

            method = revocation_capability(target)
            if method is None:
                return self._make_skip(
                    reason=(
                        "Not applicable: the authentication method "
                        f"'{target.credentials.auth_type}' cannot revoke a credential "
                        "(auth_type login with a login resource that has a delete request can)."
                    )
                )
            verify = target.tests_config.test_1_4.verify_request
            if verify is None:
                return self._make_skip(
                    reason=(
                        "No verification request configured: set "
                        "tests.domain_1.test_1_4.verify_request to an endpoint that requires "
                        "authentication (method and path)."
                    )
                )
            if not target.credentials.has_admin():
                return self._make_skip(
                    reason=(
                        f"No credentials for role '{ROLE_ADMIN}': the temporary credential is "
                        "created under the admin account."
                    )
                )

            log.info("test_1_4_starting", verify_method=verify.method, verify_path=verify.path)

            try:
                credential = method.create_temporary_credential(
                    target, context, client, ROLE_ADMIN, self.test_id
                )
            except AuthenticationSetupError as exc:
                return self._make_error(exc)
            self._log_transaction(credential.create_record, oracle_state=_STATE_TOKEN_CREATED)

            outcome = method.revoke_credential(target, context, client, credential, self.test_id)
            if not outcome.revoked:
                self._log_transaction(outcome.record, oracle_state="TOKEN_DELETE_FAILED")
                return self._make_error(
                    RuntimeError(
                        f"Revocation of the temporary credential returned "
                        f"{outcome.status_code}. Cannot verify revocation behaviour."
                    )
                )
            self._log_transaction(outcome.record, oracle_state=_STATE_TOKEN_DELETED)
            log.info("test_1_4_token_revoked", revoke_status=outcome.status_code)

            return self._verify_revocation(
                client=client,
                store=store,
                credential_auth=credential_parts(target, credential.value),
                verify_method=verify.method,
                verify_path=verify.path,
                revoke_status=outcome.status_code,
            )

        except Exception as exc:  # noqa: BLE001
            return self._make_error(exc)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _verify_revocation(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        credential_auth: RequestAuthParts,
        verify_method: str,
        verify_path: str,
        revoke_status: int,
    ) -> TestResult:
        """
        Send the verification request with the revoked credential and apply the oracle.

        Oracle:
            401 or 403 → PASS (token revocation enforced).
            2xx        → FAIL (revoked token still accepted).
        """
        reprobe_response, reprobe_record = client.request(
            method=verify_method,
            path=verify_path,
            test_id=self.test_id,
            headers=dict(credential_auth.headers),
            params=dict(credential_auth.params) or None,
        )

        if reprobe_response.status_code in _BYPASS_STATUS_CODES:
            store.add_fail_evidence(reprobe_record)
            self._log_transaction(
                reprobe_record,
                oracle_state=_STATE_REVOKED_ACCEPTED,
                is_fail=True,
            )
            return self._make_fail(
                message=(
                    f"Revoked token accepted: {verify_method} {verify_path} "
                    f"returned {reprobe_response.status_code} after token deletion."
                ),
                detail=(
                    f"Created a temporary credential for the admin account, revoked it "
                    f"(HTTP {revoke_status}), then sent {verify_method} {verify_path} "
                    f"with it.  "
                    f"Expected 401 or 403 (token revoked).  "
                    f"Received {reprobe_response.status_code}: the gateway or "
                    f"application is not enforcing token revocation."
                ),
                evidence_record_id=reprobe_record.record_id,
                additional_references=_REFERENCES,
            )

        self._log_transaction(reprobe_record, oracle_state=_STATE_REVOKED_REJECTED)

        log.info(
            "test_1_4_pass",
            reprobe_status=reprobe_response.status_code,
        )

        return self._make_pass(
            message=(
                f"Revoked token correctly rejected: "
                f"{verify_method} {verify_path} returned "
                f"{reprobe_response.status_code} after token deletion."
            )
        )
