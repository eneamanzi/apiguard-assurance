"""
src/tests/domain_1/test_1_4_token_revocation.py

Test14TokenRevocation: verifies that an explicitly revoked API token is
immediately rejected by the gateway.

Guarantee covered (docs/knowledge/methodology/methodology.it.md §1.4 — Sub-Test 1):
    After a token is deleted via the API (Forgejo-equivalent of logout /
    token revocation), any subsequent request authenticated with that token
    must be rejected with 401 or 403.  A 2xx response indicates the gateway
    or application is not enforcing token revocation, leaving a window for
    credential abuse after compromise.

Strategy and priority:
    WHITE_BOX / P2.  Requires a valid ADMIN credential (the API's
    administrator account: full access, hence WHITE_BOX) to create and delete
    a temporary test token.  The test does not access the token store
    directly; it verifies the externally observable behaviour only.

Sub-test performed, through the revocation capability of the configured
authentication method (src/tests/helpers/auth_base.py; only forgejo_token
has it: any other method gives SKIP "Not applicable"):
    1. Create a temporary credential under the admin account (registered as
       a secret and for teardown by the method).
    2. Revoke it.
    3. Re-attempt an authenticated request with it, sent as the credential
       placement of the run says.
    4. Oracle: 401/403 → PASS; 2xx → FAIL.
The re-probe path (/api/v1/user) is Forgejo's: it is valid because only the
Forgejo method can revoke today (test review, Q-29).

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

# Endpoint used for the re-probe after revocation.
# /api/v1/user returns the authenticated user's profile; it is always
# protected and reachable without path parameters.
_REPROBE_PATH: str = "/api/v1/user"

_REPROBE_METHOD: str = "GET"

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
    authentication method (Forgejo: token deletion), then re-probes with it.
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
        Orchestrate the four phases of the revocation test.

        Phases:
            1. _setup_admin_session  — acquire admin token + basic-auth header.
            2. _create_temp_token    — pre-flight cleanup, POST, register teardown.
            3. _revoke_token         — DELETE the temporary token.
            4. _verify_revocation    — re-probe with the revoked token + oracle.

        Returns:
            TestResult: PASS if revoked token returns 401/403; FAIL if 2xx;
            SKIP if credentials are missing; ERROR on unexpected exception.
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
                        f"'{target.credentials.auth_type}' cannot revoke a credential."
                    )
                )
            if not target.credentials.has_admin():
                return self._make_skip(
                    reason=(
                        f"No credentials for role '{ROLE_ADMIN}': the temporary token is "
                        "created under the admin account."
                    )
                )

            cfg = target.tests_config.test_1_4
            log.info("test_1_4_starting", token_name=cfg.token_name)

            try:
                credential = method.create_temporary_credential(
                    target, context, client, ROLE_ADMIN, cfg.token_name, self.test_id
                )
            except AuthenticationSetupError as exc:
                return self._make_error(exc)
            self._log_transaction(credential.create_record, oracle_state=_STATE_TOKEN_CREATED)

            outcome = method.revoke_credential(target, client, credential, ROLE_ADMIN, self.test_id)
            if not outcome.revoked:
                self._log_transaction(outcome.record, oracle_state="TOKEN_DELETE_FAILED")
                return self._make_error(
                    RuntimeError(
                        f"Revocation of the temporary token '{credential.name}' returned "
                        f"{outcome.status_code}. Cannot verify revocation behaviour."
                    )
                )
            self._log_transaction(outcome.record, oracle_state=_STATE_TOKEN_DELETED)
            log.info(
                "test_1_4_token_revoked",
                token_name=credential.name,
                delete_status=outcome.status_code,
            )

            return self._verify_revocation(
                client=client,
                store=store,
                credential_auth=credential_parts(target, credential.value),
                delete_path=credential.revoke_path,
                token_name=credential.name,
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
        delete_path: str,
        token_name: str,
    ) -> TestResult:
        """
        Re-probe with the revoked token and apply the oracle.

        Oracle:
            401 or 403 → PASS (token revocation enforced).
            2xx        → FAIL (revoked token still accepted).
        """
        reprobe_response, reprobe_record = client.request(
            method=_REPROBE_METHOD,
            path=_REPROBE_PATH,
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
                    f"Revoked token accepted: {_REPROBE_METHOD} {_REPROBE_PATH} "
                    f"returned {reprobe_response.status_code} after token deletion."
                ),
                detail=(
                    f"Created temporary token '{token_name}' under admin account, "
                    f"deleted it via DELETE {delete_path}, "
                    f"then re-probed {_REPROBE_METHOD} {_REPROBE_PATH} "
                    f"using the deleted token value.  "
                    f"Expected 401 or 403 (token revoked).  "
                    f"Received {reprobe_response.status_code} — the gateway or "
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
                f"{_REPROBE_METHOD} {_REPROBE_PATH} returned "
                f"{reprobe_response.status_code} after token deletion."
            )
        )
