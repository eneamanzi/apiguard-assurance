"""
src/tests/domain_1/test_1_4_token_revocation.py

Test14TokenRevocation: verifies that an explicitly revoked API token is
immediately rejected by the gateway.

Guarantee covered (Metodologia.md §Garanzia 1.4 — Sub-Test 1):
    After a token is deleted via the API (Forgejo-equivalent of logout /
    token revocation), any subsequent request authenticated with that token
    must be rejected with 401 or 403.  A 2xx response indicates the gateway
    or application is not enforcing token revocation, leaving a window for
    credential abuse after compromise.

Strategy and priority:
    GREY_BOX / P2.  Requires a valid ADMIN credential to create and delete
    a temporary test token.  The test does not access the token store
    directly; it verifies the externally observable behaviour only.

Sub-test performed:
    1. Acquire the ADMIN token via the auth dispatcher.
    2. Create a short-lived temporary API token under the admin account.
    3. Register the token path for teardown (Phase 6 safety net).
    4. Delete the temporary token immediately (= revocation).
    5. Re-attempt an authenticated request using the revoked token value.
    6. Oracle: 401/403 → PASS; 2xx → FAIL.

EvidenceStore policy:
    The re-probe response is the key evidence.
    FAIL:  store.add_fail_evidence(re-probe record) + _log_transaction(is_fail=True).
    PASS:  _log_transaction(re-probe record, oracle_state=_STATE_REVOKED_REJECTED).

DAG placement:
    depends_on = ["1.1"]  → Phase B (runs after authentication check confirms
    token creation is possible).

Dependency rule:
    Imports from: stdlib, structlog, src.core, src.tests.base,
                  src.tests.helpers.auth, src.tests.helpers.forgejo_resources.
    Must never import from: connectors/, external_tests/, config/loader.py,
                             discovery/, report/, engine.py.
"""

from __future__ import annotations

import base64
from typing import Any, ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import ROLE_ADMIN, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError, SecurityClientError
from src.core.models import TestResult, TestStrategy
from src.tests.base import BaseTest
from src.tests.helpers.auth import acquire_tokens
from src.tests.helpers.forgejo_resources import (
    ForgejoResourceError,
    get_authenticated_user,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Forgejo API path templates for token lifecycle management.
# {username} is resolved at runtime from the authenticated admin identity.
_TOKEN_CREATE_PATH_TEMPLATE: str = "/api/v1/users/{username}/tokens"  # noqa: S105 -- URL path, not a credential
_TOKEN_DELETE_PATH_TEMPLATE: str = "/api/v1/users/{username}/tokens/{name}"  # noqa: S105 -- URL path, not a credential

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
    Forgejo token-deletion API, then re-probes using the revoked token value.
    PASS if the gateway returns 401/403; FAIL if the revoked token is still
    accepted (2xx).

    Demonstrates properties P04 (TestContext token+teardown channels),
    P06-PhaseB (DAG dependency on 1.1), P16 (teardown registration),
    P19 (auth dispatcher).
    """

    test_id: ClassVar[str] = "1.4"
    test_name: ClassVar[str] = "Revoked Token Rejected After Deletion"
    domain: ClassVar[int] = 1
    priority: ClassVar[int] = 2
    strategy: ClassVar[TestStrategy] = TestStrategy.GREY_BOX
    depends_on: ClassVar[list[str]] = ["1.1"]
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
            guard = self._requires_grey_box_credentials(target)
            if guard is not None:
                return guard

            cfg = target.tests_config.test_1_4

            session = self._setup_admin_session(target, context, client)
            if isinstance(session, TestResult):
                return session
            admin_username, basic_auth_value = session

            log.info(
                "test_1_4_starting",
                admin_username="[REDACTED]",
                token_name=cfg.token_name,
            )

            create_outcome = self._create_temp_token(
                client=client,
                context=context,
                admin_username=admin_username,
                basic_auth_value=basic_auth_value,
                token_name=cfg.token_name,
            )
            if isinstance(create_outcome, TestResult):
                return create_outcome
            temp_token_value, delete_path = create_outcome

            revoke_error = self._revoke_token(
                client=client,
                delete_path=delete_path,
                basic_auth_value=basic_auth_value,
                token_name=cfg.token_name,
            )
            if revoke_error is not None:
                return revoke_error

            return self._verify_revocation(
                client=client,
                store=store,
                temp_token_value=temp_token_value,
                delete_path=delete_path,
                token_name=cfg.token_name,
            )

        except Exception as exc:  # noqa: BLE001
            return self._make_error(exc)

    # ------------------------------------------------------------------
    # Private helpers — one logical phase each
    # ------------------------------------------------------------------

    def _setup_admin_session(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
    ) -> tuple[str, str] | TestResult:
        """
        Acquire the admin token, resolve the admin username, build Basic Auth.

        Forgejo's token-creation endpoint (POST /api/v1/users/{user}/tokens)
        requires Basic Auth from the token owner; an existing API token — even
        with admin role — is rejected with 401.  This helper produces both the
        username (needed for the URL path) and the Basic Auth header value.

        Returns:
            Either (admin_username, basic_auth_value) on success, or a
            TestResult (SKIP / ERROR) describing the setup failure.
        """
        try:
            acquire_tokens(
                target,
                context,
                client,
                required_roles=frozenset({ROLE_ADMIN}),
            )
        except (AuthenticationSetupError, SecurityClientError) as exc:
            return self._make_error(exc)

        skip = self._requires_token(context, ROLE_ADMIN)
        if skip is not None:
            return skip

        try:
            admin_user: dict[str, Any] = get_authenticated_user(
                target, context, client, ROLE_ADMIN
            )
        except ForgejoResourceError as exc:
            return self._make_error(exc)

        admin_username: str = admin_user.get("login", "")
        if not admin_username:
            return self._make_error(
                ValueError(
                    "Could not determine admin username from Forgejo identity response."
                )
            )

        admin_password: str | None = target.credentials.admin_password
        if not admin_password:
            return self._make_skip(
                reason=(
                    "admin_password not configured — required for token creation step."
                )
            )

        basic_auth_value: str = base64.b64encode(
            f"{admin_username}:{admin_password}".encode()
        ).decode()
        return admin_username, basic_auth_value

    def _create_temp_token(
        self,
        client: SecurityClient,
        context: TestContext,
        admin_username: str,
        basic_auth_value: str,
        token_name: str,
    ) -> tuple[str, str] | TestResult:
        """
        Create a temporary token under the admin account; register its teardown.

        Steps performed:
            1. Pre-flight cleanup: DELETE any stale token from a previous crashed
               run (Forgejo returns 204 if it existed, 404 otherwise — both fine).
            2. POST the create request with Basic Auth + scopes=["read:user"].
            3. Extract the ``sha1`` token value from the 201 response body.
            4. Register the DELETE path with the teardown channel so Phase 6
               cleans up even if the test fails partway through.

        Returns:
            Either (temp_token_value, delete_path) on success, or a TestResult
            (ERROR) if creation failed or the response shape is unexpected.
        """
        delete_path = _TOKEN_DELETE_PATH_TEMPLATE.format(
            username=admin_username,
            name=token_name,
        )

        # Pre-flight cleanup.  Status code is intentionally ignored.
        client.request(
            method="DELETE",
            path=delete_path,
            test_id=self.test_id,
            headers={"Authorization": f"Basic {basic_auth_value}"},
        )

        create_path = _TOKEN_CREATE_PATH_TEMPLATE.format(username=admin_username)
        create_response, create_record = client.request(
            method="POST",
            path=create_path,
            test_id=self.test_id,
            headers={"Authorization": f"Basic {basic_auth_value}"},
            json={"name": token_name, "scopes": ["read:user"]},
        )

        if create_response.status_code != 201:
            self._log_transaction(create_record, oracle_state="TOKEN_CREATE_FAILED")
            return self._make_error(
                RuntimeError(
                    f"Expected 201 when creating temporary token '{token_name}', "
                    f"got {create_response.status_code}.  "
                    "Ensure the admin credential has token-creation privileges."
                )
            )

        create_body: dict[str, Any] = create_response.json()
        temp_token_value: str = create_body.get("sha1", "")
        if not temp_token_value:
            self._log_transaction(create_record, oracle_state="TOKEN_CREATE_NO_VALUE")
            return self._make_error(
                RuntimeError(
                    "Forgejo token creation response did not contain a 'sha1' field.  "
                    "Cannot proceed with revocation test."
                )
            )

        self._log_transaction(create_record, oracle_state=_STATE_TOKEN_CREATED)

        # Register teardown IMMEDIATELY after successful creation, before any
        # further assertion.  Forgejo token deletion requires Basic Auth from
        # the token owner, not an API token header.
        context.register_resource_for_teardown(
            method="DELETE",
            path=delete_path,
            headers={"Authorization": f"Basic {basic_auth_value}"},
        )

        return temp_token_value, delete_path

    def _revoke_token(
        self,
        client: SecurityClient,
        delete_path: str,
        basic_auth_value: str,
        token_name: str,
    ) -> TestResult | None:
        """
        Delete the temporary token.  Returns None on success, TestResult on error.

        A revocation that fails to return 200/204 makes the rest of the test
        meaningless — there is no way to verify rejection of a token that
        was not actually revoked.  In that case the test ERRORs out.
        """
        delete_response, delete_record = client.request(
            method="DELETE",
            path=delete_path,
            test_id=self.test_id,
            headers={"Authorization": f"Basic {basic_auth_value}"},
        )

        if delete_response.status_code not in (204, 200):
            self._log_transaction(delete_record, oracle_state="TOKEN_DELETE_FAILED")
            return self._make_error(
                RuntimeError(
                    f"Expected 204 when deleting token '{token_name}', "
                    f"got {delete_response.status_code}.  "
                    "Cannot verify revocation behaviour."
                )
            )

        self._log_transaction(delete_record, oracle_state=_STATE_TOKEN_DELETED)

        log.info(
            "test_1_4_token_revoked",
            token_name=token_name,
            delete_status=delete_response.status_code,
        )
        return None

    def _verify_revocation(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        temp_token_value: str,
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
            headers={"Authorization": f"token {temp_token_value}"},
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
