"""
src/tests/domain_2/test_2_1_rbac_enforcement.py

Test21RbacEnforcement: verifies that admin-only endpoints reject requests
from authenticated users who lack the required administrative role.

Guarantee covered (Metodologia.md §Garanzia 2.1 — Sub-Test 1):
    After authentication, the gateway or application middleware must enforce
    role-based access control (RBAC).  A request authenticated as ROLE_USER_A
    to an admin-only endpoint must return 403 Forbidden.  A 2xx response
    indicates broken function-level authorization (BFLA / OWASP API5:2023):
    the system authenticated the user but failed to authorise the action.

    Key oracle distinction: 403 (not 401) is the expected failure code.
    401 means "not authenticated"; 403 means "authenticated but not
    authorised" — the test sends a valid ROLE_USER_A token, so 401 would
    indicate the token was rejected, not the role.

Strategy and priority:
    GREY_BOX / P2.  Requires a valid ROLE_USER_A credential.  No access to
    the gateway admin plane or the application role store is needed; the test
    verifies the externally observable HTTP response only.

Sub-test performed:
    For each path in cfg.admin_endpoint_paths:
        1. Send cfg.admin_endpoint_method {path} with ROLE_USER_A token.
        2. Oracle: 403 → PASS (RBAC enforced).
                   2xx → FAIL (RBAC bypass — finding recorded).
                   Other (404, 405, 5xx) → logged as INCONCLUSIVE (no finding).

EvidenceStore policy:
    FAIL (2xx): store.add_fail_evidence(record) + _log_transaction(is_fail=True).
    PASS/INCONCLUSIVE: _log_transaction(record, oracle_state=...).

DAG placement:
    depends_on = ["1.1"]  → Phase B.  Runs after the authentication test
    confirms that ROLE_USER_A credentials produce valid tokens.

Dependency rule:
    Imports from: stdlib, structlog, src.core, src.tests.base,
                  src.tests.helpers.auth.
    Must never import from: connectors/, external_tests/, config/loader.py,
                             discovery/, report/, engine.py.
"""

from __future__ import annotations

from typing import ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError, SecurityClientError
from src.core.models import Finding, TestResult, TestStrategy
from src.tests.base import BaseTest
from src.tests.helpers.auth import acquire_tokens

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# HTTP status codes that indicate the endpoint correctly rejected the request.
# 403 is the expected response (authenticated but not authorised).
# 404 is accepted as a secondary compliant response on targets that hide the
# existence of admin resources from non-privileged users (CWE-639 mitigation).
_RBAC_ENFORCED_CODES: frozenset[int] = frozenset({403, 404})

# HTTP status codes that indicate a RBAC bypass (a non-privileged user
# received a successful response from an admin-only endpoint).
_RBAC_BYPASS_CODES: frozenset[int] = frozenset(range(200, 300))

# Oracle state labels for the Audit Trail column in the HTML report.
_STATE_RBAC_ENFORCED: str = "RBAC_ENFORCED"
_STATE_RBAC_BYPASS: str = "RBAC_BYPASS"
_STATE_RBAC_INCONCLUSIVE: str = "RBAC_INCONCLUSIVE"

# Standards references cited in every Finding this test produces.
_REFERENCES: list[str] = [
    "CWE-285",
    "OWASP-API5:2023",
    "OWASP-ASVS-v5.0.0-V8.3.1",
    "OWASP-ASVS-v5.0.0-V8.2.2",
    "NIST-SP-800-53-Rev5-AC-3",
]


class Test21RbacEnforcement(BaseTest):
    """
    Verify that admin-only endpoints reject non-privileged authenticated requests.

    Probes each path in cfg.admin_endpoint_paths using a ROLE_USER_A token
    and expects 403/404 (RBAC enforced).  A 2xx response is a FAIL finding
    (broken function-level authorisation).

    Demonstrates properties P04 (multi-role token management via TestContext),
    P19 (auth dispatcher), P21 (GREY_BOX strategy gradient), P06-PhaseB.
    """

    test_id: ClassVar[str] = "2.1"
    test_name: ClassVar[str] = "Only Authorized Users Access Privileged Endpoints"
    domain: ClassVar[int] = 2
    priority: ClassVar[int] = 2
    strategy: ClassVar[TestStrategy] = TestStrategy.GREY_BOX
    depends_on: ClassVar[list[str]] = ["1.1"]
    tags: ClassVar[list[str]] = [
        "authorization",
        "rbac",
        "OWASP-API5:2023",
        "OWASP-ASVS-V8.3.1",
        "NIST-SP-800-53-AC-3",
    ]
    cwe_id: ClassVar[str] = "CWE-285"

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Orchestrate the RBAC enforcement check.

        Phases:
            1. Acquire the ROLE_USER_A token (or SKIP/ERROR on auth failure).
            2. _probe_admin_endpoint for each path in the config list.
            3. Aggregate findings; PASS if none, FAIL if any 2xx bypass.

        Returns:
            TestResult: PASS if all endpoints return 403/404; FAIL if any
            returns 2xx; SKIP if credentials are missing; ERROR on unexpected
            exception.
        """
        try:
            guard = self._requires_grey_box_credentials(target)
            if guard is not None:
                return guard

            try:
                acquire_tokens(
                    target,
                    context,
                    client,
                    required_roles=frozenset({ROLE_USER_A}),
                )
            except (AuthenticationSetupError, SecurityClientError) as exc:
                return self._make_error(exc)

            skip = self._requires_token(context, ROLE_USER_A)
            if skip is not None:
                return skip

            user_a_token: str = context.get_token(ROLE_USER_A)  # type: ignore[assignment]
            cfg = target.tests_config.test_2_1

            log.info(
                "test_2_1_starting",
                endpoint_count=len(cfg.admin_endpoint_paths),
                method=cfg.admin_endpoint_method,
            )

            findings: list[Finding] = []
            for path in cfg.admin_endpoint_paths:
                finding = self._probe_admin_endpoint(
                    client=client,
                    store=store,
                    method=cfg.admin_endpoint_method,
                    path=path,
                    user_a_token=user_a_token,
                )
                if finding is not None:
                    findings.append(finding)

            if findings:
                return self._make_fail_multi(
                    message=(
                        f"{len(findings)} RBAC bypass(es) detected: "
                        f"non-privileged token accepted on admin endpoint(s)."
                    ),
                    findings=findings,
                )

            log.info(
                "test_2_1_pass",
                endpoints_probed=len(cfg.admin_endpoint_paths),
            )

            return self._make_pass(
                message=(
                    f"All {len(cfg.admin_endpoint_paths)} admin endpoint(s) "
                    f"correctly rejected the non-privileged token."
                )
            )

        except Exception as exc:  # noqa: BLE001
            return self._make_error(exc)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _probe_admin_endpoint(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        method: str,
        path: str,
        user_a_token: str,
    ) -> Finding | None:
        """
        Probe a single admin endpoint with the ROLE_USER_A token and apply the oracle.

        Oracle:
            2xx  → RBAC bypass: pin fail evidence, log transaction as fail,
                   return a Finding describing the bypass.
            4xx (403/404) → RBAC enforced: log transaction, return None.
            Other (405, 5xx)  → inconclusive: log transaction, return None.

        Args:
            client:       Centralized HTTP client.
            store:        EvidenceStore (only used for FAIL pinning).
            method:       HTTP method to probe (from cfg.admin_endpoint_method).
            path:         Endpoint path under test.
            user_a_token: Bearer token for the non-privileged ROLE_USER_A.

        Returns:
            Finding when the endpoint accepts the non-privileged token (FAIL),
            None when the endpoint correctly rejects it or returns an
            inconclusive code.
        """
        response, record = client.request(
            method=method,
            path=path,
            test_id=self.test_id,
            headers={"Authorization": f"Bearer {user_a_token}"},
        )

        if response.status_code in _RBAC_BYPASS_CODES:
            store.add_fail_evidence(record)
            self._log_transaction(
                record,
                oracle_state=_STATE_RBAC_BYPASS,
                is_fail=True,
            )
            return Finding(
                title=f"RBAC Bypass: {method} {path}",
                detail=(
                    f"Sent {method} {path} "
                    f"with a '{ROLE_USER_A}' token.  "
                    f"Expected 403 Forbidden (RBAC enforced).  "
                    f"Received {response.status_code} — "
                    f"a non-privileged user accessed an admin-only endpoint."
                ),
                references=_REFERENCES,
                evidence_ref=record.record_id,
            )

        if response.status_code in _RBAC_ENFORCED_CODES:
            self._log_transaction(record, oracle_state=_STATE_RBAC_ENFORCED)
        else:
            # Inconclusive: 405, 5xx, etc. — logged but not counted as FAIL.
            self._log_transaction(record, oracle_state=_STATE_RBAC_INCONCLUSIVE)

        return None
