"""
src/tests/domain_7/test_7_1_sensitive_flow_protection.py

Test 7.1: guarantee "a sensitive business flow resists automated abuse" (OWASP
API6:2023).

A high-value flow (one-time-password request, coupon redemption, sign-up,
password reset) must not be drivable by a script at machine speed: the server
must throw an anti-automation control in the way (a CAPTCHA or human-verification
challenge, or an aggressive throttle). The test submits the configured sensitive
flow repeatedly and looks for such a control.

    anti_automation_present  a burst of identical submissions meets a throttle
                             (429) or a challenge (a 4xx whose body asks for a
                             CAPTCHA / human verification) -> ENFORCED; the whole
                             burst is accepted unthrottled -> VIOLATION /
                             NO_ANTI_AUTOMATION; the flow errors for another
                             reason -> NOT_VERIFIABLE.

Boundary (rule 10): infrastructure rate limiting on any endpoint is 4.1; this is
the business-flow control on a *declared* sensitive flow, where even a modest
automated rate is abuse and the control may be a CAPTCHA, not only a 429. Login
brute force / enumeration is 1.7.

BLACK_BOX by default (sensitive flows are often reachable without a session); a
role is used when the flow is configured with one. Effect CHANGES_DATA: the
burst submits the real flow (announce it on a shared target; keep the burst
small).

Dependency rule: imports from stdlib, structlog, pydantic and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

from typing import Annotated

import structlog
from pydantic import BaseModel, ConfigDict, Field

from src.core.assessment_test import NEEDED_TO_RUN, category_of
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
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
from src.core.test_metadata import Effect, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.auth import acquire_tokens, auth_parts

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB: str = "anti_automation_present"

# A 4xx whose body carries one of these is a human-verification challenge, an
# anti-automation control even when it is not a 429.
_CHALLENGE_KEYWORDS: tuple[str, ...] = (
    "captcha",
    "recaptcha",
    "hcaptcha",
    "challenge",
    "human verification",
    "are you human",
    "bot detected",
    "too many",
    "slow down",
)

# Status codes a challenge may use (besides 429, handled as RATE_LIMITED).
_CHALLENGE_STATUS: frozenset[int] = frozenset({400, 401, 403, 409, 422})

_ENFORCED_THROTTLE: str = "ANTI_AUTOMATION_THROTTLE"
_ENFORCED_CHALLENGE: str = "ANTI_AUTOMATION_CHALLENGE"
_FLOW_BROKEN: str = "FLOW_UNAVAILABLE"


class Test71SensitiveFlow(BaseModel):
    """A sensitive business flow to drive repeatedly (config, no default)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(min_length=1, description="Path of the sensitive flow.")
    method: str = Field(default="POST", description="HTTP method of the flow (default POST).")
    body: dict[str, object] | None = Field(
        default=None, description="JSON body submitted on every request (optional)."
    )
    role: str | None = Field(
        default=None,
        min_length=1,
        description=(
            "Role whose credential drives the flow. Omit for an anonymous flow (sign-up, OTP "
            "request, password reset), the common case."
        ),
    )


class Test71Params(BaseModel):
    """Parameters of test 7.1."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    sensitive_flow: Test71SensitiveFlow | None = Field(
        default=None,
        json_schema_extra=NEEDED_TO_RUN,
        examples=[
            {
                "path": "/identity/api/auth/forgot-password",
                "method": "POST",
                "body": {"email": "user@example.com"},
                "role": "user_a",
            }
        ],
        description=(
            "The sensitive business flow to probe for an anti-automation control (a CAPTCHA, a "
            "human-verification challenge, an aggressive throttle). No default: unset, the engine "
            "records the test as SKIP before it runs."
        ),
    )
    burst_size: Annotated[int, Field(ge=2)] = Field(
        default=12,
        description=(
            "How many identical submissions the burst sends before concluding there is no "
            "anti-automation control. Kept small: the burst drives the real flow."
        ),
    )


class Test71SensitiveFlowProtection(BaseTest[Test71Params]):
    """
    Test 7.1 -- whether a sensitive business flow resists automated abuse.

    The oracle is in the module docstring and on the test page.
    """

    info = TestInfo(
        id="7.1",
        name="Sensitive Business Flow Protection",
        priority=1,
        strategy=TestStrategy.BLACK_BOX,
        cwe="CWE-799",
        references=(
            Reference(standard=Standard.OWASP_API_TOP10, id="API6:2023"),
            # Verified on the ASVS v5.0.0 source 2026-10-23: 2.4.1 (anti-automation
            # defences against rapid repetition of security-sensitive functions).
            Reference(standard=Standard.ASVS, id="v5.0.0-2.4.1"),
        ),
        tags=("business-logic", "anti-automation"),
        effect=Effect.CHANGES_DATA,
        sub_tests=(_SUB,),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Burst the configured sensitive flow and look for an anti-automation control.

        Args:
            target:  The run's target.
            context: Carries the acquired tokens (when a role is configured).
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._skip(...), or self._error(exc).
        """
        try:
            flow = self.params(target).sensitive_flow
            if flow is None:  # NEEDED_TO_RUN; the engine normally SKIPs first.
                return self._skip("No sensitive_flow configured for test 7.1.")
            headers, params = self._auth(target, context, client, flow.role)
            self._probe(client, store, flow, self.params(target).burst_size, headers, params)
            return self._finish(message=f"{flow.method} {flow.path}.")
        except AuthenticationSetupError as exc:
            return self._error(exc)
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_7_1_unexpected_error", error=str(exc))
            return self._error(exc)

    def _auth(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        role: str | None,
    ) -> tuple[dict[str, str], dict[str, str]]:
        """The credential headers and params for the configured role, or empty for anonymous."""
        if role is None:
            return {}, {}
        acquire_tokens(target, context, client, required_roles=frozenset({role}))
        parts = auth_parts(target, context, role)
        return dict(parts.headers), dict(parts.params)

    def _probe(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        flow: Test71SensitiveFlow,
        burst_size: int,
        headers: dict[str, str],
        params: dict[str, str],
    ) -> None:
        """Send the burst, judging ENFORCED at the first control or VIOLATION at the end."""
        last: EvidenceRecord | None = None
        for sent in range(1, burst_size + 1):
            record = self._send(client, flow, headers, params)
            if record is None:
                continue
            last = record
            detail = self._control(record)
            if detail is not None:
                self._judge(record, store, _SUB, Outcome.ENFORCED, detail)
                log.info("test_7_1_control_seen", path=flow.path, after=sent, detail=detail)
                return
        if last is None:
            self._record(_SUB, Outcome.NOT_VERIFIABLE, _FLOW_BROKEN)
            return
        finding = Finding(
            title=f"No anti-automation control on {flow.method} {flow.path}",
            detail=(
                f"{burst_size} identical submissions of the sensitive flow {flow.method} "
                f"{flow.path} were all accepted with no throttle (429) and no human-verification "
                "challenge. A script can drive this high-value flow at machine speed, enabling "
                "abuse such as mass sign-up, OTP flooding, or coupon draining (OWASP API6:2023, "
                "ASVS v5.0.0-2.4.1). Add a CAPTCHA or an anti-automation throttle to the flow."
            ),
            confidence=Confidence.CERTAIN,
        )
        self._judge(last, store, _SUB, Outcome.VIOLATION, "NO_ANTI_AUTOMATION", finding)

    def _control(self, record: EvidenceRecord) -> str | None:
        """The anti-automation detail if this response is a control, else None."""
        if category_of(record) == ResponseCategory.RATE_LIMITED:
            return _ENFORCED_THROTTLE
        status = record.response_status_code
        if status in _CHALLENGE_STATUS and _is_challenge(record):
            return _ENFORCED_CHALLENGE
        return None

    def _send(
        self,
        client: SecurityClient,
        flow: Test71SensitiveFlow,
        headers: dict[str, str],
        params: dict[str, str],
    ) -> EvidenceRecord | None:
        """One submission of the flow; its record, or None on a transport failure."""
        try:
            _response, record = client.request(
                flow.method.upper(),
                flow.path,
                test_id=self.info.id,
                headers=headers or None,
                params=params or None,
                json=flow.body,
            )
        except SecurityClientError as exc:
            return exc.record
        return record


def _is_challenge(record: EvidenceRecord) -> bool:
    """True when the response body reads like a CAPTCHA / human-verification challenge."""
    body = (record.response_body or "").lower()
    return any(keyword in body for keyword in _CHALLENGE_KEYWORDS)
