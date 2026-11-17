"""
src/tests/domain_7/test_7_4_webhook_verification.py

Test 7.4: guarantee "an incoming webhook is authenticated before it is acted on"
(OWASP API10:2023 unsafe consumption, CWE-347).

A webhook receiver consumes data pushed by an external service; if it acts on a
delivery without verifying its signature, anyone who can reach the endpoint can
forge events. The OWASP Webhook Security Cheat Sheet requires an HMAC (SHA-256)
over the raw body, verified on every delivery. The test sends the configured
webhook payload three ways and watches which are accepted.

    absent_signature_rejected   a delivery with no signature header is rejected
                                 (a 4xx) -> ENFORCED; accepted (2xx) -> VIOLATION
                                 / UNSIGNED_ACCEPTED;
    invalid_signature_rejected   a delivery with a wrong signature is rejected
                                 -> ENFORCED; accepted -> VIOLATION /
                                 BAD_SIGNATURE_ACCEPTED.

Positive control: when the signing secret is configured, a delivery with a
*valid* signature is sent first. A rejection of the forged deliveries is
ENFORCED only when that valid one was accepted (a 2xx). If even the valid one is
rejected, the endpoint refuses every delivery (it is down, or auth is
elsewhere): both sub-tests are NOT_VERIFIABLE / REJECTS_ALL. Without the secret,
or without a usable answer to the valid delivery, a rejection is NOT_VERIFIABLE
/ SIGNATURE_NOT_CONFIRMED: a 404 from a wrong path or a gateway's 401 would look
the same. An accepted forged delivery is a VIOLATION either way.

BLACK_BOX (a webhook receiver is protected by the signature, not a session),
effect CHANGES_DATA (a processed webhook may change data; a rejected one does
not). Announce it on a shared target.

Dependency rule: imports from stdlib, structlog, pydantic and src.core, plus
src.tests.base.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import structlog
from pydantic import BaseModel, ConfigDict, Field

from src.core.assessment_test import NEEDED_TO_RUN, category_of
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
from src.core.models import (
    Confidence,
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
from src.core.models.runtime import SECRET_VALUE
from src.core.response_category import UNINFORMATIVE_CATEGORIES
from src.core.test_metadata import Effect, OracleCase, TestInfo
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB_ABSENT: str = "absent_signature_rejected"
_SUB_INVALID: str = "invalid_signature_rejected"

# A delivery refused: invalid, unauthenticated or forbidden (until 2026-11-16
# any answer that was not a 2xx, a redirect included).
_REFUSING: frozenset[ResponseCategory] = frozenset(
    {
        ResponseCategory.INVALID_REQUEST,
        ResponseCategory.UNAUTHENTICATED,
        ResponseCategory.FORBIDDEN,
    }
)
_NOT_INTERPRETED: str = "ANSWER_NOT_INTERPRETED"

# The invalid signature: a well-formed but wrong HMAC-SHA256 hex digest.
_INVALID_SIGNATURE: str = "0" * 64

_CONTENT_TYPE: str = "application/json"

_REJECTS_ALL: str = "REJECTS_ALL"


class Test74WebhookEndpoint(BaseModel):
    """A webhook receiver endpoint to probe (config, no default)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(min_length=1, description="Path of the webhook receiver.")
    method: str = Field(default="POST", description="HTTP method of the receiver (default POST).")
    body: dict[str, object] = Field(
        description="The webhook payload sent as the JSON body on every delivery."
    )
    signature_header: str = Field(
        min_length=1,
        description="Name of the header that carries the signature (e.g. 'X-Hub-Signature-256').",
    )
    signing_secret: str = Field(
        default="",
        # A secret: config_used.yaml writes a placeholder, never the value.
        json_schema_extra=SECRET_VALUE,
        description=(
            "The shared secret the sender signs with, for the valid-signature positive control. "
            "A ${VAR} reference from the environment; never a literal in the repo. Empty: the "
            "positive control is skipped, and a rejected delivery is not verifiable (only an "
            "accepted forged one is judged)."
        ),
    )
    signature_format: str = Field(
        default="{signature}",
        description=(
            "How the header value is built from the hex digest, e.g. 'sha256={signature}' "
            "(GitHub). '{signature}' is the lowercase hex HMAC-SHA256 of the raw body."
        ),
    )


class Test74Params(BaseModel):
    """Parameters of test 7.4."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    webhook_endpoint: Test74WebhookEndpoint | None = Field(
        default=None,
        json_schema_extra=NEEDED_TO_RUN,
        examples=[
            {
                "path": "/api/webhooks/payment",
                "method": "POST",
                "body": {"event": "payment.succeeded", "amount": 100},
                "signature_header": "X-Hub-Signature-256",
                "signing_secret": "${WEBHOOK_SECRET}",  # a doc example, an env ref  # nosec B105
                "signature_format": "sha256={signature}",
            }
        ],
        description=(
            "The webhook receiver to probe for signature verification. No default: unset, the "
            "engine records the test as SKIP before it runs."
        ),
    )


def _cases(sub_test: str, forged: str, detail: str) -> tuple[OracleCase, ...]:
    """The oracle of one forged delivery."""
    return (
        OracleCase(
            sub_test=sub_test,
            when=f"{forged} answered `2xx`: accepted, which does not show it was acted on",
            outcome=Outcome.VIOLATION,
            detail=detail,
            confidence=Confidence.FIRM,
        ),
        OracleCase(
            sub_test=sub_test,
            when=f"{forged} refused (`400`, `401`, `403`, ...), and a validly signed delivery "
            "sent after it accepted",
            outcome=Outcome.ENFORCED,
            detail="SIGNATURE_REQUIRED",
        ),
        OracleCase(
            sub_test=sub_test,
            when=f"{forged} refused, and no validly signed delivery accepted (no secret, or no "
            "usable answer to it)",
            outcome=Outcome.NOT_VERIFIABLE,
            detail="SIGNATURE_NOT_CONFIRMED",
        ),
        OracleCase(
            sub_test=sub_test,
            when=f"{forged} refused, and the validly signed delivery refused too",
            outcome=Outcome.NOT_VERIFIABLE,
            detail=_REJECTS_ALL,
        ),
        OracleCase(
            sub_test=sub_test,
            when=f"{forged} answered neither `2xx` nor a refusal (a redirect, `404`, `405`)",
            outcome=Outcome.NOT_VERIFIABLE,
            detail=_NOT_INTERPRETED,
        ),
    )


class Test74WebhookVerification(BaseTest[Test74Params]):
    """Test 7.4 -- whether a webhook receiver verifies the delivery signature."""

    info = TestInfo(
        id="7.4",
        name="Webhook Signature Verification",
        priority=1,
        strategy=TestStrategy.BLACK_BOX,
        cwe="CWE-347",
        references=(
            # OWASP Webhook Security Cheat Sheet (read on the owasp.org source
            # 2026-10-23): HMAC-SHA256 over the raw body, verified on every
            # delivery; a forged delivery is unsafe consumption of an external
            # service (OWASP API10:2023).
            Reference(standard=Standard.OWASP_API_TOP10, id="API10:2023"),
        ),
        tags=("business-logic", "webhook", "authenticity"),
        effect=Effect.CHANGES_DATA,
        sub_tests=(_SUB_ABSENT, _SUB_INVALID),
        oracle=(
            *_cases(_SUB_ABSENT, "the unsigned delivery", "UNSIGNED_ACCEPTED"),
            *_cases(_SUB_INVALID, "the wrongly signed delivery", "BAD_SIGNATURE_ACCEPTED"),
        ),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Send the webhook unsigned and wrongly signed, and judge whether it is rejected.

        Args:
            target:  The run's target.
            context: Unused.
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._skip(...), or self._error(exc).
        """
        del context
        try:
            endpoint = self.params(target).webhook_endpoint
            if endpoint is None:  # NEEDED_TO_RUN; the engine normally SKIPs first.
                return self._skip("No webhook_endpoint configured for test 7.4.")
            raw = json.dumps(endpoint.body, separators=(",", ":"), sort_keys=True).encode("utf-8")
            # The forged deliveries first, the valid one last: a receiver that
            # drops a repeated event (an event-ID cache) would otherwise answer
            # the forged ones as duplicates of the valid one (until 2026-11-16
            # the valid one went first).
            refused = [
                refusal
                for sub_test, signature in ((_SUB_ABSENT, None), (_SUB_INVALID, _INVALID_SIGNATURE))
                if (
                    refusal := self._judge_delivery(
                        client, store, endpoint, raw, sub_test, signature
                    )
                )
                is not None
            ]
            control = self._positive_control(client, endpoint, raw) if refused else True
            for record, sub_test in refused:
                if control is True:
                    self._judge(record, store, sub_test, Outcome.ENFORCED, "SIGNATURE_REQUIRED")
                elif control is False:
                    self._judge(record, store, sub_test, Outcome.NOT_VERIFIABLE, _REJECTS_ALL)
                else:
                    self._judge(
                        record, store, sub_test, Outcome.NOT_VERIFIABLE, "SIGNATURE_NOT_CONFIRMED"
                    )
            notes = None if control is not None else [_NOT_CONFIRMED_NOTE]
            return self._finish(notes=notes, message=f"{endpoint.method} {endpoint.path}.")
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_7_4_unexpected_error", error=str(exc))
            return self._error(exc)

    def _positive_control(
        self, client: SecurityClient, endpoint: Test74WebhookEndpoint, raw: bytes
    ) -> bool | None:
        """
        Send a *validly* signed delivery: whether the endpoint accepts it.

        Only a True lets a rejection of the forged deliveries count as ENFORCED.

        Returns:
            True when it was accepted (a 2xx); False when it was rejected (the
            endpoint refuses every delivery, REJECTS_ALL); None when the control
            could not run (no signing secret) or its answer says nothing (no
            answer, unavailable, rate limited, server error).
        """
        if not endpoint.signing_secret:
            return None
        signature = hmac.new(
            endpoint.signing_secret.encode("utf-8"), raw, hashlib.sha256
        ).hexdigest()
        record = self._send(client, endpoint, raw, signature)
        if record is None:
            return None
        self._step(record)
        if category_of(record) in UNINFORMATIVE_CATEGORIES:
            return None
        accepted = category_of(record) == ResponseCategory.SERVED
        if not accepted:
            log.info(
                "test_7_4_valid_signature_rejected",
                path=endpoint.path,
                status=record.response_status_code,
            )
        return accepted

    def _judge_delivery(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        endpoint: Test74WebhookEndpoint,
        raw: bytes,
        sub_test: str,
        signature: str | None,
    ) -> tuple[EvidenceRecord, str] | None:
        """
        Send one forged delivery (unsigned or wrongly signed) and judge it.

        Returns:
            The record and sub-test of a refusal, judged once the validly
            signed delivery is answered; None when judged here.
        """
        record = self._send(client, endpoint, raw, signature)
        if record is None:
            self._record(sub_test, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return None
        uninformative = self._uninformative(record, sub_test)
        if uninformative is not None:
            self._judge(record, store, sub_test, Outcome.NOT_VERIFIABLE, uninformative)
            return None
        category = category_of(record)
        if category in _REFUSING:
            return record, sub_test
        if category != ResponseCategory.SERVED:
            self._judge(record, store, sub_test, Outcome.NOT_VERIFIABLE, _NOT_INTERPRETED)
            return None
        detail = "UNSIGNED_ACCEPTED" if signature is None else "BAD_SIGNATURE_ACCEPTED"
        finding = Finding(
            title=(
                f"Webhook accepted without a signature: {endpoint.method} {endpoint.path}"
                if signature is None
                else "Webhook accepted with an invalid signature: "
                f"{endpoint.method} {endpoint.path}"
            ),
            detail=(
                f"A forged delivery to {endpoint.method} {endpoint.path} was accepted (HTTP "
                f"{record.response_status_code}). The receiver does not reject webhook payloads "
                "whose authenticity it cannot verify, so anyone who can reach the endpoint can "
                "forge events (CWE-347; OWASP Webhook Security Cheat Sheet). An acceptance is not "
                "proof the event was acted on (a receiver may queue and verify later): confirm on "
                "the target. Verify an HMAC-SHA256 signature over the raw body on every delivery, "
                "in constant time, before accepting it."
            ),
            confidence=Confidence.FIRM,
        )
        self._judge(record, store, sub_test, Outcome.VIOLATION, detail, finding)
        log.info("test_7_4_forged_delivery_accepted", path=endpoint.path, detail=detail)
        return None

    def _send(
        self,
        client: SecurityClient,
        endpoint: Test74WebhookEndpoint,
        raw: bytes,
        signature: str | None,
    ) -> EvidenceRecord | None:
        """One delivery of the raw body, with the signature header when given."""
        headers: dict[str, str] = {"Content-Type": _CONTENT_TYPE}
        if signature is not None:
            headers[endpoint.signature_header] = endpoint.signature_format.format(
                signature=signature
            )
        try:
            _response, record = client.request(
                endpoint.method.upper(),
                endpoint.path,
                test_id=self.info.id,
                headers=headers,
                content=raw,
            )
        except SecurityClientError as exc:
            return exc.record
        return record


# Added when no valid-signature positive control confirmed the endpoint: a
# rejection is then not verifiable.
_NOT_CONFIRMED_NOTE: InfoNote = InfoNote(
    title="Signature enforcement not confirmed",
    detail=(
        "No validly signed delivery was accepted: no signing secret is configured, or the "
        "endpoint gave no usable answer to it. A rejection of the unsigned and wrongly signed "
        "deliveries is then not verifiable, since a wrong path, an endpoint down or a credential "
        "required elsewhere would be rejected the same way. Configure "
        "webhook_endpoint.signing_secret so that the test can confirm the endpoint accepts a "
        "correct signature."
    ),
    references=[Reference(standard=Standard.OWASP_API_TOP10, id="API10:2023")],
)
