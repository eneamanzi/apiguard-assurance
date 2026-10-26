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
*valid* signature is sent first. If even that is rejected, the endpoint refuses
every delivery (it is down, or auth is elsewhere), so a rejection does not prove
signature verification: both sub-tests are then NOT_VERIFIABLE / REJECTS_ALL,
never a false ENFORCED. Without the secret the positive control cannot run and a
note records that the enforcement is inferred, not confirmed.

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

from src.core.assessment_test import NEEDED_TO_RUN
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
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.test_metadata import Effect, TestInfo
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB_ABSENT: str = "absent_signature_rejected"
_SUB_INVALID: str = "invalid_signature_rejected"

# A delivery the endpoint acted on: a 2xx.
_ACCEPTED_STATUS: frozenset[int] = frozenset({200, 201, 202, 204})

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
        description=(
            "The shared secret the sender signs with, for the valid-signature positive control. "
            "A ${VAR} reference from the environment; never a literal in the repo. Empty: the "
            "positive control is skipped and enforcement is inferred, not confirmed."
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
                "signing_secret": "${WEBHOOK_SECRET}",  # nosec B105 -- a doc example, an env ref
                "signature_format": "sha256={signature}",
            }
        ],
        description=(
            "The webhook receiver to probe for signature verification. No default: unset, the "
            "engine records the test as SKIP before it runs."
        ),
    )


class Test74WebhookVerification(BaseTest[Test74Params]):
    """
    Test 7.4 -- whether a webhook receiver verifies the delivery signature.

    The oracle of each sub-test is in the module docstring and on the test page.
    """

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
            if self._rejects_all(client, endpoint, raw):
                self._record(_SUB_ABSENT, Outcome.NOT_VERIFIABLE, _REJECTS_ALL)
                self._record(_SUB_INVALID, Outcome.NOT_VERIFIABLE, _REJECTS_ALL)
                return self._finish(message=f"{endpoint.path} rejects a valid signature too.")
            self._judge_delivery(client, store, endpoint, raw, _SUB_ABSENT, signature=None)
            self._judge_delivery(
                client, store, endpoint, raw, _SUB_INVALID, signature=_INVALID_SIGNATURE
            )
            notes = None if endpoint.signing_secret else [_NO_SECRET_NOTE]
            return self._finish(notes=notes, message=f"{endpoint.method} {endpoint.path}.")
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_7_4_unexpected_error", error=str(exc))
            return self._error(exc)

    def _rejects_all(
        self, client: SecurityClient, endpoint: Test74WebhookEndpoint, raw: bytes
    ) -> bool:
        """
        True when a *validly* signed delivery is itself rejected.

        Only runs when the signing secret is configured. If the endpoint rejects
        a correct signature, a rejection of a bad one proves nothing about
        signature verification, so the caller records NOT_VERIFIABLE instead of
        a false ENFORCED.
        """
        if not endpoint.signing_secret:
            return False
        signature = hmac.new(
            endpoint.signing_secret.encode("utf-8"), raw, hashlib.sha256
        ).hexdigest()
        record = self._send(client, endpoint, raw, signature)
        if record is None:
            return False
        self._step(record)
        accepted = record.response_status_code in _ACCEPTED_STATUS
        if not accepted:
            log.info(
                "test_7_4_valid_signature_rejected",
                path=endpoint.path,
                status=record.response_status_code,
            )
        return not accepted

    def _judge_delivery(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        endpoint: Test74WebhookEndpoint,
        raw: bytes,
        sub_test: str,
        *,
        signature: str | None,
    ) -> None:
        """Send one delivery (unsigned or wrongly signed) and judge its acceptance."""
        record = self._send(client, endpoint, raw, signature)
        if record is None:
            self._record(sub_test, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return
        if record.response_status_code not in _ACCEPTED_STATUS:
            self._judge(record, store, sub_test, Outcome.ENFORCED, "SIGNATURE_REQUIRED")
            return
        kind = "without a signature" if signature is None else "with an invalid signature"
        detail = "UNSIGNED_ACCEPTED" if signature is None else "BAD_SIGNATURE_ACCEPTED"
        finding = Finding(
            title=f"Webhook accepted {kind}: {endpoint.method} {endpoint.path}",
            detail=(
                f"A delivery to {endpoint.method} {endpoint.path} sent {kind} was accepted "
                f"(HTTP {record.response_status_code}). The receiver acts on webhook payloads "
                "without verifying their authenticity, so anyone who can reach the endpoint can "
                "forge events (OWASP API10:2023, CWE-347; OWASP Webhook Security Cheat Sheet). "
                "Verify an HMAC-SHA256 signature over the raw body on every delivery, in "
                "constant time."
            ),
            confidence=Confidence.CERTAIN,
        )
        self._judge(record, store, sub_test, Outcome.VIOLATION, detail, finding)
        log.info("test_7_4_forged_delivery_accepted", path=endpoint.path, detail=detail)

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


# Added when no signing secret is configured: the enforcement is inferred from
# the rejection, not confirmed by a valid-signature positive control.
_NO_SECRET_NOTE: InfoNote = InfoNote(
    title="Signature enforcement inferred, not confirmed",
    detail=(
        "No signing secret was configured, so a valid-signature positive control could not run. "
        "The rejection of the unsigned and wrongly signed deliveries is consistent with signature "
        "verification, but a blanket rejection (the endpoint down, or auth elsewhere) would look "
        "the same. Configure webhook_endpoint.signing_secret to confirm the endpoint accepts a "
        "correct signature."
    ),
    references=[Reference(standard=Standard.OWASP_API_TOP10, id="API10:2023")],
)
