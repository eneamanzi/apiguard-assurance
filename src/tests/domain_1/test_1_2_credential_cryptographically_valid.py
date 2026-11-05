"""
src/tests/domain_1/test_1_2_credential_cryptographically_valid.py

Test 1.2: guarantee "a credential whose signature does not hold is refused".

The credential must be a JSON Web Token (JWT): a target that issues an opaque
token (Forgejo's sha1 API token) has no signature to attack, and the test is
`NOT_APPLICABLE/NOT_A_JWT` there. Where the credential is a JWT, the test
presents three variants that a server keeping the guarantee refuses, each
built without any key (src/core/jwt_tokens.py):

    unsigned_rejected   the algorithm set to `none`, the signature emptied;
    tampered_rejected   a claim changed, the original signature kept;
    stripped_rejected   the signature segment emptied.

All three test the one failure that matters most: a server that does not
verify the signature at all. They are sent to an anchor, a documented read
that answers 2xx with the genuine token (src/tests/helpers/anchor.py), so that
a refusal is known to be about the manipulation and not about the endpoint
refusing everyone. The genuine token is sent there first (the positive
control); the variant that answers 2xx where the genuine one does is the
violation.

The variants that need key material (an expired `exp` needs the signing
key; algorithm confusion needs the public key, which a target may publish,
crAPI's at /identity/api/auth/jwks.json, but this test neither fetches nor
implements the attack) are reported
`NOT_VERIFIABLE/NEEDS_KEY_MATERIAL`, named so the report is honest about what
was not tried, rather than skipped silently or faked.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import structlog

from src.core.assessment_test import category_of
from src.core.auth_placement import RequestAuthParts
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
from src.core.jwt_tokens import (
    ALG_NONE_SPELLINGS,
    JwtVariant,
    JwtView,
    decode,
    stripped_signature,
    with_alg_none,
    with_tampered_payload,
)
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
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.anchor import Anchor, find_anchor
from src.tests.helpers.auth import auth_parts

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The sub-tests, in the order the page lists them.
_SUB_UNSIGNED: str = "unsigned_rejected"
_SUB_TAMPERED: str = "tampered_rejected"
_SUB_STRIPPED: str = "stripped_rejected"
_SUB_CONFUSION: str = "algorithm_confusion"

# The sub-test each key-free variant belongs to.
_VARIANT_SUB: dict[JwtVariant, str] = {
    JwtVariant.ALG_NONE: _SUB_UNSIGNED,
    JwtVariant.TAMPERED_PAYLOAD: _SUB_TAMPERED,
    JwtVariant.STRIPPED_SIGNATURE: _SUB_STRIPPED,
}

# The answer categories that say nothing about the guarantee (rule 1).
_SPOILING: dict[ResponseCategory, str] = {
    ResponseCategory.UPSTREAM_UNAVAILABLE: "UPSTREAM_UNAVAILABLE",
    ResponseCategory.RATE_LIMITED: "RATE_LIMITED",
    ResponseCategory.NO_RESPONSE: "NO_RESPONSE",
    ResponseCategory.SERVER_ERROR: "SERVER_ERROR",
}

_REFERENCES: tuple[Reference, ...] = (
    # Read on the ASVS source 2026-10-22: 9.1.1 "validated using their digital
    # signature ... before accepting the token's contents" (the whole test);
    # 9.1.2 "only algorithms on an allowlist" (the alg:none bypass).
    Reference(standard=Standard.OWASP_API_TOP10, id="API2:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-9.1.1"),
    Reference(standard=Standard.ASVS, id="v5.0.0-9.1.2"),
    Reference(standard=Standard.RFC, id="8725", section="2.1"),
)


class Test12CredentialCryptographicallyValid(BaseTest):
    """
    Test 1.2 -- whether a JWT whose signature does not hold is refused.

    The oracle of each sub-test is in the module docstring and on the test
    page.
    """

    info = TestInfo(
        id="1.2",
        name="Credential Cryptographically Valid",
        priority=0,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-347",
        references=_REFERENCES,
        tags=("authentication", "jwt"),
        needs=(Need.USER_ACCOUNT,),
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB_UNSIGNED, _SUB_TAMPERED, _SUB_STRIPPED, _SUB_CONFUSION),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Confirm the genuine token works, then present each degraded variant.

        Args:
            target:  The run's target (surface, path_seed, credentials).
            context: The run's context (the role's credential).
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
            parts = auth_parts(target, context, ROLE_USER_A)
            # The token as obtained, not read back from the request parts: a
            # list of known prefixes ("Bearer ", "token ") missed any other
            # .
            token = context.get_token(ROLE_USER_A)
            if token is None:
                return self._not_a_credential_token()
            view = decode(token)
            if view is None:
                return self._not_applicable(
                    "The credential of role user_a is not a JWT (it has no three "
                    "base64url segments to decode), so there is no signature to attack: an "
                    "opaque token is checked at the server."
                )
            anchor = find_anchor(
                target, client, dict(parts.headers), dict(parts.params), self.info.id
            )
            if anchor is None:
                self._record_all(Outcome.NOT_VERIFIABLE, "NO_WORKING_ANCHOR")
                return self._finish()
            self._step(anchor.record)
            notes = self._probe_variants(client, store, context, anchor, view, parts)
            self._record(
                _SUB_CONFUSION,
                Outcome.NOT_VERIFIABLE,
                "NEEDS_KEY_MATERIAL",
            )
            return self._finish(notes=notes)
        except SecurityClientError as exc:
            return self._error(exc)

    def _probe_variants(  # noqa: PLR0913 -- the probe needs all of it
        self,
        client: SecurityClient,
        store: EvidenceStore,
        context: TestContext,
        anchor: Anchor,
        view: JwtView,
        parts: RequestAuthParts,
    ) -> list[InfoNote]:
        """
        Send the key-free variants to the anchor and judge each.

        Args:
            client:  The run's HTTP client.
            store:   The evidence store.
            context: The run's context (the secrets registry).
            anchor:  The documented read the genuine token is accepted on.
            view:   The decoded genuine token.
            parts:  The genuine credential's request parts (for the placement).

        Returns:
            A note naming the key-based cases left unverified.
        """
        # `none` in each of its spellings, the standard one first, until one is
        # accepted: one proof is enough, and a refused spelling says only that
        # this one is refused.
        unsigned = [
            (JwtVariant.ALG_NONE, with_alg_none(view, spelling), spelling)
            for spelling in ALG_NONE_SPELLINGS
        ]
        builders = (
            *unsigned,
            (JwtVariant.TAMPERED_PAYLOAD, with_tampered_payload(view), None),
            (JwtVariant.STRIPPED_SIGNATURE, stripped_signature(view), None),
        )
        unsigned_accepted = False
        for variant, degraded, spelling in builders:
            if variant == JwtVariant.ALG_NONE and unsigned_accepted:
                continue
            # Each variant keeps parts of the genuine token (the tampered one its
            # signature, the unsigned one its payload): together they rebuild it.
            # In Authorization the whole value is always redacted; registered,
            # it is redacted wherever else the credential travels (a header of
            # its own, a query parameter).
            context.register_secret(degraded, f"user_a token, {variant.value} variant")
            record = self._send_as(client, anchor, _place(degraded, parts, view))
            accepted = self._judge_variant(record, store, variant, anchor, spelling)
            unsigned_accepted = unsigned_accepted or (variant == JwtVariant.ALG_NONE and accepted)
        return [
            InfoNote(
                title="JWT attacks that need key material, not tried",
                detail=(
                    "Algorithm confusion (the public key verified as an HMAC secret) needs the "
                    "target's public key, and a token re-signed with a chosen claim needs its "
                    "signing key. This test fetches neither and implements neither, so those "
                    "cases are reported NEEDS_KEY_MATERIAL rather than passed. Where a target "
                    "publishes its public key (a JWKS endpoint), algorithm confusion can be "
                    "tried with a dedicated tool; keeping that catalogue was decided against for "
                    "this tool."
                ),
            )
        ]

    def _judge_variant(
        self,
        record: EvidenceRecord,
        store: EvidenceStore,
        variant: JwtVariant,
        anchor: Anchor,
        spelling: str | None = None,
    ) -> bool:
        """
        Say what the anchor's answer to one degraded token means.

        Args:
            record:   The answer to the degraded token.
            store:    The evidence store.
            variant:  Which degradation was sent.
            anchor:   The anchor it was sent to.
            spelling: For ALG_NONE, how `none` was written.

        Returns:
            True when the degraded token was accepted (a violation).
        """
        label = variant.value if spelling is None else f"{variant.value} (alg '{spelling}')"
        sub_test = _VARIANT_SUB[variant]
        category = category_of(record)
        if category in _SPOILING:
            self._judge(record, store, sub_test, Outcome.NOT_VERIFIABLE, _SPOILING[category])
            return False
        if category == ResponseCategory.SERVED:
            # The controls the finding rests on: the genuine token served at the
            # anchor, and the anchor refused without a credential.
            store.pin_evidence(anchor.record)
            store.pin_evidence(anchor.refused)
            self._judge(
                record,
                store,
                sub_test,
                Outcome.VIOLATION,
                f"ACCEPTED_{variant.value}",
                Finding(
                    title=f"Invalid token accepted: {label}",
                    detail=(
                        f"The genuine token is accepted at {anchor.method} {anchor.path}, and so "
                        f"was a token degraded as {label}, which answered HTTP "
                        f"{record.response_status_code}. The server does not verify the "
                        "signature before trusting the token: a changed identity or an unsigned "
                        "token is taken as authentic. Verify the signature against the issuer's "
                        "key and refuse any token whose signature does not match."
                    ),
                    supporting_refs=[anchor.record.record_id, anchor.refused.record_id],
                    confidence=Confidence.CERTAIN,
                ),
            )
            return True
        self._judge(record, store, sub_test, Outcome.ENFORCED, "REFUSED")
        return False

    def _send_as(
        self,
        client: SecurityClient,
        anchor: Anchor,
        placed: tuple[dict[str, str], dict[str, str]],
    ) -> EvidenceRecord:
        """
        Send the anchor request carrying a token where the genuine one goes.

        Args:
            client: The run's HTTP client.
            anchor: The anchor operation.
            placed: The (degraded) token's headers and query parameters (_place).

        Returns:
            The record of the answer, or of the transport failure.

        Raises:
            SecurityClientError: A failure with no record at all.
        """
        headers, params = placed
        try:
            _response, record = client.request(
                anchor.method,
                anchor.path,
                test_id=self.info.id,
                headers=headers or None,
                params=params or None,
            )
        except SecurityClientError as exc:
            if exc.record is None:
                raise
            return exc.record
        return record

    # ------------------------------------------------------------------
    # Outcomes with no probe
    # ------------------------------------------------------------------

    def _record_all(self, outcome: Outcome, detail: str) -> None:
        """Record the same outcome for the three key-free sub-tests."""
        for sub_test in (_SUB_UNSIGNED, _SUB_TAMPERED, _SUB_STRIPPED):
            self._record(sub_test, outcome, detail)

    def _not_applicable(self, reason: str) -> TestResult:
        """Record NOT_APPLICABLE on every sub-test and finish."""
        self._record_all(Outcome.NOT_APPLICABLE, "NOT_A_JWT")
        self._record(_SUB_CONFUSION, Outcome.NOT_APPLICABLE, "NOT_A_JWT")
        return self._finish(notes=[InfoNote(title="Not a JWT", detail=reason)])

    def _not_a_credential_token(self) -> TestResult:
        """The placement does not carry a single bearer-style token value."""
        self._record_all(Outcome.NOT_VERIFIABLE, "NO_TOKEN_VALUE")
        self._record(_SUB_CONFUSION, Outcome.NOT_VERIFIABLE, "NO_TOKEN_VALUE")
        return self._finish()


def _place(
    token: str, parts: RequestAuthParts, genuine: JwtView
) -> tuple[dict[str, str], dict[str, str]]:
    """
    Put a token where and how the genuine credential is placed.

    The genuine token is replaced inside the genuine credential's parts, so the
    placement's prefix ("Bearer ", "token ", a cookie's name) is kept whatever
    it is.

    Args:
        token:   The (degraded) token.
        parts:   The genuine credential's request parts.
        genuine: The decoded genuine token.

    Returns:
        (headers, query parameters) carrying the token in the same place.
    """
    original = ".".join(
        (genuine.header_segment, genuine.payload_segment, genuine.signature_segment)
    )
    headers = {name: value.replace(original, token) for name, value in parts.headers.items()}
    params = {name: value.replace(original, token) for name, value in parts.params.items()}
    return headers, params
