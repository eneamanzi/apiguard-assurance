"""
src/tests/domain_3/test_3_3_request_signing_audit.py

Test 3.3: guarantee "data in transit is protected from tampering beyond TLS"
. An HMAC request signature with a strong
algorithm and replay protection.

The test reads the gateway's signing policies through the adapter and audits
every enabled one:

    algorithm_strong  no algorithm weaker than SHA-256 (hmac-sha1, hmac-md5 are
                      broken) -> a weak one is a VIOLATION;
    replay_protected  a bounded replay window (<= the configured maximum) -> an
                      unbounded or absent window is a VIOLATION.

Request signing is an advanced, optional control that most APIs do not use. Its
**absence is not a failure**: no enabled policy -> NOT_APPLICABLE with a note
(an architectural gap to assess against the threat model, per the methodology).
WHITE_BOX (the gateway Admin API), READ_ONLY. Rebuilt on the new base from the
test on `main`: every enabled policy is audited (not only the first), and the
oracle names the gateway concept, never a gateway's own plugin.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base.
"""

from __future__ import annotations

import structlog
from pydantic import BaseModel, ConfigDict, Field

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.gateway.base import CONCEPT_SIGNING_POLICIES
from src.core.gateway.concepts import ConceptStatus, SigningPolicy
from src.core.models import (
    Confidence,
    Finding,
    InfoNote,
    Outcome,
    Reference,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.test_metadata import Effect, Need, OracleCase, TestInfo
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB_ALGO: str = "algorithm_strong"
_SUB_REPLAY: str = "replay_protected"
# What the signature must cover: the body (through its digest) and the target
# (method and path); the guarantee's failure scenario is a changed body
# (owner, 2026-11-16).
_SUB_CONTENT: str = "content_signed"

# Default forbidden HMAC algorithm: HMAC-MD5, which RFC 6151 section 2.3 says not
# to include in a new protocol design, though its known attacks "do not seem to
# indicate a practical vulnerability". HMAC-SHA-1 is not forbidden by default:
# RFC 6194 section 4, "HMAC-SHA-1 remains secure" (both read 2026-11-05; owner
# decision that day). The operator can add it.
_DEFAULT_FORBIDDEN: tuple[str, ...] = ("hmac-md5", "md5")

# Default maximum replay window: the methodology's 5 minutes (no standard sets it).
_DEFAULT_MAX_REPLAY_SECONDS: int = 300

_REFERENCES: tuple[Reference, ...] = (
    # NIST SP 800-107 Rev.1 (the security of HMAC applications) and RFC 6151
    # (HMAC-MD5 not to be used in new designs); ASVS v5.0.0 4.1.5 (per-message
    # signatures) and 11.4.1 (no MD5 for any cryptographic purpose), read
    # 2026-11-16.
    Reference(standard=Standard.NIST_SP, id="800-107r1"),
    Reference(standard=Standard.RFC, id="6151", section="2.3"),
    Reference(standard=Standard.ASVS, id="v5.0.0-4.1.5"),
    Reference(standard=Standard.ASVS, id="v5.0.0-11.4.1"),
)

_ORACLE: tuple[OracleCase, ...] = (
    OracleCase(
        sub_test=_SUB_ALGO,
        when="the policy lets a request without a valid signature through as an anonymous consumer",
        outcome=Outcome.VIOLATION,
        detail="SIGNATURE_OPTIONAL",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_ALGO,
        when="the policy allows an algorithm of `forbidden_algorithms`",
        outcome=Outcome.VIOLATION,
        detail="WEAK_ALGORITHM",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_ALGO,
        when="no allowed algorithm is forbidden",
        outcome=Outcome.ENFORCED,
        detail="STRONG_ALGORITHM",
    ),
    OracleCase(
        sub_test=_SUB_ALGO,
        when="the gateway does not state the policy's algorithms",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="ALGORITHMS_NOT_STATED",
    ),
    OracleCase(
        sub_test=_SUB_REPLAY,
        when="the gateway states that the request's date is never checked",
        outcome=Outcome.VIOLATION,
        detail="REPLAY_UNBOUNDED",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_REPLAY,
        when="a window above `max_replay_window_seconds`",
        outcome=Outcome.VIOLATION,
        detail="REPLAY_WINDOW_TOO_LARGE",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_REPLAY,
        when="a bounded window, checked against a date the signature need not cover (a fresh "
        "unsigned date passes)",
        outcome=Outcome.VIOLATION,
        detail="REPLAY_DATE_NOT_SIGNED",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_REPLAY,
        when="a window within `max_replay_window_seconds`, on a date the signature must cover",
        outcome=Outcome.ENFORCED,
        detail="REPLAY_BOUNDED",
    ),
    OracleCase(
        sub_test=_SUB_REPLAY,
        when="the gateway states no replay window",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="REPLAY_WINDOW_NOT_STATED",
    ),
    OracleCase(
        sub_test=_SUB_CONTENT,
        when="the policy requires the body's digest and the request's method and path in the "
        "signature",
        outcome=Outcome.ENFORCED,
        detail="CONTENT_SIGNED",
    ),
    OracleCase(
        sub_test=_SUB_CONTENT,
        when="a changed body is not refused: no body check, or a digest the signature need not "
        "cover (FIRM: a client may sign it anyway, the gateway does not require it)",
        outcome=Outcome.VIOLATION,
        detail="BODY_NOT_SIGNED",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_CONTENT,
        when="the body is covered, the method and path need not be",
        outcome=Outcome.VIOLATION,
        detail="TARGET_NOT_SIGNED",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_CONTENT,
        when="the gateway does not state what the signature must cover",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="CONTENT_NOT_STATED",
    ),
    *(
        OracleCase(
            sub_test=sub_test,
            when="no enabled signing policy",
            outcome=Outcome.NOT_APPLICABLE,
            detail="NO_SIGNING",
        )
        for sub_test in (_SUB_ALGO, _SUB_REPLAY, _SUB_CONTENT)
    ),
)


class Test33Params(BaseModel):
    """Parameters of test 3.3."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_replay_window_seconds: int = Field(
        default=_DEFAULT_MAX_REPLAY_SECONDS,
        ge=1,
        description=(
            "The largest acceptable replay window (clock-skew tolerance) in seconds; above it a "
            "signed request can be replayed. Default 300 (5 minutes)."
        ),
    )
    forbidden_algorithms: tuple[str, ...] = Field(
        default=_DEFAULT_FORBIDDEN,
        description=(
            "HMAC algorithms treated as weak (compared lowercased). Default md5: RFC 6151 "
            "advises against HMAC-MD5 in new designs; HMAC-SHA-1 is not weak (RFC 6194) unless "
            "added here."
        ),
    )


class Test33RequestSigningAudit(BaseTest[Test33Params]):
    """Test 3.3 -- whether a request-signing policy is required, strong and bounds replay."""

    info = TestInfo(
        id="3.3",
        name="Request Signing Audit",
        priority=3,
        strategy=TestStrategy.WHITE_BOX,
        cwe="CWE-347",
        references=_REFERENCES,
        tags=("integrity", "request-signing"),
        needs=(Need.GATEWAY,),
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB_ALGO, _SUB_REPLAY, _SUB_CONTENT),
        oracle=_ORACLE,
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Read the signing policies and audit each enabled one.

        Args:
            target:  The run's target (gateway adapter).
            context: Unused.
            client:  Unused (a configuration audit).
            store:   The test's evidence store.

        Returns:
            self._finish(), self._skip(...), or self._error(exc).
        """
        del context, client
        try:
            gateway = target.gateway
            assert gateway is not None  # noqa: S101 -- Need.GATEWAY, checked by the engine
            cfg = self.params(target)
            answer = gateway.signing_policies()
            evidence_ref = self._record_gateway_concept(
                target, store, CONCEPT_SIGNING_POLICIES, answer
            )
            if answer.status != ConceptStatus.READ:
                return self._unread_concept(CONCEPT_SIGNING_POLICIES, answer, evidence_ref)
            enabled = [p for p in answer.items if p.enabled]
            if not enabled:
                self._record(_SUB_ALGO, Outcome.NOT_APPLICABLE, "NO_SIGNING")
                self._record(_SUB_REPLAY, Outcome.NOT_APPLICABLE, "NO_SIGNING")
                self._record(_SUB_CONTENT, Outcome.NOT_APPLICABLE, "NO_SIGNING")
                return self._finish(notes=[_no_signing_note(evidence_ref)])
            forbidden = {a.lower() for a in cfg.forbidden_algorithms}
            for policy in enabled:
                self._audit_algorithm(policy, forbidden, evidence_ref)
                self._audit_replay(policy, cfg.max_replay_window_seconds, evidence_ref)
                self._audit_content(policy, evidence_ref)
            return self._finish(message=f"{len(enabled)} enabled signing policy(ies).")
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_3_3_unexpected_error", error=str(exc))
            return self._error(exc)

    def _audit_algorithm(
        self, policy: SigningPolicy, forbidden: set[str], evidence_ref: str
    ) -> None:
        """Judge whether the signature is required, and its algorithms against the forbidden set."""
        if policy.optional:
            # Kong's `anonymous`, APISIX's `anonymous_consumer`: a request with
            # no signature or a wrong one goes on as that consumer (until
            # 2026-11-16 the policy read as enforced).
            self._record(
                _SUB_ALGO,
                Outcome.VIOLATION,
                "SIGNATURE_OPTIONAL",
                Finding(
                    title=f"Request signature optional on '{policy.name}'",
                    detail=(
                        f"The signing policy '{policy.name}' lets a request without a valid "
                        "signature through as an anonymous consumer, so an unsigned or forged "
                        "request is not refused; only an access rule on that consumer could "
                        "still stop it (FIRM). Remove the anonymous fallback, or deny the "
                        "anonymous consumer on the routes that need a signature."
                    ),
                    confidence=Confidence.FIRM,
                    evidence_ref=evidence_ref,
                ),
            )
        if policy.algorithms is None:
            self._record(_SUB_ALGO, Outcome.NOT_VERIFIABLE, "ALGORITHMS_NOT_STATED")
            return
        weak = sorted({a for a in policy.algorithms if a.lower() in forbidden})
        if weak:
            self._record(
                _SUB_ALGO,
                Outcome.VIOLATION,
                "WEAK_ALGORITHM",
                Finding(
                    title=f"Weak signing algorithm on '{policy.name}': {', '.join(weak)}",
                    detail=(
                        f"The signing policy '{policy.name}' allows {', '.join(weak)}, which the "
                        "configuration treats as weak. For HMAC-MD5, RFC 6151 section 2.3 says it "
                        "should not be included in a new protocol design, though no practical "
                        "forgery is known. Allow only HMAC-SHA-256 or stronger."
                    ),
                    # A policy, not an exploit: what is certain is that the
                    # algorithm is allowed; that it is weak is the standard's
                    # advice, not a demonstrated forgery.
                    confidence=Confidence.FIRM,
                    evidence_ref=evidence_ref,
                ),
            )
            return
        self._record(_SUB_ALGO, Outcome.ENFORCED, "STRONG_ALGORITHM")

    def _audit_replay(self, policy: SigningPolicy, max_seconds: int, evidence_ref: str) -> None:
        """Judge the policy's replay window against the maximum."""
        window = policy.replay_window_seconds
        if window is None and not policy.replay_unlimited:
            # Not stated by the gateway is not "no window": only
            # replay_unlimited says the date is never checked. As for the
            # algorithms, what is not stated is not verifiable.
            self._record(_SUB_REPLAY, Outcome.NOT_VERIFIABLE, "REPLAY_WINDOW_NOT_STATED")
            return
        if window is None:
            self._record(
                _SUB_REPLAY,
                Outcome.VIOLATION,
                "REPLAY_UNBOUNDED",
                Finding(
                    title=f"No replay window on signing policy '{policy.name}'",
                    detail=(
                        f"The signing policy '{policy.name}' states no replay window (timestamp "
                        "tolerance or nonce): a captured signed request can be replayed at any "
                        "time, however strong the algorithm. Bound it to at most "
                        f"{max_seconds} seconds (max_replay_window_seconds, the methodology's "
                        "bound)."
                    ),
                    confidence=Confidence.CERTAIN,
                    evidence_ref=evidence_ref,
                ),
            )
            return
        if window > max_seconds:
            self._record(
                _SUB_REPLAY,
                Outcome.VIOLATION,
                "REPLAY_WINDOW_TOO_LARGE",
                Finding(
                    title=f"Replay window too large on '{policy.name}': {window:g} s",
                    detail=(
                        f"The signing policy '{policy.name}' allows a replay window of "
                        f"{window:g} seconds, above the {max_seconds} s maximum: a captured signed "
                        "request can be replayed within that window. Reduce the timestamp "
                        "tolerance."
                    ),
                    confidence=Confidence.CERTAIN,
                    evidence_ref=evidence_ref,
                ),
            )
            return
        if policy.date_signed is False:
            # Kong accepts X-Date or Date and requires neither in the signature
            # unless enforce_headers lists both: a captured request re-sent with
            # a fresh unsigned date passes the clock check (until 2026-11-16
            # REPLAY_BOUNDED).
            self._record(
                _SUB_REPLAY,
                Outcome.VIOLATION,
                "REPLAY_DATE_NOT_SIGNED",
                Finding(
                    title=f"Replay window checked on an unsigned date on '{policy.name}'",
                    detail=(
                        f"The signing policy '{policy.name}' bounds the replay window to "
                        f"{window:g} seconds, but does not require the date it checks to be in "
                        "the signature: a captured signed request re-sent with a fresh date "
                        "header passes the check and can be replayed at any time. Require every "
                        "date header the gateway accepts in the signature (Kong: `date` and "
                        "`x-date` in `enforce_headers`). FIRM: a client may sign the date anyway; "
                        "the gateway does not require it."
                    ),
                    confidence=Confidence.FIRM,
                    evidence_ref=evidence_ref,
                ),
            )
            return
        self._record(_SUB_REPLAY, Outcome.ENFORCED, "REPLAY_BOUNDED")

    def _audit_content(self, policy: SigningPolicy, evidence_ref: str) -> None:
        """Judge whether the signature must cover the body and the request's target."""
        if policy.body_signed is None or policy.target_signed is None:
            self._record(_SUB_CONTENT, Outcome.NOT_VERIFIABLE, "CONTENT_NOT_STATED")
            return
        if not policy.body_signed:
            self._record(
                _SUB_CONTENT,
                Outcome.VIOLATION,
                "BODY_NOT_SIGNED",
                Finding(
                    title=f"Request body not covered by the signature on '{policy.name}'",
                    detail=(
                        f"The signing policy '{policy.name}' does not refuse a changed body: the "
                        "body is not checked against a digest, or the digest need not be in the "
                        "signature (an unkeyed digest is recomputed by whoever changes the "
                        "body). A request intercepted on the way can have its body changed (an "
                        "amount, a recipient) and keep a valid signature. Check the body's digest "
                        "and require it in the signature (Kong: `validate_request_body` and "
                        "`digest` in `enforce_headers`; APISIX: `validate_request_body` and "
                        "`digest` in `signed_headers`). FIRM: a client may sign it anyway; the "
                        "gateway does not require it."
                    ),
                    confidence=Confidence.FIRM,
                    evidence_ref=evidence_ref,
                ),
            )
            return
        if not policy.target_signed:
            self._record(
                _SUB_CONTENT,
                Outcome.VIOLATION,
                "TARGET_NOT_SIGNED",
                Finding(
                    title=f"Method and path not covered by the signature on '{policy.name}'",
                    detail=(
                        f"The signing policy '{policy.name}' does not require the request's "
                        "method and path in the signature: a signed request can be re-sent to "
                        "another operation. Require them (Kong: `request-line` or "
                        "`@request-target` in `enforce_headers`; APISIX: `@request-target` in "
                        "`signed_headers`). FIRM: a client may sign them anyway."
                    ),
                    confidence=Confidence.FIRM,
                    evidence_ref=evidence_ref,
                ),
            )
            return
        self._record(_SUB_CONTENT, Outcome.ENFORCED, "CONTENT_SIGNED")


def _no_signing_note(evidence_ref: str) -> InfoNote:
    """The note for a gateway with no enabled signing policy (not a failure)."""
    return InfoNote(
        title="No request-signing policy configured",
        detail=(
            "The gateway has no enabled request-signing (HMAC) policy. This is an advanced, "
            "optional integrity control beyond TLS that most APIs do not use; its absence is not "
            "a failure but a gap to assess against the threat model (a trusted intermediary proxy "
            "on the path could tamper with a request undetected). Not applicable here. "
            f"Evidence: {evidence_ref}."
        ),
    )
