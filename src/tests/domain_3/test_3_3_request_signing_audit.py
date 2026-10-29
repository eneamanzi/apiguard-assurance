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
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB_ALGO: str = "algorithm_strong"
_SUB_REPLAY: str = "replay_protected"

# Default forbidden HMAC algorithms: broken for signatures (RFC 6151, RFC 6194).
_DEFAULT_FORBIDDEN: tuple[str, ...] = ("hmac-sha1", "hmac-md5", "sha1", "md5")

# Default maximum replay window: NIST SP 800-107 / the methodology's 5 minutes.
_DEFAULT_MAX_REPLAY_SECONDS: int = 300

_REFERENCES: tuple[Reference, ...] = (
    # NIST SP 800-107 (HMAC algorithm strength, replay window). ASVS v5.0.0-4.1.5
    # to add once verified on source (WebFetch rate-limited 2026-10-23; see the
    # group-F draft).
    Reference(standard=Standard.NIST_SP, id="800-107r1"),
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
        description="HMAC algorithms treated as weak (compared lowercased). Default sha1/md5.",
    )


class Test33RequestSigningAudit(BaseTest[Test33Params]):
    """
    Test 3.3 -- whether a request-signing policy uses a strong algorithm and
    bounds replay.

    The oracle is in the module docstring and on the test page.
    """

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
        sub_tests=(_SUB_ALGO, _SUB_REPLAY),
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
                return self._skip_for_concept(CONCEPT_SIGNING_POLICIES, answer, evidence_ref)
            enabled = [p for p in answer.items if p.enabled]
            if not enabled:
                self._record(_SUB_ALGO, Outcome.NOT_APPLICABLE, "NO_SIGNING")
                self._record(_SUB_REPLAY, Outcome.NOT_APPLICABLE, "NO_SIGNING")
                return self._finish(notes=[_no_signing_note(evidence_ref)])
            forbidden = {a.lower() for a in cfg.forbidden_algorithms}
            for policy in enabled:
                self._audit_algorithm(policy, forbidden, evidence_ref)
                self._audit_replay(policy, cfg.max_replay_window_seconds, evidence_ref)
            return self._finish(message=f"{len(enabled)} enabled signing policy(ies).")
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_3_3_unexpected_error", error=str(exc))
            return self._error(exc)

    def _audit_algorithm(
        self, policy: SigningPolicy, forbidden: set[str], evidence_ref: str
    ) -> None:
        """Judge the policy's algorithms against the forbidden set."""
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
                        f"The signing policy '{policy.name}' allows {', '.join(weak)}, broken for "
                        "signatures (RFC 6151/6194): an attacker can forge a signature and tamper "
                        "with the request undetected. Allow only HMAC-SHA-256 or stronger (NIST SP "
                        "800-107)."
                    ),
                    confidence=Confidence.CERTAIN,
                    evidence_ref=evidence_ref,
                ),
            )
            return
        self._record(_SUB_ALGO, Outcome.ENFORCED, "STRONG_ALGORITHM")

    def _audit_replay(self, policy: SigningPolicy, max_seconds: int, evidence_ref: str) -> None:
        """Judge the policy's replay window against the maximum."""
        window = policy.replay_window_seconds
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
                        f"{max_seconds} seconds (NIST SP 800-107)."
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
                        "tolerance (NIST SP 800-107)."
                    ),
                    confidence=Confidence.CERTAIN,
                    evidence_ref=evidence_ref,
                ),
            )
            return
        self._record(_SUB_REPLAY, Outcome.ENFORCED, "REPLAY_BOUNDED")


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
