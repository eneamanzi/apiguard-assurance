"""
src/tests/domain_1/test_1_3_credential_expiry.py

Test 1.3: guarantee "a credential declares an expiry, keeps it within a sane
bound, and is refused once it has passed".

The credential must be a JSON Web Token: an opaque token (Forgejo's) carries no
claims to read, and the test is `NOT_APPLICABLE/NOT_A_JWT` there. Where it is a
JWT:

    expiry_declared   the token carries an `exp` claim at all. Without one it
                      never expires, so no absolute lifetime can be enforced
                      (ASVS v5.0.0-7.3.2);
    lifetime_bounded  the span `exp - iat` is not excessive. A long-lived
                      bearer token widens the window after a theft. crAPI's
                      token lives 7 days (measured 2026-10-22), far past any
                      access-token guidance;
    expired_rejected  a token whose `exp` is in the past is refused. Minting
                      one needs the signing key, which the target does not give
                      us, so this is `NEEDS_KEY_MATERIAL` unless a key is
                      supplied: the honest answer, not a skipped check.

The lifetime bound is a heuristic (a token's purpose, access or refresh, cannot
be read from the token), so its finding is TENTATIVE: it reports the measured
lifetime and lets the reader judge, rather than failing on a fixed number ASVS
itself does not set.

The test reads the obtained token; it sends no request of its own (there is no
expired token to send without the key).

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

from datetime import UTC, datetime

import structlog

from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError
from src.core.jwt_tokens import decode
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
from src.tests.helpers.auth import auth_parts

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The sub-tests, in the order the page lists them.
_SUB_DECLARED: str = "expiry_declared"
_SUB_LIFETIME: str = "lifetime_bounded"
_SUB_EXPIRED: str = "expired_rejected"

# Above this span between `iat` and `exp`, a bearer token's absolute lifetime
# is reported as excessive. A heuristic, not a line ASVS draws: ASVS 7.3.2 asks
# for an absolute maximum "according to risk analysis", so the finding is
# TENTATIVE and carries the measured value. 24 hours is generous: it clears a
# token refreshed through a working day and flags one meant to last for days
# (crAPI's 7). Not a parameter (owner, 2026-10-22: the review removes knobs).
_LIFETIME_WARN_SECONDS: int = 86400

_REFERENCES: tuple[Reference, ...] = (
    # Read on the ASVS source 2026-10-22: 9.2.1 "accepted only if the
    # verification time is within this validity time span" (expiry enforced);
    # 7.3.2 "an absolute maximum session lifetime" (the lifetime finding).
    Reference(standard=Standard.OWASP_API_TOP10, id="API2:2023"),
    Reference(standard=Standard.RFC, id="7519", section="4.1.4"),
    Reference(standard=Standard.ASVS, id="v5.0.0-9.2.1"),
    Reference(standard=Standard.ASVS, id="v5.0.0-7.3.2"),
)


class Test13CredentialExpiry(BaseTest):
    """
    Test 1.3 -- whether a JWT declares and bounds its expiry.

    The oracle of each sub-test is in the module docstring and on the test
    page.
    """

    info = TestInfo(
        id="1.3",
        name="Credential Expiry",
        priority=0,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-613",
        references=_REFERENCES,
        tags=("authentication", "jwt"),
        needs=(Need.USER_ACCOUNT,),
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB_DECLARED, _SUB_LIFETIME, _SUB_EXPIRED),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Read the obtained token and judge its expiry claims.

        Args:
            target:  The run's target (credentials).
            context: The run's context (the role's credential).
            client:  The run's HTTP client (unused: the test reads the token).
            store:   The test's evidence store.

        Returns:
            self._finish(), or self._error(exc).
        """
        del client
        try:
            parts = auth_parts(target, context, ROLE_USER_A)
            token = _single_token(dict(parts.headers), dict(parts.params))
            view = decode(token) if token is not None else None
            if view is None:
                for sub_test in (_SUB_DECLARED, _SUB_LIFETIME, _SUB_EXPIRED):
                    self._record(sub_test, Outcome.NOT_APPLICABLE, "NOT_A_JWT")
                return self._finish(
                    notes=[
                        InfoNote(
                            title="Not a JWT",
                            detail=(
                                "The credential of role user_a is not a JWT, so it carries no "
                                "`exp` claim to read. Forgejo's API token is an opaque sha1 "
                                "value whose lifetime is managed at the server."
                            ),
                        )
                    ]
                )
            self._judge_claims(view.claims)
            self._record(_SUB_EXPIRED, Outcome.NOT_VERIFIABLE, "NEEDS_KEY_MATERIAL")
            return self._finish(notes=[_expired_note()])
        except AuthenticationSetupError as exc:
            return self._error(exc)

    def _judge_claims(self, claims: dict[str, object]) -> None:
        """
        Judge the `exp` and `iat` claims of the obtained token.

        Args:
            claims: The token's payload.
        """
        exp = _timestamp(claims.get("exp"))
        if exp is None:
            self._record(
                _SUB_DECLARED,
                Outcome.VIOLATION,
                "NO_EXP_CLAIM",
                Finding(
                    title="The credential declares no expiry",
                    detail=(
                        "The JWT of role user_a carries no `exp` claim, so it never expires on "
                        "its own: a token stolen once stays usable for good, and no absolute "
                        "session lifetime can be enforced (ASVS v5.0.0-7.3.2). Add an `exp` "
                        "claim and keep it short."
                    ),
                    confidence=Confidence.FIRM,
                ),
            )
            return
        self._record(_SUB_DECLARED, Outcome.ENFORCED, "EXP_DECLARED")
        iat = _timestamp(claims.get("iat"))
        if iat is None or exp <= iat:
            self._record(_SUB_LIFETIME, Outcome.NOT_VERIFIABLE, "NO_IAT_CLAIM")
            return
        lifetime = int(exp - iat)
        if lifetime > _LIFETIME_WARN_SECONDS:
            self._record(
                _SUB_LIFETIME,
                Outcome.VIOLATION,
                "LIFETIME_EXCESSIVE",
                Finding(
                    title="The credential's lifetime is long",
                    detail=(
                        f"The JWT of role user_a is valid for {_human(lifetime)} "
                        f"(`exp` - `iat`). A bearer token presented on every request with an "
                        "absolute lifetime this long widens the window in which a stolen token "
                        "is usable (ASVS v5.0.0-7.3.2 asks for an absolute maximum set by risk "
                        "analysis). Issue a short-lived access token and renew it. Reported with "
                        "lower confidence because the token's purpose cannot be read from it."
                    ),
                    confidence=Confidence.TENTATIVE,
                ),
            )
            return
        self._record(_SUB_LIFETIME, Outcome.ENFORCED, "LIFETIME_BOUNDED")


def _single_token(headers: dict[str, str], params: dict[str, str]) -> str | None:
    """
    The bare token from the credential parts, if exactly one value carries it.

    Args:
        headers: The credential's headers.
        params:  The credential's query parameters.

    Returns:
        The token without its scheme prefix, or None.
    """
    values = list(headers.values()) + list(params.values())
    if len(values) != 1:
        return None
    value = values[0]
    for prefix in ("Bearer ", "token ", "Token "):
        if value.startswith(prefix):
            return value[len(prefix) :]
    if "=" in value and ";" not in value.rstrip():
        return value.split("=", 1)[1]
    return value


def _timestamp(value: object) -> float | None:
    """A numeric claim as a number of seconds, or None when it is not numeric."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    return None


def _human(seconds: int) -> str:
    """A span in the largest plain unit, e.g. '7 days', '2 hours', '45 minutes'."""
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= size:
            count = seconds // size
            return f"{count} {unit}{'s' if count != 1 else ''}"
    return f"{seconds} second{'s' if seconds != 1 else ''}"


def _expired_note() -> InfoNote:
    """The note explaining why the past-expiry case was not tried."""
    return InfoNote(
        title="An expired token was not minted",
        detail=(
            "Whether a token with an `exp` in the past is refused could not be tried: minting one "
            "needs the issuer's signing key, which this target does not give us (and no tool can "
            "do without it). The check is reported NEEDS_KEY_MATERIAL rather than passed. "
            f"Reference time for any later check: {datetime.now(UTC).isoformat()}."
        ),
    )
