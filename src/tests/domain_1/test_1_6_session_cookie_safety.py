"""
src/tests/domain_1/test_1_6_session_cookie_safety.py

Test 1.6: guarantee "a session the target keeps in a cookie is kept safely"
(docs/project/test-review/group-b.md).

One sub-test, cookie_attributes: every cookie the login response sets is read
from the login artefact (TestContext.login_artefact, piece 6) and judged on
three attributes:

    Secure    the cookie is not sent over plain HTTP (CWE-614);
    HttpOnly  the page's scripts cannot read it, so cross-site scripting
              cannot steal the session (CWE-1004);
    SameSite  another site cannot make the browser send it with a request it
              did not mean to (CWE-1275).

**Every cookie the login sets is judged, whatever its name.** The old test
looked for names from a fixed list (`session`, `sid`, `PHPSESSID`,
`JSESSIONID`, `connect.sid`, ...) and skipped on all three labs; a list of
names skips exactly the cookie whose name nobody guessed. A cookie the
response is deleting (an empty value, `Max-Age=0`, a past `Expires`) is left
alone: it is being cleared, not issued.

This test sends no request of its own. The login has already happened, its
record is kept for the tests that read it, and the `Set-Cookie` headers in it
are the evidence.

What it does not check, and why. Session fixation (ASVS: the session
identifier changes when the user authenticates) needs a login that can be
repeated while carrying a cookie obtained before it. The prepared-resource
mechanism logs in once per role, and a form login with a CSRF token is not
something the tool can drive in a general way, so the check is left out and
named in the page's limitations rather than approximated.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base.
"""

from __future__ import annotations

from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import structlog

from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import (
    Confidence,
    Finding,
    Outcome,
    Reference,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The single sub-test.
_SUB_COOKIES: str = "cookie_attributes"

# The attributes judged, with the detail each missing one is recorded under and
# the catalogue entry it belongs to.
_ATTRIBUTES: tuple[tuple[str, str, str], ...] = (
    ("secure", "COOKIE_WITHOUT_SECURE", "CWE-614"),
    ("httponly", "COOKIE_WITHOUT_HTTPONLY", "CWE-1004"),
    ("samesite", "COOKIE_WITHOUT_SAMESITE", "CWE-1275"),
)

# The `SameSite` values that restrict anything. `None` is a value the standard
# allows and it restricts nothing, so it counts as absent (RFC 6265bis).
_SAMESITE_RESTRICTING: frozenset[str] = frozenset({"strict", "lax"})

_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API2:2023"),
    Reference(standard=Standard.CWE, id="CWE-614"),
    Reference(standard=Standard.CWE, id="CWE-1275"),
    Reference(standard=Standard.CWE, id="CWE-384"),
    Reference(standard=Standard.RFC, id="6265", section="4.1.2"),
)


class Test16SessionCookieSafety(BaseTest):
    """
    Test 1.6 -- whether the cookies a login sets protect the session they carry.

    The oracle is in the module docstring and on the test page.
    """

    info = TestInfo(
        id="1.6",
        name="Session Cookie Safety",
        priority=3,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-1004",
        references=_REFERENCES,
        tags=("authentication", "session"),
        needs=(Need.USER_ACCOUNT,),
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB_COOKIES,),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Judge the cookies the login response set.

        Args:
            target:  The run's target (unused: the evidence is the login's record).
            context: The run's context (the login artefact the engine obtained).
            client:  The run's HTTP client (unused: the test sends nothing).
            store:   The test's evidence store.

        Returns:
            self._finish(), or self._skip() when there was no login or it set
            no cookie.
        """
        # The login has already happened: the engine obtains the credential of
        # every account a test declares as a need before running it, so the
        # artefact is there whenever the role is configured as a login.
        del target, client
        artefact = context.login_artefact(ROLE_USER_A)
        if artefact is None:
            return self._skip(
                "No login artefact for role user_a: the credential does not come from a login "
                "(credentials.auth_type is not 'login'), so no login response can be read. A "
                "target that keeps its session in a cookie sets it on a login response."
            )
        cookies = [c for c in artefact.record.response_set_cookies if not _is_deletion(c)]
        if not cookies:
            return self._skip(
                f"The login response of role user_a (resource '{artefact.resource}') set no "
                "cookie: this target keeps no session in a cookie, so there is nothing to judge. "
                "Both lab applications answer a login with a token in the body instead."
            )
        store.pin_evidence(artefact.record)
        for raw in cookies:
            self._judge_cookie(raw, artefact.resource, artefact.record.record_id)
        return self._finish()

    def _judge_cookie(self, raw: str, resource: str, evidence_ref: str) -> None:
        """
        Judge one `Set-Cookie` of the login response.

        Args:
            raw:          The header as sent, already redacted in the record.
            resource:     The login resource that produced it.
            evidence_ref: The login record, as the finding's proof.
        """
        name = raw.split("=", 1)[0].strip()
        present = _attributes(raw)
        missing = [
            (detail, entry)
            for attribute, detail, entry in _ATTRIBUTES
            if not _restricts(attribute, present)
        ]
        if not missing:
            self._record(_SUB_COOKIES, Outcome.ENFORCED, "COOKIE_SAFE")
            return
        for detail, entry in missing:
            attribute = detail.removeprefix("COOKIE_WITHOUT_").lower()
            self._record(
                _SUB_COOKIES,
                Outcome.VIOLATION,
                detail,
                Finding(
                    title=f"Session cookie without {attribute}: {name}",
                    detail=(
                        f"The login of role user_a (resource '{resource}') sets the cookie "
                        f"'{name}' without a restricting `{attribute}` attribute. "
                        f"{_WHY[attribute]} Set it on every cookie that carries a session."
                    ),
                    evidence_ref=evidence_ref,
                    # The header as the target sent it: the observed fact.
                    confidence=Confidence.CERTAIN,
                    references=[Reference(standard=Standard.CWE, id=entry)],
                ),
            )


# Why each attribute matters, in the finding.
_WHY: dict[str, str] = {
    "secure": (
        "Without it the browser also sends the cookie over plain HTTP, where anyone on the path "
        "reads the session."
    ),
    "httponly": (
        "Without it the scripts of the page can read the cookie, so one cross-site scripting flaw "
        "hands over the session."
    ),
    "samesite": (
        "Without it, or with `SameSite=None`, another site can make the browser send the cookie "
        "with a request the user did not mean to make."
    ),
}


def _attributes(raw: str) -> dict[str, str]:
    """
    The attributes of a `Set-Cookie`, lowercase, by name.

    Args:
        raw: The header as sent ("name=value; Path=/; Secure; HttpOnly").

    Returns:
        The attributes after the first part, their values lowercase; a
        valueless attribute maps to an empty string.
    """
    found: dict[str, str] = {}
    for part in raw.split(";")[1:]:
        key, _, value = part.strip().partition("=")
        if key:
            found[key.strip().lower()] = value.strip().lower()
    return found


def _restricts(attribute: str, present: dict[str, str]) -> bool:
    """
    Whether one attribute is there and restricts something.

    Args:
        attribute: `secure`, `httponly` or `samesite`.
        present:   The cookie's attributes.

    Returns:
        True when the attribute protects the cookie. `SameSite=None` does not.
    """
    if attribute not in present:
        return False
    if attribute == "samesite":
        return present[attribute] in _SAMESITE_RESTRICTING
    return True


def _is_deletion(raw: str) -> bool:
    """
    Whether a `Set-Cookie` is clearing a cookie instead of issuing one.

    A login often clears a stale cookie, and the attributes of a cookie being
    removed say nothing about how the session is kept.

    Args:
        raw: The header as sent.

    Returns:
        True when the value is empty, `Max-Age` is zero or negative, or
        `Expires` is in the past.
    """
    first = raw.split(";", 1)[0]
    _, _, value = first.partition("=")
    if not value.strip():
        return True
    present = _attributes(raw)
    max_age = present.get("max-age")
    if max_age is not None:
        try:
            return int(max_age) <= 0
        except ValueError:
            return False
    expires = present.get("expires")
    if expires:
        try:
            when = parsedate_to_datetime(expires)
        except (TypeError, ValueError):
            return False
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        return when <= datetime.now(UTC)
    return False
