"""
src/tests/domain_1/test_1_7_authentication_resistance.py

Test 1.7: guarantee "the endpoint that authenticates a caller does not say
whether an account exists, and does not let a caller go on guessing".

Two sub-tests:

    account_enumeration  a failed authentication for an account that exists
                         answers differently from one for an account that does
                         not, by what it says or by how long it takes;
    repeated_attempts    consecutive failed attempts are slowed, blocked or
                         answered 429.

Why the status code is not enough. Measured on the labs (2026-10-22): every
case answers 401, and yet both targets say which accounts exist. crAPI answers
`Invalid Credentials` in 102 ms for an account that exists and `Given Email is
not registered!` in 14 ms for one that does not; Forgejo answers `user's
password is invalid` in about 400 ms against `user does not exist` in about
10 ms. The password hash is only verified when there is a password to verify,
which is what makes the answer slow, so the duration is a second oracle
independent of the words. Both are compared here: what the answer says and how long it took.

What the answer says is compared on the **body itself**, with the submitted
account name and password masked, not on the shared fingerprint of
src/core/references.py: that fingerprint keeps the keys of a JSON body and not
their values, and crAPI answers both cases with the same four keys and a
different `message` (measured 2026-10-22, where the fingerprint saw no
difference). Before the two are compared, the three readings of each case must
agree with each other, so that a body carrying a request id or a timestamp is
reported as unstable instead of as a disclosure.

How a failed attempt is built, on any target. The operator already declares
how to log in, as the login resource of their configuration
(`credentials.login_resource`): its method, path, body and authentication,
with the placeholders `{username}` and `{password}`. This test fills those
placeholders with values of its own instead of the role's account, so it needs
no knowledge of the target's login and no parameter: a wrong password for the
operator's own account, and an account name that cannot exist.

What is probed, and what is deliberately not.

    - the repeated attempts all go to an account that **cannot exist**, so no
      account of the operator's can be locked out. What is measured is
      therefore the limit the endpoint applies per caller, not the lockout of
      one account;
    - NIST SP 800-63B-4 section 3.2.2 requires a verifier to limit consecutive
      failed attempts "to no more than 100". The bound here is one attempt
      past that, so that "no limit appeared" is a departure from a published
      rule and not from an opinion;
    - exactly one failed attempt is sent with the operator's real account, for
      the comparison. Three timings of each are taken, the median kept, since
      one reading of a duration is noise.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base.
"""

from __future__ import annotations

import base64
import re
import statistics

import structlog

from src.core.assessment_test import category_of
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
from src.core.models import (
    PLACEHOLDER_PASSWORD,
    PLACEHOLDER_RANDOM,
    PLACEHOLDER_USERNAME,
    Confidence,
    CreateRequest,
    EvidenceRecord,
    Finding,
    Outcome,
    Reference,
    ResourceAuth,
    ResponseCategory,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.references import random_token
from src.core.templating import render
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.auth_base import role_account

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The sub-tests, in the order the page lists them.
_SUB_ENUMERATION: str = "account_enumeration"
_SUB_ATTEMPTS: str = "repeated_attempts"

# How many consecutive failed attempts are sent to the account that cannot
# exist: one past the limit NIST SP 800-63B-4 section 3.2.2 requires a verifier
# to apply ("no more than 100"), so that reaching the end is a departure from a
# published rule. Not a parameter (owner, 2026-10-22): the number comes from
# the standard, not from taste.
_MAX_ATTEMPTS: int = 101

# How many times each of the two failed attempts is repeated for the timing
# comparison, and the factor by which the medians must differ before the
# difference is called an oracle. One reading of a duration is noise; the
# labs differ by 7 times (crAPI) to 40 times (Forgejo).
_TIMING_READINGS: int = 3
_TIMING_FACTOR: float = 3.0

# Below this, two medians are not compared at all: on a fast local target the
# whole answer is a few milliseconds and the ratio of two small numbers says
# nothing.
_TIMING_FLOOR_MS: float = 5.0

# How a deliberate slowdown of repeated attempts is told from the ordinary
# variation of a fast target. The baseline is the median of the first
# _BASELINE_ATTEMPTS answers; an answer counts as slowed only when it is both a
# factor above that baseline and at least _SLOWDOWN_FLOOR_MS in absolute terms,
# and when _SLOW_CONFIRMATIONS answers in a row are. Measured 2026-10-22 on
# crAPI: against a baseline of 4.6 ms a single answer of 30.75 ms was read as a
# limit, which is a PASS claimed where there is no control; a throttle worth
# the name costs a caller far more than that.
_BASELINE_ATTEMPTS: int = 10
_SLOWDOWN_FLOOR_MS: float = 250.0
_SLOW_CONFIRMATIONS: int = 2

# The header that carries HTTP Basic, and its scheme.
_AUTHORIZATION_HEADER: str = "Authorization"
_BASIC_PREFIX: str = "Basic "

# What the submitted name is replaced by before two answers are compared, and
# the runs of digits collapsed with it.
_MASK: str = "<submitted>"
_DIGITS: re.Pattern[str] = re.compile(r"\d+")

# The answer categories that say nothing about the guarantee (rule 1).
_SPOILING: dict[ResponseCategory, str] = {
    ResponseCategory.UPSTREAM_UNAVAILABLE: "UPSTREAM_UNAVAILABLE",
    ResponseCategory.NO_RESPONSE: "NO_RESPONSE",
    ResponseCategory.SERVER_ERROR: "SERVER_ERROR",
}

# Each one read on its source, 2026-10-22 (rule 8). ASVS 6.3.8 is this test
# written out: "valid users cannot be deduced from failed authentication
# challenges, such as by basing on error messages, HTTP response codes, or
# different response times"; 6.3.1 asks for the controls against credential
# stuffing and brute force; NIST SP 800-63B-4 section 3.2.2 sets the limit of
# 100 consecutive failures.
_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API2:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-6.3.8"),
    Reference(standard=Standard.ASVS, id="v5.0.0-6.3.1"),
    Reference(standard=Standard.CWE, id="CWE-204"),
    Reference(standard=Standard.CWE, id="CWE-208"),
    Reference(standard=Standard.NIST_SP, id="800-63B-4", section="3.2.2"),
)


class Test17AuthenticationResistance(BaseTest):
    """
    Test 1.7 -- whether the login endpoint hides accounts and limits guessing.

    The oracle of each sub-test is in the module docstring and on the test
    page.
    """

    info = TestInfo(
        id="1.7",
        name="Authentication Endpoints Resist Guessing",
        priority=1,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-307",
        references=_REFERENCES,
        tags=("authentication", "brute-force"),
        needs=(Need.USER_ACCOUNT,),
        effect=Effect.STRESSES_TARGET,
        sub_tests=(_SUB_ENUMERATION, _SUB_ATTEMPTS),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Compare two failed attempts, then go on failing against an account that cannot exist.

        Args:
            target:  The run's target (the login resource, the role's account).
            context: The run's context (unused: the test builds its own requests).
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._skip() when no login can be built, or
            self._error(exc).
        """
        del context
        try:
            login = _login_request(target)
            if login is None:
                return self._skip(
                    "No login request to probe: credentials.login_resource is not configured, or "
                    "its create request authenticates with a credential rather than with an "
                    "account, so no failed attempt can be built. This test needs the way the "
                    "operator's own configuration logs in."
                )
            account = role_account(target, ROLE_USER_A)
            if account is None:
                return self._skip(
                    "Role user_a has no username and password in the configuration, so the "
                    "attempt for an account that exists cannot be made."
                )
            blocked = self._enumeration(client, store, login, account[0])
            if blocked is None:
                self._attempts(client, store, login, account[0])
            else:
                # The comparison could not be made, and its reason is the same
                # reason the attempts cannot be counted.
                self._record(_SUB_ATTEMPTS, Outcome.NOT_VERIFIABLE, blocked)
            return self._finish()
        except SecurityClientError as exc:
            return self._error(exc)

    # ------------------------------------------------------------------
    # Sub-test 1: does the answer say whether the account exists
    # ------------------------------------------------------------------

    def _enumeration(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        login: CreateRequest,
        username: str,
    ) -> str | None:
        """
        Compare a failed attempt for a real account with one for an impossible account.

        Args:
            client:   The run's HTTP client.
            store:    The evidence store.
            login:    The login request as the configuration declares it.
            username: The operator's own account name.

        Returns:
            None when the comparison was made, so the other sub-test can run;
            otherwise the reason it could not be, which that sub-test records
            as its own.
        """
        unknown = _impossible_account(username)
        known_records: list[EvidenceRecord] = []
        unknown_records: list[EvidenceRecord] = []
        for _ in range(_TIMING_READINGS):
            known_records.append(self._attempt(client, login, username, random_token()))
            unknown_records.append(self._attempt(client, login, unknown, random_token()))
        for record in known_records[:-1] + unknown_records[:-1]:
            self._step(record)
        known, other = known_records[-1], unknown_records[-1]
        for record in (known, other):
            category = category_of(record)
            if category in _SPOILING:
                self._judge(
                    record, store, _SUB_ENUMERATION, Outcome.NOT_VERIFIABLE, _SPOILING[category]
                )
                return _SPOILING[category]
        if category_of(known) == ResponseCategory.SERVED:
            self._judge(
                record=known,
                store=store,
                sub_test=_SUB_ENUMERATION,
                outcome=Outcome.NOT_VERIFIABLE,
                detail="WRONG_PASSWORD_ACCEPTED",
            )
            return "WRONG_PASSWORD_ACCEPTED"
        known_shapes = {_answer(r, username) for r in known_records}
        other_shapes = {_answer(r, unknown) for r in unknown_records}
        if len(known_shapes) != 1 or len(other_shapes) != 1:
            # The same request twice gets two different answers: something in
            # the body changes by itself (a request id, a timestamp), so a
            # difference between the two cases would prove nothing.
            self._judge(known, store, _SUB_ENUMERATION, Outcome.NOT_VERIFIABLE, "ANSWER_NOT_STABLE")
            return "ANSWER_NOT_STABLE"
        if known_shapes != other_shapes:
            self._judge(
                known,
                store,
                _SUB_ENUMERATION,
                Outcome.VIOLATION,
                "EXISTENCE_DISCLOSED_BY_ANSWER",
                Finding(
                    title="The login answer says whether the account exists",
                    detail=(
                        "A failed attempt for the account that exists was answered "
                        f"HTTP {known.response_status_code} and one for an account that cannot "
                        f"exist HTTP {other.response_status_code}, with a body that differs even "
                        "once the submitted name and password are masked, the same way on each "
                        f"of {_TIMING_READINGS} readings. Anyone can therefore sort a list of "
                        "addresses into registered and not, and spend their guessing only on the "
                        "registered ones. Answer the same way in both cases."
                    ),
                    supporting_refs=[other.record_id],
                    confidence=Confidence.CERTAIN,
                    references=[
                        Reference(standard=Standard.CWE, id="CWE-204"),
                        Reference(standard=Standard.ASVS, id="v5.0.0-6.3.8"),
                    ],
                ),
            )
        known_ms = statistics.median(_durations(known_records))
        other_ms = statistics.median(_durations(unknown_records))
        if max(known_ms, other_ms) < _TIMING_FLOOR_MS:
            self._judge(known, store, _SUB_ENUMERATION, Outcome.ENFORCED, "TIMING_TOO_SMALL")
            return None
        if known_ms >= other_ms * _TIMING_FACTOR:
            self._judge(
                known,
                store,
                _SUB_ENUMERATION,
                Outcome.VIOLATION,
                "EXISTENCE_DISCLOSED_BY_TIMING",
                Finding(
                    title="The login takes longer for an account that exists",
                    detail=(
                        "The failed attempt for the account that exists took a median of "
                        f"{known_ms:.0f} ms against {other_ms:.0f} ms for an account that cannot "
                        f"exist, over {_TIMING_READINGS} readings each. The password is only "
                        "verified when there is one to verify, and verifying it is slow by "
                        "design, so the "
                        "duration tells a caller which accounts are registered. Verify a dummy "
                        "hash when the account does not exist, so that both answers cost the "
                        "same."
                    ),
                    supporting_refs=[other.record_id],
                    confidence=Confidence.FIRM,
                    references=[
                        Reference(standard=Standard.CWE, id="CWE-208"),
                        Reference(standard=Standard.ASVS, id="v5.0.0-6.3.8"),
                    ],
                ),
            )
            return None
        self._judge(known, store, _SUB_ENUMERATION, Outcome.ENFORCED, "NO_DISCREPANCY")
        return None

    # ------------------------------------------------------------------
    # Sub-test 2: does guessing get any harder
    # ------------------------------------------------------------------

    def _attempts(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        login: CreateRequest,
        username: str,
    ) -> None:
        """
        Fail repeatedly against an account that cannot exist, up to the standard's limit.

        Args:
            client:   The run's HTTP client.
            store:    The evidence store.
            login:    The login request as the configuration declares it.
            username: The operator's account, for the shape of the impossible one.
        """
        unknown = _impossible_account(username)
        first: EvidenceRecord | None = None
        durations: list[float] = []
        baseline: float | None = None
        slow_in_a_row = 0
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            record = self._attempt(client, login, unknown, random_token())
            if first is None:
                first = record
            category = category_of(record)
            if category == ResponseCategory.RATE_LIMITED:
                self._judge(
                    record,
                    store,
                    _SUB_ATTEMPTS,
                    Outcome.ENFORCED,
                    "ATTEMPTS_LIMITED",
                )
                log.info("test_1_7_rate_limited", attempt=attempt)
                return
            if category in _SPOILING:
                self._judge(
                    record, store, _SUB_ATTEMPTS, Outcome.NOT_VERIFIABLE, _SPOILING[category]
                )
                return
            if first is not record:
                self._step(record)
            durations.append(record.elapsed_ms or 0.0)
            if attempt == _BASELINE_ATTEMPTS:
                baseline = statistics.median(durations)
            if baseline is not None and _is_slow(record, baseline):
                slow_in_a_row += 1
                if slow_in_a_row >= _SLOW_CONFIRMATIONS:
                    self._judge(record, store, _SUB_ATTEMPTS, Outcome.ENFORCED, "ATTEMPTS_SLOWED")
                    log.info(
                        "test_1_7_slowed",
                        attempt=attempt,
                        baseline_ms=round(baseline, 2),
                        elapsed_ms=record.elapsed_ms,
                    )
                    return
            else:
                slow_in_a_row = 0
        if first is None:
            self._record(_SUB_ATTEMPTS, Outcome.NOT_VERIFIABLE, "LOGIN_NOT_ANSWERING")
            return
        self._judge(
            first,
            store,
            _SUB_ATTEMPTS,
            Outcome.VIOLATION,
            "ATTEMPTS_NOT_LIMITED",
            Finding(
                title="Failed authentication attempts are not limited",
                detail=(
                    f"{_MAX_ATTEMPTS} consecutive failed attempts were answered the same way and "
                    "as quickly as the first: no 429, no growing delay, no block. NIST SP "
                    "800-63B-4 section 3.2.2 requires a verifier to limit consecutive failed "
                    "attempts to no more than 100, so guessing passwords against this endpoint "
                    "costs an attacker nothing. The attempts were made against an account that "
                    "cannot exist, so what is measured is the limit applied per caller; whether "
                    "a single account is locked out after repeated failures was not probed, "
                    "because doing so would lock a real account."
                ),
                confidence=Confidence.FIRM,
            ),
        )

    # ------------------------------------------------------------------
    # One attempt
    # ------------------------------------------------------------------

    def _attempt(
        self,
        client: SecurityClient,
        login: CreateRequest,
        username: str,
        password: str,
    ) -> EvidenceRecord:
        """
        Send the configured login request with values of this test's own.

        Args:
            client:   The run's HTTP client.
            login:    The login request as the configuration declares it.
            username: The account name to send.
            password: The password to send (always a wrong one).

        Returns:
            The record of the answer, or of the transport failure.

        Raises:
            SecurityClientError: A failure with no record at all.
        """
        values = {
            PLACEHOLDER_USERNAME: username,
            PLACEHOLDER_PASSWORD: password,
            PLACEHOLDER_RANDOM: random_token(),
        }
        headers: dict[str, str] = {}
        if login.auth is ResourceAuth.BASIC:
            encoded = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
            headers[_AUTHORIZATION_HEADER] = _BASIC_PREFIX + encoded
        try:
            _response, record = client.request(
                login.method,
                str(render(login.path, values)),
                test_id=self.info.id,
                headers=headers or None,
                json=render(login.json_body(), values),
            )
        except SecurityClientError as exc:
            if exc.record is None:
                raise
            return exc.record
        return record


def _impossible_account(username: str) -> str:
    """
    A name of the same shape as the operator's account that cannot exist.

    The shape matters: a target that validates the form of an account name
    would answer a differently shaped name because of its form, not because the
    account is unknown, and the comparison would report a disclosure that is
    not one. An address keeps its domain and changes only the part before the
    `@`, so that a target accepting only its own domain is not refused for
    that reason either. Measured 2026-10-22: the labs use both shapes, `user-a`
    on Forgejo and an address on crAPI.

    Args:
        username: The operator's own account name.

    Returns:
        A name of the same shape, with random characters no account can hold.
    """
    token = random_token()
    local, at, domain = username.partition("@")
    if at and domain:
        return f"{token}{at}{domain}"
    return token


def _login_request(target: TargetContext) -> CreateRequest | None:
    """
    The login request of the configuration, when a failed attempt can be built from it.

    Args:
        target: The run's target (credentials, resources).

    Returns:
        The create request of the login resource, or None when there is none or
        it authenticates with a credential instead of an account.
    """
    name = target.credentials.login_resource
    if name is None:
        return None
    resource = target.resources.get(name)
    if resource is None:
        return None
    if resource.create.auth is ResourceAuth.CREDENTIAL:
        return None
    return resource.create


def _answer(record: EvidenceRecord, submitted: str) -> tuple[int | None, str]:
    """
    What an answer says, for the comparison of the two cases.

    The status and the body, with the submitted account name masked and every
    run of digits collapsed, so that a body echoing what was sent or carrying a
    length or a count does not look like a disclosure. The shared fingerprint
    is not used here: for a JSON body it keeps the keys and not their values,
    and the disclosure is in a value.

    Args:
        record:    The answer.
        submitted: The account name that was sent, to mask.

    Returns:
        (status, the masked body).
    """
    body = record.response_body or ""
    body = body.replace(submitted, _MASK)
    local = submitted.split("@", 1)[0]
    if local:
        body = body.replace(local, _MASK)
    body = _DIGITS.sub("0", body)
    return record.response_status_code, " ".join(body.split())


def _durations(records: list[EvidenceRecord]) -> list[float]:
    """
    The durations of a set of answers, in milliseconds.

    Args:
        records: The records.

    Returns:
        One duration per record that has one; zero for a record without.
    """
    return [record.elapsed_ms or 0.0 for record in records]


def _is_slow(record: EvidenceRecord, baseline: float) -> bool:
    """
    Whether one answer is slow enough to be a deliberate delay.

    A verifier may answer a repeated failure more and more slowly instead of
    refusing it outright, which is a limit just as much as a 429. To tell that
    from the ordinary variation of a fast target, the answer has to be both a
    factor above the baseline and slow in absolute terms.

    Args:
        record:   The answer.
        baseline: The median of the first answers, in milliseconds.

    Returns:
        True when both conditions hold.
    """
    if record.elapsed_ms is None:
        return False
    return record.elapsed_ms >= max(baseline * _TIMING_FACTOR, _SLOWDOWN_FLOOR_MS)
