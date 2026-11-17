"""
src/tests/domain_6/test_6_1_information_disclosure.py

Test 6.1: guarantee "errors and responses disclose no internal information"
(OWASP API8:2023, CWE-209).

    no_stack_trace   a provoked error (a malformed JSON body to a documented
                     write, up to _MAX_ERROR_PROBES of them until one is
                     parsed) carries no stack trace, file-system path or
                     framework version (src/tests/data/inspector_patterns.py);
    no_debug_field   the served JSON of a sample of documented reads carries
                     no debug-named field, at any depth;
    no_leaky_header  no `X-Powered-By`, `X-AspNet-Version`,
                     `X-AspNetMvc-Version`, and no `Server` or `Via` naming a
                     version.

The oracle: info.oracle, generated on the test page. Authentication-error
enumeration is test 1.7; a debug endpoint exposing secrets is test 6.4.
GREY_BOX (a credential to reach authenticated endpoints), CHANGES_DATA: the
error probes are authenticated writes with an unparseable body, to writes
without path parameters first, otherwise to a random sibling of the
parametric path, never to one of the operator's resources.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import json as jsonlib

import httpx
import structlog

from src.core.assessment_test import category_of
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
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
from src.core.references import random_sibling_path
from src.core.test_metadata import DecisiveAnswer, Effect, Need, OracleCase, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.auth import auth_parts
from src.tests.helpers.response_inspector import (
    contains_stack_trace,
    extract_debug_fields,
    find_leaky_headers,
    has_json_object,
    versioned_value,
)
from src.tests.helpers.sampling import sample_by_service

log: structlog.BoundLogger = structlog.get_logger(__name__)
_SUB_TRACE: str = "no_stack_trace"
_SUB_DEBUG: str = "no_debug_field"
_SUB_HEADER: str = "no_leaky_header"

_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})
# How many documented writes are tried until one parses the malformed body.
_MAX_ERROR_PROBES: int = 5
_WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH"})

# The statuses that show the malformed body reached the parser and was rejected
# there (RFC 9110: 400 Bad Request, 422 Unprocessable Content); a server error
# (5xx other than unavailable) is a provoked error too.
_PARSE_ERROR_STATUS: frozenset[int] = frozenset({400, 422})
_JSON_CONTENT_TYPE: str = "application/json"

# A body that is not valid JSON, to provoke a parser error.
_MALFORMED_JSON: bytes = b'{"apiguard": "unterminated'

# ASVS v5.0.0 (read 2026-11-16): 16.5.1 a generic message on an error, no stack
# trace; 13.4.2 debug modes disabled; 13.4.6 no detailed version information.
# Each finding cites its own (until 2026-11-16 the stack trace cited 13.4.2).
_API8 = Reference(standard=Standard.OWASP_API_TOP10, id="API8:2023")
_CWE209 = Reference(standard=Standard.CWE, id="CWE-209")
_REFS_TRACE = (_API8, _CWE209, Reference(standard=Standard.ASVS, id="v5.0.0-16.5.1"))
_REFS_DEBUG = (_API8, _CWE209, Reference(standard=Standard.ASVS, id="v5.0.0-13.4.2"))
_REFS_HEADER = (_API8, Reference(standard=Standard.ASVS, id="v5.0.0-13.4.6"))
_REFERENCES: tuple[Reference, ...] = (
    _API8,
    Reference(standard=Standard.ASVS, id="v5.0.0-13.4.2"),
    Reference(standard=Standard.ASVS, id="v5.0.0-13.4.6"),
    Reference(standard=Standard.ASVS, id="v5.0.0-16.5.1"),
)

_ORACLE: tuple[OracleCase, ...] = (
    OracleCase(
        sub_test=_SUB_TRACE,
        when="the answer to a malformed JSON body carries a stack trace, a file-system path or a "
        "framework version (the request's own path left out)",
        outcome=Outcome.VIOLATION,
        detail="STACK_TRACE",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_TRACE,
        when="the malformed body is rejected by the parser (`400`, `422`) or causes a server "
        "error, with no such marker",
        outcome=Outcome.ENFORCED,
        detail="NO_STACK_TRACE",
    ),
    OracleCase(
        sub_test=_SUB_TRACE,
        when=f"none of up to {_MAX_ERROR_PROBES} writes parsed the body (refused before "
        "parsing, `404`, `415`, accepted): no error was provoked",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="ERROR_NOT_PROVOKED",
    ),
    OracleCase(
        sub_test=_SUB_TRACE,
        when="the specification documents no write (`POST`, `PUT`, `PATCH`)",
        outcome=Outcome.NOT_APPLICABLE,
        detail="NO_ERROR_PROBE",
    ),
    OracleCase(
        sub_test=_SUB_DEBUG,
        when="a served JSON body has a debug-named field at any depth (`_debug`, `_sql...`, "
        "`debugInfo`, `stackTrace`, `shardKey`, ...)",
        outcome=Outcome.VIOLATION,
        detail="DEBUG_FIELD",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_DEBUG,
        when="the served JSON bodies looked at carry no debug-named field",
        outcome=Outcome.ENFORCED,
        detail="CLEAN",
    ),
    OracleCase(
        sub_test=_SUB_DEBUG,
        when="no sampled read was served a JSON object (or an array of objects): no field was "
        "looked at",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="NO_JSON_OBJECT",
    ),
    OracleCase(
        sub_test=_SUB_HEADER,
        when="a sampled answer carries a leaky header naming a version",
        outcome=Outcome.VIOLATION,
        detail="LEAKY_HEADER",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_HEADER,
        when="a sampled answer carries `X-Powered-By` or `X-AspNet*` without a version",
        outcome=Outcome.VIOLATION,
        detail="LEAKY_HEADER",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_HEADER,
        when="no sampled answer carries a leaky header",
        outcome=Outcome.ENFORCED,
        detail="CLEAN",
    ),
    *(
        OracleCase(
            sub_test=sub_test,
            when="the specification documents no `GET` or `HEAD`",
            outcome=Outcome.NOT_APPLICABLE,
            detail="NO_READ_ENDPOINT",
        )
        for sub_test in (_SUB_DEBUG, _SUB_HEADER)
    ),
)


class Test61InformationDisclosure(BaseTest):
    """Test 6.1 -- whether a response leaks a stack trace, a debug field or a header."""

    info = TestInfo(
        id="6.1",
        name="Error and Information Disclosure",
        priority=2,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-209",
        references=_REFERENCES,
        tags=("information-disclosure", "error-handling"),
        needs=(Need.USER_ACCOUNT,),
        # CHANGES_DATA, not READ_ONLY: the error probe sends a malformed body to
        # the shortest documented write operation. No parser can build an object
        # from unterminated JSON, so nothing is created, but on a target whose
        # shortest write is a PUT on a real object a server tolerating the body
        # as empty would replace it. The declaration an operator reads before
        # pointing the tool at production says what the test sends, not what a
        # well-behaved server does with it.
        effect=Effect.CHANGES_DATA,
        sub_tests=(_SUB_TRACE, _SUB_DEBUG, _SUB_HEADER),
        oracle=_ORACLE,
        decisive_answers=(
            DecisiveAnswer(
                category=ResponseCategory.SERVER_ERROR,
                reason=(
                    "a `500` is the error this test provokes, and its body is where a stack "
                    "trace or a debug field shows: it is examined."
                ),
            ),
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
        Read a normal response and a provoked error, judging what they leak.

        Args:
            target:  The run's target (surface, path seed).
            context: The run's context (user_a credential).
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._requires_attack_surface(...), or self._error.
        """
        try:
            missing = self._requires_attack_surface(target)
            if missing is not None:
                return missing
            parts = auth_parts(target, context, ROLE_USER_A)
            headers = dict(parts.headers)
            params = dict(parts.params)
            self._check_normal(target, client, store, headers, params)
            self._check_error(target, client, store, headers, params)
            return self._finish()
        except AuthenticationSetupError as exc:
            return self._error(exc)
        except SecurityClientError as exc:
            return self._error(exc)

    def _check_normal(
        self,
        target: TargetContext,
        client: SecurityClient,
        store: EvidenceStore,
        headers: dict[str, str],
        params: dict[str, str],
    ) -> None:
        """Across a sample of GETs: judge debug fields (body) and leaky headers."""
        sample = sample_by_service(target, _SAFE_METHODS)
        if not sample:
            self._record(_SUB_DEBUG, Outcome.NOT_APPLICABLE, "NO_READ_ENDPOINT")
            self._record(_SUB_HEADER, Outcome.NOT_APPLICABLE, "NO_READ_ENDPOINT")
            return
        debug_hits: dict[str, list[str]] = {}
        header_hits: dict[str, list[str]] = {}
        # The operations whose leaky headers name a version (CERTAIN).
        versioned: set[str] = set()
        # The operations whose served JSON had fields to look at.
        inspected: set[str] = set()
        # Each sampled response is kept by path: a finding names one endpoint, and
        # its proof must be that endpoint's response (rule 6).
        records: dict[str, EvidenceRecord] = {}
        # Why the answers left out said nothing, recorded when none is left.
        silent: str | None = None
        for method, path, _template in sample:
            response, record = _send(client, method, path, headers, params)
            if response is None or record is None:
                silent = silent or ResponseCategory.NO_RESPONSE.value
                continue
            uninformative = self._uninformative(record, _SUB_DEBUG)
            if uninformative is not None:
                # An unavailable or throttled backend's answer says nothing
                # about what the API exposes (a 500 is examined: decisive).
                self._step(record)
                silent = silent or uninformative
                continue
            # Keyed by method and path: the sampler may take GET and HEAD of one
            # path, and a HEAD answer (no body) must not stand as a GET's proof.
            operation = f"{method} {path}"
            records[operation] = record
            body = _json_body(response)
            served = category_of(record) == ResponseCategory.SERVED
            if served and has_json_object(body):
                # Only a served body is the normal response the oracle is
                # about; a HEAD or a refusal has none (until 2026-11-16 they
                # counted as CLEAN, and so did an array, never looked into).
                inspected.add(operation)
                fields = extract_debug_fields(body)
                if fields:
                    debug_hits[operation] = fields
            leaky = find_leaky_headers(dict(response.headers))
            if leaky:
                header_hits[operation] = leaky
                if any(versioned_value(response.headers.get(name, "")) for name in leaky):
                    versioned.add(operation)
        if records and not inspected:
            self._record(_SUB_DEBUG, Outcome.NOT_VERIFIABLE, "NO_JSON_OBJECT")
        elif self._sampled_ok(_SUB_DEBUG, debug_hits, records, silent):
            names = _names(debug_hits)
            operation = next(iter(debug_hits))
            finding = Finding(
                title=f"Response carries a debug field: {names}",
                detail=_leak_detail(debug_hits, operation, "a debug or internal field", names),
                confidence=Confidence.FIRM,
                references=list(_REFS_DEBUG),
            )
            self._judge(
                records[operation], store, _SUB_DEBUG, Outcome.VIOLATION, "DEBUG_FIELD", finding
            )
        if self._sampled_ok(_SUB_HEADER, header_hits, records, silent):
            names = _names(header_hits)
            operation = next(iter(header_hits))
            finding = Finding(
                title=f"Response carries a leaky header: {names}",
                detail=_leak_detail(
                    header_hits,
                    operation,
                    "a leaky header (`Server` or `Via` naming a version, `X-Powered-By`, "
                    "`X-AspNet-Version`, `X-AspNetMvc-Version`)",
                    names,
                ),
                confidence=Confidence.CERTAIN if versioned else Confidence.FIRM,
                references=list(_REFS_HEADER),
            )
            self._judge(
                records[operation], store, _SUB_HEADER, Outcome.VIOLATION, "LEAKY_HEADER", finding
            )

    def _sampled_ok(
        self,
        sub_test: str,
        hits: dict[str, list[str]],
        records: dict[str, EvidenceRecord],
        silent: str | None,
    ) -> bool:
        """
        Record the sub-test when nothing leaked or nothing answered; True when a finding is due.

        With no usable answer nothing was looked at: the reason of the answers
        left out (until 2026-11-05 this was CLEAN).
        """
        if not records:
            self._record(sub_test, Outcome.NOT_VERIFIABLE, silent or "NO_RESPONSE")
            return False
        if not hits:
            self._record(sub_test, Outcome.ENFORCED, "CLEAN")
            return False
        return True

    def _check_error(
        self,
        target: TargetContext,
        client: SecurityClient,
        store: EvidenceStore,
        headers: dict[str, str],
        params: dict[str, str],
    ) -> None:
        """
        Provoke an error (malformed JSON to documented writes) and judge the body.

        The writes are tried in turn until one parses the body (a `400`,
        `422` or server error): a write refused before parsing (Forgejo's
        token scope, `403`) provokes nothing (until 2026-11-16 only the
        first write was tried, and the Forgejo labs never had an error).
        """
        probes = self._error_probes(target)
        if not probes:
            self._record(_SUB_TRACE, Outcome.NOT_APPLICABLE, "NO_ERROR_PROBE")
            return
        # Declared as JSON so that the server hands it to its JSON parser: without
        # the header crAPI answered 415 and Forgejo never parsed it (2026-11-03).
        probe_headers = {**headers, "Content-Type": _JSON_CONTENT_TYPE}
        last: EvidenceRecord | None = None
        for method, path in probes:
            response, record = _send(
                client, method, path, probe_headers, params, content=_MALFORMED_JSON
            )
            if record is None:
                continue
            if last is not None:
                self._step(last)
            last = record
            text = response.text if response is not None else ""
            markers = contains_stack_trace(_without_request(text, record.request_url, path))
            if markers:
                self._judge(
                    record,
                    store,
                    _SUB_TRACE,
                    Outcome.VIOLATION,
                    "STACK_TRACE",
                    Finding(
                        title=f"Error response leaks internal detail: {method} {path}",
                        detail=(
                            f"A provoked error at {method} {path} returned a body that matches "
                            f"internal-detail markers {markers[:5]}: a stack trace, SQL error, "
                            "file path, class name or framework version. This fingerprints the "
                            "backend and its CVEs (OWASP API8:2023, CWE-209, ASVS "
                            "v5.0.0-16.5.1). Return a generic message to the client and keep the "
                            "detail in the server logs."
                        ),
                        confidence=Confidence.FIRM,
                        references=list(_REFS_TRACE),
                    ),
                )
                return
            uninformative = self._uninformative(record, _SUB_TRACE)
            if uninformative is not None:
                # Unavailable or throttled: no error was provoked, and the
                # next write would meet the same.
                self._judge(record, store, _SUB_TRACE, Outcome.NOT_VERIFIABLE, uninformative)
                return
            status = record.response_status_code
            if (
                status in _PARSE_ERROR_STATUS
                or category_of(record) == ResponseCategory.SERVER_ERROR
            ):
                self._judge(record, store, _SUB_TRACE, Outcome.ENFORCED, "NO_STACK_TRACE")
                return
        if last is None:
            self._record(_SUB_TRACE, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return
        # Refused before parsing (401, 403, 404, 415) or even accepted, every
        # time: a clean body proves nothing.
        self._judge(last, store, _SUB_TRACE, Outcome.NOT_VERIFIABLE, "ERROR_NOT_PROVOKED")

    def _error_probes(self, target: TargetContext) -> list[tuple[str, str]]:
        """
        The writes to send the malformed body to, at most _MAX_ERROR_PROBES.

        Writes without path parameters first: an unparseable body sent there
        can modify no existing object. A parametric one is addressed to a
        random sibling, never to the operator's resource from the seed.
        """
        surface = target.attack_surface
        if surface is None:
            return []
        writes = sorted(
            (e for e in surface.endpoints if e.method.upper() in _WRITE_METHODS),
            key=lambda e: ("{" in e.path, len(e.path), e.path, e.method),
        )
        return [
            (
                e.method.upper(),
                random_sibling_path(e.path, e.parameters) if "{" in e.path else e.path,
            )
            for e in writes[:_MAX_ERROR_PROBES]
        ]


def _send(
    client: SecurityClient,
    method: str,
    path: str,
    headers: dict[str, str],
    params: dict[str, str],
    content: bytes | None = None,
) -> tuple[httpx.Response | None, EvidenceRecord | None]:
    """One request; (response, record), or (None, record) on a transport failure."""
    try:
        response, record = client.request(
            method,
            path,
            test_id="6.1",
            headers=headers or None,
            params=params or None,
            content=content,
        )
    except SecurityClientError as exc:
        return None, exc.record
    return response, record


def _json_body(response: httpx.Response) -> object:
    """The response's parsed JSON, or None when it is not JSON."""
    try:
        return response.json()
    except (ValueError, jsonlib.JSONDecodeError):
        return None


def _without_request(text: str, url: str, path: str) -> str:
    """
    A body without the request's own URL and path.

    An error body that echoes the request (Spring's "path", RFC 9457's
    "instance") would otherwise match a file-system path when the API's own
    path starts with /app/, /srv/, ...
    """
    return text.replace(url, "").replace(url.split("?")[0], "").replace(path, "")


def _names(hits: dict[str, list[str]]) -> str:
    """Every name found, once, sorted."""
    return ", ".join(sorted({name for values in hits.values() for name in values}))


def _leak_detail(hits: dict[str, list[str]], operation: str, what: str, names: str) -> str:
    """The detail of a leak finding."""
    return (
        f"{len(hits)} sampled endpoint(s) (e.g. {operation}) return {what}: {names}. This "
        "fingerprints the backend or exposes its internals (OWASP API8:2023, CWE-209). Remove it "
        "from the production response, or strip it at the gateway."
    )
