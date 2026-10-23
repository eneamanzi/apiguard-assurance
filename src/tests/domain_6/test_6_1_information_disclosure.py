"""
src/tests/domain_6/test_6_1_information_disclosure.py

Test 6.1: guarantee "errors and responses disclose no internal information"
(docs/project/test-review/group-i.md). OWASP API8:2023, CWE-209.

A response, in an error or a normal condition, must not leak a stack trace, a
debug field or a version header: these fingerprint the backend and widen the
attack surface. The test provokes errors on documented endpoints and reads a
normal response, with the shared response-inspection helpers
(src/tests/helpers/response_inspector.py):

    no_stack_trace   a provoked error (a type-mismatch path parameter, a
                     malformed JSON body) carries no stack trace, SQL error,
                     file-system path, class name or framework version;
    no_debug_field   a normal response carries no `_debug`/`_sql`/`_internal`
                     field;
    no_leaky_header  no `X-Powered-By`, no versioned `Server`, no internal
                     `X-*` header.

Authentication-error enumeration is test 1.7; a debug endpoint that exposes
secrets is test 6.4; this test is about what an ordinary response leaks
(rule 10). GREY_BOX (a credential to reach authenticated endpoints), READ_ONLY.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import json as jsonlib

import httpx
import structlog

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
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.auth import auth_parts
from src.tests.helpers.path_resolver import resolve_path_with_seed
from src.tests.helpers.response_inspector import (
    contains_stack_trace,
    extract_debug_fields,
    find_leaky_headers,
)
from src.tests.helpers.sampling import sample_by_service

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB_TRACE: str = "no_stack_trace"
_SUB_DEBUG: str = "no_debug_field"
_SUB_HEADER: str = "no_leaky_header"

_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})
_WRITE_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH"})

# A body that is not valid JSON, to provoke a parser error.
_MALFORMED_JSON: bytes = b'{"apiguard": "unterminated'

_REFERENCES: tuple[Reference, ...] = (
    # Read on the ASVS v5.0.0 source 2026-10-23: 13.4.2 (no internal detail in
    # error responses), 16.5.1 (a generic message, detail only in the logs).
    Reference(standard=Standard.OWASP_API_TOP10, id="API8:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-13.4.2"),
    Reference(standard=Standard.ASVS, id="v5.0.0-13.4.6"),
    Reference(standard=Standard.ASVS, id="v5.0.0-16.5.1"),
)


class Test61InformationDisclosure(BaseTest):
    """
    Test 6.1 -- whether a response leaks a stack trace, a debug field or a header.

    The oracle of each sub-test is in the module docstring and on the test page.
    """

    info = TestInfo(
        id="6.1",
        name="Error and Information Disclosure",
        priority=2,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-209",
        references=_REFERENCES,
        tags=("information-disclosure", "error-handling"),
        needs=(Need.USER_ACCOUNT,),
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB_TRACE, _SUB_DEBUG, _SUB_HEADER),
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
        last: EvidenceRecord | None = None
        for method, path, _template in sample:
            response, record = _send(client, method, path, headers, params)
            if response is None or record is None:
                continue
            last = record
            body = _json_object(response)
            fields = extract_debug_fields(body) if body is not None else []
            if fields:
                debug_hits[path] = fields
            leaky = find_leaky_headers(dict(response.headers))
            if leaky:
                header_hits[path] = leaky
        self._judge_sampled(
            store,
            _SUB_DEBUG,
            debug_hits,
            last,
            "DEBUG_FIELD",
            "Response carries a debug field",
            "a debug or internal field",
        )
        self._judge_sampled(
            store,
            _SUB_HEADER,
            header_hits,
            last,
            "LEAKY_HEADER",
            "Response carries a leaky header",
            "a leaky header (a versioned `Server`, `X-Powered-By`, an internal `X-*`)",
        )

    def _judge_sampled(
        self,
        store: EvidenceStore,
        sub_test: str,
        hits: dict[str, list[str]],
        record: EvidenceRecord | None,
        detail: str,
        title: str,
        what: str,
    ) -> None:
        """ENFORCED when no sampled endpoint leaked; VIOLATION naming where it did."""
        if not hits:
            self._record(sub_test, Outcome.ENFORCED, "CLEAN")
            return
        first_path = next(iter(hits))
        names = ", ".join(sorted({n for values in hits.values() for n in values}))
        finding = Finding(
            title=f"{title}: {names}",
            detail=(
                f"{len(hits)} sampled endpoint(s) (e.g. {first_path}) return {what}: {names}. This "
                "fingerprints the backend or exposes its internals (OWASP API8:2023, CWE-209). "
                "Remove it from the production response, or strip it at the gateway."
            ),
            confidence=Confidence.CERTAIN if sub_test == _SUB_HEADER else Confidence.FIRM,
        )
        if record is not None:
            self._judge(record, store, sub_test, Outcome.VIOLATION, detail, finding)
        else:
            self._record(sub_test, Outcome.VIOLATION, detail, finding)

    def _check_error(
        self,
        target: TargetContext,
        client: SecurityClient,
        store: EvidenceStore,
        headers: dict[str, str],
        params: dict[str, str],
    ) -> None:
        """Provoke an error (malformed JSON to a write endpoint) and judge the body."""
        surface = target.attack_surface
        if surface is None:
            self._record(_SUB_TRACE, Outcome.NOT_APPLICABLE, "NO_ENDPOINT")
            return
        probe = self._error_probe(target)
        if probe is None:
            self._record(_SUB_TRACE, Outcome.NOT_APPLICABLE, "NO_ERROR_PROBE")
            return
        method, path, content = probe
        response, record = _send(client, method, path, headers, params, content=content)
        if response is None or record is None:
            self._record(_SUB_TRACE, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return
        markers = contains_stack_trace(response.text)
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
                        f"internal-detail markers {markers[:5]}: a stack trace, SQL error, file "
                        "path, class name or framework version. This fingerprints the backend and "
                        "its CVEs (OWASP API8:2023, CWE-209, ASVS v5.0.0-13.4.2). Return a generic "
                        "message to the client and keep the detail in the server logs."
                    ),
                    confidence=Confidence.FIRM,
                ),
            )
            return
        self._judge(record, store, _SUB_TRACE, Outcome.ENFORCED, "NO_STACK_TRACE")

    def _error_probe(self, target: TargetContext) -> tuple[str, str, bytes] | None:
        """A request shaped to provoke a backend error: malformed JSON to a write endpoint."""
        surface = target.attack_surface
        if surface is None:
            return None
        writes = [e for e in surface.endpoints if e.method.upper() in _WRITE_METHODS]
        if not writes:
            return None
        shortest = min(writes, key=lambda e: (len(e.path), e.path, e.method))
        path = resolve_path_with_seed(shortest.path, target.path_seed)
        return shortest.method.upper(), path, _MALFORMED_JSON


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


def _json_object(response: httpx.Response) -> dict[str, object] | None:
    """The response's JSON object, or None when it is not a JSON object."""
    try:
        body = response.json()
    except (ValueError, jsonlib.JSONDecodeError):
        return None
    return body if isinstance(body, dict) else None
