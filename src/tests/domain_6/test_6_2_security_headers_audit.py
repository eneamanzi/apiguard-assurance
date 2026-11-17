"""
src/tests/domain_6/test_6_2_security_headers_audit.py

Test 6.2: guarantee "the defensive security headers are set" (OWASP API8:2023,
ASVS v5.0.0 V3.4).

On one documented read per service prefix (src/tests/helpers/sampling.py):
`X-Content-Type-Options: nosniff` (content_type_options), a CSP
`frame-ancestors` not allowing any site or else `X-Frame-Options`
(framing_protection), and the answer to an arbitrary `Origin` (cors_not_wildcard).
A header holds only when present on every sampled answer; present on some and
absent on others is an inconsistency. A header sent twice is read as browsers
read it (httpx joins the values with ", "). The oracle: info.oracle, generated
on the test page. HSTS is test 1.5. BLACK_BOX, READ_ONLY, no primary CWE (CWE-16
is a prohibited mapping category).

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import httpx
import structlog

from src.core.assessment_test import category_of
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
from src.core.test_metadata import Effect, OracleCase, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.sampling import sample_by_service

log: structlog.BoundLogger = structlog.get_logger(__name__)

_SUB_CTO: str = "content_type_options"
_SUB_FRAME: str = "framing_protection"
_SUB_CORS: str = "cors_not_wildcard"

_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})

# The arbitrary origin sent to probe CORS: a value the server must not reflect.
_PROBE_ORIGIN: str = "https://apiguard-cors-probe.example.net"

_REFERENCES: tuple[Reference, ...] = (
    # Read on the ASVS v5.0.0 source 2026-11-05: 3.4.2 (Access-Control-Allow-Origin
    # fixed or validated against an allowlist), 3.4.4 (X-Content-Type-Options:
    # nosniff), 3.4.6 (CSP frame-ancestors). 3.4.3 (a script CSP with object-src
    # and base-uri) was cited until then, and this test does not check it.
    Reference(standard=Standard.OWASP_API_TOP10, id="API8:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-3.4.2"),
    Reference(standard=Standard.ASVS, id="v5.0.0-3.4.4"),
    Reference(standard=Standard.ASVS, id="v5.0.0-3.4.6"),
)


def _header_cases(sub_test: str, header: str) -> tuple[OracleCase, ...]:
    """The cases of a header check, the same for both headers."""
    return (
        OracleCase(
            sub_test=sub_test,
            when=f"{header} on every usable sampled answer",
            outcome=Outcome.ENFORCED,
            detail="PRESENT",
        ),
        OracleCase(
            sub_test=sub_test,
            when=f"{header} absent from every usable sampled answer",
            outcome=Outcome.VIOLATION,
            detail="MISSING",
            confidence=Confidence.CERTAIN,
        ),
        OracleCase(
            sub_test=sub_test,
            when=f"{header} on some sampled answers and absent from others",
            outcome=Outcome.VIOLATION,
            detail="INCONSISTENT",
            confidence=Confidence.CERTAIN,
        ),
    )


_ORACLE: tuple[OracleCase, ...] = (
    *_header_cases(_SUB_CTO, "`X-Content-Type-Options: nosniff` (its first value)"),
    *_header_cases(
        _SUB_FRAME,
        "a CSP `frame-ancestors` not allowing any site, or else `X-Frame-Options` with "
        "one value, `DENY` or `SAMEORIGIN`,",
    ),
    OracleCase(
        sub_test=_SUB_FRAME,
        when="framing is refused on every sampled answer, by `X-Frame-Options` alone on some "
        "(ASVS v5.0.0-3.4.6 asks for `frame-ancestors`: a note)",
        outcome=Outcome.ENFORCED,
        detail="XFO_ONLY",
    ),
    OracleCase(
        sub_test=_SUB_CORS,
        when="an answer to the arbitrary `Origin` reflects it with "
        "`Access-Control-Allow-Credentials: true`",
        outcome=Outcome.VIOLATION,
        detail="CORS_ORIGIN_REFLECTED",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_CORS,
        when="an answer carries `Access-Control-Allow-Origin: *` with credentials (browsers "
        "refuse it)",
        outcome=Outcome.VIOLATION,
        detail="CORS_WILDCARD_CREDENTIALS",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_CORS,
        when="some answers grant CORS, none to the arbitrary origin with credentials",
        outcome=Outcome.ENFORCED,
        detail="CORS_BOUNDED",
    ),
    OracleCase(
        sub_test=_SUB_CORS,
        when="no served answer to the arbitrary `Origin` grants it",
        outcome=Outcome.ENFORCED,
        detail="ORIGIN_NOT_ALLOWED",
    ),
    OracleCase(
        sub_test=_SUB_CORS,
        when="no answer to the arbitrary `Origin` was served, and the refusals (`401`, `403`, "
        "...) grant nothing: the policy of a served answer is not seen",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="PROBE_NOT_SERVED",
    ),
)


class Test62SecurityHeadersAudit(BaseTest):
    """Test 6.2 -- whether the defensive security headers are present and consistent."""

    info = TestInfo(
        id="6.2",
        name="Security Headers Audit",
        priority=3,
        strategy=TestStrategy.BLACK_BOX,
        references=_REFERENCES,
        cwe="CWE-1021",
        tags=("security-headers", "cors"),
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB_CTO, _SUB_FRAME, _SUB_CORS),
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
        Sample one endpoint per service and judge the headers across the sample.

        Args:
            target:  The run's target (surface, derived facts, path seed).
            context: Unused (no credential).
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._requires_attack_surface(...), self._skip(...),
            or self._error(exc).
        """
        del context
        try:
            missing = self._requires_attack_surface(target)
            if missing is not None:
                return missing
            sample = sample_by_service(target, _SAFE_METHODS)
            if not sample:
                return self._skip("No documented GET endpoint to read the security headers from.")
            cto: dict[str, bool] = {}
            frame: dict[str, bool] = {}
            # The sampled paths framed only by X-Frame-Options.
            xfo_only: list[str] = []
            cors: dict[str, str] = {}
            # Each sampled response, and each answer to the cross-origin probe, is
            # kept by path: a finding names one endpoint, and its proof must be
            # that endpoint's response (rule 6), not the last one sampled.
            records: dict[str, EvidenceRecord] = {}
            cors_records: dict[str, EvidenceRecord] = {}
            # Why the answers left out said nothing, recorded when none is left.
            silent: str | None = None
            for _method, path, _template in sample:
                response, record = _send(client, path, {})
                if response is None or record is None:
                    silent = silent or ResponseCategory.NO_RESPONSE.value
                    continue
                uninformative = self._uninformative(record, _SUB_CTO)
                if uninformative is not None:
                    silent = silent or uninformative
                    continue
                records[path] = record
                headers = {k.lower(): v for k, v in response.headers.items()}
                cto[path] = _first_value(headers.get("x-content-type-options", "")) == "nosniff"
                frame[path] = _framing_ok(headers)
                if (
                    frame[path]
                    and _frame_ancestors(headers.get("content-security-policy", "")) is None
                ):
                    xfo_only.append(path)
                cors[path], cors_record = self._cors_ok(client, path)
                if cors_record is not None:
                    cors_records[path] = cors_record
            notes: list[InfoNote] = []
            self._judge_cto(store, cto, records, silent)
            self._judge_frame(store, frame, records, silent, xfo_only, notes)
            self._judge_cors(store, cors, cors_records, silent)
            return self._finish(notes=notes, message=f"{len(sample)} endpoint(s) sampled.")
        except SecurityClientError as exc:
            return self._error(exc)

    def _cors_ok(self, client: SecurityClient, path: str) -> tuple[str, EvidenceRecord | None]:
        """
        What the answer to an arbitrary Origin says about CORS at a path, and the answer.

        One of _CORS_REFLECTED (it reflects the origin together with
        Access-Control-Allow-Credentials: true), _CORS_WILDCARD ('*' with
        credentials), _CORS_BOUNDED (a CORS grant that is
        not unsafe), _CORS_NO_GRANT (no Access-Control-Allow-Origin at all: a browser
        refuses that origin the response) or _CORS_UNKNOWN (no answer, or one from a
        target unavailable, failing or throttling, which says nothing about CORS).
        """
        response, record = _send(client, path, {"Origin": _PROBE_ORIGIN})
        if response is None or record is None or self._uninformative(record, _SUB_CORS):
            return _CORS_UNKNOWN, record
        headers = {k.lower(): v for k, v in response.headers.items()}
        acao = headers.get("access-control-allow-origin", "").strip()
        acac = headers.get("access-control-allow-credentials", "").strip().lower()
        if not acao:
            # A refusal without CORS headers says nothing of the served
            # answer's policy (an application may add them only after its
            # authentication): until 2026-11-16 it counted as not allowed.
            served = category_of(record) == ResponseCategory.SERVED
            return (_CORS_NO_GRANT if served else _CORS_NOT_SERVED), record
        if acac == "true" and acao == _PROBE_ORIGIN:
            return _CORS_REFLECTED, record
        if acac == "true" and acao == "*":
            return _CORS_WILDCARD, record
        return _CORS_BOUNDED, record

    def _cors_silence(self, record: EvidenceRecord | None) -> str | None:
        """Why an answer to the cross-origin probe says nothing about CORS (_uninformative)."""
        return self._uninformative(record, _SUB_CORS)

    def _judge_cto(
        self,
        store: EvidenceStore,
        results: dict[str, bool],
        records: dict[str, EvidenceRecord],
        silent: str | None,
    ) -> None:
        """X-Content-Type-Options: nosniff on every sampled answer (ASVS v5.0.0-3.4.4)."""
        absent = self._absent(_SUB_CTO, results, silent)
        if not absent:
            return
        partial = len(absent) < len(results)
        finding = Finding(
            title=(
                "X-Content-Type-Options: nosniff inconsistent across services"
                if partial
                else "X-Content-Type-Options: nosniff missing"
            ),
            detail=f"X-Content-Type-Options: nosniff is {_where(absent, results)}. "
            "Set it at the gateway (ASVS v5.0.0-3.4.4).",
            confidence=Confidence.CERTAIN,
        )
        detail = "INCONSISTENT" if partial else "MISSING"
        self._violation(store, _SUB_CTO, detail, finding, records.get(absent[0]))

    def _judge_frame(
        self,
        store: EvidenceStore,
        results: dict[str, bool],
        records: dict[str, EvidenceRecord],
        silent: str | None,
        xfo_only: list[str],
        notes: list[InfoNote],
    ) -> None:
        """Framing refused on every sampled answer (ASVS v5.0.0-3.4.6)."""
        absent = self._absent(_SUB_FRAME, results, silent, enforced=not xfo_only)
        if absent is None:
            return
        if not absent:
            self._record(_SUB_FRAME, Outcome.ENFORCED, "XFO_ONLY")
            notes.append(
                InfoNote(
                    title="Framing refused by X-Frame-Options only",
                    detail=(
                        f"{len(xfo_only)} sampled endpoint(s) (e.g. {xfo_only[0]}) refuse framing "
                        "with X-Frame-Options and no CSP frame-ancestors. Browsers honour it, but "
                        "ASVS v5.0.0-3.4.6 asks for frame-ancestors and calls X-Frame-Options "
                        "obsolete. Add Content-Security-Policy: frame-ancestors 'self'."
                    ),
                )
            )
            return
        partial = len(absent) < len(results)
        finding = Finding(
            title=(
                "Clickjacking protection inconsistent across services"
                if partial
                else "Clickjacking protection missing"
            ),
            detail=f"Clickjacking protection (CSP frame-ancestors or X-Frame-Options) is "
            f"{_where(absent, results)}. Set Content-Security-Policy: frame-ancestors 'self' at "
            "the gateway (ASVS v5.0.0-3.4.6).",
            confidence=Confidence.CERTAIN,
        )
        detail = "INCONSISTENT" if partial else "MISSING"
        self._violation(store, _SUB_FRAME, detail, finding, records.get(absent[0]))

    def _absent(
        self,
        sub_test: str,
        results: dict[str, bool],
        silent: str | None,
        *,
        enforced: bool = True,
    ) -> list[str] | None:
        """
        The sampled paths without the header, recording the sub-test when nothing is due.

        No usable answer: NOT_VERIFIABLE with the reason of those left out.
        Present everywhere: ENFORCED/PRESENT, unless `enforced` is False (the
        caller records its own). Returns None when recorded here.
        """
        if not results:
            self._record(sub_test, Outcome.NOT_VERIFIABLE, silent or "NO_RESPONSE")
            return None
        absent = [p for p, ok in results.items() if not ok]
        if not absent and enforced:
            self._record(sub_test, Outcome.ENFORCED, "PRESENT")
            return None
        return absent

    def _judge_cors(
        self,
        store: EvidenceStore,
        results: dict[str, str],
        records: dict[str, EvidenceRecord],
        silent: str | None,
    ) -> None:
        """VIOLATION if any sampled endpoint has unsafe CORS; N/A if none use CORS."""
        if not results:
            self._record(_SUB_CORS, Outcome.NOT_VERIFIABLE, silent or "NO_RESPONSE")
            return
        reflected = [p for p, state in results.items() if state == _CORS_REFLECTED]
        wildcard = [p for p, state in results.items() if state == _CORS_WILDCARD]
        evaluated = [p for p, state in results.items() if state != _CORS_UNKNOWN]
        granted = [p for p, state in results.items() if state == _CORS_BOUNDED]
        if reflected:
            finding = Finding(
                title="Unsafe CORS: an arbitrary origin is allowed with credentials",
                detail=(
                    f"On {len(reflected)} sampled endpoint(s) (e.g. {reflected[0]}) the response "
                    "to a cross-origin request reflects an arbitrary Origin with "
                    "Access-Control-Allow-Credentials: true, letting any site read authenticated "
                    "responses cross-origin (OWASP API8:2023, ASVS v5.0.0-3.4.2). Validate the "
                    "Origin against a fixed list of trusted origins."
                ),
                confidence=Confidence.CERTAIN,
            )
            # The proof is the answer to the cross-origin probe on the endpoint named.
            self._violation(
                store, _SUB_CORS, "CORS_ORIGIN_REFLECTED", finding, records.get(reflected[0])
            )
            return
        if wildcard:
            # Browsers refuse a credentialed response whose
            # Access-Control-Allow-Origin is '*' (Fetch standard, CORS check), so
            # this is not the read primitive above: FIRM, and said so.
            finding = Finding(
                title="CORS allows any origin ('*') together with credentials",
                detail=(
                    f"On {len(wildcard)} sampled endpoint(s) (e.g. {wildcard[0]}) the response to "
                    "a cross-origin request carries Access-Control-Allow-Origin: * with "
                    "Access-Control-Allow-Credentials: true. Browsers refuse that combination, so "
                    "it does not expose authenticated responses as it stands; it shows a CORS "
                    "policy meant to share credentialed responses with any origin, one change "
                    "(reflecting the Origin) away from doing so (ASVS v5.0.0-3.4.2 allows '*' only "
                    "for responses with no sensitive information). Allow only a fixed list of "
                    "trusted origins."
                ),
                confidence=Confidence.FIRM,
            )
            self._violation(
                store, _SUB_CORS, "CORS_WILDCARD_CREDENTIALS", finding, records.get(wildcard[0])
            )
            return
        if evaluated and all(results[p] == _CORS_NOT_SERVED for p in evaluated):
            self._record(_SUB_CORS, Outcome.NOT_VERIFIABLE, "PROBE_NOT_SERVED")
            return
        if not evaluated:
            # No usable answer to the cross-origin probe: nothing was learnt.
            unknown = (records.get(p) for p, state in results.items() if state == _CORS_UNKNOWN)
            reason = next((r for r in map(self._cors_silence, unknown) if r), None)
            self._record(_SUB_CORS, Outcome.NOT_VERIFIABLE, reason or "NO_RESPONSE")
            return
        if not granted:
            # The answers to an arbitrary Origin grant no cross-origin access at
            # all: that origin is not allowed, which is what this check asks.
            self._record(_SUB_CORS, Outcome.ENFORCED, "ORIGIN_NOT_ALLOWED")
            return
        self._record(_SUB_CORS, Outcome.ENFORCED, "CORS_BOUNDED")

    def _violation(
        self,
        store: EvidenceStore,
        sub_test: str,
        detail: str,
        finding: Finding,
        record: EvidenceRecord | None,
    ) -> None:
        """Record a VIOLATION, pointing it to a sampled response when there is one."""
        if record is not None:
            self._judge(record, store, sub_test, Outcome.VIOLATION, detail, finding)
        else:
            self._record(sub_test, Outcome.VIOLATION, detail, finding)


# What the answer to the cross-origin probe says (_cors_ok).
_CORS_REFLECTED: str = "reflected"
_CORS_WILDCARD: str = "wildcard"
_CORS_BOUNDED: str = "bounded"
_CORS_NO_GRANT: str = "no_grant"
_CORS_NOT_SERVED: str = "not_served"
_CORS_UNKNOWN: str = "unknown"


def _where(absent: list[str], results: dict[str, bool]) -> str:
    """Where a header is missing, in words."""
    if len(absent) < len(results):
        return f"absent on {len(absent)} of {len(results)} sampled endpoints (e.g. {absent[0]})"
    return f"absent on all {len(results)} sampled endpoints (e.g. {absent[0]})"


def _first_value(value: str) -> str:
    """The first of a header's values, lowercased (Fetch reads nosniff from the first)."""
    return value.split(",")[0].strip().lower()


def _framing_ok(headers: dict[str, str]) -> bool:
    """
    CSP frame-ancestors that does not allow any site, or X-Frame-Options DENY/SAMEORIGIN.

    A frame-ancestors directive takes precedence over X-Frame-Options in a
    browser, so when it is present it decides: one allowing any site ('*', or a
    bare scheme) is no protection (any frame-ancestors passed).
    """
    sources = _frame_ancestors(headers.get("content-security-policy", ""))
    if sources is not None:
        return not sources & _ANY_ANCESTOR
    # HTML's rule: a list of values counts only when they are all the same.
    values = {v.strip().lower() for v in headers.get("x-frame-options", "").split(",")}
    return len(values) == 1 and values <= {"deny", "sameorigin"}


# frame-ancestors sources that let any site embed the page.
_ANY_ANCESTOR: frozenset[str] = frozenset({"*", "http:", "https:", "http://*", "https://*"})


def _frame_ancestors(csp: str) -> set[str] | None:
    """The sources of a CSP frame-ancestors directive, or None when there is none."""
    for directive in csp.lower().replace(",", ";").split(";"):
        tokens = directive.split()
        if tokens and tokens[0] == "frame-ancestors":
            return set(tokens[1:])
    return None


def _send(
    client: SecurityClient, path: str, headers: dict[str, str]
) -> tuple[httpx.Response | None, EvidenceRecord | None]:
    """One unauthenticated GET; (response, record), or (None, record) on a transport failure."""
    try:
        response, record = client.request("GET", path, test_id="6.2", headers=headers or None)
    except SecurityClientError as exc:
        return None, exc.record
    return response, record
