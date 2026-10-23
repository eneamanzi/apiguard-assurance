"""
src/tests/domain_6/test_6_2_security_headers_audit.py

Test 6.2: guarantee "the defensive security headers are set" (rewritten,
docs/project/test-review/group-i.md). OWASP API8:2023, OWASP ASVS v5.0.0 V3.4.

The headers that defend a browser client are present and sound, and are present
**consistently** across the services of the API (a header on one endpoint and
absent on another is a selective misconfiguration). The test samples one
documented operation per service prefix (src/tests/helpers/sampling.py):

    content_type_options  `X-Content-Type-Options: nosniff` (ASVS v5.0.0-3.4.4);
    framing_protection    a `Content-Security-Policy` with `frame-ancestors`, or
                          `X-Frame-Options: DENY`/`SAMEORIGIN`
                          (ASVS v5.0.0-3.4.6);
    cors_not_wildcard     the response to a cross-origin request does not reflect
                          an arbitrary `Origin`, nor combine
                          `Access-Control-Allow-Origin: *` with
                          `Access-Control-Allow-Credentials: true`.

Each check is ENFORCED only when it holds on every sampled endpoint; absent on
all is a VIOLATION, present on some and absent on others an inconsistency
VIOLATION. HSTS is test 1.5; Permissions-Policy is dropped (not in ASVS 3.4).
BLACK_BOX, READ_ONLY, no primary CWE (CWE-16 is a prohibited mapping category).

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import httpx
import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import SecurityClientError
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
from src.core.test_metadata import Effect, TestInfo
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
    # Read on the ASVS v5.0.0 source 2026-10-23: 3.4.3 (CSP), 3.4.4
    # (X-Content-Type-Options: nosniff), 3.4.6 (X-Frame-Options / framing).
    Reference(standard=Standard.OWASP_API_TOP10, id="API8:2023"),
    Reference(standard=Standard.ASVS, id="v5.0.0-3.4.3"),
    Reference(standard=Standard.ASVS, id="v5.0.0-3.4.4"),
    Reference(standard=Standard.ASVS, id="v5.0.0-3.4.6"),
)


class Test62SecurityHeadersAudit(BaseTest):
    """
    Test 6.2 -- whether the defensive security headers are present and consistent.

    The oracle of each sub-test is in the module docstring and on the test page.
    """

    info = TestInfo(
        id="6.2",
        name="Security Headers Audit",
        priority=3,
        strategy=TestStrategy.BLACK_BOX,
        references=_REFERENCES,
        tags=("security-headers", "cors"),
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB_CTO, _SUB_FRAME, _SUB_CORS),
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
            cors: dict[str, bool | None] = {}
            last: EvidenceRecord | None = None
            for _method, path, _template in sample:
                response, record = _send(client, path, {})
                if response is None or record is None:
                    continue
                last = record
                headers = {k.lower(): v for k, v in response.headers.items()}
                cto[path] = headers.get("x-content-type-options", "").strip().lower() == "nosniff"
                frame[path] = _framing_ok(headers)
                cors[path] = self._cors_ok(client, path)
            self._judge_header(store, _SUB_CTO, cto, last, _CTO_MSG)
            self._judge_header(store, _SUB_FRAME, frame, last, _FRAME_MSG)
            self._judge_cors(store, cors, last)
            return self._finish(message=f"{len(sample)} endpoint(s) sampled.")
        except SecurityClientError as exc:
            return self._error(exc)

    def _cors_ok(self, client: SecurityClient, path: str) -> bool | None:
        """
        Whether CORS is safe at a path: True safe, False unsafe, None not used.

        Unsafe = the response to an arbitrary Origin reflects it (or '*') together
        with Access-Control-Allow-Credentials: true.
        """
        response, _record = _send(client, path, {"Origin": _PROBE_ORIGIN})
        if response is None:
            return None
        headers = {k.lower(): v for k, v in response.headers.items()}
        acao = headers.get("access-control-allow-origin", "").strip()
        acac = headers.get("access-control-allow-credentials", "").strip().lower()
        if not acao:
            return None
        unsafe = (acao in {_PROBE_ORIGIN, "*"}) and acac == "true"
        return not unsafe

    def _judge_header(
        self,
        store: EvidenceStore,
        sub_test: str,
        results: dict[str, bool],
        record: EvidenceRecord | None,
        message: str,
    ) -> None:
        """ENFORCED if present everywhere; VIOLATION if absent everywhere or inconsistent."""
        if not results:
            self._record(sub_test, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return
        present = [p for p, ok in results.items() if ok]
        absent = [p for p, ok in results.items() if not ok]
        if not absent:
            self._record(sub_test, Outcome.ENFORCED, "PRESENT")
            return
        detail = "INCONSISTENT" if present else "MISSING"
        where = (
            f"absent on {len(absent)} of {len(results)} sampled endpoints (e.g. {absent[0]})"
            if present
            else f"absent on all {len(results)} sampled endpoints (e.g. {absent[0]})"
        )
        finding = Finding(
            title=f"{message} {detail.lower()}",
            detail=f"{message} is {where}. {_REMEDY[sub_test]}",
            confidence=Confidence.CERTAIN,
        )
        self._violation(store, sub_test, detail, finding, record)

    def _judge_cors(
        self, store: EvidenceStore, results: dict[str, bool | None], record: EvidenceRecord | None
    ) -> None:
        """VIOLATION if any sampled endpoint has unsafe CORS; N/A if none use CORS."""
        if not results:
            self._record(_SUB_CORS, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return
        unsafe = [p for p, ok in results.items() if ok is False]
        used = [p for p, ok in results.items() if ok is not None]
        if unsafe:
            finding = Finding(
                title="Unsafe CORS: an arbitrary origin is allowed with credentials",
                detail=(
                    f"On {len(unsafe)} sampled endpoint(s) (e.g. {unsafe[0]}) the response to a "
                    "cross-origin request reflects an arbitrary Origin (or '*') with "
                    "Access-Control-Allow-Credentials: true, letting any site read authenticated "
                    "responses cross-origin (OWASP API8:2023). Allow only a fixed list of trusted "
                    "origins, never '*' with credentials."
                ),
                confidence=Confidence.CERTAIN,
            )
            self._violation(store, _SUB_CORS, "CORS_WILDCARD_CREDENTIALS", finding, record)
            return
        if not used:
            self._record(_SUB_CORS, Outcome.NOT_APPLICABLE, "NO_CORS")
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


_CTO_MSG: str = "X-Content-Type-Options: nosniff"
_FRAME_MSG: str = "Clickjacking protection (CSP frame-ancestors or X-Frame-Options)"
_REMEDY: dict[str, str] = {
    _SUB_CTO: "Set X-Content-Type-Options: nosniff at the gateway (ASVS v5.0.0-3.4.4).",
    _SUB_FRAME: "Set Content-Security-Policy: frame-ancestors 'self' at the gateway "
    "(ASVS v5.0.0-3.4.6).",
}


def _framing_ok(headers: dict[str, str]) -> bool:
    """CSP frame-ancestors, or X-Frame-Options DENY/SAMEORIGIN."""
    csp = headers.get("content-security-policy", "").lower()
    xfo = headers.get("x-frame-options", "").strip().lower()
    return "frame-ancestors" in csp or xfo in {"deny", "sameorigin"}


def _send(
    client: SecurityClient, path: str, headers: dict[str, str]
) -> tuple[httpx.Response | None, EvidenceRecord | None]:
    """One unauthenticated GET; (response, record), or (None, record) on a transport failure."""
    try:
        response, record = client.request("GET", path, test_id="6.2", headers=headers or None)
    except SecurityClientError as exc:
        return None, exc.record
    return response, record
