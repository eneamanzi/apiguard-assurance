"""
src/tests/domain_1/test_1_5_insecure_credential_transport.py

Test 1.5: guarantee "a credential never travels on an insecure channel".

The credential reaches the API over HTTP. This test checks the two things the
gateway must do so that it is never carried in cleartext, each the subject of
one sub-test:

    credential_forced_onto_tls  a plain-HTTP request to a documented API path
                                is refused (nothing answers on HTTP); any
                                answer is a VIOLATION, because the request with
                                its credential crossed the cleartext channel. A
                                redirect to HTTPS is one too (TRANSPARENT_REDIRECT):
                                ASVS v5.0.0-4.1.2 lets only browser-facing
                                endpoints redirect, since an API client that
                                wrongly uses HTTP is then never told and keeps
                                sending its credential in cleartext (owner
                                decision 2026-11-04; until then a
                                301/308 to https was ENFORCED). The path is derived from the
                                specification (where a credential actually
                                travels), not `/`: a gateway redirects to HTTPS
                                only on a path it has a route for, and answers
                                `/` in cleartext (Kong, APISIX).
    hsts_present                an HTTPS response carries a sound HSTS header
                                (present, max-age within a bound,
                                includeSubDomains), so a browser never tries
                                plain HTTP. Checked on a documented API response,
                                not `/` (the gateway sets HSTS on the API, not on
                                an unrouted path).

The TLS handshake itself (protocol versions, cipher suites, certificate, known
TLS CVEs) is the subject of the external test ext.1.5.testssl, a scanner's job
we do not reimplement (rule 11). This native test
covers only the HTTP-layer enforcement.

Plain-HTTP target: when base_url is `http://`, the credential is in cleartext
on every request; credential_forced_onto_tls is a VIOLATION/PLAIN_HTTP and HSTS
is NOT_APPLICABLE (there is no TLS layer). The test never SKIPs a reachable
target, which would hide the worst transport state.

The HTTP probe is sent through the client (origin=), so it is recorded as
evidence like any other request.

Dependency rule: imports from stdlib, structlog and src.core, plus
src.tests.base and src.tests.helpers.
"""

from __future__ import annotations

import re
from typing import Annotated
from urllib.parse import urlsplit

import structlog
from pydantic import BaseModel, ConfigDict, Field

from src.core.assessment_test import category_of
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
    ResponseCategory,
    Standard,
    TestResult,
    TestStrategy,
    TransportError,
)
from src.core.test_metadata import DecisiveAnswer, Effect, OracleCase, TestInfo
from src.tests.base import BaseTest
from src.tests.helpers.path_resolver import resolve_path_with_seed

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The sub-tests, in the order the page lists them.
_SUB_TLS: str = "credential_forced_onto_tls"
_SUB_HSTS: str = "hsts_present"

# A permanent redirect (RFC 9110): the only redirect that forces HTTPS for good.
# A temporary redirect (302, 307) can be stripped by a man in the middle, so it
# does not enforce the move to TLS.
_PERMANENT_REDIRECTS: frozenset[int] = frozenset({301, 308})

# HSTS header and its parts (response headers are compared in lower case).
_HSTS_HEADER: str = "strict-transport-security"
_HSTS_INCLUDE_SUBDOMAINS: str = "includesubdomains"
# RFC 6797 section 6.1.1: max-age may be written as a quoted string.
_HSTS_MAX_AGE: re.Pattern[str] = re.compile(r'max-age\s*=\s*"?(\d+)"?', re.IGNORECASE)
_LOCATION_HEADER: str = "location"

# The HTTPS default port, dropped when deriving the plain-HTTP origin so that it
# falls back to the implicit port 80 of a real deployment.
_HTTPS_DEFAULT_PORT: int = 443

# Where to probe when the specification documents no path at all: the root,
# which still carries (or lacks) HSTS and still answers over HTTP.
_ROOT_PATH: str = "/"

# The lower bound of an acceptable HSTS floor (one day); the default is one year
# (ASVS v5.0.0-3.4.1; NIST SP 800-52r2, cited until 2026-11-16, says nothing of HSTS).
_HSTS_MIN_FLOOR_SECONDS: int = 86_400
# 426 Upgrade Required (RFC 9110 section 15.5.22): Kong's answer to plain HTTP on a
# route that accepts only HTTPS.
_UPGRADE_REQUIRED: int = 426
_HSTS_DEFAULT_MAX_AGE_SECONDS: int = 31_536_000

_REFERENCES: tuple[Reference, ...] = (
    # Read on the ASVS v5.0.0 sources 2026-10-22: RFC 9110 section 4.2.2 (an
    # `https` URI is a different origin, so a downgrade crosses a security
    # boundary); ASVS 3.4.1 (Strict-Transport-Security on all responses, max-age
    # at least one year, subdomains for L2+); 12.2.1 (TLS on all connectivity to
    # external HTTP services, no fallback to cleartext).
    # Both categories, each on its own ground (read on the source 2026-10-28):
    # API2:2023 for the credential this test exposes, API8:2023 for the
    # configuration that exposes it, whose list names "Transport Layer Security
    # (TLS) is missing" and "security directives are not sent to clients".
    Reference(standard=Standard.OWASP_API_TOP10, id="API2:2023"),
    Reference(standard=Standard.OWASP_API_TOP10, id="API8:2023"),
    Reference(standard=Standard.RFC, id="9110", section="4.2.2"),
    Reference(standard=Standard.RFC, id="6797", section="6.1"),
    Reference(standard=Standard.ASVS, id="v5.0.0-3.4.1"),
    Reference(standard=Standard.ASVS, id="v5.0.0-12.2.1"),
    # 4.1.2 (read on the source 2026-11-04): only user-facing endpoints
    # redirect from HTTP to HTTPS; other endpoints implement no transparent
    # redirect, so that a client sending cleartext requests is not hidden.
    Reference(standard=Standard.ASVS, id="v5.0.0-4.1.2"),
)
# Each finding cites its own (until 2026-11-16 every one cited all of them).
_REFS_HTTP: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API2:2023"),
    Reference(standard=Standard.OWASP_API_TOP10, id="API8:2023"),
    Reference(standard=Standard.RFC, id="9110", section="4.2.2"),
    Reference(standard=Standard.ASVS, id="v5.0.0-4.1.2"),
    Reference(standard=Standard.ASVS, id="v5.0.0-12.2.1"),
)
_REFS_HSTS: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API8:2023"),
    Reference(standard=Standard.RFC, id="6797", section="6.1"),
    Reference(standard=Standard.ASVS, id="v5.0.0-3.4.1"),
)

_ORACLE: tuple[OracleCase, ...] = (
    OracleCase(
        sub_test=_SUB_TLS,
        when="`base_url` is `http://`: no TLS at all",
        outcome=Outcome.VIOLATION,
        detail="PLAIN_HTTP",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_TLS,
        when="the plain-HTTP connection is refused: nothing listens there",
        outcome=Outcome.ENFORCED,
        detail="HTTP_PORT_UNREACHABLE",
    ),
    OracleCase(
        sub_test=_SUB_TLS,
        when="the plain-HTTP probe timed out or broke before an answer",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="HTTP_PORT_NO_ANSWER",
    ),
    OracleCase(
        sub_test=_SUB_TLS,
        when="`base_url` not on port 443 and no `http_url`: the HTTP listener is unknown",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="HTTP_LISTENER_UNKNOWN",
    ),
    OracleCase(
        sub_test=_SUB_TLS,
        when="a `301`/`308` to an `https://` location (ASVS v5.0.0-4.1.2)",
        outcome=Outcome.VIOLATION,
        detail="TRANSPARENT_REDIRECT",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_TLS,
        when="a `301`/`308` whose location is not `https`",
        outcome=Outcome.VIOLATION,
        detail="WEAK_REDIRECT",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_TLS,
        when="any other redirect",
        outcome=Outcome.VIOLATION,
        detail="TEMPORARY_REDIRECT",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_TLS,
        when="a `2xx` over plain HTTP",
        outcome=Outcome.VIOLATION,
        detail="HTTP_SERVED_CLEARTEXT",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_TLS,
        when="any other answer over plain HTTP: the same `4xx` as over HTTPS, or a `5xx`",
        outcome=Outcome.VIOLATION,
        detail="HTTP_PROCESSED_CLEARTEXT",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_TLS,
        when="`426`, or a `4xx` the same path does not get over HTTPS: the protocol is refused "
        "and the client told (owner, 2026-11-16)",
        outcome=Outcome.ENFORCED,
        detail="HTTP_REFUSED",
    ),
    OracleCase(
        sub_test=_SUB_TLS,
        when="a `4xx` other than `426`, and no HTTPS answer that says something to compare it with",
        outcome=Outcome.NOT_VERIFIABLE,
        detail="HTTPS_ANSWER_UNKNOWN",
    ),
    OracleCase(
        sub_test=_SUB_HSTS,
        when="HSTS with `max-age` at least `hsts_min_max_age_seconds` and `includeSubDomains`",
        outcome=Outcome.ENFORCED,
        detail="HSTS_COMPLIANT",
    ),
    OracleCase(
        sub_test=_SUB_HSTS,
        when="the HTTPS answer has no `Strict-Transport-Security`",
        outcome=Outcome.VIOLATION,
        detail="HSTS_MISSING",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_HSTS,
        when="`max-age` absent or below `hsts_min_max_age_seconds`",
        outcome=Outcome.VIOLATION,
        detail="HSTS_MAX_AGE_LOW",
        confidence=Confidence.CERTAIN,
    ),
    OracleCase(
        sub_test=_SUB_HSTS,
        when="`max-age` sufficient, no `includeSubDomains`",
        outcome=Outcome.VIOLATION,
        detail="HSTS_NO_SUBDOMAINS",
        confidence=Confidence.FIRM,
    ),
    OracleCase(
        sub_test=_SUB_HSTS,
        when="`base_url` is plain HTTP: no TLS to carry HSTS",
        outcome=Outcome.NOT_APPLICABLE,
        detail="NO_TLS",
    ),
)
# Any answer over plain HTTP is the verdict of credential_forced_onto_tls.
_CLEARTEXT_ANSWER: str = (
    "any answer over plain HTTP means the request crossed the network in cleartext: judged by "
    "the oracle above (no answer is `HTTP_PORT_NO_ANSWER`)."
)


class Test15Params(BaseModel):
    """
    Parameters of test 1.5.

    The HTTP probe derives its origin from base_url (scheme to `http`, the HTTPS
    default port dropped to the implicit port 80); `http_url` overrides it where
    the deployment puts HTTP on a non-standard port (the labs, with HTTPS on
    8443/9443/10443 and HTTP on 8000/9000/10000). The path is always derived from
    the specification: only the origin of `http_url` is used, its path ignored.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    hsts_min_max_age_seconds: Annotated[int, Field(ge=_HSTS_MIN_FLOOR_SECONDS)] = Field(
        default=_HSTS_DEFAULT_MAX_AGE_SECONDS,
        description=(
            "Lowest acceptable max-age (seconds) in the Strict-Transport-Security header. "
            "OWASP ASVS v5.0.0-3.4.1 asks for at least one year. "
            f"Default: {_HSTS_DEFAULT_MAX_AGE_SECONDS} (one year)."
        ),
    )
    http_url: str = Field(
        default="",
        description=(
            "The API in plain HTTP, when its HTTP listener is on a non-standard port: only the "
            "origin (scheme://host[:port]) is used, the path is derived from the specification. "
            "Empty (default) derives the origin from base_url (scheme to http, port 443 dropped); "
            "with base_url on another port, the HTTP listener is then unknown and not probed."
        ),
    )


class Test15InsecureCredentialTransport(BaseTest[Test15Params]):
    """
    Test 1.5 -- whether the credential is forced onto TLS and HSTS is set.

    The oracle of each sub-test is in the module docstring and on the test
    page.
    """

    info = TestInfo(
        id="1.5",
        name="Credentials Over an Insecure Channel",
        priority=2,
        strategy=TestStrategy.BLACK_BOX,
        cwe="CWE-319",
        references=_REFERENCES,
        tags=("transport-security", "tls", "hsts"),
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB_TLS, _SUB_HSTS),
        oracle=_ORACLE,
        decisive_answers=tuple(
            DecisiveAnswer(category=category, sub_tests=(_SUB_TLS,), reason=_CLEARTEXT_ANSWER)
            for category in (
                ResponseCategory.UPSTREAM_UNAVAILABLE,
                ResponseCategory.RATE_LIMITED,
                ResponseCategory.SERVER_ERROR,
                ResponseCategory.NO_RESPONSE,
            )
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
        Probe the HTTP listener (it should not answer), and an HTTPS response for HSTS.

        Args:
            target:  The run's target (base URL, surface, path seed).
            context: The run's context (unused: no credential is needed).
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._requires_attack_surface(...), or
            self._error(exc).
        """
        del context
        try:
            cfg = self.params(target)
            base_url = target.endpoint_base_url()
            if not base_url.startswith("https://"):
                return self._plain_http(base_url)
            missing = self._requires_attack_surface(target)
            if missing is not None:
                return missing
            probe_path = self._documented_path(target)
            # The HTTPS answer first: the plain-HTTP one is compared with it.
            https = self._check_hsts(client, store, cfg, probe_path)
            self._check_http(target, client, store, cfg, base_url, probe_path, https)
            return self._finish()
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            return self._error(exc)

    def _plain_http(self, base_url: str) -> TestResult:
        """
        The result for a target whose base URL is plain HTTP.

        Args:
            base_url: The configured base URL (an `http://` one here).

        Returns:
            self._finish() with the PLAIN_HTTP violation and HSTS not applicable.
        """
        self._record(
            _SUB_TLS,
            Outcome.VIOLATION,
            "PLAIN_HTTP",
            Finding(
                title="The API is served over plain HTTP",
                detail=(
                    f"The configured base URL is {base_url!r}, plain HTTP: there is no TLS "
                    "layer, so every credential, token and session value is sent in cleartext "
                    "and is readable by anyone on the network path. Serve the API over HTTPS "
                    "(TLS 1.2+) and set the target to its `https://` URL. This finding rests on "
                    "the configuration, not on a response, so it names no evidence record: the "
                    "base URL as the run used it is in config_used.yaml."
                ),
                confidence=Confidence.CERTAIN,
            ),
        )
        self._record(_SUB_HSTS, Outcome.NOT_APPLICABLE, "NO_TLS")
        return self._finish(message="The target is plain HTTP.")

    def _documented_path(self, target: TargetContext) -> str:
        """
        A documented path to probe: the shortest one, parameters resolved.

        A short path is likelier to need no path parameter and to have a gateway
        route; the choice does not change the verdict (every documented path must
        be forced onto TLS and carry HSTS), only which one proves it.

        Args:
            target: The run's target (surface, path seed).

        Returns:
            A concrete path, or the root when the specification documents none.
        """
        surface = target.attack_surface
        if surface is None or not surface.endpoints:
            return _ROOT_PATH
        shortest = min(surface.endpoints, key=lambda e: (len(e.path), e.path, e.method))
        return resolve_path_with_seed(shortest.path, target.path_seed)

    def _http_origin(self, cfg: Test15Params, base_url: str) -> str:
        """
        The plain-HTTP origin to probe.

        Args:
            cfg:      The test's parameters (http_url override).
            base_url: The HTTPS base URL.

        Returns:
            An origin "http://host[:port]" (no path), from http_url when set,
            else derived from base_url.
        """
        if cfg.http_url:
            parts = urlsplit(cfg.http_url)
            return f"http://{parts.netloc}"
        parts = urlsplit(base_url)
        if parts.port in (None, _HTTPS_DEFAULT_PORT):
            return f"http://{parts.hostname}"
        return f"http://{parts.hostname}:{parts.port}"

    def _check_http(
        self,
        target: TargetContext,
        client: SecurityClient,
        store: EvidenceStore,
        cfg: Test15Params,
        base_url: str,
        probe_path: str,
        https: EvidenceRecord | None,
    ) -> None:
        """
        Send a plain-HTTP GET to a documented path and judge the answer.

        Args:
            target:     The run's target (unused beyond base_url, kept for symmetry).
            client:     The run's HTTP client.
            store:      The test's evidence store.
            cfg:        The test's parameters.
            base_url:   The HTTPS base URL (to derive the HTTP origin).
            probe_path: The documented path to send over HTTP.
        """
        del target
        if not cfg.http_url and urlsplit(base_url).port not in (None, _HTTPS_DEFAULT_PORT):
            # The HTTPS listener is on a port of its own and http_url does not
            # say where the plain-HTTP one is: asking that port in cleartext
            # (Kong: 400 "plain HTTP request was sent to HTTPS port") says
            # nothing about a plain-HTTP listener.
            self._record(_SUB_TLS, Outcome.NOT_VERIFIABLE, "HTTP_LISTENER_UNKNOWN")
            return
        origin = self._http_origin(cfg, base_url)
        # The base URL's own path goes before the documented path, as the
        # HTTPS requests have it (until 2026-11-16 it was dropped: an unrouted
        # path was asked in cleartext).
        probe_path = urlsplit(base_url).path.rstrip("/") + probe_path
        try:
            response, record = client.request(
                "GET",
                probe_path,
                test_id=self.info.id,
                origin=origin,
            )
        except SecurityClientError as exc:
            # The connection refused: nothing listens there, so no request is
            # taken in cleartext. A timeout or a dropped connection says less (a
            # slow listener, a filter): not verifiable (rule 4).
            if exc.record is None:
                raise
            if exc.record.transport_error == TransportError.CONNECTION_FAILED:
                self._judge(exc.record, store, _SUB_TLS, Outcome.ENFORCED, "HTTP_PORT_UNREACHABLE")
            else:
                self._judge(
                    exc.record, store, _SUB_TLS, Outcome.NOT_VERIFIABLE, "HTTP_PORT_NO_ANSWER"
                )
            return
        self._judge_http(response.headers, record, store, origin, probe_path, https)

    def _judge_http(
        self,
        headers: object,
        record: EvidenceRecord,
        store: EvidenceStore,
        origin: str,
        probe_path: str,
        https: EvidenceRecord | None,
    ) -> None:
        """
        Judge a plain-HTTP response (ASVS v5.0.0-4.1.2): a redirect hides the
        mistake from the client, an answer serves it; an error refusing the
        protocol tells it (owner, 2026-11-16: until then every answer was a
        violation, Kong's `426 Please use HTTPS protocol` included).

        Args:
            headers:    The response headers (for the Location of a redirect).
            record:     The evidence record of the probe.
            store:      The test's evidence store.
            origin:     The HTTP origin probed (for the finding text).
            probe_path: The path probed (for the finding text).
        """
        status = record.response_status_code
        category = category_of(record)
        location = _header(headers, _LOCATION_HEADER)
        if status in _PERMANENT_REDIRECTS and location.lower().startswith("https://"):
            self._judge(
                record,
                store,
                _SUB_TLS,
                Outcome.VIOLATION,
                "TRANSPARENT_REDIRECT",
                Finding(
                    title=f"API endpoint redirects plain HTTP to HTTPS: {origin}{probe_path}",
                    detail=(
                        f"A plain-HTTP GET to {origin}{probe_path} was redirected to HTTPS (HTTP "
                        f"{status}). The request, with any credential it carried, had already "
                        "crossed the network in cleartext, and a client that wrongly uses HTTP "
                        "is never told: the redirect makes it work, so it keeps sending its "
                        "credential in cleartext. OWASP ASVS v5.0.0-4.1.2 allows the redirect "
                        "only on endpoints meant for a browser. Refuse plain HTTP on API "
                        "endpoints (close the HTTP listener for them, or answer an error)."
                    ),
                    confidence=Confidence.CERTAIN,
                    references=list(_REFS_HTTP),
                ),
            )
            return
        client_error = status is not None and 400 <= status < 500
        compared = https is not None and self._uninformative(https, _SUB_TLS) is None
        if client_error and status != _UPGRADE_REQUIRED and not compared:
            # No HTTPS answer to compare the 4xx with (none, or a 503 or 429):
            # whether the route refuses the protocol or answers as over HTTPS
            # is not known.
            self._judge(record, store, _SUB_TLS, Outcome.NOT_VERIFIABLE, "HTTPS_ANSWER_UNKNOWN")
            return
        refuses = status == _UPGRADE_REQUIRED or (
            client_error and https is not None and https.response_status_code != status
        )
        if refuses:
            # A 426, or a 4xx the HTTPS request does not get: the protocol is
            # refused, and the client is told. The same 4xx as over HTTPS (a
            # 401 on both) means the route answers over HTTP as it does over
            # HTTPS: processed in cleartext.
            self._judge(record, store, _SUB_TLS, Outcome.ENFORCED, "HTTP_REFUSED")
            return
        if category == ResponseCategory.REDIRECT:
            detail, why = (
                ("WEAK_REDIRECT", f"redirected to {location!r}, which does not force HTTPS")
                if status in _PERMANENT_REDIRECTS
                else ("TEMPORARY_REDIRECT", f"returned a temporary redirect (HTTP {status})")
            )
        elif category == ResponseCategory.SERVED:
            detail, why = (
                "HTTP_SERVED_CLEARTEXT",
                f"served the request in cleartext (HTTP {status})",
            )
        else:
            detail, why = (
                "HTTP_PROCESSED_CLEARTEXT",
                f"processed the request over cleartext and answered HTTP {status}",
            )
        self._judge(
            record,
            store,
            _SUB_TLS,
            Outcome.VIOLATION,
            detail,
            Finding(
                title=f"API request accepted over plain HTTP: {origin}{probe_path}",
                detail=(
                    f"A plain-HTTP GET to {origin}{probe_path} {why}. A client sending its "
                    "credential to this URL transmits it in cleartext: a man in the middle reads "
                    "or downgrades the connection. Refuse plain HTTP on API endpoints (close the "
                    "HTTP listener for them, or answer an error): a redirect, even to HTTPS, is "
                    "allowed only on endpoints meant for a browser (OWASP ASVS v5.0.0-4.1.2, "
                    "RFC 9110 section 4.2.2)."
                ),
                confidence=Confidence.CERTAIN,
                references=list(_REFS_HTTP),
            ),
        )

    def _check_hsts(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        cfg: Test15Params,
        probe_path: str,
    ) -> EvidenceRecord | None:
        """
        Send an HTTPS GET to a documented path and judge the HSTS header.

        Args:
            client:     The run's HTTP client (bound to the HTTPS base URL).
            store:      The test's evidence store.
            cfg:        The test's parameters (the max-age bound).
            probe_path: The documented path to read.

        Returns:
            The HTTPS answer, the plain-HTTP one's comparison; None without one.
        """
        try:
            response, record = client.request("GET", probe_path, test_id=self.info.id)
        except SecurityClientError as exc:
            # No answer on HTTPS: no header to judge (rule 4).
            if exc.record is None:
                raise
            self._judge(exc.record, store, _SUB_HSTS, Outcome.NOT_VERIFIABLE, "NO_RESPONSE")
            return None
        uninformative = self._uninformative(record, _SUB_HSTS)
        if uninformative is not None:
            # The gateway's own 503 or 429 may lack the header the API sets
            # (until 2026-11-16 judged as HSTS_MISSING, CERTAIN).
            self._judge(record, store, _SUB_HSTS, Outcome.NOT_VERIFIABLE, uninformative)
            return record
        value = _header(response.headers, _HSTS_HEADER)
        if not value:
            self._judge(
                record,
                store,
                _SUB_HSTS,
                Outcome.VIOLATION,
                "HSTS_MISSING",
                Finding(
                    title="No HSTS header on the API response",
                    detail=(
                        f"The HTTPS response to GET {probe_path} carries no "
                        "Strict-Transport-Security header, so a browser that first reaches the "
                        "host over HTTP is not told to switch to HTTPS and stay there "
                        "(ASVS v5.0.0-3.4.1). Add it with a max-age of at least "
                        f"{cfg.hsts_min_max_age_seconds} seconds and includeSubDomains."
                    ),
                    confidence=Confidence.CERTAIN,
                    references=list(_REFS_HSTS),
                ),
            )
            return record
        match = _HSTS_MAX_AGE.search(value)
        max_age = int(match.group(1)) if match else None
        if max_age is None or max_age < cfg.hsts_min_max_age_seconds:
            self._judge(
                record,
                store,
                _SUB_HSTS,
                Outcome.VIOLATION,
                "HSTS_MAX_AGE_LOW",
                Finding(
                    title="HSTS max-age is below the bound",
                    detail=(
                        f"The HSTS header on GET {probe_path} is {value!r}: its max-age "
                        f"({'absent' if max_age is None else max_age}) is below the "
                        f"{cfg.hsts_min_max_age_seconds} seconds asked for (ASVS v5.0.0-3.4.1). "
                        "A short max-age leaves a window in which a browser still tries plain "
                        "HTTP."
                    ),
                    confidence=Confidence.CERTAIN,
                    references=list(_REFS_HSTS),
                ),
            )
            return record
        if _HSTS_INCLUDE_SUBDOMAINS not in value.lower().replace(" ", ""):
            self._judge(
                record,
                store,
                _SUB_HSTS,
                Outcome.VIOLATION,
                "HSTS_NO_SUBDOMAINS",
                Finding(
                    title="HSTS does not cover subdomains",
                    detail=(
                        f"The HSTS header on GET {probe_path} is {value!r}: it has a sufficient "
                        "max-age but no includeSubDomains, so a subdomain served over HTTP is not "
                        "protected (ASVS v5.0.0-3.4.1). Add includeSubDomains unless a subdomain "
                        "is deliberately HTTP-only. Reported at lower confidence: a bounded "
                        "max-age already forces HTTPS on this host."
                    ),
                    confidence=Confidence.FIRM,
                    references=list(_REFS_HSTS),
                ),
            )
            return record
        self._judge(record, store, _SUB_HSTS, Outcome.ENFORCED, "HSTS_COMPLIANT")
        return record


def _header(headers: object, name: str) -> str:
    """
    One response header by name, case-insensitively, or the empty string.

    Args:
        headers: The response's headers (httpx.Headers, case-insensitive).
        name:    The header name in lower case.

    Returns:
        The header value, or "" when it is absent.
    """
    getter = getattr(headers, "get", None)
    if getter is None:
        return ""
    value = getter(name)
    return value if isinstance(value, str) else ""
