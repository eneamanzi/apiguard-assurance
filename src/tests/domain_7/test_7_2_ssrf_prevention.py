"""
src/tests/domain_7/test_7_2_ssrf_prevention.py

Test 7.2: guarantee "the system prevents Server-Side Request Forgery" (OWASP
API7:2023, CWE-918, P0).

A URL-accepting endpoint (a webhook, a "fetch from URL" import) must reject a
client URL that points at internal infrastructure. The test sends the payload
catalogue (src/tests/data/ssrf_payloads.py), one payload at a time, loopback
first (it fails fast, where a link-local metadata address may hang), and judges
each in its bypass class (one sub-test per class). Its oracle: info.oracle,
generated on the test page.

Two controls frame the series: a benign URL (example.com) the endpoint must
accept, sent before and again after the payloads (a rejection only counts while
the endpoint still accepts a benign URL), and an unreachable one (a random
`.invalid` host, RFC 6761): an endpoint that fetches the URL at once and
answers a failed fetch with a 4xx rejects it too, so a payload rejected the same
way was not blocked, the fetch failed. The series stops at the first payload
left without an answer or answered 502, 503 or 504 (owner decision 2026-11-04).

Honesty boundary (owner decision 2026-10-23): a 2xx means the URL was accepted,
not that the server called it; without an out-of-band listener (not built) it
is NOT_VERIFIABLE. One exception is proof, not inference: when the benign
control's answer carries the fetched page (the endpoint reflects what it
fetches), a payload's 2xx carrying a cloud-metadata marker is the internal
service's content (VIOLATION, CERTAIN).

GREY_BOX, CHANGES_DATA: each accepted URL may create an object (a webhook); with
a `resource` they are created under one object removed at teardown, without one
they stay on the target.

Dependency rule: imports from stdlib, structlog, pydantic and src.core, plus
src.tests.base, src.tests.data and src.tests.helpers.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from typing import NamedTuple
from urllib.parse import urlparse

import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, model_validator

from src.core.assessment_test import (
    NEEDED_TO_RUN,
    PARAMS_CONTEXT_RESOURCES,
    REFERS_TO_RESOURCE,
    category_of,
)
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError, SecurityClientError
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
from src.core.references import Fingerprint, fingerprint_of, random_token
from src.core.response_category import UNINFORMATIVE_CATEGORIES
from src.core.templating import (
    names_in,
    occurrences,
    placeholder_names,
    render,
    unquoted_placeholders,
)
from src.core.test_metadata import DecisiveAnswer, Effect, Need, OracleCase, TestInfo
from src.tests.base import BaseTest
from src.tests.data.ssrf_payloads import ALL_SSRF_PAYLOADS
from src.tests.helpers.auth import acquire_tokens, auth_parts
from src.tests.helpers.resources import ResourceSetupError, create_resource

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The bypass classes, each a sub-test. The names match the third element of
# every ALL_SSRF_PAYLOADS tuple (src/tests/data/ssrf_payloads.py).
_CATEGORIES: tuple[str, ...] = (
    "cloud_metadata",
    "private_ip",
    "encoding_bypass",
    "forbidden_protocol",
    "dns_bypass",
    "url_parser_confusion",
)
# The two classes SSRF is about: internal addresses reached through the server.
# Without one ENFORCED among them the test is INCONCLUSIVE, however many other
# payloads were rejected as malformed (owner decision 2026-11-04).
_ESSENTIAL: tuple[str, ...] = ("cloud_metadata", "private_ip")

# Placeholders the test fills in the configured body (src/core/templating.py).
_PLACEHOLDER_SSRF_URL: str = "ssrf_url"
_PLACEHOLDER_RANDOM_SECRET: str = "random_secret"  # noqa: S105 -- a placeholder name

# The class sent first: loopback fails fast, a link-local metadata address may
# hang off-cloud (crAPI: a 504 after 30 s) and stop the series before it.
_FIRST_CATEGORY: str = "private_ip"
# A rejection of the URL: refused as invalid or forbidden (until 2026-11-16 any
# 4xx that was not 401, 404 or 429, a 405 or 408 included).
_REJECTING: frozenset[ResponseCategory] = frozenset(
    {ResponseCategory.INVALID_REQUEST, ResponseCategory.FORBIDDEN}
)
# The page example.com serves: in an answer, the endpoint reflects what it fetched.
_BENIGN_MARKER: str = "Example Domain"
# Markers of a cloud metadata service's content (AWS, GCP, Azure).
_METADATA_MARKERS: tuple[str, ...] = (
    "ami-id",
    "instance-id",
    "security-credentials",
    "computeMetadata",
    "azEnvironment",
)

# Bytes of the value of {random_secret} (-> 32 hexadecimal characters).
_RANDOM_SECRET_BYTES: int = 16

# Non-HTTP schemes: their rejection is a scheme block, not a malformed URL,
# even when the stack reports both the same way (Go's net/http).
_NON_HTTP_SCHEMES: frozenset[str] = frozenset(
    {"file", "gopher", "dict", "ftp", "ldap", "tftp", "sftp", "netdoc", "jar", "data"}
)

# Default body-classification keywords: they only refine the ENFORCED detail
# (how the URL was rejected); they never change ENFORCED vs NOT_VERIFIABLE.
_MALFORMED_KEYWORDS: tuple[str, ...] = (
    "invalid character",
    "invalid url",
    "malformed",
    "parse error",
    "could not parse",
)
_SCHEME_KEYWORDS: tuple[str, ...] = (
    "scheme not supported",
    "scheme not allowed",
    "unsupported scheme",
    "unsupported protocol",
    "only http",
    "protocol not allowed",
)
_VALIDATION_KEYWORDS: tuple[str, ...] = (
    "not allowed",
    "forbidden",
    "private",
    "loopback",
    "blocked",
    "disallowed",
    "restricted",
    "host not allowed",
)

# ENFORCED details (how the URL was rejected) and the one NOT_VERIFIABLE detail.
_BLOCKED_MALFORMED: str = "SSRF_BLOCKED_MALFORMED"
_BLOCKED_SCHEME: str = "SSRF_BLOCKED_SCHEME"
_BLOCKED_VALIDATION: str = "SSRF_BLOCKED_VALIDATION"
_BLOCKED_UNKNOWN: str = "SSRF_BLOCKED_UNKNOWN"

# Answers that are not a rejection of the URL, though not a 2xx:
# the credential refused (expired mid-series), a redirect not followed, and a
# 404 on a path that accepted the benign URL (perhaps the fetched page's own).
_NOT_A_REJECTION: dict[ResponseCategory, str] = {
    ResponseCategory.UNAUTHENTICATED: "CREDENTIAL_REFUSED",
    ResponseCategory.REDIRECT: "REDIRECTED",
    ResponseCategory.NOT_FOUND: "NOT_FOUND",
}
_OUTBOUND_NOT_CONFIRMED: str = "OUTBOUND_NOT_CONFIRMED"
_PROBE_TIMEOUT: str = "SSRF_PROBE_TIMEOUT"
# The payloads not sent once the endpoint hung or its backend went out of
# service (owner decision 2026-11-04).
_NOT_SENT: str = "NOT_SENT_AFTER_TIMEOUT"
_UPSTREAM_UNAVAILABLE: str = "UPSTREAM_UNAVAILABLE"
_BASELINE_REJECTED: str = "BASELINE_REJECTED"
_LIKE_UNREACHABLE: str = "REJECTED_LIKE_UNREACHABLE"
_REFLECTED: str = "SSRF_CONTENT_REFLECTED"
_NOT_INTERPRETED: str = "ANSWER_NOT_INTERPRETED"
# The domain RFC 6761 reserves: a name under it never resolves.
_UNREACHABLE_DOMAIN: str = "invalid"

# A well-formed, non-internal control URL. The endpoint's answer to it is the
# baseline: if even this is rejected, a rejection of an SSRF URL is not proof of
# an SSRF defence (a precondition such as an invalid vehicle id, auth, or a down
# upstream rejects every URL alike), so the SSRF rejections are NOT_VERIFIABLE.
_BENIGN_CONTROL_URL: str = "http://example.com/"

# The situations one probe can land in, from its evidence record.
_SITUATION_ACCEPTED: str = "accepted"
_SITUATION_REJECTED: str = "rejected"
_SITUATION_UPSTREAM: str = "upstream"
_SITUATION_TIMEOUT: str = "timeout"
# A 429: the target throttled the request before evaluating its URL. Counting it
# as a rejection would let a rate limiter pass for an SSRF defence on a burst of
# 75 payloads.
_SITUATION_RATE_LIMITED: str = "rate_limited"
_SITUATION_OTHER: str = "other"


class Test72UrlAcceptingEndpoint(BaseModel):
    """
    An endpoint of the API that accepts a URL and makes the server call it.

    The test POSTs the body to the path once per payload, with the payload
    written where the body holds "{ssrf_url}". With a `resource`, a prepared
    resource is created once for user A (its teardown registered) and its values
    fill the path and the body. Checked against config.resources through the
    validation context (src/config/tests_section.py).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(
        min_length=1,
        description=(
            "Path of the endpoint (POST). With a resource it may hold the resource's values, "
            "e.g. '/api/v1/projects/{project_id}/webhooks'."
        ),
    )
    body: dict[str, object] = Field(
        description=(
            'JSON body of the request. Must contain "{ssrf_url}" exactly once, replaced by each '
            'payload URL; may contain "{random_secret}" (32 hexadecimal characters) and, with a '
            "resource, the resource's values. Placeholders in quotes."
        ),
    )
    resource: str | None = Field(
        default=None,
        min_length=1,
        json_schema_extra=REFERS_TO_RESOURCE,
        description=(
            "Name of a prepared resource (resources: in config.yaml) created for user A before "
            "probing; its values fill the placeholders of path and body, and it is deleted at "
            "teardown. Optional: without it the path is used as written."
        ),
    )

    @model_validator(mode="after")
    def placeholders_known(self, info: ValidationInfo) -> Test72UrlAcceptingEndpoint:
        """Check path and body against the resource, when the resources are known."""
        resources = (info.context or {}).get(PARAMS_CONTEXT_RESOURCES)
        if resources is None:
            return self
        values: frozenset[str] = frozenset()
        if self.resource is not None:
            known_resource = resources.get(self.resource)
            if known_resource is None:
                defined = ", ".join(sorted(resources)) or "none"
                raise ValueError(
                    f"resource: '{self.resource}' is not defined in resources (defined: {defined})."
                )
            values = frozenset(known_resource.values)
        unknown = placeholder_names(self.path) - values
        if unknown:
            raise ValueError(
                "path: unknown placeholder(s) "
                f"{', '.join(f'{{{n}}}' for n in sorted(unknown))}; known: the values of resource."
            )
        known = values | {_PLACEHOLDER_SSRF_URL, _PLACEHOLDER_RANDOM_SECRET}
        unquoted = unquoted_placeholders(self.body, known)
        if unquoted:
            raise ValueError(
                "body: write the placeholders in quotes, e.g. "
                f'"{{{sorted(unquoted)[0]}}}": unquoted, YAML reads them as a mapping.'
            )
        unknown = names_in(self.body) - known
        if unknown:
            raise ValueError(
                "body: unknown placeholder(s) "
                f"{', '.join(f'{{{n}}}' for n in sorted(unknown))}; known: "
                f"{', '.join(f'{{{n}}}' for n in sorted(known))}."
            )
        count = occurrences(self.body, _PLACEHOLDER_SSRF_URL)
        if count != 1:
            raise ValueError(
                f'body must contain "{{{_PLACEHOLDER_SSRF_URL}}}" exactly once, where the SSRF '
                f"URL goes (found {count})."
            )
        return self


class Test72Params(BaseModel):
    """Parameters of test 7.2."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    url_accepting_endpoint: Test72UrlAcceptingEndpoint | None = Field(
        default=None,
        json_schema_extra=NEEDED_TO_RUN,
        examples=[
            {
                "path": "/api/v1/projects/{project_id}/webhooks",
                "body": {"url": "{ssrf_url}", "events": ["push"]},
                "resource": "project",
            }
        ],
        description=(
            "The endpoint that accepts a URL from the client and makes the server call it (a "
            'webhook, a fetch-from-URL import): path, body (with "{ssrf_url}" where the URL '
            "goes) and, optionally, a prepared resource. No default: unset, the engine records "
            "the test as SKIP before it runs."
        ),
    )
    payload_categories: tuple[str, ...] = Field(
        default=_CATEGORIES,
        description=(
            "The bypass classes to probe. Valid values: 'cloud_metadata', 'private_ip', "
            "'encoding_bypass', 'forbidden_protocol', 'dns_bypass', 'url_parser_confusion'. A "
            "class left out is not probed and its sub-test stays empty."
        ),
    )

    @model_validator(mode="after")
    def categories_known(self) -> Test72Params:
        """Every configured category must be a known bypass class."""
        unknown = tuple(c for c in self.payload_categories if c not in _CATEGORIES)
        if unknown:
            raise ValueError(
                f"payload_categories: unknown {', '.join(unknown)}; "
                f"known: {', '.join(_CATEGORIES)}."
            )
        return self


def _cases(sub_test: str) -> tuple[OracleCase, ...]:
    """The oracle of one bypass class, the same for the six."""
    return (
        OracleCase(
            sub_test=sub_test,
            when="the payload is refused as invalid or forbidden (`400`, `403`, `422`, ...), "
            "the benign URL accepted before and after the series, and unlike the "
            "unreachable URL",
            outcome=Outcome.ENFORCED,
            detail="SSRF_BLOCKED_",
            members=("SCHEME", "MALFORMED", "VALIDATION", "UNKNOWN"),
        ),
        OracleCase(
            sub_test=sub_test,
            when="refused exactly as the unreachable URL is: a failed fetch, not a block",
            outcome=Outcome.NOT_VERIFIABLE,
            detail=_LIKE_UNREACHABLE,
        ),
        OracleCase(
            sub_test=sub_test,
            when="refused while the benign URL is refused too, before or after the series",
            outcome=Outcome.NOT_VERIFIABLE,
            detail=_BASELINE_REJECTED,
        ),
        OracleCase(
            sub_test=sub_test,
            when="accepted (`2xx`) with a cloud-metadata marker in the answer, the endpoint "
            "reflecting what it fetches",
            outcome=Outcome.VIOLATION,
            detail=_REFLECTED,
            confidence=Confidence.CERTAIN,
        ),
        OracleCase(
            sub_test=sub_test,
            when="accepted (`2xx`): the outbound call is not observable",
            outcome=Outcome.NOT_VERIFIABLE,
            detail=_OUTBOUND_NOT_CONFIRMED,
        ),
        OracleCase(
            sub_test=sub_test,
            when="`401`: the credential refused",
            outcome=Outcome.NOT_VERIFIABLE,
            detail="CREDENTIAL_REFUSED",
        ),
        OracleCase(
            sub_test=sub_test,
            when="a redirect, not followed",
            outcome=Outcome.NOT_VERIFIABLE,
            detail="REDIRECTED",
        ),
        OracleCase(
            sub_test=sub_test,
            when="`404`, perhaps the fetched page's own",
            outcome=Outcome.NOT_VERIFIABLE,
            detail="NOT_FOUND",
        ),
        OracleCase(
            sub_test=sub_test,
            when="another answer (`405`, `408`, a status of no class, a `5xx` outside the shared "
            "rule)",
            outcome=Outcome.NOT_VERIFIABLE,
            detail=_NOT_INTERPRETED,
        ),
        OracleCase(
            sub_test=sub_test,
            when="no answer: the server may still be fetching the URL",
            outcome=Outcome.NOT_VERIFIABLE,
            detail=_PROBE_TIMEOUT,
        ),
        OracleCase(
            sub_test=sub_test,
            when="not sent: an earlier payload got no answer or the gateway's `502`, `503`, `504`",
            outcome=Outcome.NOT_VERIFIABLE,
            detail=_NOT_SENT,
        ),
        OracleCase(
            sub_test=sub_test,
            when="the prepared resource could not be created",
            outcome=Outcome.NOT_VERIFIABLE,
            detail="OBJECT_NOT_CREATED",
        ),
    )


class _Payload(NamedTuple):
    """One SSRF payload: the URL to inject, its label, its bypass class."""

    url: str
    description: str
    category: str


class Test72SSRFPrevention(BaseTest[Test72Params]):
    """Test 7.2 -- whether a URL-accepting endpoint rejects SSRF payloads."""

    info = TestInfo(
        id="7.2",
        name="Server-Side Request Forgery Prevention",
        priority=0,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-918",
        references=(
            Reference(standard=Standard.OWASP_API_TOP10, id="API7:2023"),
            # WSTG-INPV-19 (SSRF) is the source of the payload catalogue
            # (src/tests/data/ssrf_payloads.py), with PayloadsAllTheThings.
            # NIST SP 800-204 was cited here until 2026-10-28 and was dropped:
            # its section 3.2.2 is "Internet-based Attacks", about the inbound
            # surface of a microservices application, and the publication never
            # mentions SSRF, server-side request forgery or an outbound call.
            Reference(standard=Standard.WSTG, id="WSTG-v42-INPV-19"),
            # ASVS v5.0.0 1.3.6 (read 2026-11-16): SSRF prevented by an allowlist of
            # protocols, domains, paths and ports.
            Reference(standard=Standard.ASVS, id="v5.0.0-1.3.6"),
        ),
        tags=("ssrf", "business-logic"),
        needs=(Need.USER_ACCOUNT,),
        effect=Effect.CHANGES_DATA,
        sub_tests=_CATEGORIES,
        oracle=tuple(case for category in _CATEGORIES for case in _cases(category)),
        essential_sub_tests=_ESSENTIAL,
        decisive_answers=(
            DecisiveAnswer(
                category=ResponseCategory.NO_RESPONSE,
                reason=(
                    "a payload left without an answer may be the server still fetching the "
                    "URL: recorded `SSRF_PROBE_TIMEOUT`, and the payloads after it are not sent."
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
        Send each SSRF payload to the configured endpoint and judge its rejection.

        Args:
            target:  The run's target (surface, resources, path seed).
            context: Carries the acquired tokens.
            client:  The run's HTTP client.
            store:   The test's evidence store.

        Returns:
            self._finish(), self._skip(...), or self._error(exc).
        """
        try:
            cfg = self.params(target)
            endpoint = cfg.url_accepting_endpoint
            if endpoint is None:  # NEEDED_TO_RUN; the engine normally SKIPs first.
                return self._skip("No url_accepting_endpoint configured for test 7.2.")
            payloads = sorted(
                (
                    _Payload(url, desc, cat)
                    for url, desc, cat in ALL_SSRF_PAYLOADS
                    if cat in cfg.payload_categories
                ),
                key=lambda payload: payload.category != _FIRST_CATEGORY,
            )
            if not payloads:
                return self._skip("No SSRF payload category is enabled.")
            try:
                acquire_tokens(target, context, client, required_roles=frozenset({ROLE_USER_A}))
            except (AuthenticationSetupError, SecurityClientError) as exc:
                return self._error(exc)
            auth = auth_parts(target, context, ROLE_USER_A)
            headers, params = dict(auth.headers), dict(auth.params)
            enabled = [c for c in _CATEGORIES if c in cfg.payload_categories]
            try:
                values = self._resource_values(target, context, client, endpoint)
            except (ResourceSetupError, SecurityClientError) as exc:
                # A backend out of rotation or throttled refuses the creation:
                # nothing to probe (until 2026-11-16 the test ended in ERROR).
                log.warning("test_7_2_object_not_created", error=str(exc))
                for category in enabled:
                    self._record(category, Outcome.NOT_VERIFIABLE, "OBJECT_NOT_CREATED")
                return self._finish(message="The prepared resource could not be created.")
            path = str(render(endpoint.path, values))
            # Baseline: a benign well-formed URL, to tell an SSRF defence from a
            # precondition (bad id, auth, down upstream) that rejects every URL.
            control = self._request(
                client, path, endpoint.body, values, _BENIGN_CONTROL_URL, headers, params
            )
            baseline = _situation(control)
            if control is not None:
                self._step(control)
            if baseline in (_SITUATION_UPSTREAM, _SITUATION_TIMEOUT, _SITUATION_RATE_LIMITED):
                # A control the endpoint did not evaluate (down, silent or throttled)
                # leaves nothing to compare the payloads with; the control is not a
                # payload, so its silence is a plain NO_RESPONSE (until 2026-11-16 a
                # silent or failing control was named UPSTREAM_UNAVAILABLE).
                detail = _control_reason(control)
                for category in enabled:
                    self._record(category, Outcome.NOT_VERIFIABLE, detail)
                return self._finish(
                    notes=[_UPSTREAM_NOTE], message=f"endpoint not evaluating URLs at {path}."
                )
            baseline_accepts = baseline == _SITUATION_ACCEPTED
            reflects = control is not None and _BENIGN_MARKER in (control.response_body or "")
            unreachable = self._request(
                client,
                path,
                endpoint.body,
                values,
                f"http://{random_token()}.{_UNREACHABLE_DOMAIN}/",
                headers,
                params,
            )
            if unreachable is not None:
                self._step(unreachable)
            failed_fetch = (
                fingerprint_of(unreachable)
                if unreachable is not None and _situation(unreachable) == _SITUATION_REJECTED
                else None
            )
            series = _Series(
                path,
                endpoint.body,
                values,
                headers,
                params,
                baseline_accepts,
                reflects,
                failed_fetch,
            )
            accepted_any = False
            stopped = False
            for index, payload in enumerate(payloads):
                accepted, stop = self._probe(client, store, series, payload)
                accepted_any |= accepted
                if stop:
                    # The backend hung on an internal URL, or the gateway took it
                    # out of service: each further URL would add a timeout, and a
                    # gateway's health check counts them (on crAPI, Kong's took the
                    # backend out after three, and the tests that ran next got
                    # 503). Not sent; not verifiable (owner decision 2026-11-04).
                    for unsent in payloads[index + 1 :]:
                        self._record(unsent.category, Outcome.NOT_VERIFIABLE, _NOT_SENT)
                    stopped = len(payloads) > index + 1
                    log.warning("test_7_2_stopped", sent=index + 1, total=len(payloads))
                    break
            # The benign URL again: a rejection counts only while the endpoint
            # still accepts it (a quota or a duplicate rule may have started
            # refusing every URL during the series).
            closing = self._request(
                client, path, endpoint.body, values, _BENIGN_CONTROL_URL, headers, params
            )
            if closing is not None:
                self._step(closing)
            still_accepts = _situation(closing) == _SITUATION_ACCEPTED
            for record, category, detail in series.pending:
                if still_accepts:
                    self._judge(record, store, category, Outcome.ENFORCED, detail)
                else:
                    self._judge(record, store, category, Outcome.NOT_VERIFIABLE, _BASELINE_REJECTED)
            notes: list[InfoNote] = []
            if reflects:
                notes.append(_REFLECTS_NOTE)
            if not baseline_accepts or (series.pending and not still_accepts):
                notes.append(_BASELINE_NOTE)
            if stopped:
                notes.append(_STOPPED_NOTE)
            if accepted_any:
                notes.append(_LISTENER_NOTE)
            return self._finish(
                notes=notes or None,
                message=(
                    f"{len(payloads)} payloads on {path}; a PASS needs a cloud-metadata or "
                    "private-IP URL seen rejected."
                ),
            )
        except Exception as exc:  # noqa: BLE001 -- top-level guard (BaseTest contract)
            log.exception("test_7_2_unexpected_error", error=str(exc))
            return self._error(exc)

    def _resource_values(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        endpoint: Test72UrlAcceptingEndpoint,
    ) -> dict[str, str]:
        """Create the endpoint's prepared resource (if any) and return its values."""
        if endpoint.resource is None:
            return {}
        prepared = create_resource(
            target, context, client, endpoint.resource, ROLE_USER_A, self.info.id
        )
        return dict(prepared.values)

    def _request(
        self,
        client: SecurityClient,
        path: str,
        body_template: dict[str, object],
        resource_values: dict[str, str],
        url: str,
        headers: dict[str, str],
        params: dict[str, str],
    ) -> EvidenceRecord | None:
        """Send one URL to the endpoint; its record, or None on a transport failure."""
        secret = secrets.token_hex(_RANDOM_SECRET_BYTES)
        substitutions: dict[str, str] = {
            _PLACEHOLDER_SSRF_URL: url,
            _PLACEHOLDER_RANDOM_SECRET: secret,
            **resource_values,
        }
        body = render(body_template, substitutions)
        try:
            _response, record = client.request(
                "POST",
                path,
                test_id=self.info.id,
                headers=headers or None,
                params=params or None,
                json=body,
            )
        except SecurityClientError as exc:
            return exc.record
        return record

    def _probe(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        series: _Series,
        payload: _Payload,
    ) -> tuple[bool, bool]:
        """
        Send one payload and judge it (info.oracle); an ENFORCED waits in series.pending.

        Returns:
            (accepted, stop): whether the endpoint accepted the URL unproven (a 2xx), and
            whether to send no more (no response, or the gateway's 502, 503 or
            504: the backend hung or is out of service).
        """
        record = self._request(
            client,
            series.path,
            series.body,
            series.values,
            payload.url,
            series.headers,
            series.params,
        )
        situation = _situation(record)
        category = payload.category
        if record is None or situation == _SITUATION_TIMEOUT:
            self._judge_or_record(store, category, Outcome.NOT_VERIFIABLE, _PROBE_TIMEOUT, record)
            log.warning("test_7_2_probe_timeout", category=category, url=payload.url)
            return False, True
        if situation in (_SITUATION_UPSTREAM, _SITUATION_RATE_LIMITED):
            # The shared rule names the answer; a 5xx outside its categories
            # (501, 511) did not evaluate the URL either.
            reason = self._uninformative(record, category) or _NOT_INTERPRETED
            self._judge(record, store, category, Outcome.NOT_VERIFIABLE, reason)
            return False, category_of(record) == ResponseCategory.UPSTREAM_UNAVAILABLE
        if situation == _SITUATION_ACCEPTED:
            body = record.response_body or ""
            if series.reflects and any(marker in body for marker in _METADATA_MARKERS):
                self._judge(
                    record,
                    store,
                    category,
                    Outcome.VIOLATION,
                    _REFLECTED,
                    Finding(
                        title=f"SSRF: internal content returned for {payload.description}",
                        detail=(
                            f"POST {series.path} with the URL {payload.url} answered 2xx with a "
                            "cloud-metadata marker in its body, and the same endpoint returns the "
                            "content of a benign URL it fetches (example.com's page): the server "
                            "fetched an internal address and returned its content (OWASP "
                            "API7:2023, CWE-918, ASVS v5.0.0-1.3.6). Validate the URL against an "
                            "allowlist of destinations and block internal ranges."
                        ),
                        confidence=Confidence.CERTAIN,
                    ),
                )
                return False, False
            self._judge(record, store, category, Outcome.NOT_VERIFIABLE, _OUTBOUND_NOT_CONFIRMED)
            log.info("test_7_2_url_accepted", category=category, url=payload.url)
            return True, False
        not_a_rejection = _NOT_A_REJECTION.get(category_of(record))
        if not_a_rejection is not None or situation != _SITUATION_REJECTED:
            detail = not_a_rejection or _NOT_INTERPRETED
            self._judge(record, store, category, Outcome.NOT_VERIFIABLE, detail)
            return False, False
        if not series.baseline_accepts:
            self._judge(record, store, category, Outcome.NOT_VERIFIABLE, _BASELINE_REJECTED)
            return False, False
        if series.failed_fetch is not None and fingerprint_of(record) == series.failed_fetch:
            # The unreachable URL is answered the same way: the endpoint tried
            # the URL and reports a failed fetch (crAPI's contact_mechanic
            # answers 400 "could not connect"), not a block.
            self._judge(record, store, category, Outcome.NOT_VERIFIABLE, _LIKE_UNREACHABLE)
            return False, False
        series.pending.append(
            (record, category, _classify_rejection(payload.url, record.response_body or ""))
        )
        return False, False

    def _judge_or_record(
        self,
        store: EvidenceStore,
        category: str,
        outcome: Outcome,
        detail: str,
        record: EvidenceRecord | None,
    ) -> None:
        """Judge the record when there is one, else record the outcome without it."""
        if record is not None:
            self._judge(record, store, category, outcome, detail)
        else:
            self._record(category, outcome, detail)


class _Series:
    """What every payload of the series is sent and judged with."""

    def __init__(
        self,
        path: str,
        body: dict[str, object],
        values: dict[str, str],
        headers: dict[str, str],
        params: dict[str, str],
        baseline_accepts: bool,
        reflects: bool,
        failed_fetch: Fingerprint | None,
    ) -> None:
        """Keep the request parts and the controls' lessons; ENFORCED judgements wait in pending."""
        self.path = path
        self.body = body
        self.values = values
        self.headers = headers
        self.params = params
        self.baseline_accepts = baseline_accepts
        self.reflects = reflects
        self.failed_fetch = failed_fetch
        self.pending: list[tuple[EvidenceRecord, str, str]] = []


_REFLECTS_NOTE: InfoNote = InfoNote(
    title="The endpoint returns the content it fetches",
    detail=(
        "The answer to the benign control URL (http://example.com/) carries that page's content: "
        "the endpoint fetches a client URL and returns what it got. An internal address it "
        "accepts is then readable through it; a payload answer carrying a cloud-metadata marker "
        "is reported as proven."
    ),
    references=[Reference(standard=Standard.OWASP_API_TOP10, id="API7:2023")],
)

# One note added to the result when any URL was accepted: it names the deferred
# out-of-band listener that would be needed to turn OUTBOUND_NOT_CONFIRMED
# into a verdict.
_LISTENER_NOTE: InfoNote = InfoNote(
    title="SSRF outbound call not confirmed",
    detail=(
        "One or more SSRF URLs were accepted by the endpoint (a 2xx). Acceptance is not proof "
        "that the server made the outbound call: confirming that needs an out-of-band listener "
        "(a URL the tool controls; a hit on it proves the SSRF), which this tool does not "
        "provide. An accepted URL is therefore reported NOT_VERIFIABLE, never a pass. Review "
        "these endpoints by hand, or point the configured URL at a listener you control."
    ),
    references=[Reference(standard=Standard.OWASP_API_TOP10, id="API7:2023")],
)

# Added when the benign control URL was itself rejected: a precondition rejects
# every URL, so the SSRF rejections are NOT_VERIFIABLE, not an SSRF defence.
_BASELINE_NOTE: InfoNote = InfoNote(
    title="SSRF rejections not attributable to a URL defence",
    detail=(
        "A benign, well-formed control URL was also rejected by the endpoint, so the SSRF "
        "payloads were rejected for a reason unrelated to their target (an invalid resource id, "
        "an authorization or validation precondition, or a down upstream), not by an SSRF "
        "defence. The rejections are reported NOT_VERIFIABLE. Configure the endpoint's body so a "
        "benign URL is accepted (a valid resource id), then re-run."
    ),
    references=[Reference(standard=Standard.OWASP_API_TOP10, id="API7:2023")],
)

# Added when the endpoint did not evaluate URLs at all (down / erroring).
_STOPPED_NOTE: InfoNote = InfoNote(
    title="Payloads not sent after a timeout",
    detail=(
        "A payload left the endpoint without an answer, or the gateway answered 502, 503 or "
        "504: the backend hung on the URL or is out of service. The remaining payloads were not "
        "sent (NOT_SENT_AFTER_TIMEOUT), because each would add a timeout and a gateway's health "
        "check counts them: it can take the backend out of service for every client. Re-run "
        "with fewer payload_categories, or once the endpoint answers again, to verify them."
    ),
    references=[Reference(standard=Standard.OWASP_API_TOP10, id="API7:2023")],
)

_UPSTREAM_NOTE: InfoNote = InfoNote(
    title="URL-accepting endpoint unavailable",
    detail=(
        "The configured url_accepting_endpoint did not return a usable response to a benign "
        "control URL (a 5xx, or no response), so it is down or erroring and could not evaluate "
        "the SSRF payloads. Nothing is verifiable until the endpoint is healthy; re-run then."
    ),
    references=[Reference(standard=Standard.OWASP_API_TOP10, id="API7:2023")],
)


def _situation(record: EvidenceRecord | None) -> str:
    """
    Classify one probe's record: accepted, rejected, throttled, upstream-error, or timeout.

    Args:
        record: The evidence record of the probe, or None on a transport failure.

    Returns:
        One of the _SITUATION_* constants; "other" for an answer of none of them.
    """
    if record is None or record.response_status_code is None:
        return _SITUATION_TIMEOUT
    category = category_of(record)
    if category == ResponseCategory.SERVED:
        return _SITUATION_ACCEPTED
    if category == ResponseCategory.RATE_LIMITED:
        return _SITUATION_RATE_LIMITED
    # Any 5xx: the endpoint did not evaluate the URL (it is down or erroring),
    # never ENFORCED.
    if 500 <= record.response_status_code < 600:
        return _SITUATION_UPSTREAM
    if category in _REJECTING:
        return _SITUATION_REJECTED
    return _SITUATION_OTHER


def _control_reason(record: EvidenceRecord | None) -> str:
    """Why the benign control says nothing: its uninformative category, or a silent 5xx."""
    if record is None:
        return ResponseCategory.NO_RESPONSE.value
    category = category_of(record)
    if category in UNINFORMATIVE_CATEGORIES:
        return category.value
    return _UPSTREAM_UNAVAILABLE


def _classify_rejection(url: str, body: str) -> str:
    """
    How the endpoint rejected the URL, for the ENFORCED detail.

    A non-HTTP scheme is a scheme block even when the stack reports it like a
    malformed URL (Go's net/http). Otherwise the response body's keywords place
    it: a parser error (malformed), an SSRF-aware rejection (validation), or an
    unspecified rejection (unknown). All are ENFORCED; the detail only says how.

    Args:
        url:  The injected payload URL.
        body: The response body text.

    Returns:
        One of the _BLOCKED_* detail constants.
    """
    scheme = urlparse(url).scheme.lower()
    if scheme in _NON_HTTP_SCHEMES:
        return _BLOCKED_SCHEME
    lowered = body.lower()
    if _matches(lowered, _SCHEME_KEYWORDS):
        return _BLOCKED_SCHEME
    if _matches(lowered, _MALFORMED_KEYWORDS):
        return _BLOCKED_MALFORMED
    if _matches(lowered, _VALIDATION_KEYWORDS):
        return _BLOCKED_VALIDATION
    return _BLOCKED_UNKNOWN


def _matches(lowered_body: str, keywords: Sequence[str]) -> bool:
    """True when any keyword is a substring of the already-lowercased body."""
    return any(keyword in lowered_body for keyword in keywords)
