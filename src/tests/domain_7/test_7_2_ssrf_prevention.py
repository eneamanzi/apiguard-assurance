"""
src/tests/domain_7/test_7_2_ssrf_prevention.py

Test 7.2: guarantee "the system prevents Server-Side Request Forgery" (OWASP
API7:2023, CWE-918, P0).

A URL-accepting endpoint (a webhook, a "fetch from URL" import) must reject a
client URL that points at internal infrastructure: cloud metadata (IMDS),
loopback and RFC-1918 ranges, obfuscated forms of them, non-HTTP schemes,
wildcard-DNS and parser-confusion bypasses. The test sends the SSRF payload
catalogue (src/tests/data/ssrf_payloads.py) to the configured endpoint, one
payload at a time, and judges each.

    cloud_metadata, private_ip, encoding_bypass, forbidden_protocol,
    dns_bypass, url_parser_confusion  -- one sub-test per bypass class; each
                          payload of an enabled class is judged on its own.

Oracle (per payload):
    rejected (a 4xx, or a transport refusal of a bad scheme)   -> ENFORCED
                          (the detail says how: validation, malformed, scheme);
    accepted (a 2xx)                                           -> NOT_VERIFIABLE
                          / OUTBOUND_NOT_CONFIRMED;
    timeout (no response)                                      -> NOT_VERIFIABLE
                          / SSRF_PROBE_TIMEOUT (ambiguous: the server may have
                          blocked on the outbound call).

Honesty boundary (owner decision 2026-10-23): a 2xx means the endpoint accepted
the URL, which is *not* proof the server made the outbound call. Confirming the
call needs an out-of-band listener (a URL the tool controls; a hit on it proves
the SSRF), which is not built and not planned, so an accepted URL is
NOT_VERIFIABLE, never a PASS and never an unproven VIOLATION. This is a
permanent boundary of the test, not a gap waiting to be filled.

GREY_BOX (the endpoint usually needs a credential), effect CHANGES_DATA (it
creates webhooks / submits URLs on the target; with a `resource` the object is
created once and removed at teardown).

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
    EvidenceRecord,
    InfoNote,
    Outcome,
    Reference,
    ResponseCategory,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.templating import (
    names_in,
    occurrences,
    placeholder_names,
    render,
    unquoted_placeholders,
)
from src.core.test_metadata import Effect, Need, TestInfo
from src.tests.base import BaseTest
from src.tests.data.ssrf_payloads import ALL_SSRF_PAYLOADS
from src.tests.helpers.auth import acquire_tokens, auth_parts
from src.tests.helpers.resources import create_resource

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

# Placeholders the test fills in the configured body (src/core/templating.py).
_PLACEHOLDER_SSRF_URL: str = "ssrf_url"
_PLACEHOLDER_RANDOM_SECRET: str = "random_secret"  # noqa: S105 -- a placeholder name

# A 2xx means the endpoint accepted the URL (the outbound call is a separate,
# unobservable event -- see the honesty boundary in the module docstring).
_ACCEPTED_STATUS_CODES: frozenset[int] = frozenset({200, 201, 202, 204})

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
_OUTBOUND_NOT_CONFIRMED: str = "OUTBOUND_NOT_CONFIRMED"
_PROBE_TIMEOUT: str = "SSRF_PROBE_TIMEOUT"
_UPSTREAM_UNAVAILABLE: str = "UPSTREAM_UNAVAILABLE"
_BASELINE_REJECTED: str = "BASELINE_REJECTED"

# A well-formed, non-internal control URL. The endpoint's answer to it is the
# baseline: if even this is rejected, a rejection of an SSRF URL is not proof of
# an SSRF defence (a precondition such as an invalid vehicle id, auth, or a down
# upstream rejects every URL alike), so the SSRF rejections are NOT_VERIFIABLE.
_BENIGN_CONTROL_URL: str = "http://example.com/"

# Response categories that mean the endpoint did not evaluate the URL (it is
# down or erroring), not that it rejected it: never ENFORCED.
_SPOILING: frozenset[ResponseCategory] = frozenset(
    {
        ResponseCategory.UPSTREAM_UNAVAILABLE,
        ResponseCategory.SERVER_ERROR,
        ResponseCategory.NO_RESPONSE,
    }
)

# The situations one probe can land in, from its evidence record.
_SITUATION_ACCEPTED: str = "accepted"
_SITUATION_REJECTED: str = "rejected"
_SITUATION_UPSTREAM: str = "upstream"
_SITUATION_TIMEOUT: str = "timeout"


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
            "e.g. '/api/v1/repos/{owner}/{repo}/hooks'."
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
                "path": "/api/v1/repos/{owner}/{repo}/hooks",
                "body": {"type": "gitea", "config": {"url": "{ssrf_url}", "content_type": "json"}},
                "resource": "repository",
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


class _Payload(NamedTuple):
    """One SSRF payload: the URL to inject, its label, its bypass class."""

    url: str
    description: str
    category: str


class Test72SSRFPrevention(BaseTest[Test72Params]):
    """
    Test 7.2 -- whether a URL-accepting endpoint rejects SSRF payloads.

    The oracle of each sub-test is in the module docstring and on the test page.
    """

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
        ),
        tags=("ssrf", "business-logic"),
        needs=(Need.USER_ACCOUNT,),
        effect=Effect.CHANGES_DATA,
        sub_tests=_CATEGORIES,
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
            payloads = [
                _Payload(url, desc, cat)
                for url, desc, cat in ALL_SSRF_PAYLOADS
                if cat in cfg.payload_categories
            ]
            if not payloads:
                return self._skip("No SSRF payload category is enabled.")
            try:
                acquire_tokens(target, context, client, required_roles=frozenset({ROLE_USER_A}))
            except (AuthenticationSetupError, SecurityClientError) as exc:
                return self._error(exc)
            auth = auth_parts(target, context, ROLE_USER_A)
            headers, params = dict(auth.headers), dict(auth.params)
            values = self._resource_values(target, context, client, endpoint)
            path = str(render(endpoint.path, values))
            enabled = [c for c in _CATEGORIES if c in cfg.payload_categories]
            # Baseline: a benign well-formed URL, to tell an SSRF defence from a
            # precondition (bad id, auth, down upstream) that rejects every URL.
            control = self._request(
                client, path, endpoint.body, values, _BENIGN_CONTROL_URL, headers, params
            )
            baseline = _situation(control)
            if control is not None:
                self._step(control)
            if baseline in (_SITUATION_UPSTREAM, _SITUATION_TIMEOUT):
                for category in enabled:
                    self._record(category, Outcome.NOT_VERIFIABLE, _UPSTREAM_UNAVAILABLE)
                return self._finish(
                    notes=[_UPSTREAM_NOTE], message=f"endpoint not evaluating URLs at {path}."
                )
            baseline_accepts = baseline == _SITUATION_ACCEPTED
            accepted_any = False
            for payload in payloads:
                accepted_any |= self._probe(
                    client,
                    store,
                    path,
                    endpoint.body,
                    values,
                    payload,
                    headers,
                    params,
                    baseline_accepts,
                )
            notes: list[InfoNote] = []
            if accepted_any:
                notes.append(_LISTENER_NOTE)
            if not baseline_accepts:
                notes.append(_BASELINE_NOTE)
            return self._finish(notes=notes or None, message=f"{len(payloads)} payloads on {path}.")
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
        path: str,
        body_template: dict[str, object],
        resource_values: dict[str, str],
        payload: _Payload,
        headers: dict[str, str],
        params: dict[str, str],
        baseline_accepts: bool,
    ) -> bool:
        """
        Send one payload and judge it. Return True when the URL was accepted.

        Oracle (module docstring):
            accepted (2xx)        -> NOT_VERIFIABLE / OUTBOUND_NOT_CONFIRMED;
            rejected (4xx)        -> ENFORCED when the benign control was accepted
                                     (a real SSRF rejection), else NOT_VERIFIABLE /
                                     BASELINE_REJECTED (the endpoint rejects every
                                     URL alike -- not a proof of SSRF defence);
            upstream (5xx, down)  -> NOT_VERIFIABLE / UPSTREAM_UNAVAILABLE;
            no response (timeout) -> NOT_VERIFIABLE / SSRF_PROBE_TIMEOUT.

        Returns:
            True when the endpoint accepted the URL (a 2xx), else False.
        """
        record = self._request(
            client, path, body_template, resource_values, payload.url, headers, params
        )
        situation = _situation(record)
        category = payload.category
        if record is None or situation == _SITUATION_TIMEOUT:
            self._judge_or_record(store, category, Outcome.NOT_VERIFIABLE, _PROBE_TIMEOUT, record)
            log.warning("test_7_2_probe_timeout", category=category, url=payload.url)
            return False
        if situation == _SITUATION_UPSTREAM:
            self._judge(record, store, category, Outcome.NOT_VERIFIABLE, _UPSTREAM_UNAVAILABLE)
            return False
        if situation == _SITUATION_ACCEPTED:
            self._judge(record, store, category, Outcome.NOT_VERIFIABLE, _OUTBOUND_NOT_CONFIRMED)
            log.info("test_7_2_url_accepted", category=category, url=payload.url)
            return True
        if not baseline_accepts:
            self._judge(record, store, category, Outcome.NOT_VERIFIABLE, _BASELINE_REJECTED)
            return False
        detail = _classify_rejection(payload.url, record.response_body or "")
        self._judge(record, store, category, Outcome.ENFORCED, detail)
        return False

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
    Classify one probe's record: accepted, rejected, upstream-error, or timeout.

    Args:
        record: The evidence record of the probe, or None on a transport failure.

    Returns:
        One of the _SITUATION_* constants.
    """
    if record is None or record.response_status_code is None:
        return _SITUATION_TIMEOUT
    status = record.response_status_code
    if status in _ACCEPTED_STATUS_CODES:
        return _SITUATION_ACCEPTED
    if category_of(record) in _SPOILING or 500 <= status < 600:
        return _SITUATION_UPSTREAM
    return _SITUATION_REJECTED


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
