"""
src/tests/domain_7/test_7_2_ssrf_prevention.py

Guarantee 7.2 — The System Prevents Server-Side Request Forgery (SSRF).

References: OWASP API7:2023, CWE-918, OWASP ASVS v5.0.0 V1.3.6,
NIST SP 800-204 Section 3.2.2, methodology section 7.2.

Strategy: GREY_BOX (P0)
    The injection endpoints of the labs (Forgejo webhooks, crAPI
    contact_mechanic) require authentication. The SSRF risk is classified P0 regardless of the
    authentication prerequisite: an authenticated attacker (or one who
    has obtained any valid credential) can still pivot to internal
    infrastructure. See methodology section 7.2, 'Assunzioni e Prerequisiti'.

Priority: P0 (OWASP API7:2023 — critical infrastructure risk)

The endpoint that accepts a URL (tests.domain_7.test_7_2.url_accepting_endpoint,
no default):
    POST its path with its body, where
    "{ssrf_url}" is replaced by each payload URL and "{random_secret}" by a
    fresh random value (registered as a secret). A 2xx response means the
    application accepted the URL without validation; a 4xx that it was
    rejected at validation time.

    With its resource, a prepared resource (resources: in config.yaml)
    is created once for user A before the probes (src/tests/helpers/
    resources.py, teardown registered by it); its values fill the path and
    the body. On the Forgejo labs it is a repository, and the probes create
    webhooks on it (POST /api/v1/repos/{owner}/{repo}/hooks, URL in
    config.url); the hooks go with the repository at teardown. A resource
    that cannot be created gives ERROR.

Sub-tests and oracles:
    A (cloud_metadata)     AWS/GCP/Azure/DigitalOcean IMDS endpoint URLs.
                           2xx  -> SSRF_ALLOWED      -> FAIL finding
                           4xx  -> SSRF_BLOCKED_*    -> no finding
                           timeout -> SSRF_TIMEOUT   -> InfoNote (ambiguous)

    B (private_ip)         RFC-1918, loopback, and unspecified-address URLs
                           (including 0.0.0.0 and [::]).
                           Same oracle as sub-test A.

    C (encoding_bypass)    Obfuscated loopback/IMDS variants (decimal, hex,
                           octal, abbreviated dotted, IPv4-mapped IPv6,
                           URL-encoded, double URL-encoded, mixed-case host).
                           Same oracle as sub-test A.

    D (forbidden_protocol) Non-HTTP protocol URLs (file://, gopher://, etc.).
                           Same oracle as sub-test A.

    E (dns_bypass)         Public wildcard DNS hostnames resolving to private
                           IPs (nip.io, sslip.io). Tests DNS-name blacklist
                           bypass. Same oracle as sub-test A.

    F (url_parser_confusion) Authority-component ambiguity exploits
                           (@ symbol, backslash, embedded credentials).
                           Same oracle as sub-test A.

    G (redirect)           Open-redirect SSRF via operator-controlled server.
                           Executed only when cfg.ssrf_redirect_server_url
                           is non-empty.  SKIP with InfoNote otherwise.

EvidenceStore policy:
    FAIL (2xx) responses -> store.add_fail_evidence(record).
    Non-2xx and timeout responses -> _log_transaction() only; not stored.
    Never call both add_fail_evidence() and pin_evidence() on the same record.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from typing import Annotated, NamedTuple
from urllib.parse import urlparse

import structlog
from pydantic import BaseModel, Field, ValidationInfo, model_validator

from src.core.assessment_test import (
    NEEDED_TO_RUN,
    PARAMS_CONTEXT_RESOURCES,
    REFERS_TO_RESOURCE,
)
from src.core.auth_placement import RequestAuthParts
from src.core.client import SecurityClient
from src.core.context import ROLE_USER_A, TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import AuthenticationSetupError, SecurityClientError
from src.core.models import (
    Finding,
    InfoNote,
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
from src.core.test_metadata import Need, TestInfo
from src.tests.base import BaseTest
from src.tests.data.ssrf_payloads import ALL_SSRF_PAYLOADS
from src.tests.helpers.auth import acquire_tokens, auth_parts
from src.tests.helpers.resources import create_resource

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Parameters: tests.domain_7.test_7_2 in config.yaml
# ---------------------------------------------------------------------------

# All six payload categories available in ssrf_payloads.ALL_SSRF_PAYLOADS.
# The category strings must exactly match the third element of each
# ALL_SSRF_PAYLOADS tuple.  The operator can restrict the probe to a subset
# by overriding this list in config.yaml.
TEST_72_ALL_PAYLOAD_CATEGORIES: list[str] = [
    "cloud_metadata",
    "private_ip",
    "encoding_bypass",
    "forbidden_protocol",
    "dns_bypass",
    "url_parser_confusion",
]

# Keywords that, when found in a non-2xx response body, confirm that the
# application rejected the SSRF URL through explicit validation rather than
# some other error path.
#
# Methodology ref: Garanzia 7.2 -- oracle classification.
TEST_72_BLOCK_RESPONSE_KEYWORDS_DEFAULT: list[str] = [
    "invalid host",
    "not allowed",
    "forbidden",
    "scheme not supported",
    "scheme not allowed",
    "host not allowed",
    "private",
    "loopback",
    "blocked",
    "disallowed",
    "restricted",
]

# Keywords that, when found in a non-2xx response body, indicate the URL was
# rejected because it is syntactically invalid to the application's HTTP
# client or URL parser -- NOT because of an explicit SSRF defence.
#
# These keywords are checked BEFORE ssrf_block_response_keywords.  A match
# produces oracle state SSRF_BLOCKED_AS_MALFORMED_URL; the distinction
# prevents overstating the application's defensive posture in the report.
#
# Example: Go's net/url rejects "http://%31%32%37%2e%30%2e%30%2e%31"
# with "invalid character" (RFC 3986 forbids percent-encoded octets in
# host components), which Forgejo propagates as a 422.  This is a parser
# side-effect, not an SSRF-aware block.
#
# Methodology ref: Garanzia 7.2 -- oracle classification note.
TEST_72_MALFORMED_URL_KEYWORDS_DEFAULT: list[str] = [
    "invalid character",
    "invalid url",
    "url malformed",
    "malformed url",
    "parse error",
    "url parse",
    "could not parse",
    "bad url",
]

# Keywords that, when found in a non-2xx response body, indicate the URL was
# rejected because its scheme (protocol) is not supported by the application --
# NOT because the URL is syntactically malformed and NOT because of an explicit
# SSRF IP/range defence.
#
# This is a third classification level checked AFTER ssrf_malformed_url_keywords
# and BEFORE ssrf_block_response_keywords.  A match produces oracle state
# SSRF_BLOCKED_UNSUPPORTED_SCHEME.
#
# The distinction matters for report accuracy:
#   - file:///etc/passwd is syntactically VALID (RFC 3986 compliant), but
#     Forgejo rejects it with "Invalid url" because Go's net/http only dials
#     http/https schemes.  Classifying this as SSRF_BLOCKED_AS_MALFORMED_URL
#     is technically wrong -- the URL is well-formed, the scheme is just not
#     accepted.
#   - Separating this state makes the Audit Trail honest: the protocol was
#     blocked, but not because of SSRF-aware IP range validation.
#
# In Forgejo, the response body for unsupported schemes is the same "Invalid url"
# as for malformed URLs (both come from Go's net/url validator).  To distinguish
# them, the test checks the *injected URL's scheme* directly (see
# _classify_blocked_state in test_7_2_ssrf_prevention.py) rather than relying
# solely on keyword matching.  These keywords serve as a fallback for other
# application stacks that emit more descriptive error messages.
#
# Methodology ref: Garanzia 7.2 -- oracle classification, level 2 (new).
TEST_72_UNSUPPORTED_SCHEME_KEYWORDS_DEFAULT: list[str] = [
    "scheme not supported",
    "scheme not allowed",
    "unsupported scheme",
    "unsupported protocol",
    "invalid scheme",
    "only http",
    "only https",
    "protocol not allowed",
]

# The endpoint that accepts a URL (url_accepting_endpoint). No default: it
# depends on the API, so the test returns SKIP until it is set.
#
# Placeholders the test fills in its body (src/core/templating.py):
#   {ssrf_url}       each payload URL (required, exactly once)
#   {random_secret}  32 random hexadecimal characters, fresh per request
TEST_72_PLACEHOLDER_SSRF_URL: str = "ssrf_url"

TEST_72_PLACEHOLDER_RANDOM_SECRET: str = "random_secret"  # noqa: S105 -- a placeholder name


# Default intended timeout for individual SSRF probe requests (milliseconds).
# Reserved for future per-request timeout override in SecurityClient.
# Currently the global target.read_timeout governs all requests.
# NIST SP 800-204 S3.2.2 recommends tight timeouts on outbound connections.
TEST_72_REQUEST_TIMEOUT_MS_DEFAULT: int = 10_000

TEST_72_REQUEST_TIMEOUT_MS_MIN: int = 1_000


class Test72UrlAcceptingEndpoint(BaseModel):
    """
    An endpoint of the API that accepts a URL and makes the server call it.

    The test POSTs the body to the path once per payload URL, written where the
    body has "{ssrf_url}". With resource, a prepared resource is created first
    for user A, its values fill the path and the body, and it is deleted at
    teardown. Checked against config.resources through the validation context
    (src/config/tests_section.py); without it (defaults) only the shape is.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    path: str = Field(
        min_length=1,
        description=(
            "Path of the endpoint (POST). With resource it may hold the resource's values, "
            "e.g. '/api/v1/repos/{owner}/{repo}/hooks'."
        ),
    )
    body: dict[str, object] = Field(
        description=(
            'JSON body of the request. Must contain "{ssrf_url}" exactly once, replaced by '
            'each payload URL; may contain "{random_secret}" (32 random hexadecimal '
            "characters) and, with resource, the resource's values. Placeholders in quotes."
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
        """
        Check the path and the body against the resource, when the resources are known.

        resource must name a resource of config.yaml; the path may use its
        values; the body must hold {ssrf_url} exactly once and may use
        {random_secret} and the resource's values, in quotes
        (docs/04-architecture/05-design-decisions.md, D6).
        """
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
                f"{', '.join(f'{{{n}}}' for n in sorted(unknown))}; known: the values of "
                "resource."
            )
        known = values | {TEST_72_PLACEHOLDER_SSRF_URL, TEST_72_PLACEHOLDER_RANDOM_SECRET}
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
        count = occurrences(self.body, TEST_72_PLACEHOLDER_SSRF_URL)
        if count != 1:
            raise ValueError(
                f'body must contain "{{{TEST_72_PLACEHOLDER_SSRF_URL}}}" exactly once, where '
                f"the SSRF URL goes (found {count})."
            )
        return self


class Test72Params(BaseModel):
    """
    Tuning parameters for Test 7.2 (SSRF Prevention).

    The test verifies that the system blocks Server-Side Request Forgery by
    rejecting user-controlled URLs that target internal infrastructure, as
    defined by OWASP API7:2023 and methodology section 7.2.

    The endpoint that accepts a URL (config-driven, no default):
        url_accepting_endpoint, an endpoint of the target that accepts a URL,
        sent as POST: its path and body (with "{ssrf_url}" where the URL
        goes); without it the test returns SKIP. When the endpoint belongs to
        an object that must exist first, its resource names a prepared
        resource created for user A, whose values fill the path and the body.
        Forgejo example (test-environments/forgejo-kong/config.yaml): resource
        'repository', POST
        /api/v1/repos/{owner}/{repo}/hooks with the URL in config.url.

    Sub-tests:
        A (cloud_metadata):       Cloud IMDS endpoints (AWS EC2, AWS ECS,
                                  GCP, Azure, DigitalOcean).
                                  Oracle: 4xx -> PASS; 2xx -> FAIL.
        B (private_ip):           RFC-1918 and loopback IP URLs.
                                  Oracle: 4xx -> PASS; 2xx -> FAIL.
        C (encoding_bypass):      Obfuscated loopback/IMDS variants (decimal,
                                  hex, octal, IPv4-mapped IPv6, URL-encoded).
                                  Oracle: 4xx -> PASS; 2xx -> FAIL.
        D (forbidden_protocol):   Non-HTTP protocol URLs.
                                  Oracle: 4xx -> PASS; 2xx -> FAIL.
        E (dns_bypass):           nip.io / sslip.io wildcard DNS hostnames
                                  resolving to private IPs.
                                  Oracle: 4xx -> PASS; 2xx -> FAIL.
        F (url_parser_confusion): @ authority ambiguity and backslash exploits
                                  (Orange Tsai, BlackHat 2017).
                                  Oracle: 4xx -> PASS; 2xx -> FAIL.
        G (redirect):             Open-redirect chain via operator-controlled
                                  server. Executed only when
                                  ssrf_redirect_server_url is non-empty.
                                  Oracle: 4xx -> PASS; 2xx -> FAIL; SKIP
                                  otherwise.

    EvidenceStore policy:
        Every 2xx (FAIL) response is stored via store.add_fail_evidence().
        Non-2xx (PASS) and SecurityClientError (timeout) responses are logged
        via _log_transaction() only; not stored in EvidenceStore.

    Design note -- GREY_BOX at P0:
        The injection endpoints of the labs (Forgejo webhooks, crAPI
        contact_mechanic) require authentication. SSRF is OWASP API7:2023 P0 regardless of the
        authentication prerequisite; an authenticated attacker can still
        pivot to internal infrastructure. GREY_BOX reflects the auth
        prerequisite, not a lower risk classification.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    # -- Payload categories --

    payload_categories: tuple[str, ...] = Field(
        default_factory=lambda: tuple(TEST_72_ALL_PAYLOAD_CATEGORIES),
        description=(
            "Payload categories to include in the SSRF probe. "
            "Valid values: 'cloud_metadata', 'private_ip', 'encoding_bypass', "
            "'forbidden_protocol', 'dns_bypass', 'url_parser_confusion'. "
            "Removing a category reduces coverage; the omitted sub-test is not "
            "reported as SKIP -- the category is simply not probed. "
            f"Default: all six categories {TEST_72_ALL_PAYLOAD_CATEGORIES}."
        ),
    )

    # -- The endpoint that accepts a URL (config-driven, no default) --

    url_accepting_endpoint: Test72UrlAcceptingEndpoint | None = Field(
        default=None,
        examples=[
            {
                "path": "/api/repos/{repo_id}/hooks",
                "body": {"callback_url": "{ssrf_url}"},
                "resource": "repository",
            }
        ],
        json_schema_extra=NEEDED_TO_RUN,
        description=(
            "An endpoint of the API that accepts a URL from the client and makes the server "
            "call it (a webhook, an import from a URL): path, body and, optionally, a prepared "
            "resource. The test sends the SSRF payload URLs to it. No default: unset, the test "
            "returns SKIP."
        ),
    )

    # -- Redirect sub-test (sub-test G) --

    ssrf_redirect_server_url: str = Field(
        default="",
        description=(
            "URL of an operator-controlled public server that responds with "
            "302 Location pointing to an internal SSRF target "
            "(e.g. http://169.254.169.254/...). "
            "When non-empty, sub-test G (redirect following) is executed: "
            "the injection URL is set to this server and the oracle checks "
            "whether the application re-validates the redirected target URL. "
            "When empty (default), sub-test G is SKIPPED with an InfoNote "
            "documenting the gap. "
            "This server must be reachable from the test runner's network "
            "and must be under your control. "
            "Default: '' (empty -- redirect sub-test skipped)."
        ),
    )

    # -- Oracle classification keywords --

    ssrf_block_response_keywords: tuple[str, ...] = Field(
        default_factory=lambda: tuple(TEST_72_BLOCK_RESPONSE_KEYWORDS_DEFAULT),
        description=(
            "Case-insensitive substrings checked against the response body of "
            "non-2xx SSRF probe responses. "
            "A match classifies the oracle state as SSRF_BLOCKED_BY_VALIDATION "
            "(explicit URL rejection). No match produces SSRF_BLOCKED_UNKNOWN "
            "(URL rejected for an unspecified reason). "
            "Both states produce no Finding. "
            "Override with gateway- or application-specific error message "
            "fragments for more precise Audit Trail classification. "
            f"Default: {TEST_72_BLOCK_RESPONSE_KEYWORDS_DEFAULT}."
        ),
    )

    ssrf_malformed_url_keywords: tuple[str, ...] = Field(
        default_factory=lambda: tuple(TEST_72_MALFORMED_URL_KEYWORDS_DEFAULT),
        description=(
            "Case-insensitive substrings that, when found in a non-2xx SSRF "
            "probe response body, indicate the URL was rejected because it is "
            "syntactically invalid to the HTTP parser -- NOT because of an "
            "explicit SSRF defence and NOT because the scheme is unsupported. "
            "Checked FIRST (Level 1). "
            "A match produces oracle state SSRF_BLOCKED_AS_MALFORMED_URL. "
            "No Finding is generated; the distinction only affects the Audit "
            "Trail column of the HTML report. "
            "Example: Go's net/url rejects 'http://%31%32%37...' with "
            "'invalid character'; this is a parser side-effect, not an "
            "SSRF-aware block. "
            f"Default: {TEST_72_MALFORMED_URL_KEYWORDS_DEFAULT}."
        ),
    )

    ssrf_unsupported_scheme_keywords: tuple[str, ...] = Field(
        default_factory=lambda: tuple(TEST_72_UNSUPPORTED_SCHEME_KEYWORDS_DEFAULT),
        description=(
            "Case-insensitive substrings that, when found in a non-2xx SSRF "
            "probe response body, indicate the URL was rejected because its "
            "scheme (protocol) is not accepted by the application -- NOT "
            "because the URL is syntactically malformed and NOT because of an "
            "explicit SSRF IP/range defence. "
            "Checked SECOND (Level 2), after ssrf_malformed_url_keywords. "
            "A match produces oracle state SSRF_BLOCKED_UNSUPPORTED_SCHEME. "
            "No Finding is generated. "
            "Important: in Forgejo/Go, 'file://', 'gopher://', 'dict://' etc. "
            "are rejected with the same 'Invalid url' message as malformed URLs. "
            "The test therefore also checks the injected URL's scheme directly "
            "when the response body gives no clear signal -- these keywords "
            "serve as a fallback for application stacks with more descriptive "
            "error messages. "
            f"Default: {TEST_72_UNSUPPORTED_SCHEME_KEYWORDS_DEFAULT}."
        ),
    )

    # -- Probe timeout --

    ssrf_request_timeout_ms: Annotated[
        int,
        Field(ge=TEST_72_REQUEST_TIMEOUT_MS_MIN),
    ] = Field(
        default=TEST_72_REQUEST_TIMEOUT_MS_DEFAULT,
        description=(
            "Intended timeout in milliseconds for individual SSRF probe requests. "
            "Reserved for future per-request timeout override support in "
            "SecurityClient. Currently the global target.read_timeout "
            "governs all requests; this field documents the operator's intent "
            "and will be honoured automatically once SecurityClient supports "
            "per-request timeout overrides. "
            "NIST SP 800-204 Section 3.2.2 recommends tight timeouts on "
            "outbound connections from API servers. "
            f"Default: {TEST_72_REQUEST_TIMEOUT_MS_DEFAULT} ms (10 s). "
            f"Minimum: {TEST_72_REQUEST_TIMEOUT_MS_MIN} ms."
        ),
    )


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Label of the generated webhook secret in the redacted evidence (Q-31).
_WEBHOOK_SECRET_LABEL: str = "7.2 webhook secret"  # noqa: S105 -- a label, not a credential

# Bytes of the value of {random_secret} (32 hexadecimal characters).
_RANDOM_SECRET_BYTES: int = 16

# HTTP status codes considered 'accepted' -- the webhook was created and
# the URL was not validated.  A 201 is the normal success code; 200 would
# be unusual but equally dangerous.
_ACCEPTED_STATUS_CODES: frozenset[int] = frozenset({200, 201})

# Oracle state labels for the Audit Trail column in the HTML report.
_STATE_SSRF_ALLOWED: str = "SSRF_ALLOWED"
_STATE_SSRF_BLOCKED_AS_MALFORMED_URL: str = "SSRF_BLOCKED_AS_MALFORMED_URL"
_STATE_SSRF_BLOCKED_UNSUPPORTED_SCHEME: str = "SSRF_BLOCKED_UNSUPPORTED_SCHEME"
_STATE_SSRF_BLOCKED_BY_VALIDATION: str = "SSRF_BLOCKED_BY_VALIDATION"
_STATE_SSRF_BLOCKED_UNKNOWN: str = "SSRF_BLOCKED_UNKNOWN"
_STATE_SSRF_TIMEOUT: str = "SSRF_TIMEOUT"
_STATE_SSRF_REDIRECT_ALLOWED: str = "SSRF_REDIRECT_ALLOWED"
_STATE_SSRF_REDIRECT_BLOCKED: str = "SSRF_REDIRECT_BLOCKED"
_STATE_SSRF_REDIRECT_TIMEOUT: str = "SSRF_REDIRECT_TIMEOUT"

# References cited in every Finding produced by this test.
# URL schemes that are not HTTP/HTTPS and whose rejection must be classified
# as SSRF_BLOCKED_UNSUPPORTED_SCHEME rather than SSRF_BLOCKED_AS_MALFORMED_URL.
# These URLs are syntactically valid (RFC 3986 compliant) -- they carry a
# well-formed scheme, authority, and path.  Forgejo/Go rejects them with the
# same "Invalid url" body as malformed URLs because net/http only dials http
# and https.  The response body alone is therefore insufficient to distinguish
# "syntactically broken URL" from "valid URL with unsupported scheme".
# Checking the scheme of the *injected URL* directly resolves the ambiguity.
_NON_HTTP_SCHEMES: frozenset[str] = frozenset(
    {
        "file",
        "gopher",
        "dict",
        "ftp",
        "ldap",
        "tftp",
        "sftp",
        "netdoc",
        "jar",
        "data",
    }
)

_REFERENCES: tuple[str, ...] = (
    "OWASP-API7:2023",
    "CWE-918",
    "OWASP-ASVS-v5.0.0-V1.3.6",
    "NIST-SP-800-204-S3.2.2",
)

# Redirect sub-test skip message (sub-test G, redirect server absent).
_REDIRECT_SKIP_REASON: str = (
    "Sub-test G (SSRF via redirect chain) was not executed: "
    "cfg.ssrf_redirect_server_url is empty. "
    "To test redirect-following SSRF, configure an operator-controlled public "
    "server that responds with 302 Location pointing to an internal target "
    "(e.g. http://169.254.169.254/...) and set "
    "'tests.domain_7.test_7_2.ssrf_redirect_server_url' in config.yaml."
)


# ---------------------------------------------------------------------------
# Internal data structures
# ---------------------------------------------------------------------------


class _SSRFPayloadEntry(NamedTuple):
    """
    Typed representation of a single SSRF payload from ALL_SSRF_PAYLOADS.

    Using NamedTuple (not dataclass) to remain hashable and avoidcollection
    with mutable-default pitfalls.  NamedTuple fields are read-only by design.

    Attributes:
        url:         The URL string to inject into the webhook config.url field.
        description: Short label used in Finding.detail and log entries.
        category:    Category string matching ALL_SSRF_PAYLOADS tuple element [2].
    """

    url: str
    description: str
    category: str


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------


class Test72SSRFPrevention(BaseTest[Test72Params]):
    """
    Test 7.2 — The System Prevents Server-Side Request Forgery (SSRF).

    Verifies that user-controlled URLs sent to the configured injection
    endpoint (e.g. Forgejo webhook creation) are validated against private IP
    ranges, cloud metadata endpoints, obfuscated loopback addresses, and
    forbidden protocol schemes.
    """

    info = TestInfo(
        id="7.2",
        name="Server-Side Request Forgery (SSRF) Prevention",
        priority=0,
        strategy=TestStrategy.GREY_BOX,
        cwe="CWE-918",
        tags=(
            "ssrf",
            "business-logic",
            "OWASP-API7:2023",
            "CWE-918",
        ),
        needs=(Need.USER_ACCOUNT,),
    )

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Probe the configured injection endpoint with SSRF payloads and verify rejection.

        Execution sequence:
            1. Guard: GREY_BOX credentials must be present.
            2. Acquire tokens for all configured roles.
            3. Guard: user_a token must be available.
            4. Create assessment test repository (Phase 6 teardown registered
               immediately on creation).
            5. Sub-tests A-D: for each enabled payload category, POST a webhook
               creation request with the SSRF URL in config.url.
            6. Sub-test G: test open-redirect SSRF if redirect server configured.
            7. Return PASS/FAIL based on accumulated findings.

        Returns:
            TestResult(PASS)  if all probed SSRF URLs were rejected (4xx) or
                              timed out with no successful acceptance.
            TestResult(FAIL)  if one or more SSRF URLs were accepted (2xx).
                              Each acceptance produces one Finding.
            TestResult(SKIP)  if no payload category is enabled (without the
                              user_a credentials or the injection endpoint
                              the engine records SKIP before running it:
                              info.needs, NEEDED_TO_RUN).
            TestResult(ERROR) on unexpected infrastructure failure.
        """
        try:
            cfg = self.params(target)
            endpoint = cfg.url_accepting_endpoint
            # NEEDED_TO_RUN: the engine skips the test when it is unset.
            assert endpoint is not None  # noqa: S101
            path_template = endpoint.path
            body_template = endpoint.body

            try:
                acquire_tokens(target, context, client, required_roles=frozenset({ROLE_USER_A}))
            except (AuthenticationSetupError, SecurityClientError) as exc:
                return self._make_error(exc)

            user_a_auth = auth_parts(target, context, ROLE_USER_A)

            # Build active payload set from the enabled categories.
            active_payloads = self._build_active_payloads(cfg.payload_categories)

            if not active_payloads:
                return self._make_skip(
                    reason=(
                        "No SSRF payload categories are enabled in "
                        "cfg.payload_categories. Nothing to probe."
                    )
                )

            log.info(
                "test_7_2_starting",
                payload_count=len(active_payloads),
                categories=cfg.payload_categories,
                redirect_server_configured=bool(cfg.ssrf_redirect_server_url),
            )

            # The endpoint that accepts a URL: with a resource, the resource is
            # created once for user A (its teardown registered) and its values
            # fill the path and the body; without it, the path is used as written.
            resource_values: dict[str, str] = {}
            if endpoint.resource is not None:
                prepared = create_resource(
                    target, context, client, endpoint.resource, ROLE_USER_A, self.info.id
                )
                resource_values = dict(prepared.values)
            webhook_path = str(render(path_template, resource_values))

            log.info(
                "test_7_2_injection_endpoint_resolved",
                resource=endpoint.resource,
                webhook_path=webhook_path,
            )

            # Accumulate findings across all sub-tests.
            findings: list[Finding] = []
            timeout_notes: list[InfoNote] = []

            # Sub-tests A-F: systematic SSRF payload injection.
            findings, timeout_notes = self._run_payload_subtests(
                payloads=active_payloads,
                webhook_path=webhook_path,
                user_a_auth=user_a_auth,
                cfg_keywords=cfg.ssrf_block_response_keywords,
                cfg_malformed_keywords=cfg.ssrf_malformed_url_keywords,
                cfg_scheme_keywords=cfg.ssrf_unsupported_scheme_keywords,
                cfg_body_template=dict(body_template),
                resource_values=resource_values,
                client=client,
                store=store,
                context=context,
            )

            # Sub-test G: open-redirect SSRF.
            self._run_redirect_subtest(
                redirect_server_url=cfg.ssrf_redirect_server_url,
                webhook_path=webhook_path,
                user_a_auth=user_a_auth,
                cfg_keywords=cfg.ssrf_block_response_keywords,
                cfg_malformed_keywords=cfg.ssrf_malformed_url_keywords,
                cfg_scheme_keywords=cfg.ssrf_unsupported_scheme_keywords,
                body_template=dict(body_template),
                resource_values=resource_values,
                client=client,
                store=store,
                context=context,
                findings=findings,
                timeout_notes=timeout_notes,
            )
            if findings:
                finding_count = len(findings)
                log.info(
                    "test_7_2_ssrf_vulnerabilities_found",
                    finding_count=finding_count,
                    timeout_note_count=len(timeout_notes),
                )
                # Use _make_fail() with notes so timeout_notes (ambiguous probe
                # outcomes documented as InfoNote) are preserved in the TestResult
                # alongside the confirmed SSRF findings.  Before this fix,
                # TestResult(...) was built directly here without notes=, causing
                # timeout annotations to be silently dropped from the report.
                #
                # _make_fail() builds exactly one Finding from self.info.name /
                # self.info.cwe, which matches the single-finding contract of the
                # native helper.  The full list of per-payload findings is NOT
                # individually surfaced here because the native _make_fail() is
                # designed for a single consolidated Finding; the per-payload
                # detail is available in the transaction_log and evidence.json.
                return self._make_fail(
                    message=(
                        f"{finding_count} SSRF vulnerability/vulnerabilities detected: "
                        f"the application accepted webhook URLs targeting internal "
                        f"infrastructure without validation."
                    ),
                    detail=(
                        f"{finding_count} SSRF payload(s) produced an unblocked response "
                        f"(2xx / redirect to private IP). "
                        f"The webhook creation endpoint did not reject URLs targeting "
                        f"internal infrastructure. "
                        f"See transaction_log and evidence.json for per-payload detail."
                    ),
                    notes=timeout_notes if timeout_notes else None,
                )

            all_notes = timeout_notes or None
            pass_message = (
                f"All {len(active_payloads)} SSRF payload(s) were correctly rejected. "
                f"Webhook creation endpoint enforces URL validation against internal targets."
            )
            if not cfg.ssrf_redirect_server_url:
                # Append redirect gap note only when no redirect test ran.
                redirect_gap_note = InfoNote(
                    title="Sub-test G (Redirect Following) Not Executed",
                    detail=_REDIRECT_SKIP_REASON,
                    references=list(_REFERENCES),
                )
                all_notes = list(timeout_notes) + [redirect_gap_note]

            return self._make_pass(message=pass_message, notes=all_notes or None)

        except Exception as exc:  # noqa: BLE001
            return self._make_error(exc)

    # ---------------------------------------------------------------------------
    # Private helpers
    # ---------------------------------------------------------------------------

    def _build_active_payloads(self, categories: Sequence[str]) -> list[_SSRFPayloadEntry]:
        """
        Filter ALL_SSRF_PAYLOADS to the configured category subset.

        Args:
            categories: List of category strings to include.

        Returns:
            List of _SSRFPayloadEntry with only the matching categories.
            Order matches the declaration order in ALL_SSRF_PAYLOADS.
        """
        active: list[_SSRFPayloadEntry] = []
        category_set: frozenset[str] = frozenset(categories)
        for url, description, category in ALL_SSRF_PAYLOADS:
            if category in category_set:
                active.append(
                    _SSRFPayloadEntry(url=url, description=description, category=category)
                )
        return active

    def _run_payload_subtests(
        self,
        payloads: list[_SSRFPayloadEntry],
        webhook_path: str,
        user_a_auth: RequestAuthParts,
        cfg_keywords: Sequence[str],
        cfg_malformed_keywords: Sequence[str],
        cfg_scheme_keywords: Sequence[str],
        cfg_body_template: dict[str, object],
        resource_values: dict[str, str],
        client: SecurityClient,
        store: EvidenceStore,
        context: TestContext,
    ) -> tuple[list[Finding], list[InfoNote]]:
        """
        Execute sub-tests A-F: inject each payload URL into the configured body template.

        For each payload, POST an injection request and classify the response
        according to the oracle logic documented in the module docstring.

        Args:
            payloads:              Active payload entries to probe.
            webhook_path:          Resolved injection endpoint path.
            user_a_auth:           Request parts carrying the user_a credential.
            cfg_keywords:          Case-insensitive SSRF-validation block keywords.
            cfg_malformed_keywords: Case-insensitive URL-parser-error keywords;
                                   checked FIRST (Level 1) to detect syntactically
                                   broken URLs before scheme or SSRF checks.
            cfg_scheme_keywords:   Case-insensitive keywords that identify URLs
                                   rejected for having an unsupported scheme
                                   (Level 2 check). The test also inspects the
                                   injected URL's scheme directly when response
                                   bodies are not discriminant (e.g. Forgejo).
            cfg_body_template:     Operator-configured request body template.
                                   Filled by _build_webhook_body on each probe.
            resource_values:       Values of the endpoint's resource ({} without it).
            client:                Centralized HTTP client.
            store:                 Evidence store for FAIL transactions.

        Returns:
            Tuple of (findings, timeout_notes).
            findings      -- One Finding per accepted (2xx) URL.
            timeout_notes -- One InfoNote per timed-out probe request.
        """
        findings: list[Finding] = []
        timeout_notes: list[InfoNote] = []

        for entry in payloads:
            log.debug(
                "test_7_2_probing_payload",
                category=entry.category,
                description=entry.description,
                url=entry.url,
            )

            webhook_body = self._build_webhook_body(
                ssrf_url=entry.url,
                body_template=cfg_body_template,
                resource_values=resource_values,
                context=context,
            )

            try:
                response, record = client.request(
                    method="POST",
                    path=webhook_path,
                    test_id=self.info.id,
                    headers=dict(user_a_auth.headers),
                    params=dict(user_a_auth.params) or None,
                    json=webhook_body,
                )
            except SecurityClientError as exc:
                # Transport-layer failure: the server did not respond before
                # the read timeout expired.  This can indicate that Forgejo
                # attempted an outbound connection to the SSRF target and
                # blocked on it.  Outcome is ambiguous: document as InfoNote.
                log.warning(
                    "test_7_2_probe_timeout",
                    category=entry.category,
                    description=entry.description,
                    url=entry.url,
                    error=str(exc),
                )
                timeout_notes.append(
                    InfoNote(
                        title=(f"SSRF Probe Timeout: {entry.category} / {entry.description}"),
                        detail=(
                            f"POST {webhook_path} with SSRF URL '{entry.url}' "
                            f"({entry.description}) did not return a response "
                            f"within the configured read timeout. "
                            f"This may indicate the server attempted an outbound "
                            f"connection to the SSRF target and blocked on it "
                            f"(ambiguous outcome -- potential SSRF). "
                            f"Transport error: {exc}"
                        ),
                        references=list(_REFERENCES),
                    )
                )
                continue

            if response.status_code in _ACCEPTED_STATUS_CODES:
                # The URL was accepted without validation: when the
                # application uses it (e.g. a webhook firing), it will attempt
                # an outbound HTTP request to entry.url.
                store.add_fail_evidence(record)
                self._log_transaction(record, oracle_state=_STATE_SSRF_ALLOWED, is_fail=True)
                findings.append(
                    Finding(
                        title=(
                            f"SSRF URL Accepted by the Injection Endpoint: "
                            f"{entry.category} / {entry.description}"
                        ),
                        detail=(
                            f"POST {webhook_path} with SSRF URL '{entry.url}' "
                            f"({entry.description}, category: {entry.category}) "
                            f"returned HTTP {response.status_code}. "
                            f"The URL was accepted without validation. When the "
                            f"application uses it (for example a webhook firing), "
                            f"it would issue an outbound HTTP request to "
                            f"'{entry.url}', potentially "
                            f"exposing cloud credentials (IMDS), internal service "
                            f"data, or enabling internal network enumeration. "
                            f"Expected: 4xx rejection at URL validation time."
                        ),
                        references=list(_REFERENCES),
                        evidence_ref=record.record_id,
                    )
                )
                log.info(
                    "test_7_2_ssrf_url_accepted",
                    category=entry.category,
                    description=entry.description,
                    url=entry.url,
                    status_code=response.status_code,
                )
            else:
                # Non-2xx: URL was rejected.  Classify the oracle state with
                # three-level precedence:
                #   1. Parser-level rejection (malformed URL syntax) →
                #      SSRF_BLOCKED_AS_MALFORMED_URL
                #   2. Explicit SSRF validation keyword matched →
                #      SSRF_BLOCKED_BY_VALIDATION
                #   3. Unknown rejection cause →
                #      SSRF_BLOCKED_UNKNOWN
                oracle_state = self._classify_blocked_state(
                    response_body=response.text,
                    injected_url=entry.url,
                    malformed_keywords=cfg_malformed_keywords,
                    scheme_keywords=cfg_scheme_keywords,
                    block_keywords=cfg_keywords,
                )
                self._log_transaction(record, oracle_state=oracle_state)
                log.debug(
                    "test_7_2_ssrf_url_blocked",
                    category=entry.category,
                    description=entry.description,
                    url=entry.url,
                    status_code=response.status_code,
                    oracle_state=oracle_state,
                )

        return findings, timeout_notes

    def _run_redirect_subtest(
        self,
        redirect_server_url: str,
        webhook_path: str,
        user_a_auth: RequestAuthParts,
        cfg_keywords: Sequence[str],
        cfg_malformed_keywords: Sequence[str],
        cfg_scheme_keywords: Sequence[str],
        body_template: dict[str, object],
        resource_values: dict[str, str],
        client: SecurityClient,
        store: EvidenceStore,
        context: TestContext,
        findings: list[Finding],
        timeout_notes: list[InfoNote],
    ) -> bool | None:
        """
        Execute sub-test G: SSRF via open-redirect chain.

        Implements sub-test G. Skips with an InfoNote appended to
        timeout_notes if the redirect server URL is empty. Otherwise, injects
        the redirect server URL into the body_template and verifies that the
        application re-validates the final redirect destination.

        Args:
            redirect_server_url:   Operator-controlled redirect server URL.
            webhook_path:          Resolved injection endpoint path.
            user_a_auth:           Request parts carrying the user_a credential.
            cfg_keywords:          SSRF-validation block keywords.
            cfg_malformed_keywords: URL-parser-error keywords; checked first.
            cfg_scheme_keywords:   Unsupported-scheme keywords; checked second.
            body_template:         Operator-configured request body template.
            resource_values:       Values of the endpoint's resource ({} without it).
            client:                Centralized HTTP client.
            store:                 Evidence store for FAIL transactions.
            findings:              Mutable list; findings are appended in-place.
            timeout_notes:         Mutable list; InfoNote entries appended in-place.

        Returns:
            True  if the sub-test ran (redirect server configured).
            None  if the sub-test was skipped (redirect server not configured).
        """
        if not redirect_server_url:
            # Gap documented as InfoNote on the PASS result; no SKIP raised here
            # because sub-tests A-D may have already produced findings that
            # override this.  The redirect gap note is appended by the caller.
            return None

        log.info(
            "test_7_2_redirect_subtest_starting",
            redirect_server_url=redirect_server_url,
        )

        webhook_body = self._build_webhook_body(
            ssrf_url=redirect_server_url,
            body_template=body_template,
            resource_values=resource_values,
            context=context,
        )

        try:
            response, record = client.request(
                method="POST",
                path=webhook_path,
                test_id=self.info.id,
                headers=dict(user_a_auth.headers),
                params=dict(user_a_auth.params) or None,
                json=webhook_body,
            )
        except SecurityClientError as exc:
            log.warning(
                "test_7_2_redirect_probe_timeout",
                redirect_server_url=redirect_server_url,
                error=str(exc),
            )
            timeout_notes.append(
                InfoNote(
                    title="SSRF Redirect Sub-test Timeout",
                    detail=(
                        f"POST {webhook_path} with redirect server URL "
                        f"'{redirect_server_url}' (sub-test G) did not return "
                        f"a response within the configured read timeout. "
                        f"Transport error: {exc}"
                    ),
                    references=list(_REFERENCES),
                )
            )
            return None

        if response.status_code in _ACCEPTED_STATUS_CODES:
            store.add_fail_evidence(record)
            self._log_transaction(record, oracle_state=_STATE_SSRF_REDIRECT_ALLOWED, is_fail=True)
            findings.append(
                Finding(
                    title="SSRF via Open-Redirect Chain: Redirect URL Accepted",
                    detail=(
                        f"POST {webhook_path} with redirect server URL "
                        f"'{redirect_server_url}' (sub-test G) returned "
                        f"HTTP {response.status_code}. "
                        f"The application accepted the webhook URL without "
                        f"re-validating the redirect destination. "
                        f"An attacker can use a public redirect server that "
                        f"chains to an internal target to bypass IP-based "
                        f"SSRF blacklists. "
                        f"Expected: 4xx -- the application must validate the "
                        f"final redirect target, not only the initial URL."
                    ),
                    references=list(_REFERENCES),
                    evidence_ref=record.record_id,
                )
            )
        else:
            oracle_state = self._classify_blocked_state(
                response_body=response.text,
                injected_url=redirect_server_url,
                malformed_keywords=cfg_malformed_keywords,
                scheme_keywords=cfg_scheme_keywords,
                block_keywords=cfg_keywords,
            )
            self._log_transaction(record, oracle_state=oracle_state)
            log.info(
                "test_7_2_redirect_url_blocked",
                redirect_server_url=redirect_server_url,
                status_code=response.status_code,
                oracle_state=oracle_state,
            )

        return True

    @staticmethod
    def _build_webhook_body(
        ssrf_url: str,
        body_template: dict[str, object],
        resource_values: dict[str, str],
        context: TestContext,
    ) -> dict[str, object]:
        """
        Construct the injection request body from the operator-configured template.

        Fills every placeholder (src/core/templating.py) at any depth:
            {ssrf_url}        -> ssrf_url (the payload URL to inject)
            {random_secret}   -> secrets.token_hex(16), fresh per call
            resource values   -> the values of the endpoint's resource
        Non-string values are preserved. The configuration schema checked the
        names at startup.

        Args:
            ssrf_url:        The SSRF candidate URL to inject.
            body_template:   the endpoint's body.
            resource_values: Values of the endpoint's resource ({} without it).
            context:         The run's TestContext: the generated secret is
                             registered there, so it is redacted in the evidence.

        Returns:
            Dict suitable for passing as the json= argument to client.request().
        """
        random_secret: str = secrets.token_hex(_RANDOM_SECRET_BYTES)
        context.register_secret(random_secret, _WEBHOOK_SECRET_LABEL)
        body = render(
            body_template,
            {
                **resource_values,
                TEST_72_PLACEHOLDER_SSRF_URL: ssrf_url,
                TEST_72_PLACEHOLDER_RANDOM_SECRET: random_secret,
            },
        )
        assert isinstance(body, dict)  # noqa: S101 -- render keeps the structure (mypy narrowing)
        return body

    @staticmethod
    def _classify_blocked_state(
        response_body: str,
        injected_url: str,
        malformed_keywords: Sequence[str],
        scheme_keywords: Sequence[str],
        block_keywords: Sequence[str],
    ) -> str:
        """
        Classify a non-2xx response with four-level oracle precedence.

        The four levels are applied in order; the first match wins.

        Level 1 — Unsupported URL scheme:
            If the scheme of `injected_url` is in _NON_HTTP_SCHEMES (primary
            check via urlparse), OR any `scheme_keywords` substring is present
            in the response body (fallback for verbose stacks), return
            SSRF_BLOCKED_UNSUPPORTED_SCHEME.

            This level is checked FIRST -- before malformed keywords -- because
            Forgejo/Go returns the same "Invalid url" response body for both
            non-HTTP schemes (file://, gopher://) and syntactically invalid
            http:// URLs (percent-encoded hosts, backslash tricks).  If this
            level were checked second, 'file:///etc/passwd' would incorrectly
            match the "invalid url" keyword at Level 2 and be classified as
            SSRF_BLOCKED_AS_MALFORMED_URL.  By checking scheme first, non-HTTP
            URLs are correctly classified before the malformed check runs.

        Level 2 — Syntactically malformed URL (parser error):
            If any `malformed_keywords` substring is present in the response
            body, return SSRF_BLOCKED_AS_MALFORMED_URL.  At this point the
            URL's scheme is known to be http/https (Level 1 did not match),
            so "invalid url" in malformed_keywords is unambiguous: the URL is
            genuinely broken at the syntax level, not rejected for its scheme.
            Example: 'http://%31%32%37%2e...' (percent-encoded host, RFC 3986
            violation) and 'http://safe.example.com\\@127.0.0.1/' (backslash
            authority trick) both produce "Invalid url" in Forgejo.

        Level 3 — Explicit SSRF validation:
            If any `block_keywords` substring is present, return
            SSRF_BLOCKED_BY_VALIDATION.  The application has an explicit
            IP/hostname/scheme blocklist (e.g. 'loopback', 'private',
            'host not allowed').

        Level 4 — Unknown rejection cause:
            None of the above matched.  Return SSRF_BLOCKED_UNKNOWN.
            No Finding is generated for any of the four blocked states;
            the distinction exists solely for Audit Trail accuracy.

        Args:
            response_body:      Raw response body text (may be empty).
            injected_url:       The URL that was injected into the request.
                                Used in Level 1 to inspect the scheme directly.
            malformed_keywords: URL-parser-error keyword list (Level 2).
            scheme_keywords:    Unsupported-scheme keyword list (Level 1
                                fallback for verbose application stacks).
            block_keywords:     SSRF-validation keyword list (Level 3).

        Returns:
            One of: _STATE_SSRF_BLOCKED_UNSUPPORTED_SCHEME,
                    _STATE_SSRF_BLOCKED_AS_MALFORMED_URL,
                    _STATE_SSRF_BLOCKED_BY_VALIDATION,
                    _STATE_SSRF_BLOCKED_UNKNOWN.
        """
        body_lower = response_body.lower()

        # Level 1: unsupported URL scheme.
        # Extract the scheme from the injected URL directly via urlparse (stdlib).
        # This check must come BEFORE the malformed-keywords check at Level 2
        # because Forgejo/Go returns the same "Invalid url" body for both
        # non-HTTP schemes (file://, gopher://) and syntactically malformed
        # http:// URLs (percent-encoded hosts, backslash tricks).
        # By checking the scheme first, a non-HTTP URL like 'file:///etc/passwd'
        # is immediately classified as SSRF_BLOCKED_UNSUPPORTED_SCHEME without
        # ever reaching the "invalid url" keyword at Level 2.  An http:// URL
        # with an invalid host passes Level 1 and is correctly caught at Level 2.
        try:
            injected_scheme = urlparse(injected_url).scheme.lower()
        except Exception:  # noqa: BLE001
            injected_scheme = ""
        if injected_scheme in _NON_HTTP_SCHEMES:
            return _STATE_SSRF_BLOCKED_UNSUPPORTED_SCHEME
        # Fallback: keyword matching for stacks with descriptive error messages
        # (e.g. "scheme not allowed" on non-Forgejo targets).
        for keyword in scheme_keywords:
            if keyword.lower() in body_lower:
                return _STATE_SSRF_BLOCKED_UNSUPPORTED_SCHEME

        # Level 2: syntactically malformed URL (parser-level error).
        # "invalid url" is safe here because Level 1 has already handled all
        # non-HTTP schemes.  Any remaining URL with "invalid url" in the response
        # body has an http:// or https:// scheme and is therefore a genuine
        # parse failure (e.g. percent-encoded host, backslash authority trick).
        for keyword in malformed_keywords:
            if keyword.lower() in body_lower:
                return _STATE_SSRF_BLOCKED_AS_MALFORMED_URL

        # Level 3: explicit SSRF IP/hostname validation keyword.
        for keyword in block_keywords:
            if keyword.lower() in body_lower:
                return _STATE_SSRF_BLOCKED_BY_VALIDATION

        # Level 4: rejection cause unknown.
        return _STATE_SSRF_BLOCKED_UNKNOWN
