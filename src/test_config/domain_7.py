"""
src/test_config/domain_7.py

Pydantic v2 configuration models for Domain 7 (Business Logic and Sensitive
Flows) tests.

This module owns all per-test tuning parameters for tests 7.x.
It follows the same structural convention as domain_6.py: one *Config class
per test, aggregated by a TestDomain7Config class at the bottom.

Currently implemented tests:
    Test 7.2 -- SSRF Prevention (GREY_BOX, P0)

Adding a new Domain 7 test requires:
    1. Defining a Test7XConfig model in this file.
    2. Adding a field to TestDomain7Config below.
    3. Adding a field to RuntimeTestsConfig (src/test_config/runtime.py); the engine
       wires it automatically (RuntimeTestsConfig.from_domains).
    4. Adding the tests.domain_7.test_7_x block to config.yaml.

Dependency rule: imports only from pydantic and the stdlib.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field, model_validator

# ---------------------------------------------------------------------------
# Constants -- Test 7.2 payload categories
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

# ---------------------------------------------------------------------------
# Constants -- Test 7.2 oracle classification keywords
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Constants -- Test 7.2 injection vector defaults
# ---------------------------------------------------------------------------

# Injection endpoint. No default: it depends on the API, so the test returns
# SKIP until injection_path_template and injection_body_template are set. With
# injection_resource, a prepared resource (resources: in config.yaml) is created
# first and its values fill the path and the body.
#
# Placeholders the test fills in injection_body_template (src/core/templating.py;
# the configuration schema checks them, this module cannot import src.core):
#   {ssrf_url}       each payload URL (required, exactly once)
#   {random_secret}  32 random hexadecimal characters, fresh per request
TEST_72_PLACEHOLDER_SSRF_URL: str = "ssrf_url"
TEST_72_PLACEHOLDER_RANDOM_SECRET: str = "random_secret"  # noqa: S105 -- a placeholder name

# Keys removed in Phase E (docs/project/resources-design.md, 5.6), rejected with
# the new form.
_TEST_72_REMOVED_KEYS: dict[str, str] = {
    "injection_mode": (
        "removed: set injection_resource to the name of a prepared resource (resources:) "
        "whose values fill the path (formerly 'forgejo_webhook'); without it the path is "
        "used as written (formerly 'fixed_path')"
    ),
    "injection_url_field": ("removed: the URL goes where injection_body_template has {ssrf_url}"),
}

# Default intended timeout for individual SSRF probe requests (milliseconds).
# Reserved for future per-request timeout override in SecurityClient.
# Currently the global execution.read_timeout governs all requests.
# NIST SP 800-204 S3.2.2 recommends tight timeouts on outbound connections.
TEST_72_REQUEST_TIMEOUT_MS_DEFAULT: int = 10_000
TEST_72_REQUEST_TIMEOUT_MS_MIN: int = 1_000

# ---------------------------------------------------------------------------
# Test 7.2 -- SSRF Prevention
# ---------------------------------------------------------------------------


class Test72SSRFConfig(BaseModel):
    """
    Tuning parameters for Test 7.2 (SSRF Prevention).

    The test verifies that the system blocks Server-Side Request Forgery by
    rejecting user-controlled URLs that target internal infrastructure, as
    defined by OWASP API7:2023 and methodology section 7.2.

    Injection vector (config-driven, no default):
        An endpoint of the target that accepts a URL, sent as POST. Set
        injection_path_template and injection_body_template (with "{ssrf_url}"
        where the URL goes); without them the test returns SKIP. When the
        endpoint belongs to an object that must exist first, injection_resource
        names a prepared resource created for user A, whose values fill the
        path and the body. Forgejo example (test-environments/forgejo-kong/
        config.yaml): resource 'repository', POST
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

    # -- Injection vector (config-driven) --

    injection_resource: str | None = Field(
        default=None,
        min_length=1,
        description=(
            "Name of a prepared resource (resources: in config.yaml) created for user A "
            "before probing; its values fill the placeholders of injection_path_template "
            "and injection_body_template, and it is deleted at teardown. Optional: without "
            "it the path is used as written."
        ),
    )

    injection_path_template: str | None = Field(
        default=None,
        min_length=1,
        description=(
            "Path of the SSRF injection endpoint (POST). With injection_resource it may "
            "hold the resource's values, e.g. '/api/v1/repos/{owner}/{repo}/hooks'. "
            "Unset (with injection_body_template), the test returns SKIP. "
            "Methodology ref: Garanzia 7.2 -- Injection vector."
        ),
    )

    injection_body_template: dict[str, object] | None = Field(
        default=None,
        description=(
            "JSON body of the injection request; required with injection_path_template. "
            'Must contain "{ssrf_url}" exactly once, replaced by each payload URL; may '
            'contain "{random_secret}" (32 random hexadecimal characters) and, with '
            "injection_resource, the resource's values. Placeholders in quotes. "
            "Methodology ref: Garanzia 7.2 -- Injection vector."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def reject_removed_keys(cls, data: object) -> object:
        """Reject the keys removed in Phase E, naming the new form."""
        if isinstance(data, dict):
            for key, message in _TEST_72_REMOVED_KEYS.items():
                if key in data:
                    raise ValueError(f"{key}: {message} (tests.domain_7.test_7_2).")
        return data

    @model_validator(mode="after")
    def injection_endpoint_complete(self) -> Test72SSRFConfig:
        """
        Require the path and the body together, and both with a resource.

        Without them the test returns SKIP. The placeholders ({ssrf_url} once,
        the resource's values) are checked by the configuration schema, which
        also knows the resources.
        """
        if self.injection_path_template is None and self.injection_body_template is None:
            if self.injection_resource is not None:
                raise ValueError(
                    "injection_resource requires injection_path_template and "
                    "injection_body_template (tests.domain_7.test_7_2)."
                )
            return self
        missing = [
            name
            for name, value in (
                ("injection_path_template", self.injection_path_template),
                ("injection_body_template", self.injection_body_template),
            )
            if not value
        ]
        if missing:
            raise ValueError(
                f"the injection endpoint requires {' and '.join(missing)} "
                "(tests.domain_7.test_7_2)."
            )
        return self

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
            "SecurityClient. Currently the global execution.read_timeout "
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
# Domain-level aggregator
# ---------------------------------------------------------------------------


class TestDomain7Config(BaseModel):
    """
    Aggregator for all Domain 7 (Business Logic and Sensitive Flows) test configs.

    One field per implemented test in the domain.  tests_config.py imports
    only this class.  The default_factory on each field makes the entire
    config.yaml block optional; defaults are methodology-compliant.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    test_7_2: Test72SSRFConfig = Field(
        default_factory=Test72SSRFConfig,
        description=(
            "Tuning parameters for Test 7.2 (SSRF Prevention). "
            "Maps to 'tests.domain_7.test_7_2' in config.yaml."
        ),
    )
