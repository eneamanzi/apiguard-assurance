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

Injection vector (tests.domain_7.test_7_2, no default):
    POST injection_path_template with injection_body_template, where
    "{ssrf_url}" is replaced by each payload URL and "{random_secret}" by a
    fresh random value (registered as a secret). A 2xx response means the
    application accepted the URL without validation; a 4xx that it was
    rejected at validation time.

    With injection_resource, a prepared resource (resources: in config.yaml)
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
from typing import ClassVar, NamedTuple
from urllib.parse import urlparse

import structlog

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
from src.core.templating import render
from src.test_config.domain_7 import (
    TEST_72_PLACEHOLDER_RANDOM_SECRET,
    TEST_72_PLACEHOLDER_SSRF_URL,
)
from src.tests.base import BaseTest
from src.tests.data.ssrf_payloads import ALL_SSRF_PAYLOADS
from src.tests.helpers.auth import acquire_tokens, auth_parts
from src.tests.helpers.resources import create_resource

log: structlog.BoundLogger = structlog.get_logger(__name__)

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


class Test72SSRFPrevention(BaseTest):
    """
    Test 7.2 — The System Prevents Server-Side Request Forgery (SSRF).

    Verifies that user-controlled URLs sent to the configured injection
    endpoint (e.g. Forgejo webhook creation) are validated against private IP
    ranges, cloud metadata endpoints, obfuscated loopback addresses, and
    forbidden protocol schemes.
    """

    test_id: ClassVar[str] = "7.2"
    test_name: ClassVar[str] = "Server-Side Request Forgery (SSRF) Prevention"
    priority: ClassVar[int] = 0
    domain: ClassVar[int] = 7
    strategy: ClassVar[TestStrategy] = TestStrategy.GREY_BOX
    depends_on: ClassVar[list[str]] = []
    requires_pass: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = [
        "ssrf",
        "business-logic",
        "OWASP-API7:2023",
        "CWE-918",
    ]
    cwe_id: ClassVar[str] = "CWE-918"

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
            TestResult(SKIP)  if no injection endpoint is configured, no Grey Box
                              credentials are configured or the user_a token
                              is unavailable.
            TestResult(ERROR) on unexpected infrastructure failure.
        """
        try:
            cfg = target.tests_config.test_7_2
            path_template = cfg.injection_path_template
            body_template = cfg.injection_body_template
            if path_template is None or body_template is None:
                return self._make_skip(
                    reason=(
                        "No SSRF injection endpoint configured: set "
                        "tests.domain_7.test_7_2.injection_path_template and "
                        "injection_body_template to an endpoint of the target that accepts a URL."
                    )
                )

            guard = self._requires_credentials(target)
            if guard is not None:
                return guard

            try:
                acquire_tokens(target, context, client, required_roles=frozenset({ROLE_USER_A}))
            except (AuthenticationSetupError, SecurityClientError) as exc:
                return self._make_error(exc)

            skip = self._requires_token(context, ROLE_USER_A)
            if skip is not None:
                return skip

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

            # The injection endpoint: with injection_resource, the resource is
            # created once for user A (its teardown registered) and its values
            # fill the path and the body; without it, the path is used as written.
            resource_values: dict[str, str] = {}
            if cfg.injection_resource is not None:
                prepared = create_resource(
                    target, context, client, cfg.injection_resource, ROLE_USER_A, self.test_id
                )
                resource_values = dict(prepared.values)
            webhook_path = str(render(path_template, resource_values))

            log.info(
                "test_7_2_injection_endpoint_resolved",
                injection_resource=cfg.injection_resource,
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
                # _make_fail() builds exactly one Finding from self.test_name /
                # self.cwe_id, which matches the single-finding contract of the
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
            resource_values:       Values of injection_resource ({} without it).
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
                    test_id=self.test_id,
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
            resource_values:       Values of injection_resource ({} without it).
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
                test_id=self.test_id,
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
            resource values   -> the values of injection_resource
        Non-string values are preserved. The configuration schema checked the
        names at startup.

        Args:
            ssrf_url:        The SSRF candidate URL to inject.
            body_template:   cfg.injection_body_template.
            resource_values: Values of injection_resource ({} without it).
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
