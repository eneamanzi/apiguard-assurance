"""
src/tests/domain_6/test_6_4_hardcoded_credentials_audit.py

Test 6.4 -- Hardcoded Credentials Audit.

Guarantee (3_TOP_metodologia.md, Section 6.4):
    Service credentials used by the Gateway (database passwords, API keys,
    TLS private keys) must be managed via a dedicated Secret Manager and must
    NOT be hardcoded in configuration files, environment variables exposed via
    debug endpoints, or container image layers.  Credentials that are static
    and non-rotating cannot be revoked without redeployment and, once exposed
    via path traversal or repository leak, provide direct backend access
    bypassing the Gateway entirely.

    This test covers the two sub-tests that are mechanically verifiable from
    outside the infrastructure without filesystem access:

    Sub-test A -- Debug / Actuator Endpoint Exposure (empirical, always runs):
        Unauthenticated GET requests are sent to a configurable list of debug
        and actuator paths (Spring Boot /actuator/env, Go /debug/vars, etc.).
        A 2xx response whose body contains credential-like patterns is a FAIL.
        The desired outcome is 401, 403, or 404 on every probed path.

    Sub-test B -- Kong Admin API Configuration Audit (runs only when Admin API
        is available):
        The Kong Admin API is queried for services and plugins.  Every service
        URL and every plugin configuration value is scanned with compiled regex
        patterns for known credential formats (URL-embedded credentials, AWS
        Access Key IDs, Stripe live/test keys, GitHub PATs) and for high-entropy
        values in semantically sensitive config keys (password, secret, api_key,
        token, credential).  Any match is a FAIL finding.

    Sub-test B gap note (Admin API absent):
        When target.admin_api_available is False, Sub-test B cannot run.
        Rather than returning SKIP (which would conceal the result of Sub-test A),
        the test attaches an InfoNote documenting the audit gap.  The operator
        must perform a manual configuration audit to close the gap.

Strategy: WHITE_BOX -- Configuration Audit (methodology section 6.4).
    Sub-test A uses only network connectivity (no credentials); it is
    BLACK_BOX in nature but is classified under WHITE_BOX at the test level
    because its primary function is a configuration audit.  Sub-test B requires
    Kong Admin API access, which is the defining characteristic of WHITE_BOX
    tests in this tool.  The test runs Sub-test A regardless of Admin API
    availability, making it useful even in fully DB-less Kong deployments.

Priority: P2 -- Application Logic / Defense in Depth (methodology matrix).
    Hardcoded credentials are a critical vulnerability if exploited but require
    insider access or a separate path traversal to exploit; they are not
    directly exploitable from the network perimeter alone.

Sub-tests (executed in this order):
--------------------------------------------------------------------------
Sub-test A -- Debug endpoint probe
    For each path in cfg.debug_endpoint_paths:
        1. Send unauthenticated GET.
        2. If status is 2xx: scan response body with all credential patterns.
        3. If any pattern matches: FAIL finding with matched pattern name,
           path, and status code.
        4. If no pattern matches: INFO log (accessible but no credentials).
        5. If status is not 2xx: log as ENDPOINT_BLOCKED (desired outcome).

    Oracle:
        2xx response + credential pattern match  -> FAIL
        2xx response + no credential pattern     -> no finding (still informative)
        Non-2xx response                         -> ENDPOINT_BLOCKED (best outcome)

Sub-test B -- Kong Admin API credential scan
    Executed only when target.admin_api_available is True.
    1. Fetch all services from /services.
    2. For each service: scan the 'url' field with URL credential pattern.
    3. Fetch all plugins from /plugins.
    4. For each plugin: recursively scan the 'config' dict with all patterns.
    5. Semantic check: for config keys matching _SEMANTIC_CREDENTIAL_KEYS,
       flag values with length >= _MIN_CREDENTIAL_VALUE_LENGTH that are not
       in _PLACEHOLDER_STRINGS.

    Oracle:
        URL-embedded credentials found in service URL  -> FAIL
        Known credential pattern found in plugin config -> FAIL
        Semantic key with high-entropy value found      -> FAIL
        No matches                                      -> no additional finding
--------------------------------------------------------------------------

EvidenceStore policy:
    Sub-test A: every HTTP transaction is logged via _log_transaction().
    Transactions that produce a FAIL finding are additionally stored via
    store.add_fail_evidence() for inclusion in evidence.json.
    Sub-test B: no EvidenceRecord objects are produced (Kong Admin API helper
    uses its own internal httpx client, not SecurityClient).  The transaction_log
    for Sub-test B findings will be empty -- this is correct per the config-audit
    pattern documented in ADDING_TESTS.md.
"""

from __future__ import annotations

import re
from typing import Any, ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import (
    Finding,
    InfoNote,
    TestResult,
    TestStatus,
    TestStrategy,
)
from src.tests.base import BaseTest
from src.tests.helpers.kong_admin import KongAdminError, get_plugins, get_services

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Oracle state labels (appear verbatim in the HTML Audit Trail column)
# ---------------------------------------------------------------------------

_STATE_ENDPOINT_BLOCKED: str = "ENDPOINT_BLOCKED"
_STATE_ENDPOINT_BLOCKED_BY_APP: str = "ENDPOINT_BLOCKED_BY_APP"
_STATE_ENDPOINT_OPEN_NO_CREDS: str = "ENDPOINT_OPEN_NO_CREDENTIALS"
_STATE_ENDPOINT_OPEN_WITH_DATA: str = "ENDPOINT_OPEN_WITH_DATA"
_STATE_CREDENTIAL_EXPOSED: str = "CREDENTIAL_EXPOSED"

# ---------------------------------------------------------------------------
# Credential detection constants
# ---------------------------------------------------------------------------

# Minimum length (characters) for a config value to be considered a real
# credential rather than a placeholder such as 'xxx' or 'CHANGE_ME'.
# Rationale: placeholders are typically short; real secrets are >= 8 chars.
_MIN_CREDENTIAL_VALUE_LENGTH: int = 8

# Known placeholder strings that must NOT trigger a finding even if the
# config key is semantically sensitive.  Case-insensitive comparison is
# applied during scanning (lowercased before membership test).
_PLACEHOLDER_STRINGS: frozenset[str] = frozenset(
    {
        "change_me",
        "changeme",
        "changeit",
        "change-me",
        "xxx",
        "yyy",
        "zzz",
        "placeholder",
        "example",
        "your_secret",
        "your-secret",
        "your_password",
        "your-password",
        "password",
        "password123",
        "secret",
        "secret123",
        "none",
        "null",
        "false",
        "true",
        "0",
        "1",
        "",
        "test",
        "testing",
        "sample",
        "replace_me",
        "replace-me",
        "todo",
    }
)

# Config key fragments whose presence in a plugin config key name suggests
# the value is a credential.  Matched case-insensitively as substrings.
_SEMANTIC_CREDENTIAL_KEY_FRAGMENTS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "api-key",
        # Note: 'token' is intentionally excluded.  It is too broad and would
        # produce false positives on legitimate rate-limiting config fields such
        # as 'tokens_consumed_per_request'.  Use specific compound forms instead.
        "auth_token",
        "authtoken",
        "access_token",
        "refresh_token",
        "bearer_token",
        "credential",
        "credentials",
        "private_key",
        "privatekey",
        "private-key",
        "access_key",
        "accesskey",
        "secret_key",
        "secretkey",
        "client_secret",
        "clientsecret",
        "db_password",
        "db_passwd",
        "database_password",
        "redis_password",
        "smtp_password",
    }
)

# ---------------------------------------------------------------------------
# Compiled credential detection patterns
# ---------------------------------------------------------------------------

# Named tuples: (compiled_pattern, human_readable_name).
# All patterns are applied to both response bodies (Sub-test A) and plugin
# config string values (Sub-test B).
#
# Pattern sources:
#   URL-embedded credentials:  RFC 3986 userinfo component; OWASP ASVS V13.3.1.
#   AWS Access Key ID:         AWS IAM key format (20-char AKIA prefix).
#   Stripe keys:               Stripe API key format documentation.
#   GitHub PAT:                GitHub token format (ghp_ prefix, 36 alphanum).
#   Private key material:      PKCS#1 / SEC1 PEM header (RFC 7468).
_CREDENTIAL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"://[^:@\s\"']{1,64}:[^@\s\"']{8,}@"),
        "URL-embedded credentials (user:password@host)",
    ),
    (
        re.compile(r"AKIA[A-Z0-9]{16}"),
        "AWS Access Key ID (AKIA prefix)",
    ),
    (
        re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
        "Stripe live API key (sk_live_ prefix)",
    ),
    (
        re.compile(r"sk_test_[A-Za-z0-9]{24,}"),
        "Stripe test API key (sk_test_ prefix)",
    ),
    (
        re.compile(r"ghp_[A-Za-z0-9]{36}"),
        "GitHub Personal Access Token (ghp_ prefix)",
    ),
    (
        re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
        "PEM private key material",
    ),
]

# ---------------------------------------------------------------------------
# Standard references cited in every Finding produced by this test
# ---------------------------------------------------------------------------

_REFERENCES: list[str] = [
    "CWE-798",
    "OWASP-API8:2023",
    "OWASP-ASVS-V13.3.1",
    "OWASP-ASVS-V13.3.4",
    "OWASP-ASVS-V13.4.1",
    "NIST-SP-800-53-Rev5-IA-5(1)",
    "NIST-SP-800-204-S5.4",
]


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------


class Test64HardcodedCredentialsAudit(BaseTest):
    """
    Test 6.4 -- Hardcoded Credentials Audit.

    Verifies that service credentials are not exposed via accessible debug
    endpoints or hardcoded in Kong service/plugin configuration.

    Combines an empirical Black-Box probe (Sub-test A, always runs) with an
    optional Admin API configuration audit (Sub-test B, runs only when
    target.admin_api_available is True).
    """

    test_id: ClassVar[str] = "6.4"
    test_name: ClassVar[str] = "Service Credentials Not Hardcoded or Exposed"
    priority: ClassVar[int] = 2
    domain: ClassVar[int] = 6
    strategy: ClassVar[TestStrategy] = TestStrategy.WHITE_BOX
    depends_on: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = [
        "hardcoded-credentials",
        "secret-management",
        "configuration-audit",
        "CWE-798",
        "OWASP-API8:2023",
    ]
    cwe_id: ClassVar[str] = "CWE-798"

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Run Sub-test A (debug endpoint probe) always; run Sub-test B (Admin API
        audit) only when the Admin API is available.

        Returns FAIL if any credential pattern match is found in either sub-test.
        Returns PASS (possibly with an InfoNote gap warning) when no matches are
        found.  Never returns SKIP: Sub-test A always has work to do.
        """
        try:
            cfg = target.tests_config.test_6_4

            log.info(
                "test_6_4_starting",
                debug_paths_count=len(cfg.debug_endpoint_paths),
                admin_api_available=target.admin_api_available,
            )

            findings: list[Finding] = []

            # ---- Sub-test A: debug endpoint probe (always) ---------------
            a_findings, a_notes = self._probe_debug_endpoints(
                cfg.debug_endpoint_paths,
                cfg.gateway_block_body_fragment,
                target,
                client,
                store,
            )
            findings.extend(a_findings)

            # ---- Sub-test B: Kong Admin API audit (conditional) ----------
            notes: list[InfoNote] = list(a_notes)  # start with any open-with-data notes
            if target.admin_api_available:
                admin_base_url = target.admin_endpoint_base_url()
                # admin_endpoint_base_url() returns None only when
                # admin_api_url is None, already excluded by the
                # admin_api_available guard above.
                assert admin_base_url is not None, (  # noqa: S101
                    "admin_endpoint_base_url() returned None despite "
                    "admin_api_available=True. TargetContext invariant violation."
                )
                b_findings = self._audit_kong_configuration(admin_base_url)
                findings.extend(b_findings)
                # Always document the inherent scope limits of this test,
                # even when the Admin API audit ran successfully.  The HTTP-only
                # tool cannot inspect docker-compose files, Dockerfiles,
                # OS-level environment variables, or container image layers.
                notes.append(
                    InfoNote(
                        title=(
                            "Manual Verification Required: Filesystem and Container "
                            "Layer Credentials Not Auditable via HTTP"
                        ),
                        detail=(
                            "This test audits Kong service/plugin configuration via "
                            "the Admin API and probes known debug endpoints over HTTP. "
                            "It CANNOT detect hardcoded credentials in: "
                            "(1) docker-compose.yml or .env files "
                            "(e.g. POSTGRES_PASSWORD, SECRET_KEY environment variables); "
                            "(2) Dockerfile ENV or RUN layers "
                            "(inspect with: docker history <image>); "
                            "(3) OS-level environment variables injected at runtime "
                            "(inspect with: docker inspect <container> | grep -i env); "
                            "(4) Secret Manager references vs. literal values "
                            "(only a filesystem audit can distinguish them). "
                            "Manual action required: run "
                            "'grep -rEi "
                            '"(password|secret|api_key|token)\\s*[=:]\\s*\\S{8,}" '
                            "docker-compose.yml .env Dockerfile' "
                            "and review all environment variable blocks for plaintext "
                            "credentials. "
                            "References: OWASP ASVS V13.3.1, CWE-798, "
                            "NIST SP 800-53 IA-5(1)."
                        ),
                        references=[
                            "OWASP-ASVS-V13.3.1",
                            "CWE-798",
                            "NIST-SP-800-53-Rev5-IA-5(1)",
                        ],
                    )
                )
            else:
                notes.append(
                    InfoNote(
                        title="Admin API Audit Gap: Kong Configuration Not Scanned",
                        detail=(
                            "The Kong Admin API is not configured "
                            "(target.admin_api_available=False). "
                            "Sub-test B -- which scans Kong service URLs and plugin "
                            "configs for hardcoded credentials -- could not run. "
                            "To close this gap, configure 'target.admin_api_url' in "
                            "config.yaml and re-run the assessment with WHITE_BOX "
                            "strategy enabled. "
                            "Manual action required: inspect /etc/kong/kong.conf and "
                            "all plugin config blocks for credential-like values. "
                            "References: OWASP ASVS V13.3.1, CWE-798."
                        ),
                        references=["OWASP-ASVS-V13.3.1", "CWE-798"],
                    )
                )

            if findings:
                return TestResult(
                    test_id=self.test_id,
                    status=TestStatus.FAIL,
                    message=f"{len(findings)} hardcoded credential exposure(s) detected.",
                    findings=findings,
                    notes=notes,
                    transaction_log=list(self._transaction_log),
                    **self._metadata_kwargs(),
                )

            return self._make_pass(
                message=(
                    f"No credential patterns detected across "
                    f"{len(cfg.debug_endpoint_paths)} debug path(s) probed"
                    + (
                        " and Kong service/plugin configuration audited."
                        if target.admin_api_available
                        else ". Kong configuration audit skipped (Admin API unavailable)."
                    )
                ),
                notes=notes,
            )

        except Exception as exc:  # noqa: BLE001
            log.exception("test_6_4_unexpected_error", error=str(exc))
            return self._make_error(exc)

    # ------------------------------------------------------------------
    # Sub-test A helpers: debug endpoint probe
    # ------------------------------------------------------------------

    def _probe_debug_endpoints(
        self,
        paths: list[str],
        gateway_block_fragment: str,
        target: TargetContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> tuple[list[Finding], list[InfoNote]]:
        """
        Send unauthenticated GET to each configured debug path.

        Returns a tuple of:
          - findings: list of Finding objects (one per path where a credential
            pattern is detected in a 2xx response body).
          - notes: list of InfoNote objects for paths that return 2xx with
            structured data but no credential patterns (open-with-data state).

        Oracle states produced:
          ENDPOINT_BLOCKED         -- non-2xx from Gateway (deny-by-default).
                                      Identified by gateway_block_fragment in body.
          ENDPOINT_BLOCKED_BY_APP  -- non-2xx forwarded to and rejected by the app.
          ENDPOINT_OPEN_NO_CREDENTIALS -- 2xx, no patterns detected, empty body.
          ENDPOINT_OPEN_WITH_DATA  -- 2xx, structured response, no credentials.
          CREDENTIAL_EXPOSED       -- 2xx, credential pattern match (FAIL).

        Args:
            paths: List of paths to probe.
            gateway_block_fragment: Substring identifying a Gateway-level block
                in a non-2xx response body.  Empty string disables the distinction
                (all non-2xx classified as ENDPOINT_BLOCKED).
            target: TargetContext (used for base URL resolution via client).
            client: SecurityClient for HTTP requests.
            store: EvidenceStore for FAIL evidence persistence.
        """
        findings: list[Finding] = []
        notes: list[InfoNote] = []

        for path in paths:
            log.debug("test_6_4_probing_debug_path", path=path)

            try:
                response, record = client.request(
                    method="GET",
                    path=path,
                    test_id=self.test_id,
                    # No Authorization header: unauthenticated probe.
                )
            except Exception as exc:  # noqa: BLE001
                # Transport error (connection refused, timeout): the endpoint
                # is unreachable, which is a safe outcome.  Log and continue.
                log.warning(
                    "test_6_4_debug_probe_transport_error",
                    path=path,
                    error=str(exc),
                )
                continue

            status = response.status_code
            is_success = 200 <= status < 300
            body = response.text

            if not is_success:
                # Distinguish Gateway-level block from application-level block.
                # When gateway_block_fragment is non-empty and found in the body,
                # the Gateway rejected the request before forwarding it.
                # Otherwise the Gateway forwarded and the app rejected — still
                # safe, but architecturally distinct: the upstream app saw the request.
                # An empty gateway_block_fragment disables the distinction entirely.
                if gateway_block_fragment and gateway_block_fragment in body:
                    oracle_state = _STATE_ENDPOINT_BLOCKED
                    log.debug(
                        "test_6_4_debug_endpoint_blocked_by_gateway",
                        path=path,
                        status_code=status,
                    )
                else:
                    oracle_state = _STATE_ENDPOINT_BLOCKED_BY_APP
                    log.debug(
                        "test_6_4_debug_endpoint_blocked_by_app",
                        path=path,
                        status_code=status,
                    )
                self._log_transaction(record, oracle_state=oracle_state)
                continue

            # 2xx: the debug endpoint is reachable without authentication.
            # Scan the response body for credential patterns.
            matched = self._scan_text_for_credentials(body)

            if matched:
                store.add_fail_evidence(record)
                self._log_transaction(
                    record,
                    oracle_state=_STATE_CREDENTIAL_EXPOSED,
                    is_fail=True,
                )
                for pattern_name, snippet in matched:
                    log.warning(
                        "test_6_4_credential_pattern_matched",
                        path=path,
                        status_code=status,
                        pattern=pattern_name,
                    )
                    findings.append(
                        Finding(
                            title=(f"Credential Pattern Exposed via Debug Endpoint: {path}"),
                            detail=(
                                f"Sent GET {path} with no Authorization header. "
                                f"Received HTTP {status}. "
                                f"Response body matched the pattern: "
                                f"'{pattern_name}'. "
                                f"Partial match (redacted): {snippet!r}. "
                                f"Debug endpoints that return 2xx to unauthenticated "
                                f"requests and whose body contains credential-like "
                                f"patterns expose service secrets to any network "
                                f"attacker. The endpoint must return 401/403 or be "
                                f"disabled entirely in production. "
                                f"References: OWASP ASVS V13.3.1, CWE-798, "
                                f"NIST SP 800-204 Section 5.4."
                            ),
                            references=_REFERENCES,
                            evidence_ref=record.record_id,
                        )
                    )
            elif body.strip():
                # 2xx with a non-empty body but no credential patterns.
                # The endpoint is accessible without authentication and returns
                # structured data.  This is information disclosure even if no
                # credential is present: an attacker learns server configuration
                # parameters.  Record as OPEN_WITH_DATA and emit an InfoNote.
                self._log_transaction(
                    record,
                    oracle_state=_STATE_ENDPOINT_OPEN_WITH_DATA,
                )
                body_preview = body.strip()[:200]
                log.info(
                    "test_6_4_debug_endpoint_open_with_data",
                    path=path,
                    status_code=status,
                    body_preview=body_preview,
                )
                notes.append(
                    InfoNote(
                        title=(f"Unauthenticated Debug Endpoint Returns Structured Data: {path}"),
                        detail=(
                            f"GET {path} returned HTTP {status} without authentication. "
                            f"No credential pattern was detected in the response body, "
                            f"but the endpoint returns non-empty structured data "
                            f"(preview: {body_preview!r}). "
                            f"This constitutes information disclosure about server "
                            f"configuration. The endpoint should require authentication "
                            f"(401/403) or be disabled in production. "
                            f"No credential pattern match was detected, so this is "
                            f"recorded as an informational note rather than a finding. "
                            f"If this endpoint is intentionally public, verify that its "
                            f"response never includes sensitive configuration values "
                            f"under any server configuration. "
                            f"References: OWASP API8:2023 Security Misconfiguration, "
                            f"OWASP ASVS V13.3.1, CWE-497."
                        ),
                        references=[
                            "OWASP-API8:2023",
                            "OWASP-ASVS-V13.3.1",
                            "CWE-497",
                        ],
                    )
                )
            else:
                # 2xx with empty body — no data, no credentials.
                self._log_transaction(
                    record,
                    oracle_state=_STATE_ENDPOINT_OPEN_NO_CREDS,
                )
                log.info(
                    "test_6_4_debug_endpoint_open_empty_body",
                    path=path,
                    status_code=status,
                )

        return findings, notes

    # ------------------------------------------------------------------
    # Sub-test B helpers: Kong Admin API credential scan
    # ------------------------------------------------------------------

    def _audit_kong_configuration(self, admin_base_url: str) -> list[Finding]:
        """
        Scan Kong services and plugins for hardcoded credential patterns.

        Returns a list of Finding objects.  An empty list means no credential
        patterns were found in the audited configuration.
        """
        findings: list[Finding] = []

        log.info("test_6_4_admin_audit_starting", admin_base_url=admin_base_url)

        # ---- Scan service URLs ----------------------------------------
        services = self._fetch_services(admin_base_url)
        if services is not None:
            for svc in services:
                svc_name: str = svc.get("name", "<unnamed>")
                url_value: str | None = svc.get("url")
                if url_value and isinstance(url_value, str):
                    matched = self._scan_text_for_credentials(url_value)
                    for pattern_name, snippet in matched:
                        log.warning(
                            "test_6_4_credential_in_service_url",
                            service_name=svc_name,
                            pattern=pattern_name,
                        )
                        findings.append(
                            Finding(
                                title=(f"Credential Hardcoded in Kong Service URL: {svc_name}"),
                                detail=(
                                    f"Kong service '{svc_name}' has a URL field "
                                    f"containing a credential-like pattern: "
                                    f"'{pattern_name}'. "
                                    f"Partial match (redacted): {snippet!r}. "
                                    f"Embedding credentials in service URLs stores "
                                    f"them in Kong's configuration database in plaintext. "
                                    f"Credentials must be managed via a dedicated Secret "
                                    f"Manager and referenced at runtime, not hardcoded. "
                                    f"References: OWASP ASVS V13.3.1, CWE-798."
                                ),
                                references=_REFERENCES,
                                evidence_ref=None,
                            )
                        )

        # ---- Scan plugin configs ---------------------------------------
        plugins = self._fetch_plugins(admin_base_url)
        if plugins is not None:
            for plugin in plugins:
                plugin_name: str = plugin.get("name", "<unnamed>")
                plugin_id: str = plugin.get("id", "<no-id>")
                config_block: Any = plugin.get("config", {})
                if isinstance(config_block, dict):
                    config_findings = self._scan_config_dict(
                        config_block,
                        context_label=f"plugin '{plugin_name}' (id={plugin_id})",
                    )
                    findings.extend(config_findings)

        return findings

    def _fetch_services(self, admin_base_url: str) -> list[dict[str, Any]] | None:
        """
        Retrieve Kong services via Admin API.

        Returns None on KongAdminError so the caller can produce a partial
        result rather than an ERROR.
        """
        try:
            return get_services(admin_base_url)
        except KongAdminError as exc:
            log.error(
                "test_6_4_kong_services_fetch_failed",
                admin_base_url=admin_base_url,
                error=str(exc),
            )
            return None

    def _fetch_plugins(self, admin_base_url: str) -> list[dict[str, Any]] | None:
        """
        Retrieve Kong plugins via Admin API.

        Returns None on KongAdminError so the caller can produce a partial
        result rather than an ERROR.
        """
        try:
            return get_plugins(admin_base_url)
        except KongAdminError as exc:
            log.error(
                "test_6_4_kong_plugins_fetch_failed",
                admin_base_url=admin_base_url,
                error=str(exc),
            )
            return None

    def _scan_config_dict(
        self,
        data: dict[str, Any],
        context_label: str,
        _depth: int = 0,
    ) -> list[Finding]:
        """
        Recursively scan a configuration dictionary for credential patterns.

        Two detection strategies are applied at each leaf string value:

        1. Pattern match: the value is tested against all _CREDENTIAL_PATTERNS.
           A match is flagged regardless of the key name.

        2. Semantic match: if the (lowercased) key name contains any fragment
           from _SEMANTIC_CREDENTIAL_KEY_FRAGMENTS, and the value is a string
           with length >= _MIN_CREDENTIAL_VALUE_LENGTH, and the lowercased
           value is not in _PLACEHOLDER_STRINGS, the value is flagged as a
           probable credential stored in plaintext.

        Recursion depth is capped at 10 to prevent pathological configs from
        causing infinite recursion.
        """
        findings: list[Finding] = []
        max_depth = 10

        if _depth > max_depth:
            log.debug(
                "test_6_4_config_scan_max_depth_reached",
                context_label=context_label,
                depth=_depth,
            )
            return findings

        for key, value in data.items():
            if isinstance(value, dict):
                findings.extend(self._scan_config_dict(value, context_label, _depth + 1))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        findings.extend(self._scan_config_dict(item, context_label, _depth + 1))
            elif isinstance(value, str):
                # Strategy 1: known credential patterns (key-agnostic).
                matched_patterns = self._scan_text_for_credentials(value)
                for pattern_name, snippet in matched_patterns:
                    log.warning(
                        "test_6_4_credential_pattern_in_plugin_config",
                        context_label=context_label,
                        key=key,
                        pattern=pattern_name,
                    )
                    findings.append(
                        Finding(
                            title=(f"Credential Pattern in Kong Config: {context_label}"),
                            detail=(
                                f"Config key '{key}' in {context_label} contains "
                                f"a credential-like pattern: '{pattern_name}'. "
                                f"Partial match (redacted): {snippet!r}. "
                                f"Secrets must not be stored as plaintext values "
                                f"in Kong plugin configuration. Use a Secret Manager "
                                f"and reference secrets at runtime. "
                                f"References: OWASP ASVS V13.3.1, CWE-798."
                            ),
                            references=_REFERENCES,
                            evidence_ref=None,
                        )
                    )

                # Strategy 2: semantic key match with high-entropy value.
                key_lower = key.lower()
                is_semantic_credential_key = any(
                    fragment in key_lower for fragment in _SEMANTIC_CREDENTIAL_KEY_FRAGMENTS
                )
                value_lower = value.strip().lower()
                is_placeholder = value_lower in _PLACEHOLDER_STRINGS
                is_long_enough = len(value.strip()) >= _MIN_CREDENTIAL_VALUE_LENGTH

                if (
                    is_semantic_credential_key
                    and is_long_enough
                    and not is_placeholder
                    and not matched_patterns  # avoid duplicate finding for same value
                ):
                    log.warning(
                        "test_6_4_semantic_credential_key_in_plugin_config",
                        context_label=context_label,
                        key=key,
                        value_length=len(value.strip()),
                    )
                    findings.append(
                        Finding(
                            title=(
                                f"Probable Plaintext Credential in Kong Config: {context_label}"
                            ),
                            detail=(
                                f"Config key '{key}' in {context_label} has a name "
                                f"suggesting it holds a credential "
                                f"(contains fragment from semantic key list: "
                                f"{_SEMANTIC_CREDENTIAL_KEY_FRAGMENTS!r}) "
                                f"and its value has {len(value.strip())} characters "
                                f"(>= the {_MIN_CREDENTIAL_VALUE_LENGTH}-character "
                                f"minimum to exclude known placeholders). "
                                f"The value does not match any known placeholder. "
                                f"If this value is a real credential it must be "
                                f"replaced with a Secret Manager reference. "
                                f"References: OWASP ASVS V13.3.1, NIST SP 800-53 IA-5(1)."
                            ),
                            references=_REFERENCES,
                            evidence_ref=None,
                        )
                    )

        return findings

    # ------------------------------------------------------------------
    # Shared credential detection utility
    # ------------------------------------------------------------------

    @staticmethod
    def _scan_text_for_credentials(
        text: str,
    ) -> list[tuple[str, str]]:
        """
        Search text for matches against all _CREDENTIAL_PATTERNS.

        Returns a list of (pattern_name, redacted_snippet) tuples for every
        pattern that matches.  The snippet is truncated and partially redacted
        to avoid writing live credentials into the report or log output.

        A match on multiple patterns produces multiple entries -- one per
        distinct matched pattern.
        """
        results: list[tuple[str, str]] = []
        for compiled, pattern_name in _CREDENTIAL_PATTERNS:
            match = compiled.search(text)
            if match:
                raw = match.group(0)
                # Redact the middle section: show first 4 and last 4 chars only.
                if len(raw) > 12:  # noqa: PLR2004 -- inline literal intentional
                    snippet = raw[:4] + "[REDACTED]" + raw[-4:]
                else:
                    snippet = raw[:2] + "[REDACTED]"
                results.append((pattern_name, snippet))
        return results
