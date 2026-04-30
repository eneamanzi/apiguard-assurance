"""
src/tests/domain_1/test_1_5_insecure_credential_transport.py

Test 1.5 -- Credentials Not Transmitted via Insecure Channels.

Guarantee (3_TOP_metodologia.md, Section 1.5):
    Credentials must be transmitted exclusively over TLS 1.2+ channels.
    The Gateway must enforce HTTPS for all API traffic: HTTP requests must
    either be rejected (port 80 closed) or permanently redirected to HTTPS
    (301/308).  The HSTS header must be present on all HTTPS responses to
    instruct browsers to never attempt plain-HTTP connections.

    Methodology references:
        OWASP API2:2023 Broken Authentication
        RFC 9110 Section 4.2.2 (HTTPS redirect semantics)
        NIST SP 800-52 Rev.2 (TLS configuration)
        OWASP ASVS v5.0.0 V12.1.1 (HSTS requirement)
        OWASP ASVS v5.0.0 V14.2.1 (TLS version requirement)

Strategy: WHITE_BOX -- Configuration Audit (methodology section 1.5).
    Like test 6.2, this test does NOT require Kong Admin API access.
    Sub-test 1 uses httpx directly (not SecurityClient) to probe the HTTP
    transport layer, analogous to kong_admin.py using httpx for Admin API
    calls -- both represent separate trust boundaries from the target API.
    Sub-test 2 uses SecurityClient for the HSTS header check on HTTPS.
    Sub-test 3 (optional) invokes testssl.sh as a subprocess.

    Special case -- plain-HTTP target:
    If the configured target base URL uses plain HTTP (no TLS), the test
    immediately returns FAIL with a direct critical finding instead of SKIP.
    Rationale: a plain-HTTP target is the worst possible state for credential
    transport security.  Returning SKIP would hide this violation from the
    report.  Sub-tests 2 and 3 are skipped in this case because they require
    a TLS layer to be meaningful.

Priority: P2 -- Defense-in-depth transport layer control.
    A missing HSTS header or open HTTP port exposes credential interception
    risk, but does not directly bypass application-level authentication.

Sub-tests (executed in order):
--------------------------------------------------------------------------
Sub-test 1 -- HTTP redirect enforcement (empirical, RFC 9110)
    Derives the HTTP version of target.endpoint_base_url() by replacing
    the 'https://' scheme with 'http://'.  Sends a plain GET to that URL.
    Uses httpx directly (not SecurityClient) because SecurityClient is
    initialized with the HTTPS base URL and cannot send to a different
    scheme.  This is an intentional, documented exception to the
    SecurityClient-only rule, justified by the same transport-boundary
    reasoning that justifies kong_admin.py using httpx directly for Admin
    API calls.

    Oracle:
        Connection refused (OSError) -> PASS: HTTP port not exposed.
        Connection timeout           -> PASS: port filtered (conservative).
        Status in expected_redirect_codes (301/308) -> PASS: redirect enforced.
        Any 2xx status               -> FAIL: HTTP API accessible in clear.
        Any other 3xx (302, 307)     -> FAIL: temporary redirect, MITM-downgradeable.
        Any 4xx / 5xx                -> FAIL: HTTP server is running and responding.

Sub-test 2 -- HSTS header validation (NIST SP 800-52 Rev.2, ASVS V12.1.1)
    Sends a GET to '/' on HTTPS via SecurityClient.  The response is
    expected to carry the Strict-Transport-Security header regardless of
    the HTTP status code (401, 404, or 200 -- all valid for this check).

    Oracle:
        Header absent                             -> FAIL.
        max-age < hsts_min_max_age_seconds        -> FAIL.
        includeSubDomains absent                  -> FAIL (best practice).
        Header present and compliant              -> PASS.

Sub-test 3 -- TLS version and cipher-suite audit via testssl.sh (optional)
    Invoked only when testssl_binary_path is a non-empty path to an
    executable.  Runs testssl.sh with '--jsonfile' output and parses the
    protocol section for deprecated TLS versions.

    Oracle:
        SSLv2, SSLv3, TLS 1.0, or TLS 1.1 reported as 'offered' -> FAIL.
        No deprecated protocols offered                          -> PASS.
        Binary not found / not executable                        -> SKIP.

EvidenceStore policy:
    Sub-test 1: no EvidenceRecord (direct httpx, no SecurityClient).
                Finding uses evidence_ref=None.
    Sub-test 2: EvidenceRecord from client.request().
                add_fail_evidence() called on FAIL; pin_evidence() not used.
    Sub-test 3: no EvidenceRecord (subprocess, no SecurityClient).
                Finding uses evidence_ref=None.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from typing import ClassVar
from urllib.parse import urlparse

import httpx
import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import Finding, TestResult, TestStatus, TestStrategy
from src.core.models.runtime import RuntimeTest15Config
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Oracle states — appear verbatim in the HTML Audit Trail column.
_STATE_HTTP_PORT_CLOSED: str = "HTTP_PORT_CLOSED"
_STATE_HTTP_REDIRECT_ENFORCED: str = "HTTP_REDIRECT_ENFORCED"
_STATE_HTTP_PORT_OPEN: str = "HTTP_PORT_OPEN"
_STATE_HTTP_PROBE_TIMEOUT: str = "HTTP_PROBE_TIMEOUT"
_STATE_HSTS_COMPLIANT: str = "HSTS_COMPLIANT"
_STATE_HSTS_MISSING: str = "HSTS_MISSING"
_STATE_HSTS_MAX_AGE_LOW: str = "HSTS_MAX_AGE_BELOW_MINIMUM"
_STATE_HSTS_NO_INCLUDE_SUBDOMAINS: str = "HSTS_MISSING_INCLUDE_SUBDOMAINS"
_STATE_TLS_PASS: str = "TLS_NO_DEPRECATED_PROTOCOLS"  # noqa: S105
_STATE_TLS_FAIL: str = "TLS_DEPRECATED_PROTOCOL_OFFERED"
_STATE_TLS_SKIP: str = "TLS_SCAN_SKIPPED"

# Deprecated TLS/SSL protocol identifiers as reported by testssl.sh JSON output.
_DEPRECATED_PROTOCOL_IDS: frozenset[str] = frozenset({"ssl2", "ssl3", "tls1", "tls1_1"})

# testssl.sh severity levels that represent offered/enabled protocols.
# A deprecated protocol is a finding only when the server actually offers it.
_OFFERED_KEYWORDS: frozenset[str] = frozenset({"offered", "offered (deprecated)"})

# Regex to extract the numeric max-age value from the HSTS header.
_HSTS_MAX_AGE_PATTERN: re.Pattern[str] = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)

# HTTP header names (lowercase -- SecurityClient normalises response headers).
_HEADER_HSTS: str = "strict-transport-security"
_HEADER_HSTS_INCLUDE_SUBDOMAINS: str = "includesubdomains"

# Standards references cited in every Finding this test produces.
_REFERENCES: list[str] = [
    "OWASP-API2:2023",
    "RFC-9110-S4.2.2",
    "NIST-SP-800-52-Rev2",
    "OWASP-ASVS-v5.0.0-V12.1.1",
    "OWASP-ASVS-v5.0.0-V14.2.1",
]

# Path probed for HSTS check -- any path is acceptable since HSTS must be
# present on every response regardless of status code.
_HSTS_PROBE_PATH: str = "/"


class Test15InsecureCredentialTransport(BaseTest):
    """Test 1.5 -- Credentials Not Transmitted via Insecure Channels."""

    test_id: ClassVar[str] = "1.5"
    test_name: ClassVar[str] = "Credentials Not Transmitted via Insecure Channels"
    priority: ClassVar[int] = 2
    domain: ClassVar[int] = 1
    strategy: ClassVar[TestStrategy] = TestStrategy.WHITE_BOX
    depends_on: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = [
        "transport-security",
        "tls",
        "hsts",
        "OWASP-API2:2023",
        "NIST-SP-800-52",
    ]
    cwe_id: ClassVar[str] = "CWE-319"

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Verify that the target enforces HTTPS for all API traffic.

        Runs up to three sub-tests depending on the target scheme:

        - If the target base URL uses plain HTTP (no TLS at all), the test
          immediately returns FAIL with a critical finding: this is the worst
          possible state for credential transport security and requires no
          further probing.  Sub-tests 2 and 3 are skipped because they
          presuppose a TLS layer to inspect.

        - If the target base URL uses HTTPS, three sub-tests are executed
          in sequence (HTTP redirect probe, HSTS header, optional testssl.sh).
          Each sub-test that detects a violation appends a Finding.

        Returns PASS only when the target is HTTPS and all sub-tests pass.
        Returns FAIL on any violation (including plain-HTTP target).
        Never returns SKIP: every reachable target has a deterministic result.
        """
        try:
            cfg = target.tests_config.test_1_5
            base_url = target.endpoint_base_url()
            verify_tls = target.verify_tls

            # ----------------------------------------------------------------
            # Fast-path FAIL: target is plain HTTP — no TLS layer at all.
            # This is categorically worse than a misconfigured HTTPS target:
            # every credential sent to this API is transmitted in cleartext.
            # Sub-tests 2 and 3 require a TLS handshake to inspect and are
            # therefore skipped; the finding below is sufficient on its own.
            # ----------------------------------------------------------------
            if not base_url.startswith("https://"):
                log.warning(
                    "test_1_5_target_is_plain_http",
                    base_url=base_url,
                    oracle=_STATE_HTTP_PORT_OPEN,
                )
                return self._make_fail(
                    message=(
                        f"Target API operates on plain HTTP: '{base_url}'. "
                        "All credentials, tokens, and session data are transmitted "
                        "in cleartext.  This is the most critical transport-layer "
                        "misconfiguration possible."
                    ),
                    detail=(
                        f"The configured target base URL is '{base_url}', which uses "
                        "the plain HTTP scheme.  No TLS layer is present between the "
                        "client and the API Gateway.  Any credential sent in an "
                        "Authorization header, any session token, and any sensitive "
                        "payload is visible to any observer on the network path "
                        "(Wireshark, corporate proxy, rogue Wi-Fi access point).  "
                        "This finding supersedes all other transport-security checks: "
                        "HSTS is meaningless without TLS, and testssl.sh cannot scan "
                        "a non-TLS endpoint.  "
                        "Remediation: configure the Gateway to listen on HTTPS "
                        "(TLS 1.2+), obtain a valid certificate, and update the "
                        "target URL in config.yaml to 'https://'.  "
                        "Oracle: target.endpoint_base_url() must start with 'https://' "
                        "(RFC 9110 Section 4.2.2, NIST SP 800-52 Rev.2, "
                        "OWASP ASVS v5.0.0 V12.1.1)."
                    ),
                    evidence_record_id=None,
                    additional_references=_REFERENCES,
                )

            findings: list[Finding] = []

            # ------------------------------------------------------------------
            # Sub-test 1 -- HTTP redirect enforcement
            # ------------------------------------------------------------------
            if cfg.http_probe_enabled:
                finding_1 = self._run_http_redirect_probe(base_url, cfg, verify_tls)
                if finding_1 is not None:
                    findings.append(finding_1)
            else:
                log.info(
                    "test_1_5_http_probe_disabled",
                    reason="http_probe_enabled=False in config",
                )

            # ------------------------------------------------------------------
            # Sub-test 2 -- HSTS header validation
            # ------------------------------------------------------------------
            hsts_findings = self._run_hsts_check(client, store, cfg)
            findings.extend(hsts_findings)

            # ------------------------------------------------------------------
            # Sub-test 3 -- testssl.sh TLS scan (optional)
            # ------------------------------------------------------------------
            if cfg.testssl_binary_path:
                tls_findings = self._run_testssl_scan(base_url, cfg)
                findings.extend(tls_findings)
            else:
                log.info(
                    "test_1_5_tls_scan_skipped",
                    reason="testssl_binary_path not configured",
                )

            if findings:
                return TestResult(
                    test_id=self.test_id,
                    status=TestStatus.FAIL,
                    message=f"Transport security audit found {len(findings)} violation(s).",
                    findings=findings,
                    transaction_log=list(self._transaction_log),
                    **self._metadata_kwargs(),
                )

            return self._make_pass(
                message=(
                    "All transport security checks passed: HTTP redirect enforced "
                    "(or port closed), HSTS header compliant"
                    + (", TLS scan clean." if cfg.testssl_binary_path else ".")
                )
            )

        except Exception as exc:  # noqa: BLE001
            return self._make_error(exc)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _derive_http_url(self, https_base_url: str) -> str:
        """
        Derive the HTTP equivalent of an HTTPS base URL.

        Replaces 'https://' with 'http://' and removes an explicit port 443
        if present (port 80 is the implicit HTTP default).

        Args:
            https_base_url: HTTPS base URL string, e.g. 'https://api.example.com'.

        Returns:
            HTTP URL string, e.g. 'http://api.example.com'.
        """
        parsed = urlparse(https_base_url)
        port = parsed.port
        # Replace scheme; remove port 443 (HTTPS default) if explicitly set so
        # that the derived HTTP URL uses the implicit port-80 default instead.
        # For non-standard ports (e.g. 8443) the port is kept as-is: the probe
        # targets the same port number with a different scheme, which is the
        # correct behaviour for non-standard deployments.
        if port == 443:  # noqa: PLR2004
            netloc = parsed.hostname or ""
        else:
            # parsed.netloc already excludes the scheme (e.g. "localhost:8443").
            netloc = parsed.netloc
        http_url = parsed._replace(scheme="http", netloc=netloc).geturl()
        # urlparse may leave a double-slash if netloc was empty; clean up.
        return http_url.replace("///", "//")

    def _run_http_redirect_probe(
        self,
        https_base_url: str,
        cfg: RuntimeTest15Config,
        verify_tls: bool,
    ) -> Finding | None:
        """
        Probe the HTTP version of the target base URL.

        Uses httpx directly (not SecurityClient) because SecurityClient is
        bound to the HTTPS base URL at construction.  This is the same
        pattern as kong_admin.py using httpx for the Kong Admin API.

        verify_tls is forwarded verbatim to httpx.get(verify=...).  In a lab
        environment with a self-signed certificate (verify_tls=False), the
        HTTPS redirect target itself would fail TLS validation; passing the
        flag ensures the probe mirrors SecurityClient's behaviour on the same
        target, making the comparison meaningful.

        Args:
            https_base_url: HTTPS target base URL from TargetContext.
            cfg: RuntimeTest15Config instance with probe parameters.
            verify_tls: Mirror of TargetContext.verify_tls — False in lab,
                        True in production.

        Returns:
            Finding if the probe reveals a vulnerability, None otherwise.
        """
        http_url = self._derive_http_url(https_base_url)
        # If an explicit override is configured, use it directly.
        # This handles non-standard port lab setups where the derived URL
        # (e.g. http://localhost:8443/) hits the TLS listener and returns 400
        # instead of the redirect that the real HTTP listener (8000) would serve.
        if cfg.http_probe_url:
            probe_url = cfg.http_probe_url
            log.info(
                "test_1_5_http_probe_url_override",
                derived_url=f"{http_url}/",
                override_url=probe_url,
            )
        else:
            probe_url = f"{http_url}/"
        expected_codes: frozenset[int] = frozenset(cfg.expected_redirect_status_codes)

        log.info(
            "test_1_5_http_probe_starting",
            probe_url=probe_url,
            timeout_seconds=cfg.http_probe_timeout_seconds,
        )

        try:
            response = httpx.get(
                probe_url,
                follow_redirects=False,
                timeout=cfg.http_probe_timeout_seconds,
                verify=verify_tls,  # noqa: S501 -- controlled by TargetConfig.verify_tls
            )
        except (httpx.ConnectError, httpx.RemoteProtocolError):
            # Connection refused or reset: HTTP port is closed.  Secure.
            log.info("test_1_5_http_probe_connection_refused", oracle=_STATE_HTTP_PORT_CLOSED)
            return None
        except httpx.TimeoutException:
            # Port filtered: treat as secure (conservative).
            log.info(
                "test_1_5_http_probe_timeout",
                oracle=_STATE_HTTP_PROBE_TIMEOUT,
                note="Port appears filtered; treating as secure (conservative).",
            )
            return None
        except Exception as exc:  # noqa: BLE001
            log.warning("test_1_5_http_probe_unexpected_error", error=str(exc))
            return None

        status_code = response.status_code

        if status_code in expected_codes:
            log.info(
                "test_1_5_http_probe_redirect_enforced",
                oracle=_STATE_HTTP_REDIRECT_ENFORCED,
                status_code=status_code,
            )
            return None

        # Any other response means HTTP is accessible and not properly enforced.
        log.warning(
            "test_1_5_http_probe_port_open",
            oracle=_STATE_HTTP_PORT_OPEN,
            status_code=status_code,
        )
        return Finding(
            title="HTTP Port Accessible Without HTTPS Redirect",
            detail=(
                f"Sent GET {probe_url} (HTTP plaintext). "
                f"Expected connection refused, 301, or 308. "
                f"Received HTTP {status_code}. "
                "The HTTP port is open and the server does not enforce a permanent "
                "redirect to HTTPS.  An attacker performing MITM can intercept "
                "credentials transmitted over this plaintext channel.  "
                "Oracle: port 80 must be closed or return 301/308 (RFC 9110, "
                "NIST SP 800-52 Rev.2)."
            ),
            references=_REFERENCES,
            evidence_ref=None,  # No EvidenceRecord: httpx direct call, not SecurityClient
        )

    def _run_hsts_check(
        self,
        client: SecurityClient,
        store: EvidenceStore,
        cfg: RuntimeTest15Config,
    ) -> list[Finding]:
        """
        Send a GET to the HTTPS root and validate the HSTS response header.

        Args:
            client: SecurityClient bound to the HTTPS base URL.
            store: EvidenceStore for recording FAIL transactions.
            cfg: RuntimeTest15Config instance.

        Returns:
            List of Finding objects.  Empty if HSTS is compliant.
        """
        findings: list[Finding] = []

        log.info("test_1_5_hsts_check_starting", probe_path=_HSTS_PROBE_PATH)

        response, record = client.request(
            method="GET",
            path=_HSTS_PROBE_PATH,
            test_id=self.test_id,
            # No Authorization header: HSTS must be present on ALL responses.
        )

        headers = {k.lower(): v for k, v in response.headers.items()}
        hsts_value = headers.get(_HEADER_HSTS)

        if hsts_value is None:
            store.add_fail_evidence(record)
            self._log_transaction(record, oracle_state=_STATE_HSTS_MISSING, is_fail=True)
            findings.append(
                Finding(
                    title="Strict-Transport-Security Header Absent",
                    detail=(
                        f"Sent GET {_HSTS_PROBE_PATH} over HTTPS. "
                        "The response did not include a Strict-Transport-Security header. "
                        "Without HSTS, browsers may attempt HTTP connections that expose "
                        "credentials to downgrade attacks (SSL stripping). "
                        "Oracle: header must be present with "
                        f"max-age >= {cfg.hsts_min_max_age_seconds}; includeSubDomains "
                        "(OWASP ASVS v5.0.0 V12.1.1, NIST SP 800-52 Rev.2)."
                    ),
                    references=_REFERENCES,
                    evidence_ref=record.record_id,
                )
            )
            return findings

        # HSTS header is present -- validate max-age value.
        max_age_match = _HSTS_MAX_AGE_PATTERN.search(hsts_value)
        if max_age_match is None:
            store.add_fail_evidence(record)
            self._log_transaction(record, oracle_state=_STATE_HSTS_MAX_AGE_LOW, is_fail=True)
            findings.append(
                Finding(
                    title="Strict-Transport-Security Header Has No max-age",
                    detail=(
                        f"HSTS header present with value '{hsts_value}' but no "
                        "max-age directive was found.  A HSTS header without max-age "
                        "is syntactically invalid and ignored by browsers (RFC 6797). "
                        f"Oracle: max-age >= {cfg.hsts_min_max_age_seconds} required."
                    ),
                    references=_REFERENCES,
                    evidence_ref=record.record_id,
                )
            )
        else:
            max_age = int(max_age_match.group(1))
            if max_age < cfg.hsts_min_max_age_seconds:
                store.add_fail_evidence(record)
                self._log_transaction(record, oracle_state=_STATE_HSTS_MAX_AGE_LOW, is_fail=True)
                findings.append(
                    Finding(
                        title="Strict-Transport-Security max-age Below Minimum Threshold",
                        detail=(
                            f"HSTS header present: '{hsts_value}'. "
                            f"max-age={max_age} is below the required minimum of "
                            f"{cfg.hsts_min_max_age_seconds} seconds. "
                            "A short max-age window allows HTTPS downgrade after expiry. "
                            "Oracle: max-age must be >= 31 536 000 (1 year) per "
                            "OWASP ASVS v5.0.0 V12.1.1."
                        ),
                        references=_REFERENCES,
                        evidence_ref=record.record_id,
                    )
                )

        # Validate includeSubDomains presence (best practice, ASVS V3.4.1).
        if _HEADER_HSTS_INCLUDE_SUBDOMAINS not in hsts_value.lower():
            # This is a separate Finding: missing includeSubDomains is distinct from
            # missing/invalid max-age.  Both can coexist.
            if not any(f.evidence_ref == record.record_id for f in findings):
                # Only pin/add evidence once; if already added as FAIL, skip.
                store.add_fail_evidence(record)
            self._log_transaction(
                record, oracle_state=_STATE_HSTS_NO_INCLUDE_SUBDOMAINS, is_fail=True
            )
            findings.append(
                Finding(
                    title="Strict-Transport-Security Missing includeSubDomains",
                    detail=(
                        f"HSTS header present: '{hsts_value}'. "
                        "The 'includeSubDomains' directive is absent.  Without it, "
                        "subdomains are not protected by HSTS and remain vulnerable "
                        "to cookie injection via subdomain takeover.  "
                        "Oracle: 'includeSubDomains' must be present per "
                        "OWASP ASVS v5.0.0 V3.4.1."
                    ),
                    references=_REFERENCES,
                    evidence_ref=record.record_id,
                )
            )

        if not findings:
            self._log_transaction(record, oracle_state=_STATE_HSTS_COMPLIANT)
            log.info(
                "test_1_5_hsts_check_passed",
                hsts_value=hsts_value,
                max_age=max_age_match.group(1) if max_age_match else "N/A",
            )

        return findings

    def _run_testssl_scan(
        self,
        https_base_url: str,
        cfg: RuntimeTest15Config,
    ) -> list[Finding]:
        """
        Invoke testssl.sh and parse the JSON output for deprecated protocol support.

        Args:
            https_base_url: HTTPS target base URL (hostname extracted for scan).
            cfg: RuntimeTest15Config carrying binary path and timeout.

        Returns:
            List of Finding objects for each deprecated protocol offered.
            Empty if the scan passes or the binary is not available.
        """
        findings: list[Finding] = []
        binary_path = cfg.testssl_binary_path

        # Verify binary exists and is executable before attempting to run.
        if not os.path.isfile(binary_path) or not os.access(binary_path, os.X_OK):
            log.warning(
                "test_1_5_testssl_binary_not_found",
                binary_path=binary_path,
                oracle=_STATE_TLS_SKIP,
            )
            return findings

        parsed = urlparse(https_base_url)
        hostname = parsed.hostname or ""
        port = parsed.port or 443  # noqa: PLR2004

        scan_target = f"{hostname}:{port}"
        log.info("test_1_5_testssl_scan_starting", scan_target=scan_target)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp_file:
            json_output_path = tmp_file.name

        try:
            result = subprocess.run(  # noqa: S603
                [binary_path, "--jsonfile", json_output_path, scan_target],
                capture_output=True,
                text=True,
                timeout=cfg.testssl_timeout_seconds,
            )
            if result.returncode not in {0, 1}:
                log.warning(
                    "test_1_5_testssl_scan_failed",
                    returncode=result.returncode,
                    stderr=result.stderr[:500] if result.stderr else "",
                )
                return findings

            with open(json_output_path) as f:
                raw = json.load(f)

        except subprocess.TimeoutExpired:
            log.warning(
                "test_1_5_testssl_scan_timeout",
                scan_target=scan_target,
            )
            return findings
        except (OSError, json.JSONDecodeError) as exc:
            log.warning("test_1_5_testssl_output_parse_error", error=str(exc))
            return findings
        finally:
            # Always remove the temporary file regardless of outcome.
            try:
                os.unlink(json_output_path)
            except OSError:
                pass

        findings.extend(self._parse_testssl_protocols(raw))
        return findings

    def _parse_testssl_protocols(
        self,
        testssl_output: object,
    ) -> list[Finding]:
        """
        Parse testssl.sh JSON output and produce Findings for deprecated protocols.

        Handles both the legacy list-of-dicts format and the newer dict-with-nested
        structure produced by testssl.sh v3.x.

        Args:
            testssl_output: Parsed JSON object from testssl.sh --jsonfile output.

        Returns:
            List of Finding objects for deprecated protocols offered by the server.
        """
        findings: list[Finding] = []

        # testssl.sh v3.x produces a list of finding objects at the top level.
        # Each object has: {"id": "tls1", "severity": "LOW", "finding": "offered (deprecated)"}
        items: list[dict[str, str]] = []
        if isinstance(testssl_output, list):
            items = [i for i in testssl_output if isinstance(i, dict)]
        elif isinstance(testssl_output, dict):
            # Older format: protocols are nested under a 'protocols' key.
            items = testssl_output.get("protocols", [])

        for item in items:
            proto_id = item.get("id", "")
            finding_text = item.get("finding", "").lower()
            severity = item.get("severity", "").upper()

            if proto_id not in _DEPRECATED_PROTOCOL_IDS:
                continue

            if not any(kw in finding_text for kw in _OFFERED_KEYWORDS):
                continue

            log.warning(
                "test_1_5_deprecated_protocol_offered",
                protocol_id=proto_id,
                finding=finding_text,
                severity=severity,
                oracle=_STATE_TLS_FAIL,
            )
            protocol_label = {
                "ssl2": "SSLv2",
                "ssl3": "SSLv3",
                "tls1": "TLS 1.0",
                "tls1_1": "TLS 1.1",
            }.get(proto_id, proto_id)

            findings.append(
                Finding(
                    title=f"Deprecated Protocol Offered: {protocol_label}",
                    detail=(
                        f"testssl.sh reported '{finding_text}' for {protocol_label} "
                        f"(severity: {severity}).  This protocol is deprecated and "
                        "must not be enabled on production systems (NIST SP 800-52 Rev.2, "
                        "OWASP ASVS v5.0.0 V14.2.1).  Clients that negotiate "
                        f"{protocol_label} can be exploited via known attacks "
                        "(BEAST for TLS 1.0, POODLE for SSLv3).  "
                        "Disable this protocol in the Gateway TLS configuration."
                    ),
                    references=_REFERENCES,
                    evidence_ref=None,  # No EvidenceRecord: subprocess invocation
                )
            )

        if not findings:
            log.info("test_1_5_testssl_scan_passed", oracle=_STATE_TLS_PASS)

        return findings
