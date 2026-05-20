"""
src/connectors/sslyze.py

SslyzeConnector: BaseLibraryConnector wrapper for the sslyze TLS scanner.

This connector is the third D1.P5 connector tier (BaseLibraryConnector — Python
library, not a subprocess).  sslyze is imported lazily inside run() so that
the rest of the codebase is unaffected when the library is absent; the
registry will call is_available() and inject a skip reason before run() is
ever called.

Usage: `pip install "apiguard-assurance[sslyze]"` or
       `pip install sslyze>=6.0`

Output normalisation:
    Each TLS issue becomes a finding dict with keys: id, severity, finding, cve.
    Severity levels follow the same CRITICAL/HIGH/MEDIUM scale as the testssl
    connector so that ExtTest15SslyzeAnalysis can reuse the same oracle logic.

    CRITICAL: SSLv2 supported, Heartbleed, ROBOT strong oracle.
    HIGH:     SSLv3 supported, OpenSSL CCS injection, ROBOT weak oracle,
              client renegotiation DoS, untrusted certificate chain,
              SHA-1 in certificate chain.
    MEDIUM:   TLS 1.0/1.1 supported, TLS compression (CRIME), TLS 1.3 early
              data (replay), fallback SCSV missing, insecure renegotiation,
              HSTS missing or max-age too short.

`command` and `command_json` in ConnectorRawOutput:
    sslyze is a Python library (no subprocess).  Both fields carry the CLI
    equivalent string (`sslyze --regular {host}:{port}`) so the HTML report
    shows a reproducible command the analyst can run for manual verification.

Dependency rule:
    Imports from: stdlib, structlog, sslyze (optional), src.connectors.base,
                  src.core.exceptions.
    Must never import from: tests/, external_tests/, config/, discovery/,
                            report/, engine.py.
"""

from __future__ import annotations

import time
import urllib.parse
import warnings
from typing import TYPE_CHECKING, Any, ClassVar, cast

import structlog

from src.connectors.base import BaseLibraryConnector, ConnectorRawOutput, ConnectorResult
from src.connectors.types import TlsFinding
from src.core.exceptions import ExternalToolError

if TYPE_CHECKING:
    # sslyze is an optional dependency.  Import its types only for static
    # analysis; the runtime import lives inside run() so this module can be
    # loaded even when sslyze is not installed.
    from sslyze.scanner.models import AllScanCommandsAttempts

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Minimum HSTS max-age (seconds) below which a MEDIUM finding is raised.
# NIST SP 800-52 Rev.2 and OWASP ASVS v5.0.0 V12.1.1 require >= 1 year.
_HSTS_MIN_MAX_AGE_SECONDS: int = 31_536_000

# ROBOT scan result values that indicate vulnerability.
# Sourced from sslyze.plugins.robot.implementation.RobotScanResultEnum.
_ROBOT_STRONG_ORACLE: str = "VULNERABLE_STRONG_ORACLE"
_ROBOT_WEAK_ORACLE: str = "VULNERABLE_WEAK_ORACLE"


# ---------------------------------------------------------------------------
# SslyzeConnector
# ---------------------------------------------------------------------------


class SslyzeConnector(BaseLibraryConnector):
    """
    Connector for the sslyze Python TLS scanner library (tier: BaseLibraryConnector).

    Performs a comprehensive TLS scan of the target host, normalises the
    structured sslyze results into the ConnectorRawOutput format, and returns
    all findings unfiltered.  Severity partitioning (FAIL / NOTE / IGNORE) is
    the exclusive responsibility of ExtTest15SslyzeAnalysis._evaluate().

    ClassVars:
        TOOL_NAME:      Human-readable name used in logs and ConnectorResult.
        LIBRARY_MODULE: Python module name passed to importlib.util.find_spec()
                        by the inherited is_available() implementation.
    """

    TOOL_NAME: ClassVar[str] = "sslyze"
    LIBRARY_MODULE: ClassVar[str] = "sslyze"

    def run(
        self,
        target_url: str,
        timeout_seconds: int,
    ) -> ConnectorResult:
        """
        Execute a TLS scan against target_url and return normalised findings.

        Imports sslyze lazily so the module only runs when the library is
        confirmed available (checked by is_available() before this is called).
        Suppresses DeprecationWarnings from sslyze's trust-store loader, which
        are informational noise about legacy certificates in OS trust stores.

        Args:
            target_url:      Base URL of the target API (scheme://host:port/...).
            timeout_seconds: Per-connection network timeout (sourced from
                             target.external_tools.sslyze.timeout_seconds).

        Returns:
            ConnectorResult: All normalised findings, unfiltered.

        Raises:
            ExternalToolError: On connectivity failure, scan error, or any
                               unexpected exception during the scan.
        """
        parsed = urllib.parse.urlparse(target_url)
        host: str = parsed.hostname or target_url
        port: int = parsed.port or 443

        command: str = f"sslyze --regular {host}:{port}"
        command_json: str = f"sslyze --json_out=- --regular {host}:{port}"

        log.info(
            "sslyze_connector_run_starting",
            host=host,
            port=port,
            timeout_seconds=timeout_seconds,
        )

        start_ms: int = int(time.monotonic() * 1000)

        try:
            # Lazy import: sslyze is optional; the registry guarantees it is
            # available before run() is ever called.
            # Use documented submodule paths (top-level re-exports trigger
            # static-analysis warnings about non-exported names).
            from sslyze.scanner.models import ServerScanRequest  # noqa: PLC0415
            from sslyze.scanner.scanner import Scanner  # noqa: PLC0415
            from sslyze.server_setting import (  # noqa: PLC0415
                ServerNetworkConfiguration,
                ServerNetworkLocation,
            )

            location = ServerNetworkLocation(host, port)
            net_cfg = ServerNetworkConfiguration(
                tls_server_name_indication=host,
                # Clamp per-connection timeout to avoid an individual check
                # consuming the entire budget; sslyze runs many checks.
                network_timeout=min(timeout_seconds, 20),
                network_max_retries=1,
            )
            req = ServerScanRequest(
                server_location=location,
                network_configuration=net_cfg,
            )

            scanner = Scanner()
            scanner.queue_scans([req])

            # Suppress CryptographyDeprecationWarning emitted by sslyze's
            # trust-store loader for legacy CA certificates in OS trust stores.
            # These are irrelevant to the security assessment of the target.
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=DeprecationWarning)
                scan_results = list(scanner.get_results())

        except ExternalToolError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ExternalToolError(
                message=f"sslyze scan failed for {host}:{port}: {exc}",
                tool_name=self.TOOL_NAME,
                exit_code=-1,
                timed_out=False,
            ) from exc

        execution_ms: int = int(time.monotonic() * 1000) - start_ms

        if not scan_results:
            raise ExternalToolError(
                message=f"sslyze returned no results for {host}:{port}.",
                tool_name=self.TOOL_NAME,
                exit_code=-1,
                timed_out=False,
            )

        result = scan_results[0]
        if result.scan_result is None:
            err_trace: str = ""
            if result.connectivity_error_trace:
                err_trace = str(result.connectivity_error_trace)[:300]
            raise ExternalToolError(
                message=(
                    f"sslyze could not connect to {host}:{port}.  "
                    f"Connectivity error: {err_trace}"
                ),
                tool_name=self.TOOL_NAME,
                exit_code=-1,
                timed_out=False,
            )

        all_findings: list[TlsFinding] = self._normalize_findings(
            result.scan_result
        )

        log.info(
            "sslyze_connector_run_complete",
            host=host,
            port=port,
            findings_count=len(all_findings),
            execution_time_ms=execution_ms,
        )

        raw_output: ConnectorRawOutput = {
            "command": command,
            "command_json": command_json,
            # Boundary cast: ConnectorRawOutput.results is the generic
            # cross-connector contract (list[dict[str, Any]]).  The TLS-specific
            # TlsFinding TypedDict is a structural subtype of dict[str, str]
            # which is itself a subtype of dict[str, Any], but list[X] is
            # invariant in X, so mypy needs the widening cast at this boundary.
            "results": cast("list[dict[str, Any]]", all_findings),
            "all_count": len(all_findings),
        }

        return ConnectorResult(
            tool_name=self.TOOL_NAME,
            tool_version=self.get_version(),
            raw_output=raw_output,
            exit_code=0,
            execution_time_ms=execution_ms,
            timed_out=False,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _normalize_findings(
        self, scan_result: AllScanCommandsAttempts
    ) -> list[TlsFinding]:
        """
        Convert sslyze's structured scan result into a flat list of TlsFinding.

        All findings are returned unfiltered — severity partitioning is the
        responsibility of the test oracle in ExtTest15SslyzeAnalysis._evaluate().

        Args:
            scan_result: sslyze AllScanCommandsAttempts object — the
                ``scan_result`` attribute of ServerScanResult, containing one
                attempt per scan command (cipher suites per protocol version,
                certificate info, vulnerability checks, HTTP headers).

        Returns:
            list[TlsFinding]: Normalised findings, possibly empty.  See
            ``src/connectors/types/tls_findings.py`` for the field contract.
        """
        findings: list[TlsFinding] = []

        # --- Weak protocol support (deprecated TLS/SSL versions) ---

        ssl2 = scan_result.ssl_2_0_cipher_suites
        if ssl2.result and ssl2.result.accepted_cipher_suites:
            findings.append({
                "id": "ssl_2_0",
                "severity": "CRITICAL",
                "finding": (
                    f"SSLv2 supported: {len(ssl2.result.accepted_cipher_suites)} "
                    f"accepted cipher suite(s).  RFC 6176: SSLv2 must be disabled."
                ),
                "cve": "",
            })

        ssl3 = scan_result.ssl_3_0_cipher_suites
        if ssl3.result and ssl3.result.accepted_cipher_suites:
            findings.append({
                "id": "ssl_3_0",
                "severity": "HIGH",
                "finding": (
                    f"SSLv3 supported: {len(ssl3.result.accepted_cipher_suites)} "
                    f"accepted cipher suite(s).  RFC 7568: SSLv3 must be disabled."
                ),
                "cve": "",
            })

        tls10 = scan_result.tls_1_0_cipher_suites
        if tls10.result and tls10.result.accepted_cipher_suites:
            findings.append({
                "id": "tls_1_0",
                "severity": "MEDIUM",
                "finding": (
                    f"TLS 1.0 supported: {len(tls10.result.accepted_cipher_suites)} "
                    f"accepted cipher suite(s).  RFC 8996: TLS 1.0 deprecated."
                ),
                "cve": "",
            })

        tls11 = scan_result.tls_1_1_cipher_suites
        if tls11.result and tls11.result.accepted_cipher_suites:
            findings.append({
                "id": "tls_1_1",
                "severity": "MEDIUM",
                "finding": (
                    f"TLS 1.1 supported: {len(tls11.result.accepted_cipher_suites)} "
                    f"accepted cipher suite(s).  RFC 8996: TLS 1.1 deprecated."
                ),
                "cve": "",
            })

        # --- Known vulnerabilities ---

        hb = scan_result.heartbleed
        if hb.result and hb.result.is_vulnerable_to_heartbleed:
            findings.append({
                "id": "heartbleed",
                "severity": "CRITICAL",
                "finding": (
                    "Vulnerable to Heartbleed: attacker can read up to 64 KB of "
                    "server process memory per request.  Patch OpenSSL immediately."
                ),
                "cve": "CVE-2014-0160",
            })

        rob = scan_result.robot
        if rob.result:
            rv: str = rob.result.robot_result.value
            if rv == _ROBOT_STRONG_ORACLE:
                findings.append({
                    "id": "robot_strong_oracle",
                    "severity": "CRITICAL",
                    "finding": (
                        "Vulnerable to ROBOT attack (strong oracle): RSA PKCS#1 v1.5 "
                        "padding oracle allows passive MITM decryption of TLS sessions."
                    ),
                    "cve": "",
                })
            elif rv == _ROBOT_WEAK_ORACLE:
                findings.append({
                    "id": "robot_weak_oracle",
                    "severity": "HIGH",
                    "finding": (
                        "Vulnerable to ROBOT attack (weak oracle): may allow RSA PKCS#1 "
                        "v1.5 padding oracle attacks with sufficient queries."
                    ),
                    "cve": "",
                })

        ccs = scan_result.openssl_ccs_injection
        if ccs.result and ccs.result.is_vulnerable_to_ccs_injection:
            findings.append({
                "id": "openssl_ccs_injection",
                "severity": "HIGH",
                "finding": (
                    "Vulnerable to OpenSSL CCS Injection: attacker can force weak "
                    "keying material via premature ChangeCipherSpec injection."
                ),
                "cve": "CVE-2014-0224",
            })

        rn = scan_result.session_renegotiation
        if rn.result:
            if rn.result.is_vulnerable_to_client_renegotiation_dos:
                findings.append({
                    "id": "client_renegotiation_dos",
                    "severity": "HIGH",
                    "finding": (
                        "Client-initiated renegotiation DoS: server accepts unrestricted "
                        "renegotiation requests, enabling CPU exhaustion attacks."
                    ),
                    "cve": "",
                })
            if not rn.result.supports_secure_renegotiation:
                findings.append({
                    "id": "insecure_renegotiation",
                    "severity": "MEDIUM",
                    "finding": (
                        "Secure renegotiation not supported (RFC 5746): MITM injection "
                        "during handshake renegotiation is possible."
                    ),
                    "cve": "",
                })

        # --- Protocol features that increase attack surface ---

        tc = scan_result.tls_compression
        if tc.result and tc.result.supports_compression:
            findings.append({
                "id": "tls_compression",
                "severity": "MEDIUM",
                "finding": (
                    "TLS compression enabled: vulnerable to CRIME side-channel attack "
                    "(compression ratio leaks plaintext content)."
                ),
                "cve": "",
            })

        ed = scan_result.tls_1_3_early_data
        if ed.result and ed.result.supports_early_data:
            findings.append({
                "id": "tls_1_3_early_data",
                "severity": "MEDIUM",
                "finding": (
                    "TLS 1.3 0-RTT early data enabled: non-idempotent requests sent "
                    "as early data are vulnerable to replay attacks."
                ),
                "cve": "",
            })

        fb = scan_result.tls_fallback_scsv
        if fb.result and not fb.result.supports_fallback_scsv:
            findings.append({
                "id": "tls_fallback_scsv_missing",
                "severity": "MEDIUM",
                "finding": (
                    "TLS_FALLBACK_SCSV not supported: protocol downgrade attacks "
                    "(e.g. POODLE) are not mitigated at the handshake level."
                ),
                "cve": "",
            })

        # --- Certificate chain ---

        ci = scan_result.certificate_info
        if ci.result:
            for depl in ci.result.certificate_deployments:
                path_results = depl.path_validation_results
                if path_results:
                    all_untrusted = all(
                        pv.verified_certificate_chain is None
                        for pv in path_results
                    )
                    if all_untrusted:
                        first_err: str = (
                            path_results[0].validation_error or "validation failed"
                        )
                        findings.append({
                            "id": "cert_chain_not_trusted",
                            "severity": "HIGH",
                            "finding": (
                                f"Certificate chain not trusted by any OS trust store.  "
                                f"First error: {first_err[:200]}"
                            ),
                            "cve": "",
                        })
                if depl.verified_chain_has_sha1_signature is True:
                    findings.append({
                        "id": "cert_sha1_signature",
                        "severity": "HIGH",
                        "finding": (
                            "Certificate chain contains a SHA-1 signature: SHA-1 is "
                            "cryptographically broken.  Replace with SHA-256 or stronger."
                        ),
                        "cve": "",
                    })

        # --- HTTP security headers ---

        hh = scan_result.http_headers
        if hh.result:
            hsts = hh.result.strict_transport_security_header
            if hsts is None:
                findings.append({
                    "id": "hsts_missing",
                    "severity": "MEDIUM",
                    "finding": (
                        "Strict-Transport-Security (HSTS) header absent.  "
                        "NIST SP 800-52 Rev.2 requires HSTS on all HTTPS endpoints."
                    ),
                    "cve": "",
                })
            elif hsts.max_age is not None and hsts.max_age < _HSTS_MIN_MAX_AGE_SECONDS:
                findings.append({
                    "id": "hsts_max_age_too_short",
                    "severity": "MEDIUM",
                    "finding": (
                        f"HSTS max-age={hsts.max_age}s is below the recommended "
                        f"minimum of {_HSTS_MIN_MAX_AGE_SECONDS}s (1 year).  "
                        f"NIST SP 800-52 Rev.2, OWASP ASVS v5.0.0 V12.1.1."
                    ),
                    "cve": "",
                })

        return findings
