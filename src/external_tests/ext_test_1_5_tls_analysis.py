"""
src/external_tests/ext_test_1_5_tls_analysis.py

ExtTest15TlsAnalysis: external test for deep TLS stack analysis via testssl.sh.

Relationship with Test 1.5 (native):
    Test 1.5 (src/tests/domain_1/test_1_5_insecure_credential_transport.py) covers
    the PYTHON-verifiable parts of Garanzia 1.5:
        Sub-test 1: HTTP redirect enforcement (httpx probe)
        Sub-test 2: HSTS header validation (SecurityClient GET /)
        Sub-test 3: (legacy) inline testssl.sh via testssl_binary_path config

    This external test extends the coverage with a CONNECTOR-managed TLS scan:
        Full TLS stack inspection: protocol versions (TLS 1.0/1.1, SSLv3),
        cipher suite weaknesses, certificate chain, forward secrecy,
        HSTS/HPKP headers at TLS level, Certificate Transparency SCTs, and
        any CVE-tagged vulnerability testssl.sh has templates for.

    The split follows the HYBRID pattern defined in Z-CHECKLIST.md:
        Native part   -> handles HTTP-level checks (redirects, HSTS headers)
        External part -> handles TLS-level checks (protocols, ciphers, CVEs)

    IMPORTANT: if config.tests.domain_1.test_1_5.testssl_binary_path is also
    set to a non-empty path, testssl.sh will be invoked twice -- once from
    native test 1.5 sub-test 3 and once from this external test.  Set
    testssl_binary_path = "" when this external test is enabled to avoid
    duplicate scans and duplicate findings under different test_ids.

Test ID uniqueness:
    This test uses test_id = "ext.1.5" (NOT "1.5") to avoid collision with the
    native Test 1.5 in the engine's test_lookup dict (keyed by test_id).
    engine.py constructs: test_lookup = {t.__class__.test_id: t for t in all_tests}
    Two tests with the same id would cause silent overwrite of one of them.

Timeout source (Proposal C):
    target.external_tools.testssl.timeout_seconds is the canonical source for
    the testssl.sh runtime timeout.  With ExternalToolsConfig on TargetContext,
    every ExternalToolTest uses the uniform pattern:
        target.external_tools.<tool>.timeout_seconds
    ExternalToolsConfig.testssl.timeout_seconds also controls the per-tool
    activation filter (whether this test is scheduled at all by the registry).

Oracle (Section 1.5, NIST SP 800-52 Rev.2, OWASP ASVS v5.0.0 V14.2.1):
    CRITICAL or HIGH severity finding -> FAIL with one Finding per item.
    MEDIUM or WARN severity only      -> PASS with informational note in message.
    OK / INFO / LOW                   -> silently ignored (not surfaced in report).
    No findings at all                -> PASS.

    Severity partitioning is the responsibility of this test, not the connector.
    TestsslConnector passes all findings unfiltered; this module applies the
    three-bucket split: FAIL_SEVERITIES / NOTE_SEVERITIES / ignored.

DAG placement:
    depends_on = [] -> Phase A (no prerequisites, runs alongside other A-tests).
    Consistent with the native 1.5 which also has depends_on = [].

Dependency rule:
    Imports from: stdlib, structlog, src.connectors, src.external_tests.base,
                  src.core.context, src.core.models, src.core.evidence.
    Must never import from: tests/, config/loader.py, discovery/, report/,
                             engine.py.
"""

from __future__ import annotations

import re
from typing import ClassVar

import structlog

from src.connectors.base import BaseConnector, ConnectorResult
from src.connectors.testssl import TestsslConnector
from src.core.context import TargetContext
from src.core.models import Finding, InfoNote, TestStrategy
from src.core.models.results import TestResult
from src.external_tests.base import ExternalToolTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Severity levels that trigger FAIL: each item produces one Finding object.
# Defined here (not in the connector) because the decision of what constitutes
# a failure belongs to the test oracle, not to the data-delivery layer.
FAIL_SEVERITIES: frozenset[str] = frozenset({"HIGH", "CRITICAL"})

# Severity levels that produce an InfoNote (PASS-with-observation).
# Items in this bucket are surfaced to the analyst but do not trigger FAIL.
NOTE_SEVERITIES: frozenset[str] = frozenset({"WARN", "MEDIUM"})

# Severity levels that are silently ignored (OK, INFO, LOW).
# These are positive results or purely informational messages with no security
# relevance to the Garanzia 1.5 oracle.  They are not surfaced in the report.
# Not declared as a frozenset constant because the ignore rule is expressed as
# "anything that is NOT in FAIL_SEVERITIES and NOT in NOTE_SEVERITIES",
# which automatically handles any future severity values testssl.sh might add.

# Standards references cited in every Finding and InfoNote this test produces.
_REFERENCES: tuple[str, ...] = (
    "OWASP-API2:2023",
    "NIST-SP-800-52-Rev2",
    "OWASP-ASVS-v5.0.0-V14.2.1",
    "OWASP-ASVS-v5.0.0-V12.1.2",
)

# Human-readable label for each testssl.sh severity level.
# testssl uses: CRITICAL, HIGH, MEDIUM, WARN, OK, INFO, DEBUG.
# Only CRITICAL/HIGH trigger FAIL; MEDIUM/WARN produce InfoNote.
_SEVERITY_LABEL: dict[str, str] = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "WARN": "Warning",
    "OK": "OK",
    "INFO": "Info",
    "LOW": "Low",
}

# Placeholder value testssl.sh writes when a check was not performed.
# e.g. security_headers returns "--" when the target is not HTTP.
# InfoNote detail is suppressed and replaced with a fixed message when
# the finding text is exactly this placeholder.
_TESTSSL_NOT_TESTED_PLACEHOLDER: str = "--"

# InfoNote suffix appended after the finding detail to guide the analyst.
# Defined as a constant to avoid verbatim repetition across every note and
# to make it easy to tune the wording without touching multiple callsites.
_NOTE_ANALYST_SUFFIX: str = (
    "Analyst review recommended -- not an automatic FAIL per Garanzia 1.5 oracle "
    "(NIST SP 800-52 Rev.2)."
)

# Regex for absolute paths in finding text: matches /any/path/filename or
# C:\any\path\filename.  We keep only the filename (last component) to avoid
# leaking filesystem layout in reports (e.g. "/home/user/.../openssl.Linux.x86_64"
# becomes "openssl.Linux.x86_64").
#
# Promoted to module level (A6) to avoid:
#   1. Recompiling the regex on every call to _evaluate().
#   2. The import-inside-function anti-pattern (``import re as _re`` was
#      inside _evaluate(), which violates the no-import-in-function-body rule).
_ABS_PATH_RE: re.Pattern[str] = re.compile(r"[/\\][^ ,\"'\t\n]*[/\\]([^ ,\"'\t\n]+)")

# Remediation text mapped by testssl.sh finding ID prefix.
# Keys are substrings matched against the finding ID (lowercase).
# The first matching entry wins; the fallback key "" matches everything.
# Having a per-category mapping avoids the generic "disable this protocol/cipher"
# text appearing for certificate or trust-chain findings where it makes no sense.
_REMEDIATION_BY_ID: dict[str, str] = {
    # Certificate trust and chain
    "cert_chain": (
        "Replace the self-signed or untrusted certificate with one signed by "
        "a recognised Certificate Authority (CA) trusted by all clients."
    ),
    "cert_": (
        "Review certificate configuration: validity period, revocation (OCSP/CRL), "
        "key usage extensions, and Subject Alternative Names."
    ),
    # Protocol version weaknesses
    "sslv2": "Disable SSLv2 in the API Gateway TLS configuration (deprecated, RFC 6176).",
    "sslv3": "Disable SSLv3 in the API Gateway TLS configuration (deprecated, RFC 7568).",
    "tls1 ": "Disable TLS 1.0 in the API Gateway TLS configuration (deprecated, RFC 8996).",
    "tls1_1": "Disable TLS 1.1 in the API Gateway TLS configuration (deprecated, RFC 8996).",
    # Cipher suite weaknesses
    "rc4": "Remove RC4 cipher suites from the API Gateway TLS configuration (RFC 7465).",
    "beast": "Disable TLS 1.0 or enable 1/n-1 record splitting to mitigate BEAST.",
    "lucky13": "Prefer AEAD cipher suites (GCM, CHACHA20) to eliminate LUCKY13 exposure.",
    "sweet32": "Replace 3DES cipher suites with AES-GCM equivalents (RFC 7525 Section 4.3).",
    "logjam": "Use DH parameters >= 2048 bit or prefer ECDHE key exchange.",
    "drown": "Ensure no SSLv2 endpoint shares the RSA private key used by this server.",
    "robot": "Apply vendor patch for ROBOT (RSA PKCS#1 v1.5 oracle); prefer ECDHE.",
    "heartbleed": "Patch OpenSSL immediately (CVE-2014-0160). This is a critical data exposure.",
    "poodle": "Disable SSLv3 (POODLE) and TLS_FALLBACK_SCSV if not already enabled.",
    "ticketbleed": "Upgrade F5 BIG-IP firmware or disable session tickets.",
    "crime": "Disable TLS compression in the API Gateway configuration.",
    "breach": ("Disable HTTP-level compression for sensitive endpoints or use per-request nonces."),
    # Forward secrecy
    "forward_secrecy": (
        "Configure ECDHE or DHE cipher suites to enable forward secrecy "
        "(NIST SP 800-52 Rev.2 Section 3.3.1)."
    ),
    # Overall grade / summary
    "overall_grade": (
        "Address all CRITICAL and HIGH findings above to improve the TLS grade. "
        "An overall grade of T indicates an untrusted certificate chain."
    ),
    # Fallback for any finding ID not matched above
    "": (
        "Remediate per NIST SP 800-52 Rev.2 and OWASP ASVS v5.0.0 V14.2.1. "
        "Consult the testssl.sh finding ID and detail for specific guidance."
    ),
}


def _get_remediation(finding_id: str) -> str:
    """
    Return the most specific remediation text for a testssl.sh finding ID.

    Iterates _REMEDIATION_BY_ID in insertion order (Python 3.7+ dict guarantee)
    and returns the value for the first key that is a substring of
    finding_id.lower().  The fallback key "" always matches, so the function
    never returns None.

    Args:
        finding_id: testssl.sh finding ID string (e.g. "cert_chain_of_trust").

    Returns:
        str: Remediation guidance string.
    """
    finding_id_lower = finding_id.lower()
    for key, remediation in _REMEDIATION_BY_ID.items():
        if key in finding_id_lower:
            return remediation
    # Unreachable in practice because "" always matches, but satisfies type checker.
    return _REMEDIATION_BY_ID[""]


def _clean_note_detail(raw_finding: str) -> str:
    """
    Strip absolute paths and handle the not-tested placeholder in finding text.

    Applied to MEDIUM/WARN finding text before building InfoNote objects.
    Two transformations:
        1. Absolute path stripping: ``/home/user/.../openssl.Linux.x86_64``
           becomes ``openssl.Linux.x86_64`` to avoid leaking filesystem layout.
        2. Placeholder suppression: testssl uses "--" when a check was not
           executed (e.g. security_headers on a non-HTTP target).  Returning
           "--" as the note detail is misleading; it is replaced with an
           explicit "check not executed" message.

    Args:
        raw_finding: Raw finding text string from testssl.sh.

    Returns:
        str: Cleaned finding text suitable for inclusion in an InfoNote.
    """
    text = raw_finding.strip()
    if not text or text == _TESTSSL_NOT_TESTED_PLACEHOLDER:
        return "Check was not executed for this target configuration."
    # Replace any absolute path with its filename component only.
    return _ABS_PATH_RE.sub(lambda m: m.group(1), text)


# ---------------------------------------------------------------------------
# ExtTest15TlsAnalysis
# ---------------------------------------------------------------------------


class ExtTest15TlsAnalysis(ExternalToolTest):
    """
    External test for Garanzia 1.5 -- deep TLS stack analysis via testssl.sh.

    Wraps TestsslConnector to perform a comprehensive TLS scan of the API
    Gateway's HTTPS listener.  Covers protocol versions, cipher suite strength,
    certificate chain validity, forward secrecy, and CVE-tagged vulnerabilities
    that testssl.sh's built-in template set identifies.

    Severity partitioning (oracle):
        The connector delivers ALL findings unfiltered.  This test partitions
        them into three buckets using FAIL_SEVERITIES and NOTE_SEVERITIES:

        FAIL bucket   (HIGH, CRITICAL)  -> one Finding per item -> FAIL result.
        NOTE bucket   (WARN, MEDIUM)    -> one InfoNote per item -> PASS-with-note.
        IGNORE bucket (OK, INFO, LOW)   -> silently discarded, not shown in report.

    See module docstring for oracle logic, DAG placement, and test_id rationale.
    """

    # --- Orchestrator metadata ---
    test_id: ClassVar[str] = "ext.1.5"
    test_name: ClassVar[str] = "TLS Stack Analysis (testssl.sh)"
    domain: ClassVar[int] = 1
    priority: ClassVar[int] = 2
    strategy: ClassVar[TestStrategy] = TestStrategy.WHITE_BOX
    depends_on: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = [
        "transport-security",
        "tls",
        "cipher-suite",
        "protocol-version",
        "testssl",
        "OWASP-API2:2023",
        "NIST-SP-800-52",
    ]
    cwe_id: ClassVar[str] = "CWE-326"  # Inadequate Encryption Strength

    # --- External tool identifier ---
    # Must match the key in ExternalToolsConfig for is_tool_enabled() filtering.
    tool_name: ClassVar[str] = "testssl"

    # ------------------------------------------------------------------
    # Abstract method implementations
    # ------------------------------------------------------------------

    def _build_connector(self) -> BaseConnector:
        """
        Instantiate a fresh TestsslConnector.

        Called by _get_connector() when no injected connector is available.
        Object construction only -- no I/O, no discovery.

        Returns:
            TestsslConnector: Ready-to-use connector instance.
        """
        return TestsslConnector()

    def _invoke_connector(
        self,
        connector: BaseConnector,
        target: TargetContext,
        target_url: str,
    ) -> ConnectorResult:
        """
        Call connector.run() with testssl-specific parameters.

        Timeout source (Proposal C):
            target.external_tools.testssl.timeout_seconds is the authoritative
            source for the testssl.sh runtime timeout.  This replaces the
            previous pattern of reading from
            target.tests_config.test_1_5.testssl_timeout_seconds, which was a
            semantically incorrect location left over from when testssl.sh was
            part of the native test.  With ExternalToolsConfig on TargetContext,
            every ExternalToolTest uses the same uniform access pattern:
                target.external_tools.<tool>.timeout_seconds

        extra_flags source:
            target.external_tools.testssl.extra_flags carries the full flag
            string from config.yaml (e.g. "--quiet --color 0 --connect-timeout 10").
            Passing it explicitly to connector.run() ensures that flags set in
            config.yaml override the connector's _DEFAULT_EXTRA_FLAGS constant.
            Not passing it caused the connector to silently ignore config.yaml
            flags and always fall back to the default "--quiet --color 0".

        Args:
            connector:   TestsslConnector instance (injected or freshly built).
            target:      Frozen TargetContext with target URL and config.
            target_url:  HTTPS URL returned by target.effective_endpoint_base_url().

        Returns:
            ConnectorResult: Complete (unfiltered) testssl.sh output.

        Raises:
            ExternalToolError: Propagated to _run() for timeout/OS error handling.
        """
        # Both fields are guaranteed non-None here: the Pydantic validator in
        # BaseExternalToolConfig rejects enabled=True with timeout_seconds=None
        # at Phase 1 (ConfigurationError -- bloccante), so if this code runs,
        # timeout_seconds was set in config.yaml.  extra_flags has a non-None
        # default ("--quiet --color 0"), so it is always a str.
        timeout_seconds: int = target.external_tools.testssl.timeout_seconds  # type: ignore[assignment]
        extra_flags: str = target.external_tools.testssl.extra_flags

        log.info(
            "ext_test_1_5_invoke_connector",
            target_url=target_url,
            timeout_seconds=timeout_seconds,
            extra_flags=extra_flags,
        )

        return connector.run(
            target_url=target_url,
            timeout_seconds=timeout_seconds,
            extra_flags=extra_flags,
        )

    def _evaluate(
        self,
        result: ConnectorResult,
        artifact_ref: str,
    ) -> TestResult:
        """
        Apply the oracle to ConnectorResult and return a TestResult.

        Oracle (Section 1.5 of 3_TOP_metodologia.md, NIST SP 800-52 Rev.2):

            FAIL bucket (CRITICAL / HIGH):
                Each qualifying finding becomes a separate Finding object.
                The test returns FAIL.  InfoNotes from the NOTE bucket are
                attached alongside so the analyst sees the full picture.

            NOTE bucket (MEDIUM / WARN only, no HIGH/CRITICAL):
                Each item becomes an InfoNote object.  The test returns PASS.

            IGNORE bucket (OK / INFO / LOW):
                Silently discarded.  These are positive results or informational
                messages with no security relevance to the Garanzia 1.5 oracle.
                They do not appear in the report at all.

            No findings at all:
                PASS.  TLS configuration is clean.

        Severity partitioning:
            The connector delivers all findings unfiltered (see testssl.py).
            This method partitions them using the module-level FAIL_SEVERITIES
            and NOTE_SEVERITIES frozensets.  Any severity not in either set
            falls into the IGNORE bucket (the three sets are mutually exclusive
            and collectively exhaustive for any severity value testssl.sh emits).

        Args:
            result:       ConnectorResult from TestsslConnector.run().
            artifact_ref: Evidence record ID from store.pin_artifact().

        Returns:
            TestResult: PASS or FAIL.  Never raises.
        """
        all_findings: list[dict] = result.raw_output.get("results", [])
        all_count: int = result.raw_output.get("all_count", 0)

        log.info(
            "ext_test_1_5_oracle_evaluation",
            all_count=all_count,
        )

        if not all_findings:
            return self._make_pass(
                message=(
                    "testssl.sh TLS scan found no issues. "
                    f"Total findings analysed: {all_count}. "
                    "All protocols, cipher suites, and certificate parameters "
                    "are within acceptable bounds."
                )
            )

        # Three-bucket partition: FAIL / NOTE / IGNORE.
        # IGNORE items are not assigned to a variable -- they are implicitly
        # discarded by not being included in either of the two named buckets.
        fail_items: list[dict] = [
            item
            for item in all_findings
            if str(item.get("severity", "")).upper() in FAIL_SEVERITIES
        ]
        note_items: list[dict] = [
            item
            for item in all_findings
            if str(item.get("severity", "")).upper() in NOTE_SEVERITIES
        ]
        # Items not in FAIL_SEVERITIES or NOTE_SEVERITIES (OK, INFO, LOW) are
        # silently ignored -- no variable assignment needed.

        ignored_count = len(all_findings) - len(fail_items) - len(note_items)
        log.debug(
            "ext_test_1_5_severity_partition",
            fail_count=len(fail_items),
            note_count=len(note_items),
            ignored_count=ignored_count,
        )

        # Build InfoNote objects for all NOTE bucket items (MEDIUM/WARN).
        # Constructed before the FAIL/PASS branch so both paths share the same
        # list (no duplication of InfoNote construction logic).
        all_notes: list[InfoNote] = []
        for item in note_items:
            sev_raw = str(item.get("severity", "")).upper()
            sev_label = _SEVERITY_LABEL.get(sev_raw, sev_raw or "?")
            note_id = str(item.get("id", "unknown"))
            raw_finding = str(item.get("finding", ""))
            cve_ids = str(item.get("cve", "")).strip()
            cwe_ids = str(item.get("cwe", "")).strip()

            clean_detail = _clean_note_detail(raw_finding)

            detail_parts = [clean_detail]
            if cve_ids:
                detail_parts.append(f"CVE: {cve_ids}.")
            if cwe_ids:
                detail_parts.append(f"CWE: {cwe_ids}.")
            detail_parts.append(_NOTE_ANALYST_SUFFIX)

            all_notes.append(
                InfoNote(
                    title=f"[{sev_label}] TLS observation: {note_id}",
                    detail=" ".join(detail_parts),
                    references=list(_REFERENCES),
                )
            )

        if fail_items:
            # FAIL path: at least one HIGH or CRITICAL finding.
            # Notes (MEDIUM/WARN) are attached alongside so the analyst sees
            # the full picture in the same expanded detail panel.
            findings = [self._build_finding(item, artifact_ref) for item in fail_items]
            note_count = len(all_notes)
            message_parts = [f"testssl.sh found {len(fail_items)} critical/high TLS issue(s)."]
            if note_count:
                message_parts.append(
                    f"Additionally, {note_count} MEDIUM/WARN observation(s) are listed as notes."
                )
            return self._make_fail(
                message=" ".join(message_parts),
                findings=findings,
                notes=all_notes,
            )

        # PASS-with-note path: only NOTE items, no FAIL items.
        log.info(
            "ext_test_1_5_pass_with_notes",
            note_count=len(all_notes),
        )
        return self._make_pass(
            message=(
                f"testssl.sh found {len(note_items)} MEDIUM/WARN item(s) "
                "below the FAIL threshold. "
                f"Raw evidence: artifact_ref={artifact_ref}."
            ),
            notes=all_notes,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_finding(
        self,
        item: dict,
        artifact_ref: str,
    ) -> Finding:
        """
        Construct a Finding object from a single testssl.sh finding dict.

        Args:
            item:         Single finding dict from ConnectorResult.raw_output["results"].
            artifact_ref: Evidence record ID for cross-referencing in the report.

        Returns:
            Finding: A fully populated Finding object.
        """
        finding_id: str = str(item.get("id", "unknown"))
        severity: str = str(item.get("severity", "UNKNOWN")).upper()
        finding_text: str = str(item.get("finding", "")).strip()
        cve_ids: str = str(item.get("cve", "")).strip()
        cwe_id: str = str(item.get("cwe", "")).strip()

        severity_label = _SEVERITY_LABEL.get(severity, severity)
        remediation = _get_remediation(finding_id)

        title = f"[{severity_label}] TLS Issue: {finding_id}"

        detail_parts = [
            f"testssl.sh reported a {severity_label.lower()} severity TLS issue.",
            f"Finding ID: {finding_id}.",
        ]
        # Skip the finding detail if testssl returned its "not tested" placeholder.
        # "--" means the check was not executed (e.g. security_headers on a non-HTTP
        # scan target), so there is no meaningful detail to surface.
        if finding_text and finding_text != _TESTSSL_NOT_TESTED_PLACEHOLDER:
            detail_parts.append(f"Detail: {finding_text}.")
        if cve_ids:
            detail_parts.append(f"CVE references: {cve_ids}.")
        if cwe_id:
            detail_parts.append(f"CWE reference: {cwe_id}.")
        detail_parts.append(f"Remediation: {remediation}")

        # Build references list: always include standard refs; add CVE/CWE if present.
        references = list(_REFERENCES)
        if cve_ids:
            for cve in cve_ids.split():
                references.append(cve.strip())
        if cwe_id and cwe_id not in references:
            references.append(cwe_id)

        return Finding(
            title=title,
            detail=" ".join(detail_parts),
            references=references,
            evidence_ref=artifact_ref,
        )
