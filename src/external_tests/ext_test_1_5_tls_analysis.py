"""
src/external_tests/ext_test_1_5_tls_analysis.py

Test ext.1.5.testssl: the TLS handshake part of guarantee 1.5 (credentials
never travel on an insecure channel), scanned by testssl.sh.

The native test 1.5 covers the HTTP layer (a plain-HTTP request forced onto
HTTPS, the HSTS header). The TLS handshake itself -- protocol versions, cipher
suites, forward secrecy, the certificate chain, known TLS CVEs -- is a scanner's
job, and testssl.sh does it: we launch it, point it at the gateway's HTTPS
listener, and judge its findings (rule 11). We do
not reimplement the handshake.

One tool, not two (owner, 2026-10-22): testssl.sh is installed by
install_tools.sh and is the most comprehensive on protocols, ciphers and
CVE-tagged weaknesses, so it is the single TLS analysis tool for this
guarantee.

Oracle (sub-test tls_configuration):

    HIGH / CRITICAL finding (weak protocol, weak cipher, known CVE,       VIOLATION/<id>   FIRM
      untrusted certificate chain)
    a HIGH/CRITICAL finding that the certificate's revocation cannot      NOT_VERIFIABLE/  -
      be checked (no OCSP/CRL): reported, not failed -- the normal        CERT_REVOCATION_
      state of an internal private-CA gateway, not a cleartext risk       NOT_CHECKABLE
    WARN / MEDIUM finding                                                 a note
    no HIGH/CRITICAL finding                                              ENFORCED/        -
                                                                          NO_TLS_WEAKNESS
    the scan could not connect / timed out                                ERROR (base handles it)

The tool's severity is kept in the finding's text as information; it is not the
oracle by itself (the id's meaning is). A finding's confidence is FIRM: the tool
observed the weakness on the target, and we did not re-derive it ourselves.

Dependency rule:
    Imports from: stdlib, structlog, src.connectors, src.core,
                  src.external_tests.base.
    Must never import from: tests/, config/, discovery/, report/, engine.py.
"""

from __future__ import annotations

import structlog

from src.connectors.base import BaseConnector, ConnectorResult
from src.connectors.testssl import TestsslConnector
from src.connectors.types import TlsFinding
from src.core.context import TargetContext
from src.core.models import (
    Confidence,
    Finding,
    InfoNote,
    Outcome,
    Reference,
    Standard,
    TestResult,
    TestStrategy,
)
from src.core.test_metadata import Effect, TestInfo
from src.external_tests.base import ExternalToolTest, ToolRun

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The single sub-test.
_SUB_TLS: str = "tls_configuration"

# testssl.sh severities that are a weakness of the target.
_FAIL_SEVERITIES: frozenset[str] = frozenset({"HIGH", "CRITICAL"})
# Severities surfaced as a note, not a violation.
_NOTE_SEVERITIES: frozenset[str] = frozenset({"WARN", "MEDIUM"})
# Below these (OK, INFO, LOW) a finding is a positive or informational result
# and is not shown.

# A HIGH/CRITICAL finding whose id says the certificate's revocation status
# could not be checked (no OCSP/CRL). On an internal gateway with a private CA
# this is the normal state, not a cleartext-interception risk, so it is reported
# NOT_VERIFIABLE with a note instead of failing the test (owner, 2026-10-22).
_REVOCATION_MARKERS: tuple[str, ...] = ("revocation",)

_REFERENCES: tuple[Reference, ...] = (
    Reference(standard=Standard.OWASP_API_TOP10, id="API2:2023"),
    Reference(standard=Standard.NIST_SP, id="800-52"),
    Reference(standard=Standard.ASVS, id="v5.0.0-12.1.1"),
)


def _is_revocation(finding: TlsFinding) -> bool:
    """True when a finding is about the certificate's revocation status."""
    identifier = str(finding.get("id", "")).lower()
    return any(marker in identifier for marker in _REVOCATION_MARKERS)


def _severity(finding: TlsFinding) -> str:
    """The finding's severity in upper case, or '' when absent."""
    return str(finding.get("severity", "")).upper()


def _configured_authority_notes(target: TargetContext) -> list[InfoNote]:
    """
    Note that the certificate was judged trusting target.tls.ca_bundle too.

    Without it the tool judges the certificate as anyone on the Internet would;
    with it, as a client of the organisation that configured that authority. The
    reader must know which.

    Args:
        target: The run's TargetContext.

    Returns:
        One note when target.tls.ca_bundle is set, else none.
    """
    if target.tls_ca_bundle is None:
        return []
    return [
        InfoNote(
            title="Certificate trust established through the configured authority",
            detail=(
                f"The certificate chain was checked trusting target.tls.ca_bundle "
                f"({target.tls_ca_bundle.name}) in addition to the tool's own authorities. "
                "A certificate trusted only through it is not trusted by clients that do not "
                "have that authority (e.g. on the public Internet)."
            ),
        )
    ]


class ExtTest15TlsAnalysis(ExternalToolTest):
    """
    Test ext.1.5.testssl -- the TLS handshake of guarantee 1.5, via testssl.sh.

    The oracle is in the module docstring and on the test page.
    """

    info = TestInfo(
        id="ext.1.5.testssl",
        name="TLS Stack Analysis (testssl.sh)",
        priority=2,
        strategy=TestStrategy.BLACK_BOX,
        cwe="CWE-326",
        references=_REFERENCES,
        tags=("transport-security", "tls", "cipher-suite", "protocol-version"),
        tool="testssl",
        effect=Effect.READ_ONLY,
        sub_tests=(_SUB_TLS,),
    )

    def _build_connector(self) -> BaseConnector:
        """Instantiate a fresh TestsslConnector (no I/O)."""
        return TestsslConnector()

    def _invoke_connector(
        self,
        connector: BaseConnector,
        target: TargetContext,
        target_url: str,
    ) -> ConnectorResult:
        """
        Run testssl.sh against the gateway's HTTPS listener.

        Args:
            connector:  The TestsslConnector (injected or freshly built).
            target:     The run's target (timeout, flags, ca_bundle).
            target_url: The HTTPS base URL (target.endpoint_base_url()).

        Returns:
            The connector's result (every finding, unfiltered).
        """
        # enabled=True guarantees timeout_seconds is set (Phase 1 validator); the
        # default flags are non-None.
        timeout_seconds: int = target.external_tools.testssl.timeout_seconds  # type: ignore[assignment]
        extra_flags: str = target.external_tools.testssl.extra_flags
        assert isinstance(connector, TestsslConnector)
        return connector.run(
            target_url=target_url,
            timeout_seconds=timeout_seconds,
            extra_flags=extra_flags,
            ca_bundle=target.tls_ca_bundle,
        )

    def _context_notes(self, target: TargetContext) -> list[InfoNote]:
        """State that certificate trust used the configured authority (target.tls.ca_bundle)."""
        return _configured_authority_notes(target)

    def _evaluate(self, result: ConnectorResult, run: ToolRun) -> TestResult:
        """
        Map testssl.sh's findings to the oracle and return the result.

        Args:
            result: The connector's result (raw_output['results']).
            run:    The evaluation context (artifact_ref for the findings' proof).

        Returns:
            self._finish() with the judgements and the notes.
        """
        findings: list[TlsFinding] = result.raw_output.get("results", [])
        notes: list[InfoNote] = []
        weaknesses = 0
        for finding in findings:
            severity = _severity(finding)
            if severity in _FAIL_SEVERITIES:
                if _is_revocation(finding):
                    self._record_revocation(finding)
                    notes.append(_revocation_note(finding))
                else:
                    self._record_weakness(finding, run.artifact_ref)
                    weaknesses += 1
            elif severity in _NOTE_SEVERITIES:
                notes.append(_finding_note(finding))
        if weaknesses == 0:
            self._record(_SUB_TLS, Outcome.ENFORCED, "NO_TLS_WEAKNESS")
        return self._finish(notes=notes)

    def _record_weakness(self, finding: TlsFinding, artifact_ref: str) -> None:
        """
        Record one HIGH/CRITICAL finding as a VIOLATION.

        Args:
            finding:      The testssl.sh finding.
            artifact_ref: The evidence record of the tool's output.
        """
        identifier = str(finding.get("id", "unknown"))
        severity = _severity(finding)
        text = str(finding.get("finding", "")).strip()
        cve = str(finding.get("cve", "")).strip()
        cve_part = f" ({cve})" if cve else ""
        self._record(
            _SUB_TLS,
            Outcome.VIOLATION,
            "TLS_WEAKNESS",
            Finding(
                title=f"TLS weakness ({severity.lower()}): {identifier}",
                detail=(
                    f"testssl.sh reported {identifier} as {severity}{cve_part}: {text}. A client "
                    "sending its credential over this TLS configuration can be downgraded or have "
                    "its traffic decrypted. Disable the weak protocol, cipher or feature in the "
                    "gateway's TLS configuration (NIST SP 800-52 Rev.2, ASVS v5.0.0-12.1.1)."
                ),
                confidence=Confidence.FIRM,
                evidence_ref=artifact_ref,
            ),
        )

    def _record_revocation(self, finding: TlsFinding) -> None:
        """
        Record a revocation-check finding as NOT_VERIFIABLE (not a violation).

        Args:
            finding: The testssl.sh revocation finding.
        """
        del finding
        self._record(_SUB_TLS, Outcome.NOT_VERIFIABLE, "CERT_REVOCATION_NOT_CHECKABLE")


def _revocation_note(finding: TlsFinding) -> InfoNote:
    """The note explaining the revocation-check finding, reported but not failed."""
    text = str(finding.get("finding", "")).strip()
    return InfoNote(
        title="Certificate revocation could not be checked",
        detail=(
            f"testssl.sh reported {finding.get('id', 'cert_revocation')!r} ({text}): the "
            "certificate offers no revocation mechanism (OCSP or CRL). This is reported, not "
            "failed: it is the normal state of an internal gateway with a private CA, and it is "
            "not a cleartext-interception risk the way a weak protocol is. On a certificate "
            "rooted in a public CA, enable OCSP so a compromised certificate can be revoked."
        ),
    )


def _finding_note(finding: TlsFinding) -> InfoNote:
    """A note for a WARN/MEDIUM finding, surfaced for the analyst without failing."""
    identifier = str(finding.get("id", "unknown"))
    severity = _severity(finding)
    text = str(finding.get("finding", "")).strip()
    return InfoNote(
        title=f"TLS note ({severity.lower()}): {identifier}",
        detail=(
            f"testssl.sh reported {identifier} as {severity}: {text}. Reviewed by the analyst, "
            "not an automatic failure under the 1.5 oracle (NIST SP 800-52 Rev.2)."
        ),
    )
