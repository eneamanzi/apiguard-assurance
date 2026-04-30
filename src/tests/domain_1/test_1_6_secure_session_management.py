"""
src/tests/domain_1/test_1_6_secure_session_management.py

Test 1.6 -- Secure Session Management in Distributed Architectures.

Guarantee (3_TOP_metodologia.md, Section 1.6):
    Session cookies emitted by the API must carry the mandatory security
    attributes: HttpOnly, Secure, and SameSite.  Without HttpOnly, JavaScript
    running in a compromised page can exfiltrate the session token.  Without
    Secure, the cookie is transmitted over plain HTTP.  Without SameSite, the
    cookie is eligible for CSRF attacks from cross-origin pages.

    Methodology references:
        OWASP API2:2023 Broken Authentication
        OWASP ASVS v5.0.0 V3.2.1 (session fixation prevention)
        OWASP ASVS v5.0.0 V3.2.3 (SameSite cookie attribute)
        NIST SP 800-63B-4 Section 4.2 (session management)
        NIST SP 800-204A Section 4.3 (distributed session consistency)

Strategy: WHITE_BOX -- Configuration Audit (methodology section 1.6, P3).
    Sends unauthenticated GET requests to the configured probe paths and
    inspects Set-Cookie response headers.  No Kong Admin API access is
    required.  The _requires_admin_api guard is intentionally NOT applied.

Priority: P3 -- Compliance and static best-practice.
    A missing cookie attribute is a defence-in-depth gap.  REST APIs that
    use stateless JWT bearer tokens will produce zero cookies and the test
    will SKIP cleanly with an informational note.

Sub-tests:
--------------------------------------------------------------------------
Sub-test 1 -- Cookie attribute discovery
    For each path in cookie_probe_paths, sends a GET without an
    Authorization header.  Collects all Set-Cookie headers.  Filters to
    cookies whose names match session_cookie_names (case-insensitive).
    If no session cookies are found on any probe path, returns SKIP.

Sub-test 2 -- HttpOnly attribute check (ASVS V3.2.3)
    Each session cookie must carry the HttpOnly flag.  Absence is a FAIL.

Sub-test 3 -- Secure attribute check (ASVS V3.2.3)
    Each session cookie must carry the Secure flag.  Absence is a FAIL.

Sub-test 4 -- SameSite attribute check (ASVS V3.2.3)
    When check_samesite is True: each session cookie must carry SameSite
    set to expected_samesite_value.  A value of 'None' is always a FAIL.

Session fixation empirical sub-test -- NOT implemented (documented gap):
    The full session fixation check (ASVS V3.2.1) requires a target-specific
    login flow with a browser-level session cookie exchange that cannot be
    implemented generically in a config-driven agnostic tool.  This gap is
    documented via an InfoNote on PASS results so that the analyst can
    perform the check manually following 3_TOP_metodologia.md Section 1.6.

EvidenceStore policy:
    FAIL transactions from client.request() are passed to
    store.add_fail_evidence().  PASS transactions are logged via
    _log_transaction() but not stored in the EvidenceStore.
    pin_evidence() is never used in this test.
"""

from __future__ import annotations

from typing import ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import EvidenceRecord, Finding, InfoNote, TestResult, TestStatus, TestStrategy
from src.core.models.runtime import RuntimeTest16Config
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Oracle state labels — appear verbatim in the HTML Audit Trail column.
_STATE_NO_COOKIES: str = "NO_SESSION_COOKIES_FOUND"
_STATE_COOKIES_FOUND: str = "SESSION_COOKIES_FOUND"
_STATE_COOKIE_COMPLIANT: str = "COOKIE_ATTRIBUTES_COMPLIANT"
_STATE_COOKIE_MISSING_HTTPONLY: str = "COOKIE_MISSING_HTTPONLY"
_STATE_COOKIE_MISSING_SECURE: str = "COOKIE_MISSING_SECURE"
_STATE_COOKIE_SAMESITE_FAIL: str = "COOKIE_SAMESITE_NONCOMPLIANT"
_STATE_COOKIE_SAMESITE_NONE: str = "COOKIE_SAMESITE_NONE_FORBIDDEN"

# Standards references cited in every Finding this test produces.
_REFERENCES: list[str] = [
    "OWASP-API2:2023",
    "OWASP-ASVS-v5.0.0-V3.2.3",
    "NIST-SP-800-63B-4-S4.2",
    "NIST-SP-800-204A-S4.3",
]

# SameSite 'None' is never acceptable for a session cookie because it makes
# the cookie available in all cross-site contexts, negating CSRF protection.
_SAMESITE_FORBIDDEN_VALUE: str = "none"


class Test16SecureSessionManagement(BaseTest):
    """Test 1.6 -- Secure Session Management in Distributed Architectures."""

    test_id: ClassVar[str] = "1.6"
    test_name: ClassVar[str] = "Secure Session Management in Distributed Architectures"
    priority: ClassVar[int] = 3
    domain: ClassVar[int] = 1
    strategy: ClassVar[TestStrategy] = TestStrategy.WHITE_BOX
    depends_on: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = [
        "session-management",
        "cookies",
        "OWASP-API2:2023",
        "OWASP-ASVS-V3.2",
    ]
    cwe_id: ClassVar[str] = "CWE-614"

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Audit session cookie security attributes across configured probe paths.

        Probes each path in cfg.cookie_probe_paths and inspects Set-Cookie
        response headers.  Filters to cookies whose names match
        cfg.session_cookie_names.  Audits HttpOnly, Secure, and SameSite on
        each found session cookie.

        Returns:
            SKIP if no session cookies are discovered (API uses stateless tokens).
            FAIL if at least one session cookie is missing a required attribute.
            PASS if all found cookies carry all required attributes.
            ERROR on unexpected exception.
        """
        try:
            cfg = target.tests_config.test_1_6
            session_cookie_names_lower: frozenset[str] = frozenset(
                n.lower() for n in cfg.session_cookie_names
            )

            # Collect (record, cookie_name, cookie_attrs) tuples across all paths.
            all_session_cookies: list[tuple[EvidenceRecord, str, dict[str, str]]] = []

            for probe_path in cfg.cookie_probe_paths:
                log.info(
                    "test_1_6_probing_path",
                    path=probe_path,
                )
                response, record = client.request(
                    method="GET",
                    path=probe_path,
                    test_id=self.test_id,
                    # No Authorization header: cookie audit does not require auth.
                )

                # httpx provides response.cookies as a Cookies mapping, but the
                # Set-Cookie header parsing there loses the attributes (HttpOnly,
                # Secure, SameSite).  We parse the raw Set-Cookie headers manually.
                raw_set_cookie_headers: list[str] = (
                    response.headers.get_list("set-cookie")
                    if hasattr(response.headers, "get_list")
                    else [v for k, v in response.headers.multi_items() if k.lower() == "set-cookie"]
                )

                found_on_this_path: list[tuple[EvidenceRecord, str, dict[str, str]]] = []
                for raw_header in raw_set_cookie_headers:
                    parsed_name, parsed_attrs = self._parse_set_cookie(raw_header)
                    if parsed_name.lower() not in session_cookie_names_lower:
                        log.debug(
                            "test_1_6_non_session_cookie_skipped",
                            cookie_name=parsed_name,
                            path=probe_path,
                        )
                        continue
                    log.info(
                        "test_1_6_session_cookie_found",
                        cookie_name=parsed_name,
                        path=probe_path,
                        attributes=list(parsed_attrs.keys()),
                    )
                    found_on_this_path.append((record, parsed_name, parsed_attrs))

                # Log the transaction only after filtering: the oracle state now
                # reflects what was actually found, not a premature assumption.
                oracle_state = _STATE_NO_COOKIES if not found_on_this_path else _STATE_COOKIES_FOUND
                self._log_transaction(record, oracle_state=oracle_state)
                all_session_cookies.extend(found_on_this_path)

            if not all_session_cookies:
                log.info(
                    "test_1_6_no_session_cookies_found",
                    probed_paths=list(cfg.cookie_probe_paths),
                    watched_names=list(cfg.session_cookie_names),
                )
                return self._make_skip(
                    reason=(
                        f"No session cookies matching {list(cfg.session_cookie_names)} "
                        f"were found on any of the probed paths: "
                        f"{list(cfg.cookie_probe_paths)}.  "
                        "This is expected for REST APIs that use stateless JWT bearer "
                        "tokens.  Test 1.5 covers transport-layer enforcement for "
                        "bearer token confidentiality."
                    )
                )

            # Audit each found session cookie.
            findings: list[Finding] = []
            for record, cookie_name, attrs in all_session_cookies:
                new_findings = self._audit_cookie_attributes(record, cookie_name, attrs, store, cfg)
                findings.extend(new_findings)

            if findings:
                return TestResult(
                    test_id=self.test_id,
                    status=TestStatus.FAIL,
                    message=(
                        f"Session cookie attribute audit found {len(findings)} "
                        f"violation(s) across {len(all_session_cookies)} "
                        "session cookie(s)."
                    ),
                    findings=findings,
                    transaction_log=list(self._transaction_log),
                    **self._metadata_kwargs(),
                )

            # All cookies are compliant: return PASS with a manual-check InfoNote.
            return self._make_pass(
                message=(
                    f"All {len(all_session_cookies)} session cookie(s) carry "
                    "HttpOnly, Secure, and SameSite attributes."
                ),
                notes=[
                    InfoNote(
                        title="Manual Verification Required: Session Fixation (ASVS V3.2.1)",
                        detail=(
                            "The automated tool verified cookie attribute compliance "
                            "(HttpOnly, Secure, SameSite) but cannot verify session "
                            "fixation prevention (OWASP ASVS v5.0.0 V3.2.1).  "
                            "Session fixation requires observing whether the session "
                            "cookie value changes after login, which requires a "
                            "target-specific browser-level login flow outside the "
                            "scope of a config-driven agnostic tool.  "
                            "Perform this check manually following "
                            "3_TOP_metodologia.md Section 1.6: capture the pre-login "
                            "cookie, authenticate, and verify the cookie value differs "
                            "post-authentication."
                        ),
                        references=["OWASP-ASVS-v5.0.0-V3.2.1", "NIST-SP-800-63B-4-S4.2"],
                    )
                ],
            )

        except Exception as exc:  # noqa: BLE001
            return self._make_error(exc)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_set_cookie(header_value: str) -> tuple[str, dict[str, str]]:
        """
        Parse a raw Set-Cookie header string into a (name, attributes) pair.

        The first segment is the 'name=value' pair for the cookie itself.
        Subsequent semicolon-separated segments are attributes (HttpOnly,
        Secure, SameSite, Path, Domain, etc.).

        Args:
            header_value: Raw Set-Cookie header value string, e.g.
                'session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/'.

        Returns:
            Tuple of (cookie_name, attributes_dict) where cookie_name is the
            name segment of the first 'name=value' pair and attributes_dict maps
            lowercased attribute names to their values (empty string for
            flag-only attributes like HttpOnly and Secure).
        """
        segments = [s.strip() for s in header_value.split(";")]
        if not segments:
            return ("", {})

        # First segment is the cookie 'name=value'.
        first_segment = segments[0]
        if "=" in first_segment:
            cookie_name = first_segment.split("=", 1)[0].strip()
        else:
            cookie_name = first_segment.strip()

        # Remaining segments are attributes.
        attrs: dict[str, str] = {}
        for segment in segments[1:]:
            if "=" in segment:
                attr_name, attr_value = segment.split("=", 1)
                attrs[attr_name.strip().lower()] = attr_value.strip()
            else:
                # Flag attribute (HttpOnly, Secure) — no value.
                attrs[segment.strip().lower()] = ""

        return (cookie_name, attrs)

    def _audit_cookie_attributes(
        self,
        record: EvidenceRecord,
        cookie_name: str,
        attrs: dict[str, str],
        store: EvidenceStore,
        cfg: RuntimeTest16Config,
    ) -> list[Finding]:
        """
        Audit a single session cookie's attributes and return Findings for violations.

        Calls store.add_fail_evidence() at most once per record (via the
        _ensure_evidence_stored closure) and calls self._log_transaction()
        exactly once at the end, after all attribute checks are complete.
        This avoids duplicate audit-trail entries when a cookie fails multiple
        checks simultaneously (e.g. missing both HttpOnly and Secure).

        Args:
            record: EvidenceRecord from the probe request that returned this cookie.
            cookie_name: The cookie name (for human-readable Finding titles).
            attrs: Parsed attribute dictionary (lowercase keys) from _parse_set_cookie.
            store: EvidenceStore for recording FAIL evidence.
            cfg: RuntimeTest16Config carrying the check parameters.

        Returns:
            List of Finding objects.  Empty if all attributes are compliant.
        """
        findings: list[Finding] = []
        evidence_stored = False

        # Helper that ensures add_fail_evidence is called at most once per record.
        def _ensure_evidence_stored() -> None:
            nonlocal evidence_stored
            if not evidence_stored:
                store.add_fail_evidence(record)
                evidence_stored = True

        # --- HttpOnly check ---
        if "httponly" not in attrs:
            _ensure_evidence_stored()
            findings.append(
                Finding(
                    title=f"Session Cookie '{cookie_name}' Missing HttpOnly Attribute",
                    detail=(
                        f"The Set-Cookie header for '{cookie_name}' does not include "
                        "the HttpOnly attribute.  Without HttpOnly, JavaScript code "
                        "executing in the page context (e.g., via XSS) can read the "
                        "cookie value and exfiltrate it to an attacker-controlled "
                        "server.  "
                        "Oracle: all session cookies must carry HttpOnly "
                        "(OWASP ASVS v5.0.0 V3.2.3)."
                    ),
                    references=_REFERENCES,
                    evidence_ref=record.record_id,
                )
            )

        # --- Secure check ---
        if "secure" not in attrs:
            _ensure_evidence_stored()
            findings.append(
                Finding(
                    title=f"Session Cookie '{cookie_name}' Missing Secure Attribute",
                    detail=(
                        f"The Set-Cookie header for '{cookie_name}' does not include "
                        "the Secure attribute.  Without Secure, the browser will "
                        "transmit the cookie over plain HTTP connections, enabling "
                        "MITM interception of the session identifier.  "
                        "Oracle: all session cookies must carry Secure "
                        "(OWASP ASVS v5.0.0 V3.2.3)."
                    ),
                    references=_REFERENCES,
                    evidence_ref=record.record_id,
                )
            )

        # --- SameSite check ---
        if cfg.check_samesite:
            samesite_value = attrs.get("samesite")

            if samesite_value is None:
                _ensure_evidence_stored()
                findings.append(
                    Finding(
                        title=f"Session Cookie '{cookie_name}' Missing SameSite Attribute",
                        detail=(
                            f"The Set-Cookie header for '{cookie_name}' does not include "
                            "the SameSite attribute.  Absent SameSite defaults to 'Lax' "
                            "in modern browsers, but this is an implicit behaviour that "
                            "may not hold across all browser versions and contexts.  "
                            f"Oracle: SameSite must be explicitly set to "
                            f"'{cfg.expected_samesite_value}' "
                            "(OWASP ASVS v5.0.0 V3.2.3)."
                        ),
                        references=_REFERENCES,
                        evidence_ref=record.record_id,
                    )
                )
            elif samesite_value.lower() == _SAMESITE_FORBIDDEN_VALUE:
                _ensure_evidence_stored()
                findings.append(
                    Finding(
                        title=(f"Session Cookie '{cookie_name}' Has Forbidden SameSite=None"),
                        detail=(
                            f"The Set-Cookie header for '{cookie_name}' declares "
                            "SameSite=None.  This makes the cookie available in all "
                            "cross-site request contexts, completely negating CSRF "
                            "protection.  SameSite=None requires the Secure attribute "
                            "and is only appropriate for cross-site tracking cookies, "
                            "never for session identifiers.  "
                            "Oracle: session cookies must never use SameSite=None "
                            "(OWASP ASVS v5.0.0 V3.2.3)."
                        ),
                        references=_REFERENCES,
                        evidence_ref=record.record_id,
                    )
                )
            elif samesite_value.lower() != cfg.expected_samesite_value.lower():
                _ensure_evidence_stored()
                findings.append(
                    Finding(
                        title=(
                            f"Session Cookie '{cookie_name}' Has Unexpected "
                            f"SameSite Value '{samesite_value}'"
                        ),
                        detail=(
                            f"The Set-Cookie header for '{cookie_name}' declares "
                            f"SameSite={samesite_value}.  The configured expected "
                            f"value is '{cfg.expected_samesite_value}'.  "
                            f"If 'Strict' is required, 'Lax' is insufficient: it "
                            "still allows the cookie to be sent with top-level "
                            "navigation GET requests from cross-origin pages.  "
                            "Oracle: SameSite must match the configured policy "
                            "(OWASP ASVS v5.0.0 V3.2.3)."
                        ),
                        references=_REFERENCES,
                        evidence_ref=record.record_id,
                    )
                )

        # Single _log_transaction call at the end, after all checks.
        # The oracle state summarises the worst violation found; if the cookie
        # is fully compliant the COMPLIANT state is used.  This ensures exactly
        # one audit-trail entry per probe record regardless of how many attribute
        # checks failed simultaneously.
        if findings:
            # Derive oracle state from the first (most severe) finding title.
            if any("HttpOnly" in f.title for f in findings):
                final_oracle = _STATE_COOKIE_MISSING_HTTPONLY
            elif any("Secure" in f.title for f in findings):
                final_oracle = _STATE_COOKIE_MISSING_SECURE
            else:
                final_oracle = _STATE_COOKIE_SAMESITE_FAIL
            self._log_transaction(record, oracle_state=final_oracle, is_fail=True)
            log.warning(
                "test_1_6_cookie_violations_found",
                cookie_name=cookie_name,
                finding_count=len(findings),
                oracle=final_oracle,
            )
        else:
            self._log_transaction(record, oracle_state=_STATE_COOKIE_COMPLIANT)
            log.info(
                "test_1_6_cookie_attributes_compliant",
                cookie_name=cookie_name,
                attributes=list(attrs.keys()),
            )

        return findings
