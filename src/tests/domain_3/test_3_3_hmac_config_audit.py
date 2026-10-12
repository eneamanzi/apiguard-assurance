"""
src/tests/domain_3/test_3_3_hmac_config_audit.py

Test 3.3 -- HMAC Authentication Configuration Audit.

Guarantee (Domain 3 -- Message Integrity and Cryptographic Controls):
    When HMAC authentication is deployed via the Kong hmac-auth plugin, its
    configuration must not allow replay attacks (excessive clock_skew) and must
    not permit weak or broken HMAC algorithms. A misconfigured hmac-auth plugin
    exposes authenticated requests to capture-and-replay attacks and, in the
    case of broken algorithms, to signature forgery.

Methodology:
    WHITE_BOX configuration audit via the Kong Admin API. No HTTP requests are
    issued to the target API; all evidence is derived from the plugin configuration
    object returned by GET /plugins. This approach mirrors Tests 4.2 and 4.3:
    empirical probing cannot distinguish a compliant configuration from a
    misconfigured one without injecting signed requests, which would require
    consumer credentials outside the tool's scope.

Strategy: WHITE_BOX -- Configuration Audit via Kong Admin API.
    The methodology prescribes White Box for this control: the tester has
    read access to the Gateway configuration (Admin API). Auditing the plugin
    config directly is more reliable and less invasive than empirical probing.

Priority: P3 -- HMAC is an optional authentication method. Many deployments
    use JWT exclusively and this test will SKIP. The finding severity is HIGH
    if hmac-auth is present and misconfigured (replay or broken algorithm).

Sub-tests (executed only when hmac-auth plugin is found and enabled):
--------------------------------------------------------------------------
Sub-test A -- Plugin Discovery
    Retrieves all installed plugins via GET /plugins and filters for 'hmac-auth'.
    Outcome:
        - Plugin absent or disabled: SKIP with InfoNote describing HMAC semantics
          and suggesting manual verification if HMAC is used elsewhere.
        - Plugin present and enabled: proceeds to sub-tests B and C.

Sub-test B -- Clock Skew Validation
    Checks the plugin's 'clock_skew' field against the oracle threshold
    (config.tests.domain_3.test_3_3.max_clock_skew_seconds, default 300 s).
    Oracle:
        clock_skew in (0, max_clock_skew_seconds]  -> compliant
        clock_skew == 0 or absent                  -> Finding: not configured
        clock_skew > max_clock_skew_seconds         -> Finding: window too wide

Sub-test C -- Algorithm Audit
    Checks the plugin's 'algorithms' list against the operator-configured
    forbidden_algorithms list (default: ['hmac-sha1', 'hmac-md5']).
    Oracle:
        No forbidden algorithm present             -> compliant
        Forbidden algorithm found                  -> Finding per algorithm

    The Finding detail distinguishes severity:
        hmac-md5:   cryptographically broken (RFC 6151 -- MD5 collision attacks);
                    must not be used in any new security-sensitive context.
        hmac-sha1:  deprecated per NIST SP 800-131A Rev. 2 (2019) and PCI-DSS v4
                    Requirement 12.3.3; not broken in the HMAC construction but
                    excluded from modern security profiles.

Sub-test E -- Coverage Scope Analysis
    Determines which services and routes are actually protected by the active
    HMAC plugin instance(s).  Kong allows plugins to be scoped globally (service=null
    AND route=null), to a single service, or to a single route.  A plugin that is
    correctly configured (compliant clock_skew and algorithms) but scoped to a single
    non-critical path still leaves the rest of the API traffic unprotected.

    This sub-test never produces a Finding.  It always emits an InfoNote documenting:
      - Global scope: all traffic is covered, no gaps.
      - Partial scope: which services/routes are covered and which are not,
        derived dynamically from GET /services and GET /routes without any
        hardcoded names.  Routes under a covered service are treated as implicitly
        covered even without a direct route-scope plugin instance.

    The InfoNote is attached to the result regardless of the PASS/FAIL status
    produced by sub-tests B and C, because coverage gaps are an independent
    architectural observation.

Sub-test D -- Body Validation Observability
    Checks whether 'validate_request_body' is enabled in the plugin config.
    This sub-test never produces a Finding. It always emits an InfoNote on
    the PASS result documenting the body-integrity posture of the deployment,
    since the correct value is context-dependent (POST/PUT-heavy APIs should
    enable it; GET-only APIs may leave it disabled by design).

Gateway access:
    The sub-tests read the gateway concepts "request signing policies" and
    "routes" (src/core/gateway/concepts.py) through the adapter; on Kong, the
    plugins named in plugin_names and the field names of this test's
    configuration are passed to the Kong adapter. Policies not supported or
    not accessible give SKIP; routes not readable give a degraded coverage
    note. The descriptions above use Kong's terms for the original design.

EvidenceStore policy:
    No HTTP request is made to the target API. The concepts read are stored
    as artifacts (BaseTest._record_gateway_concept); findings point to the
    signing policies read (evidence_ref), the coverage note to the routes.
--------------------------------------------------------------------------
"""

from __future__ import annotations

from typing import ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.gateway.base import CONCEPT_ROUTES, CONCEPT_SIGNING_POLICIES
from src.core.gateway.concepts import (
    ConceptRead,
    ConceptScope,
    ConceptStatus,
    GatewayRoute,
    SigningPolicy,
)
from src.core.models import (
    Finding,
    InfoNote,
    TestResult,
    TestStrategy,
)
from src.test_config.domain_3 import Test33Config
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# OWASP/NIST references cited in every Finding produced by this test.
_REFERENCES: tuple[str, ...] = (
    "OWASP-API2:2023",
    "CWE-326",
    "NIST-SP-800-107-Rev1-S5.3.2",
    "NIST-SP-800-131A-Rev2-2019",
    "RFC-2104",
    "RFC-6151",
    "OWASP-ASVS-v5.0.0-V2.9.1",
)

# NIST/OWASP references cited in every InfoNote produced by the coverage scope sub-test.
_SCOPE_REFERENCES: tuple[str, ...] = (
    "NIST-SP-800-204-S3.1",
    "OWASP-API9:2023",
    "OWASP-ASVS-v5.0.0-V2.9.1",
)

# Algorithm-specific severity notes embedded in Finding.detail.
# Keyed by algorithm name (lowercase); partial match via 'in' is used
# so variants like 'hmac-sha1' and 'sha1' both resolve to the right note.
_ALGORITHM_SEVERITY_NOTES: dict[str, str] = {
    "hmac-md5": (
        "HMAC-MD5 is cryptographically broken. MD5 collisions are achievable "
        "in seconds on commodity hardware (RFC 6151, Wang et al. 2005). While "
        "HMAC-MD5 does not directly expose the key via collision, its use "
        "violates the principle of defense-in-depth and is prohibited by "
        "NIST SP 800-131A Rev. 2. Remove 'hmac-md5' from the algorithms list "
        "immediately and rotate any HMAC keys that may have been used with it."
    ),
    "hmac-sha1": (
        "HMAC-SHA1 is deprecated, not broken. The HMAC construction prevents "
        "the length-extension attacks that affect raw SHA-1, but SHA-1 is "
        "deprecated for all cryptographic purposes per NIST SP 800-131A Rev. 2 "
        "(2019) and is excluded from PCI-DSS v4.0 Requirement 12.3.3. "
        "Migrate consumers to HMAC-SHA256 or stronger and schedule removal "
        "of 'hmac-sha1' from the allowed algorithms list."
    ),
}
_ALGORITHM_SEVERITY_NOTE_DEFAULT: str = (
    "This algorithm has been identified as forbidden by the operator-configured "
    "forbidden_algorithms list (config.tests.domain_3.test_3_3.forbidden_algorithms). "
    "Review the algorithm's security posture and migrate consumers to a stronger "
    "alternative (hmac-sha256, hmac-sha384, hmac-sha512)."
)


class Test33HMACConfigAudit(BaseTest):
    """
    Test 3.3 -- HMAC Authentication Configuration Audit.

    Audits the Kong hmac-auth plugin configuration (when present) for:
    - Excessive clock_skew (replay-attack exposure).
    - Forbidden/weak HMAC algorithms (signature forgery risk).
    - Body validation posture (informational note on PASS).

    This is a WHITE_BOX configuration audit: no HTTP requests are made to
    the target API. All evidence is derived from the Kong Admin API response.
    """

    test_id: ClassVar[str] = "3.3"
    test_name: ClassVar[str] = (
        "HMAC Authentication Configuration Does Not Allow Replay or Weak Algorithms"
    )
    domain: ClassVar[int] = 3
    priority: ClassVar[int] = 3
    strategy: ClassVar[TestStrategy] = TestStrategy.WHITE_BOX
    depends_on: ClassVar[list[str]] = []
    requires_pass: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = [
        "authentication",
        "cryptography",
        "hmac",
        "replay-protection",
        "white-box",
        "OWASP-API2:2023",
        "CWE-326",
    ]
    cwe_id: ClassVar[str] = "CWE-326"

    # ------------------------------------------------------------------
    # execute
    # ------------------------------------------------------------------

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Audit the request signing (HMAC) policy through the gateway adapter.

        Execution flow:
            1. Guard: requires a gateway adapter (_requires_admin_api).
            2. Read the concept "request signing policies" (on Kong: the
               plugins named in plugin_names) and store it as evidence; not
               supported or not accessible: SKIP with the reason.
            3. No policy, or the first one disabled: SKIP with an InfoNote.
            4. Audit the first policy: replay window (Sub-test B), algorithms
               (Sub-test C), body coverage note (Sub-test D), coverage scope
               note from the routes concept (Sub-test E).
            5. PASS with notes, or FAIL with findings pointing to the stored
               concept.

        Returns:
            TestResult with status PASS, FAIL, SKIP, or ERROR.
        """
        try:
            skip_guard = self._requires_admin_api(target)
            if skip_guard is not None:
                return skip_guard

            gateway = target.gateway
            assert gateway is not None  # noqa: S101

            cfg = target.tests_config.test_3_3
            plugin_names: list[str] = list(cfg.plugin_names)

            log.info(
                "test_3_3_starting",
                gateway_adapter=gateway.adapter_name,
                plugin_names=plugin_names,
                max_clock_skew_seconds=cfg.max_clock_skew_seconds,
                forbidden_algorithms=cfg.forbidden_algorithms,
            )

            if not plugin_names:
                log.warning("test_3_3_plugin_names_empty")
                return self._make_skip(
                    reason=(
                        "plugin_names is empty in config.tests.domain_3.test_3_3. "
                        "No HMAC plugin names configured to search for. "
                        "Add at least one plugin name (e.g. 'hmac-auth') to enable this audit."
                    )
                )

            policies = gateway.signing_policies()
            evidence_ref = self._record_gateway_concept(
                target, store, CONCEPT_SIGNING_POLICIES, policies
            )
            if policies.status != ConceptStatus.READ:
                return self._skip_for_concept(CONCEPT_SIGNING_POLICIES, policies, evidence_ref)

            if not policies.items:
                log.info("test_3_3_plugin_not_found", searched_names=plugin_names)
                return self._make_skip_with_note(plugin_names=plugin_names)

            policy = policies.items[0]
            if not policy.enabled:
                log.info("test_3_3_plugin_disabled", policy=policy.source)
                return self._make_skip_with_note(
                    plugin_names=plugin_names,
                    plugin_id=policy.source,
                    disabled=True,
                )

            log.info(
                "test_3_3_plugin_found",
                policy=policy.source,
                replay_window_seconds=policy.replay_window_seconds,
                algorithms=policy.algorithms,
                body_signed=policy.body_signed,
            )

            findings: list[Finding] = []
            clock_finding = self._audit_clock_skew(policy, cfg, evidence_ref)
            if clock_finding is not None:
                findings.append(clock_finding)
            findings.extend(self._audit_algorithms(policy, cfg, evidence_ref))

            body_note = self._build_body_validation_note(policy, cfg.field_validate_body)
            routes = gateway.routes()
            routes_ref = self._record_gateway_concept(target, store, CONCEPT_ROUTES, routes)
            coverage_note = self._audit_coverage_scope(policies.items, routes, routes_ref)
            notes: list[InfoNote] = [coverage_note, body_note]

            if findings:
                return self._make_fail_multi(
                    message=(
                        f"HMAC policy audit found {len(findings)} violation(s) "
                        f"({policy.source}). "
                        "Misconfigured HMAC authentication exposes the Gateway to "
                        "replay attacks or signature forgery."
                    ),
                    findings=findings,
                    notes=notes,
                )

            return self._make_pass(
                message=(
                    f"HMAC policy ({policy.source}) configuration is compliant: "
                    f"clock_skew <= {cfg.max_clock_skew_seconds} s and no forbidden "
                    "algorithms are configured."
                ),
                notes=notes,
            )

        except Exception as exc:  # noqa: BLE001
            log.exception("test_3_3_unexpected_error", error=str(exc))
            return self._make_error(exc)

    def _make_skip_with_note(
        self,
        plugin_names: list[str],
        plugin_id: str | None = None,
        disabled: bool = False,
    ) -> TestResult:
        """
        Build a SKIP TestResult with an InfoNote explaining HMAC semantics.

        Called when no HMAC plugin was found (disabled=False, plugin_id=None)
        or when a matching plugin exists but is disabled (disabled=True).
        The InfoNote documents what HMAC authentication is and what an analyst
        should verify manually if HMAC is in use outside of the gateway plugin
        system (e.g. at the application layer).

        Args:
            plugin_names: Names that were searched for in the plugin list.
            plugin_id:    Gateway plugin id if the plugin was found but disabled.
            disabled:     True if the plugin exists but is disabled.

        Returns:
            TestResult with status=SKIP, skip_reason, and a single InfoNote.
        """
        searched: str = ", ".join(f"'{n}'" for n in plugin_names)

        if disabled:
            skip_reason = (
                f"HMAC plugin (id: {plugin_id}) matching {searched} is installed "
                "but disabled on this Gateway instance. "
                "No active HMAC authentication configuration to audit. "
                "If the plugin was intentionally disabled, this SKIP is expected. "
                "If HMAC is expected to be active, verify plugin configuration."
            )
            note_detail = (
                f"A gateway HMAC plugin (id: {plugin_id}, searched names: {searched}) "
                "is installed on this Gateway instance but is currently disabled. "
                "HMAC authentication is therefore not enforced by the gateway for "
                "any route or service.\n\n"
                "HMAC-based request authentication (RFC 2104 / draft-cavage-http-signatures) "
                "adds an integrity and authenticity guarantee to API requests beyond what "
                "bearer tokens provide: each request is signed with a shared secret, making "
                "it infeasible for an attacker to modify in transit without invalidating the "
                "signature. When active, the key security parameters to audit are:\n"
                "  - clock_skew: the replay-attack window (smaller is safer; oracle: <= 300 s)\n"
                "  - algorithms: the HMAC algorithms clients may use (hmac-md5 and hmac-sha1 "
                "are deprecated or broken and should not appear in this list)\n"
                "  - validate_request_body: whether the request body is included in the "
                "signature (recommended for POST/PUT/PATCH endpoints)\n\n"
                "Re-enable the plugin to resume coverage of this control, or mark this "
                "SKIP as accepted if HMAC is intentionally not used."
            )
        else:
            skip_reason = (
                f"No HMAC plugin matching {searched} is installed on this Gateway instance. "
                "HMAC authentication is not in use; no configuration to audit. "
                "If HMAC is implemented at the application layer rather than the Gateway, "
                "manual verification of the application's HMAC configuration is required. "
                "To search for a different plugin name, update "
                "config.tests.domain_3.test_3_3.plugin_names."
            )
            note_detail = (
                f"No gateway plugin matching {searched} is registered on this Gateway "
                "instance. This test audits the HMAC plugin's security-critical parameters "
                "(clock_skew, algorithms, validate_request_body) and cannot proceed "
                "without an active plugin configuration.\n\n"
                "HMAC-based request authentication (RFC 2104 / draft-cavage-http-signatures) "
                "adds an integrity and authenticity guarantee to API requests beyond what "
                "bearer tokens provide: each request is signed with a shared secret, making "
                "it infeasible for an attacker to modify in transit without invalidating the "
                "signature. If this control is a requirement of your security policy but "
                "HMAC is implemented at the application layer (not via the gateway), verify "
                "the application's configuration against these parameters manually:\n"
                "  - Replay window: the timestamp tolerance must be <= 300 s "
                "(NIST SP 800-107 Rev. 1 Section 5.3.2)\n"
                "  - Allowed algorithms: must not include hmac-md5 (broken, RFC 6151) or "
                "hmac-sha1 (deprecated, NIST SP 800-131A Rev. 2)\n"
                "  - Body integrity: signature should cover the request body for "
                "state-mutating methods (POST, PUT, PATCH) to prevent body-swap attacks\n\n"
                "If a different plugin name is used by this gateway, update "
                "config.tests.domain_3.test_3_3.plugin_names accordingly."
            )

        return self._make_skip(
            skip_reason,
            notes=[
                InfoNote(
                    title="HMAC Authentication Not Active: Manual Verification Recommended",
                    detail=note_detail,
                    references=[
                        "RFC-2104",
                        "NIST-SP-800-107-Rev1-S5.3.2",
                        "NIST-SP-800-131A-Rev2-2019",
                        "RFC-6151",
                        "OWASP-ASVS-v5.0.0-V2.9.1",
                    ],
                )
            ],
        )

    # ------------------------------------------------------------------
    # Sub-test E: coverage scope analysis
    # ------------------------------------------------------------------

    def _audit_coverage_scope(
        self,
        policies: tuple[SigningPolicy, ...],
        routes: ConceptRead[GatewayRoute],
        routes_ref: str,
    ) -> InfoNote:
        """
        Determine which backends and routes are protected by request signing.

        A policy applies globally, to a backend (all its routes), or to one
        route. A correctly configured policy scoped to a single non-critical
        path still leaves the rest of the API unprotected: this sub-test
        surfaces that gap. Backends and routes are named as in the routes
        concept, so a policy on a backend covers the routes that send to it.

        This method never raises: routes that cannot be read give a degraded
        note listing only the policy scopes.

        Args:
            policies:   Signing policies read from the gateway.
            routes:     The routes concept answer.
            routes_ref: Evidence record of the routes answer.

        Returns:
            InfoNote documenting the coverage scope.  Never a Finding.
        """
        enabled = [p for p in policies if p.enabled]
        if not enabled:
            return InfoNote(
                title="HMAC Coverage Scope: No Enabled Instances Found",
                detail=(
                    "No enabled HMAC policy was found during coverage scope analysis, "
                    "although the policy audited above is enabled. Re-run the "
                    "assessment to confirm."
                ),
                references=list(_SCOPE_REFERENCES),
            )

        global_policies = [p for p in enabled if p.scope == ConceptScope.GLOBAL]
        if global_policies:
            sources = [p.source for p in global_policies]
            log.debug("test_3_3_coverage_scope_global", policies=sources)
            return InfoNote(
                title="HMAC Coverage: Global — All Traffic Protected",
                detail=(
                    f"The HMAC policy {', '.join(repr(src) for src in sources)} "
                    f"{'is' if len(sources) == 1 else 'are'} applied globally. Every "
                    "request reaching the Gateway, regardless of path, method or backend, "
                    "is subject to HMAC authentication. No coverage gaps exist."
                    "\n\nA global policy is the most protective scope: future routes and "
                    "backends are covered without any reconfiguration."
                ),
                references=list(_SCOPE_REFERENCES),
            )

        scope_lines = [f"{p.source}: {p.scope.value} '{p.name}'" for p in enabled]
        log.info("test_3_3_coverage_scope_partial", enabled_policy_count=len(enabled))

        if routes.status != ConceptStatus.READ:
            return InfoNote(
                title="HMAC Coverage: Scoped — Gap Analysis Unavailable",
                detail=(
                    "The HMAC policy is NOT applied globally: traffic outside the "
                    "covered scopes is NOT protected by HMAC authentication.\n\n"
                    "Active policies and their scopes:\n"
                    + "\n".join(f"  - {line}" for line in scope_lines)
                    + "\n\nThe gap analysis (uncovered backends and routes) needs the "
                    f"gateway's routes, which could not be read ({routes.status.value}: "
                    f"{routes.reason}). Evidence: {routes_ref}. Verify manually that all "
                    "intended traffic paths are covered."
                ),
                references=list(_SCOPE_REFERENCES),
            )

        covered_backends = {p.name for p in enabled if p.scope == ConceptScope.BACKEND}
        covered_routes = {p.name for p in enabled if p.scope == ConceptScope.ROUTE}
        all_backends = {r.backend for r in routes.items if r.backend} | covered_backends
        route_label = {r.name: (", ".join(r.paths) or r.name) for r in routes.items}
        via_backend = {r.name for r in routes.items if r.backend in covered_backends}
        effectively_covered = covered_routes | via_backend
        uncovered_backends = all_backends - covered_backends
        uncovered_routes = set(route_label) - effectively_covered

        log.info(
            "test_3_3_coverage_gap_summary",
            total_backends=len(all_backends),
            covered_backends=len(covered_backends),
            uncovered_backends=len(uncovered_backends),
            total_routes=len(route_label),
            covered_routes=len(effectively_covered),
            uncovered_routes=len(uncovered_routes),
        )

        has_gaps = bool(uncovered_backends or uncovered_routes)
        title_suffix = (
            "Partial Coverage — Gaps Detected" if has_gaps else "Partial Scope — Full Coverage"
        )
        detail_parts: list[str] = [
            "The HMAC policy is NOT applied globally.  All active policies are "
            "scoped to specific backends or routes.  Traffic outside the covered "
            "scopes is NOT protected by HMAC authentication.\n",
            "Active policies and their scopes:",
            *[f"  - {line}" for line in scope_lines],
        ]
        sections = (
            ("Backends WITH HMAC coverage (backend-scope policy):", "+", sorted(covered_backends)),
            ("Backends WITHOUT HMAC coverage:", "-", sorted(uncovered_backends)),
            (
                "Routes WITH HMAC coverage (route-scope policy or via their backend):",
                "+",
                sorted(
                    f"{route_label.get(r, r)}"
                    + (" [via backend]" if r in via_backend and r not in covered_routes else "")
                    for r in effectively_covered
                    if r in route_label
                ),
            ),
            (
                "Routes WITHOUT HMAC coverage:",
                "-",
                sorted(route_label.get(r, r) for r in uncovered_routes),
            ),
        )
        for heading, sign, names in sections:
            if names:
                detail_parts += [f"\n{heading}", *[f"  {sign} '{n}'" for n in names]]
        if has_gaps:
            detail_parts.append(
                "\nRecommended action: evaluate whether the uncovered backends and "
                "routes require HMAC authentication.  If so, either add policies "
                "scoped to each uncovered resource, or replace the scoped policies "
                "with a single global one."
            )
        else:
            detail_parts.append(
                "\nAll backends and routes are covered by at least one HMAC policy "
                "(directly or via their backend).  No traffic gaps were detected."
            )
        detail_parts.append(f"\nEvidence: {routes_ref}.")
        return InfoNote(
            title=f"HMAC Coverage Scope: {title_suffix}",
            detail="\n".join(detail_parts),
            references=list(_SCOPE_REFERENCES),
        )

    # ------------------------------------------------------------------
    # Sub-test B: replay window audit
    # ------------------------------------------------------------------

    def _audit_clock_skew(
        self,
        policy: SigningPolicy,
        cfg: Test33Config,
        evidence_ref: str,
    ) -> Finding | None:
        """
        Validate the replay window against the oracle threshold.

        Three conditions produce a Finding:
            1. The gateway does not state the replay window.
            2. It equals cfg.clock_skew_unconfigured_value (unlimited window).
            3. It exceeds cfg.max_clock_skew_seconds (window too wide).

        Args:
            policy:       The signing policy audited.
            cfg:          Test33Config with the oracle threshold.
            evidence_ref: Evidence record of the concept read.

        Returns:
            Finding if the replay window is non-compliant, None if compliant.
        """
        field_name: str = cfg.field_clock_skew
        ident = policy.source

        if policy.replay_window_seconds is None:
            log.info("test_3_3_clock_skew_absent", policy=ident)
            return Finding(
                title=f"HMAC '{field_name}' Field Absent on '{ident}'",
                detail=(
                    f"The gateway does not state the replay window ('{field_name}') of the "
                    f"HMAC policy {ident}. Without it, replay-attack protection posture for "
                    "HMAC authentication cannot be audited. "
                    f"Oracle: '{field_name}' must be > {cfg.clock_skew_unconfigured_value} "
                    f"and <= {cfg.max_clock_skew_seconds} s "
                    "(NIST SP 800-107 Rev. 1 Section 5.3.2)."
                ),
                references=list(_REFERENCES),
                evidence_ref=evidence_ref,
            )

        value_s = int(policy.replay_window_seconds)

        if value_s == cfg.clock_skew_unconfigured_value:
            log.info("test_3_3_clock_skew_unconfigured", policy=ident, value=value_s)
            return Finding(
                title=(
                    f"HMAC Replay Window Unlimited: '{field_name}' = "
                    f"{cfg.clock_skew_unconfigured_value} on '{ident}'"
                ),
                detail=(
                    f"The HMAC policy {ident} has '{field_name}' = "
                    f"{cfg.clock_skew_unconfigured_value}, which disables "
                    "timestamp-based replay protection. An attacker who captures a valid "
                    "HMAC-signed request can replay it indefinitely — the gateway will "
                    "continue accepting it as authentic regardless of how much time has "
                    "elapsed. "
                    f"Oracle: '{field_name}' must be > {cfg.clock_skew_unconfigured_value} "
                    f"and <= {cfg.max_clock_skew_seconds} s "
                    "(NIST SP 800-107 Rev. 1 Section 5.3.2, 5-minute window). "
                    "Recommended action: set the field to a value between 60 and "
                    f"{cfg.max_clock_skew_seconds} seconds in the gateway configuration."
                ),
                references=list(_REFERENCES),
                evidence_ref=evidence_ref,
            )

        if value_s > cfg.max_clock_skew_seconds:
            log.info(
                "test_3_3_clock_skew_too_wide",
                policy=ident,
                value=value_s,
                oracle_max_seconds=cfg.max_clock_skew_seconds,
            )
            return Finding(
                title=f"HMAC Replay Window Too Wide: '{field_name}' = {value_s} s on '{ident}'",
                detail=(
                    f"The HMAC policy {ident} has '{field_name}' = {value_s} s "
                    f"({value_s / 60:.1f} min), which exceeds the oracle threshold of "
                    f"{cfg.max_clock_skew_seconds} s ({cfg.max_clock_skew_seconds / 60:.0f} min) "
                    "from NIST SP 800-107 Rev. 1 Section 5.3.2. "
                    f"A {value_s}-second window means an attacker who captures a signed "
                    f"request can replay it for up to {value_s / 60:.1f} minutes before the "
                    "gateway rejects it. "
                    f"Recommended action: reduce '{field_name}' to "
                    f"<= {cfg.max_clock_skew_seconds} s in the gateway configuration."
                ),
                references=list(_REFERENCES),
                evidence_ref=evidence_ref,
            )

        log.debug("test_3_3_clock_skew_compliant", policy=ident, value=value_s)
        return None

    # ------------------------------------------------------------------
    # Sub-test C: algorithm audit
    # ------------------------------------------------------------------

    def _audit_algorithms(
        self,
        policy: SigningPolicy,
        cfg: Test33Config,
        evidence_ref: str,
    ) -> list[Finding]:
        """
        Check the allowed algorithms for any operator-forbidden algorithm.

        Produces one Finding per forbidden algorithm found, or one Finding
        when the gateway does not state the allowed algorithms (an empty list
        states that none is allowed and gives no finding).

        Args:
            policy:       The signing policy audited.
            cfg:          Test33Config with the forbidden_algorithms list.
            evidence_ref: Evidence record of the concept read.

        Returns:
            List of Findings. Empty if clean.
        """
        field_name: str = cfg.field_algorithms
        ident = policy.source

        if policy.algorithms is None:
            log.info("test_3_3_algorithms_field_absent", policy=ident)
            return [
                Finding(
                    title=f"HMAC '{field_name}' Field Absent on '{ident}'",
                    detail=(
                        f"The gateway does not state the allowed algorithms ('{field_name}') "
                        f"of the HMAC policy {ident}. The active set then defaults to the "
                        "gateway's built-in list, which historically includes 'hmac-sha1' "
                        "and 'hmac-md5'. Configure the list explicitly to restrict it to "
                        "hmac-sha256, hmac-sha384, or hmac-sha512."
                    ),
                    references=list(_REFERENCES),
                    evidence_ref=evidence_ref,
                )
            ]

        configured_algorithms: list[str] = [a.lower() for a in policy.algorithms]
        findings: list[Finding] = []
        for forbidden_alg in (a.lower() for a in cfg.forbidden_algorithms):
            if forbidden_alg not in configured_algorithms:
                log.debug("test_3_3_algorithm_not_found", policy=ident, algorithm=forbidden_alg)
                continue
            severity_note = _ALGORITHM_SEVERITY_NOTES.get(
                forbidden_alg, _ALGORITHM_SEVERITY_NOTE_DEFAULT
            )
            log.info("test_3_3_forbidden_algorithm_found", policy=ident, algorithm=forbidden_alg)
            findings.append(
                Finding(
                    title=f"Forbidden HMAC Algorithm '{forbidden_alg}' Allowed on '{ident}'",
                    detail=(
                        f"The HMAC policy {ident} allows the algorithm '{forbidden_alg}' "
                        f"in its allowed list ({configured_algorithms}). {severity_note} "
                        "Recommended action: remove this algorithm from the allowed list "
                        "and ensure all consumers are migrated to hmac-sha256 or stronger "
                        "before the next key rotation."
                    ),
                    references=list(_REFERENCES),
                    evidence_ref=evidence_ref,
                )
            )
        return findings

    # ------------------------------------------------------------------
    # Sub-test D: body validation observability note
    # ------------------------------------------------------------------

    @staticmethod
    def _build_body_validation_note(policy: SigningPolicy, field_validate_body: str) -> InfoNote:
        """
        Build an InfoNote describing whether the body is covered by the signature.

        This sub-test never fails: the correct value depends on the API's usage.

        Args:
            policy:              The signing policy audited.
            field_validate_body: The gateway's field name, for the note (from
                                 cfg.field_validate_body).

        Returns:
            InfoNote documenting the body validation posture.
        """
        validate_body: bool = bool(policy.body_signed)
        ident = policy.source
        if validate_body:
            detail = (
                f"The HMAC policy {ident} has '{field_validate_body}' = true. "
                "The HMAC signature covers the full request body in addition to the headers, "
                "preventing body-swap attacks where an attacker intercepts a signed request "
                "and replaces the body with a malicious payload. This is the recommended "
                "configuration for APIs that accept POST, PUT, or PATCH requests with "
                "sensitive payloads."
            )
        else:
            body_field_note = (
                f"(field '{field_validate_body}' not stated -- gateway defaults to false)"
                if policy.body_signed is None
                else f"'{field_validate_body}' = false"
            )
            detail = (
                f"The HMAC policy {ident} has {body_field_note}. "
                "The HMAC signature covers only the request headers (method, path, date, "
                "Authorization), not the body. An attacker who intercepts a signed request "
                "could replace the body with a malicious payload and the gateway would "
                "accept it as authentic. "
                "Whether this is acceptable depends on the API's usage pattern:\n"
                "  - GET-only APIs: body validation is irrelevant (no body to protect).\n"
                "  - POST/PUT/PATCH APIs handling sensitive operations: enabling "
                f"'{field_validate_body}' is strongly recommended.\n"
                "This note is informational. Enable body validation in the gateway "
                "configuration if body integrity is a requirement of your security policy."
            )
        return InfoNote(
            title=f"HMAC Body Validation: '{field_validate_body}' = {validate_body} on '{ident}'",
            detail=detail,
            references=[
                "RFC-2104",
                "OWASP-ASVS-v5.0.0-V2.9.1",
            ],
        )
