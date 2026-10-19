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
    Oracle (on the concept's replay window, whatever the gateway calls it):
        window in (0, max_clock_skew_seconds]      -> compliant
        no date check (replay_unlimited) or absent -> Finding: not configured
        window > max_clock_skew_seconds             -> Finding: window too wide

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
    "routes" (src/core/gateway/concepts.py) through the adapter, which knows
    which plugins hold a policy and how their fields are named (block 10b,
    docs/architecture/design-decisions.md, D8). Policies not supported or not
    accessible give SKIP; routes not readable give a degraded coverage note.
    The descriptions above use Kong's terms for the original design.

EvidenceStore policy:
    No HTTP request is made to the target API. The concepts read are stored
    as artifacts (BaseTest._record_gateway_concept); findings point to the
    signing policies read (evidence_ref), the coverage note to the routes.
--------------------------------------------------------------------------
"""

from __future__ import annotations

from typing import Annotated

import structlog
from pydantic import BaseModel, Field

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
from src.core.test_metadata import Need, TestInfo
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Parameters: tests.domain_3.test_3_3 in config.yaml
# ---------------------------------------------------------------------------

TEST_33_MAX_CLOCK_SKEW_SECONDS_DEFAULT: int = 300

TEST_33_MAX_CLOCK_SKEW_SECONDS_MIN: int = 1

# Default algorithms treated as forbidden.
# hmac-md5: cryptographically broken (MD5 collision attacks, RFC 6151).
# hmac-sha1: deprecated per NIST SP 800-131A Rev. 2 (2019) for signature use;
#   not broken in the HMAC construction, but excluded from modern TLS cipher
#   suites and flagged by PCI-DSS v4 Requirement 12.3.3.
_TEST_33_FORBIDDEN_ALGORITHMS_DEFAULT: list[str] = ["hmac-sha1", "hmac-md5"]


class Test33Params(BaseModel):
    """
    Tuning parameters for Test 3.3 (HMAC Authentication Configuration Audit).

    Audits the gateway's request signing (HMAC) policies, read through the
    gateway adapter's neutral concept (SigningPolicy), for replay-attack
    exposure (replay window oracle) and weak algorithm usage
    (forbidden_algorithms oracle). Which plugins and fields hold a policy is
    the adapter's knowledge, not a parameter of the test.

    References:
        - NIST SP 800-107 Rev. 1 Section 5.3.2: clock-skew window for HMAC-based
          timestamp validation should not exceed 5 minutes (300 seconds).
        - RFC 2104 Section 3: HMAC security does not degrade over time, but
          replay prevention is the caller's responsibility.
        - NIST SP 800-131A Rev. 2 (2019): SHA-1 deprecated for digital signatures;
          HMAC-SHA1 still provides integrity but is excluded from modern profiles.
        - RFC 6151: MD5 considered broken for cryptographic use; HMAC-MD5 must not
          be used in new security-sensitive applications.
        - OWASP ASVS v5.0.0 V2.9.1: HMAC keys must be generated using a CSPRNG,
          minimum 128 bits; weak algorithms prohibited.
    """

    model_config = {"frozen": True, "extra": "forbid"}

    # --- Oracle thresholds (security policy) --------------------------------

    max_clock_skew_seconds: Annotated[
        int,
        Field(ge=TEST_33_MAX_CLOCK_SKEW_SECONDS_MIN),
    ] = Field(
        default=TEST_33_MAX_CLOCK_SKEW_SECONDS_DEFAULT,
        description=(
            "Maximum acceptable replay window (in seconds) of a signing policy "
            "(the allowed difference between the request's date and the gateway's clock). "
            "A larger window increases the replay-attack surface: an attacker who "
            "captures a signed request can replay it until the window expires. "
            "NIST SP 800-107 Rev. 1 Section 5.3.2 recommends <= 300 s (5 minutes). "
            f"Default: {TEST_33_MAX_CLOCK_SKEW_SECONDS_DEFAULT}."
        ),
    )

    forbidden_algorithms: tuple[str, ...] = Field(
        default_factory=lambda: tuple(_TEST_33_FORBIDDEN_ALGORITHMS_DEFAULT),
        description=(
            "HMAC algorithms whose presence in a signing policy's allowed list "
            "constitutes a security finding. "
            "'hmac-md5': cryptographically broken (RFC 6151); must never be used. "
            "'hmac-sha1': deprecated per NIST SP 800-131A Rev. 2 and PCI-DSS v4 "
            "Requirement 12.3.3; acceptable to remove from this list only if the "
            "deployment has a documented exception. "
            "Default: ['hmac-sha1', 'hmac-md5']."
        ),
    )


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


class Test33HMACConfigAudit(BaseTest[Test33Params]):
    """
    Test 3.3 -- HMAC Authentication Configuration Audit.

    Audits the Kong hmac-auth plugin configuration (when present) for:
    - Excessive clock_skew (replay-attack exposure).
    - Forbidden/weak HMAC algorithms (signature forgery risk).
    - Body validation posture (informational note on PASS).

    This is a WHITE_BOX configuration audit: no HTTP requests are made to
    the target API. All evidence is derived from the Kong Admin API response.
    """

    info = TestInfo(
        id="3.3",
        name="HMAC Authentication Configuration Does Not Allow Replay or Weak Algorithms",
        priority=3,
        strategy=TestStrategy.WHITE_BOX,
        cwe="CWE-326",
        tags=(
            "authentication",
            "cryptography",
            "hmac",
            "replay-protection",
            "white-box",
            "OWASP-API2:2023",
            "CWE-326",
        ),
        needs=(Need.GATEWAY,),
    )

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
            1. A gateway adapter is configured (Need.GATEWAY: the engine skips
               the test otherwise).
            2. Read the concept "request signing policies" (the adapter knows
               which plugins hold one) and store it as evidence; not
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
            gateway = target.gateway
            assert gateway is not None  # noqa: S101 -- Need.GATEWAY, checked by the engine

            cfg = self.params(target)

            log.info(
                "test_3_3_starting",
                gateway_adapter=gateway.adapter_name,
                max_clock_skew_seconds=cfg.max_clock_skew_seconds,
                forbidden_algorithms=cfg.forbidden_algorithms,
            )

            policies = gateway.signing_policies()
            evidence_ref = self._record_gateway_concept(
                target, store, CONCEPT_SIGNING_POLICIES, policies
            )
            if policies.status != ConceptStatus.READ:
                return self._skip_for_concept(CONCEPT_SIGNING_POLICIES, policies, evidence_ref)

            if not policies.items:
                log.info("test_3_3_plugin_not_found", gateway_adapter=gateway.adapter_name)
                return self._make_skip_with_note()

            policy = policies.items[0]
            if not policy.enabled:
                log.info("test_3_3_plugin_disabled", policy=policy.source)
                return self._make_skip_with_note(plugin_id=policy.source, disabled=True)

            log.info(
                "test_3_3_plugin_found",
                policy=policy.source,
                replay_window_seconds=policy.replay_window_seconds,
                replay_unlimited=policy.replay_unlimited,
                algorithms=policy.algorithms,
                body_signed=policy.body_signed,
            )

            findings: list[Finding] = []
            clock_finding = self._audit_clock_skew(policy, cfg, evidence_ref)
            if clock_finding is not None:
                findings.append(clock_finding)
            findings.extend(self._audit_algorithms(policy, cfg, evidence_ref))

            body_note = self._build_body_validation_note(policy)
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
                    f"replay window <= {cfg.max_clock_skew_seconds} s and no forbidden "
                    "algorithms are configured."
                ),
                notes=notes,
            )

        except Exception as exc:  # noqa: BLE001
            log.exception("test_3_3_unexpected_error", error=str(exc))
            return self._make_error(exc)

    def _make_skip_with_note(
        self,
        plugin_id: str | None = None,
        disabled: bool = False,
    ) -> TestResult:
        """
        Build a SKIP TestResult with an InfoNote explaining HMAC semantics.

        Called when the gateway has no request signing policy (disabled=False,
        plugin_id=None) or when its policy exists but is disabled (disabled=True).
        The InfoNote documents what HMAC authentication is and what an analyst
        should verify manually if HMAC is in use outside of the gateway plugin
        system (e.g. at the application layer).

        Args:
            plugin_id:    Source of the policy (plugin and id) if found but disabled.
            disabled:     True if the plugin exists but is disabled.

        Returns:
            TestResult with status=SKIP, skip_reason, and a single InfoNote.
        """
        if disabled:
            skip_reason = (
                f"The HMAC signing policy ({plugin_id}) is installed "
                "but disabled on this Gateway instance. "
                "No active HMAC authentication configuration to audit. "
                "If the plugin was intentionally disabled, this SKIP is expected. "
                "If HMAC is expected to be active, verify plugin configuration."
            )
            note_detail = (
                f"A gateway HMAC signing policy ({plugin_id}) "
                "is installed on this Gateway instance but is currently disabled. "
                "HMAC authentication is therefore not enforced by the gateway for "
                "any route or service.\n\n"
                "HMAC-based request authentication (RFC 2104 / draft-cavage-http-signatures) "
                "adds an integrity and authenticity guarantee to API requests beyond what "
                "bearer tokens provide: each request is signed with a shared secret, making "
                "it infeasible for an attacker to modify in transit without invalidating the "
                "signature. When active, the key security parameters to audit are:\n"
                "  - the replay window: how far the request's date may be from the "
                "gateway's clock (smaller is safer; oracle: <= 300 s)\n"
                "  - the allowed algorithms: hmac-md5 and hmac-sha1 "
                "are deprecated or broken and should not be allowed\n"
                "  - body signing: whether the request body is included in the "
                "signature (recommended for POST/PUT/PATCH endpoints)\n\n"
                "Re-enable the plugin to resume coverage of this control, or mark this "
                "SKIP as accepted if HMAC is intentionally not used."
            )
        else:
            skip_reason = (
                "No HMAC request signing policy is configured on this Gateway instance. "
                "HMAC authentication is not in use; no configuration to audit. "
                "If HMAC is implemented at the application layer rather than the Gateway, "
                "manual verification of the application's HMAC configuration is required."
            )
            note_detail = (
                "No HMAC request signing policy is configured on this Gateway "
                "instance. This test audits a signing policy's security-critical parameters "
                "(replay window, allowed algorithms, body signing) and cannot proceed "
                "without an active policy.\n\n"
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
                "If the gateway signs requests with a plugin its adapter does not "
                "recognise, the adapter must learn it (src/core/gateway/)."
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
        cfg: Test33Params,
        evidence_ref: str,
    ) -> Finding | None:
        """
        Validate the replay window against the oracle threshold.

        Three conditions produce a Finding:
            1. The gateway does not check the request's date at all
               (replay_unlimited: a captured request can be replayed forever).
            2. The gateway does not state the replay window.
            3. The window exceeds cfg.max_clock_skew_seconds (too wide).

        Args:
            policy:       The signing policy audited.
            cfg:          Test33Params with the oracle threshold.
            evidence_ref: Evidence record of the concept read.

        Returns:
            Finding if the replay window is non-compliant, None if compliant.
        """
        ident = policy.source
        oracle = (
            f"Oracle: the replay window must be set and <= {cfg.max_clock_skew_seconds} s "
            "(NIST SP 800-107 Rev. 1 Section 5.3.2, 5-minute window)."
        )

        if policy.replay_unlimited:
            log.info("test_3_3_clock_skew_unconfigured", policy=ident)
            return Finding(
                title=f"HMAC Replay Window Unlimited on '{ident}'",
                detail=(
                    f"The HMAC policy {ident} does not check the request's date, which "
                    "disables timestamp-based replay protection. An attacker who captures a "
                    "valid HMAC-signed request can replay it indefinitely: the gateway will "
                    "continue accepting it as authentic regardless of how much time has "
                    f"elapsed. {oracle} Recommended action: set the replay window to a value "
                    f"between 60 and {cfg.max_clock_skew_seconds} seconds in the gateway "
                    "configuration."
                ),
                references=list(_REFERENCES),
                evidence_ref=evidence_ref,
            )

        if policy.replay_window_seconds is None:
            log.info("test_3_3_clock_skew_absent", policy=ident)
            return Finding(
                title=f"HMAC Replay Window Not Stated on '{ident}'",
                detail=(
                    f"The gateway does not state the replay window of the HMAC policy {ident}. "
                    "Without it, replay-attack protection posture for HMAC authentication "
                    f"cannot be audited. {oracle}"
                ),
                references=list(_REFERENCES),
                evidence_ref=evidence_ref,
            )

        value_s = int(policy.replay_window_seconds)

        if value_s > cfg.max_clock_skew_seconds:
            log.info(
                "test_3_3_clock_skew_too_wide",
                policy=ident,
                value=value_s,
                oracle_max_seconds=cfg.max_clock_skew_seconds,
            )
            return Finding(
                title=f"HMAC Replay Window Too Wide: {value_s} s on '{ident}'",
                detail=(
                    f"The HMAC policy {ident} has a replay window of {value_s} s "
                    f"({value_s / 60:.1f} min), which exceeds the oracle threshold of "
                    f"{cfg.max_clock_skew_seconds} s ({cfg.max_clock_skew_seconds / 60:.0f} min) "
                    "from NIST SP 800-107 Rev. 1 Section 5.3.2. "
                    f"A {value_s}-second window means an attacker who captures a signed "
                    f"request can replay it for up to {value_s / 60:.1f} minutes before the "
                    "gateway rejects it. "
                    "Recommended action: reduce the replay window to "
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
        cfg: Test33Params,
        evidence_ref: str,
    ) -> list[Finding]:
        """
        Check the allowed algorithms for any operator-forbidden algorithm.

        Produces one Finding per forbidden algorithm found, or one Finding
        when the gateway does not state the allowed algorithms (an empty list
        states that none is allowed and gives no finding).

        Args:
            policy:       The signing policy audited.
            cfg:          Test33Params with the forbidden_algorithms list.
            evidence_ref: Evidence record of the concept read.

        Returns:
            List of Findings. Empty if clean.
        """
        ident = policy.source

        if policy.algorithms is None:
            log.info("test_3_3_algorithms_field_absent", policy=ident)
            return [
                Finding(
                    title=f"HMAC Allowed Algorithms Not Stated on '{ident}'",
                    detail=(
                        "The gateway does not state the allowed algorithms "
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
    def _build_body_validation_note(policy: SigningPolicy) -> InfoNote:
        """
        Build an InfoNote describing whether the body is covered by the signature.

        This sub-test never fails: the correct value depends on the API's usage.

        Args:
            policy: The signing policy audited.

        Returns:
            InfoNote documenting the body validation posture.
        """
        validate_body: bool = bool(policy.body_signed)
        ident = policy.source
        if validate_body:
            detail = (
                f"The HMAC policy {ident} signs the request body. "
                "The HMAC signature covers the full request body in addition to the headers, "
                "preventing body-swap attacks where an attacker intercepts a signed request "
                "and replaces the body with a malicious payload. This is the recommended "
                "configuration for APIs that accept POST, PUT, or PATCH requests with "
                "sensitive payloads."
            )
        else:
            body_field_note = (
                "does not state whether it signs the request body (the gateway default: not signed)"
                if policy.body_signed is None
                else "does not sign the request body"
            )
            detail = (
                f"The HMAC policy {ident} {body_field_note}. "
                "The HMAC signature covers only the request headers (method, path, date, "
                "Authorization), not the body. An attacker who intercepts a signed request "
                "could replace the body with a malicious payload and the gateway would "
                "accept it as authentic. "
                "Whether this is acceptable depends on the API's usage pattern:\n"
                "  - GET-only APIs: body validation is irrelevant (no body to protect).\n"
                "  - POST/PUT/PATCH APIs handling sensitive operations: enabling "
                "body signing is strongly recommended.\n"
                "This note is informational. Enable body validation in the gateway "
                "configuration if body integrity is a requirement of your security policy."
            )
        return InfoNote(
            title=f"HMAC Body {'Signed' if validate_body else 'Not Signed'} on '{ident}'",
            detail=detail,
            references=[
                "RFC-2104",
                "OWASP-ASVS-v5.0.0-V2.9.1",
            ],
        )
