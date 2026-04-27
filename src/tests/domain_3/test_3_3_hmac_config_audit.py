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

EvidenceStore policy:
    WHITE_BOX configuration audit. No HTTP requests are issued to the target
    API, therefore no EvidenceRecord is produced and _log_transaction() is
    never called. Findings carry evidence_ref=None. The plugin configuration
    values are included verbatim in the Finding.detail field.
--------------------------------------------------------------------------
"""

from __future__ import annotations

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
from src.tests.helpers.kong_admin import (
    KongAdminError,
    get_plugins,
    get_routes,
    get_services,
)

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# OWASP/NIST references cited in every Finding produced by this test.
_REFERENCES: list[str] = [
    "OWASP-API2:2023",
    "CWE-326",
    "NIST-SP-800-107-Rev1-S5.3.2",
    "NIST-SP-800-131A-Rev2-2019",
    "RFC-2104",
    "RFC-6151",
    "OWASP-ASVS-v5.0.0-V2.9.1",
]

# NIST/OWASP references cited in every InfoNote produced by the coverage scope sub-test.
_SCOPE_REFERENCES: list[str] = [
    "NIST-SP-800-204-S3.1",
    "OWASP-API9:2023",
    "OWASP-ASVS-v5.0.0-V2.9.1",
]

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
        Audit Kong hmac-auth plugin configuration via the Admin API.

        Execution flow:
            1. Guard: requires Admin API to be configured (_requires_admin_api).
            2. Fetch all Kong plugins via get_plugins().
            3. Filter for the 'hmac-auth' plugin.
            4. If plugin absent or disabled: return SKIP with InfoNote.
            5. If plugin present and enabled:
               a. Audit clock_skew (Sub-test B).
               b. Audit algorithms list (Sub-test C).
               c. Build body validation InfoNote (Sub-test D).
            6. Return PASS with notes, or FAIL with findings.

        No HTTP requests are made to the target API. No _log_transaction()
        calls are needed because there are no EvidenceRecords.

        Returns:
            TestResult with status PASS, FAIL, SKIP, or ERROR.
        """
        try:
            skip_guard = self._requires_admin_api(target)
            if skip_guard is not None:
                return skip_guard

            admin_base_url = target.admin_endpoint_base_url()
            assert admin_base_url is not None, (  # noqa: S101
                "admin_endpoint_base_url() returned None despite admin_api_available=True. "
                "This is a TargetContext invariant violation."
            )

            cfg = target.tests_config.test_3_3
            plugin_names: list[str] = list(cfg.plugin_names)

            log.info(
                "test_3_3_starting",
                admin_base_url=admin_base_url,
                plugin_names=plugin_names,
                max_clock_skew_seconds=cfg.max_clock_skew_seconds,
                forbidden_algorithms=cfg.forbidden_algorithms,
                field_clock_skew=cfg.field_clock_skew,
                field_algorithms=cfg.field_algorithms,
            )

            if not plugin_names:
                # Operator configured an empty list: no plugin names to search for.
                log.warning("test_3_3_plugin_names_empty")
                return self._make_skip(
                    reason=(
                        "plugin_names is empty in config.tests.domain_3.test_3_3. "
                        "No HMAC plugin names configured to search for. "
                        "Add at least one plugin name (e.g. 'hmac-auth') to enable this audit."
                    )
                )

            # Sub-test A: fetch all plugins and find the first matching name.
            plugins = self._fetch_plugins(admin_base_url)
            if plugins is None:
                return self._make_error(
                    RuntimeError(
                        "Kong Admin API call failed -- see structured log for details. "
                        "Verify that admin_api_url is correct and the Kong Admin API "
                        "is reachable from this host."
                    )
                )

            hmac_plugin = self._find_hmac_plugin(plugins, plugin_names)

            if hmac_plugin is None:
                log.info("test_3_3_plugin_not_found", searched_names=plugin_names)
                return self._make_skip_with_note(plugin_names=plugin_names)

            if not hmac_plugin.get("enabled", False):
                plugin_id = hmac_plugin.get("id", "<unknown>")
                plugin_found_name = hmac_plugin.get("name", "<unknown>")
                log.info(
                    "test_3_3_plugin_disabled",
                    plugin_name=plugin_found_name,
                    plugin_id=plugin_id,
                )
                return self._make_skip_with_note(
                    plugin_names=plugin_names,
                    plugin_id=plugin_id,
                    disabled=True,
                )

            plugin_id = hmac_plugin.get("id", "<unknown>")
            plugin_found_name = hmac_plugin.get("name", "<unknown>")
            plugin_config: dict[str, Any] = hmac_plugin.get("config", {})

            log.info(
                "test_3_3_plugin_found",
                plugin_name=plugin_found_name,
                plugin_id=plugin_id,
                clock_skew=plugin_config.get(cfg.field_clock_skew),
                algorithms=plugin_config.get(cfg.field_algorithms),
                validate_request_body=plugin_config.get(cfg.field_validate_body),
            )

            findings: list[Finding] = []

            # Sub-test B: clock_skew validation.
            clock_finding = self._audit_clock_skew(plugin_config, plugin_id, cfg)
            if clock_finding is not None:
                findings.append(clock_finding)

            # Sub-test C: algorithm audit.
            algo_findings = self._audit_algorithms(plugin_config, plugin_id, cfg)
            findings.extend(algo_findings)

            # Sub-test D: body validation observability note (always emitted on PASS/FAIL).
            body_note = self._build_body_validation_note(
                plugin_config, plugin_id, cfg.field_validate_body
            )

            # Sub-test E: coverage scope analysis (always emitted, never a Finding).
            # Passes the full plugin list so the analysis can find ALL enabled hmac
            # instances, not just the primary one audited by B/C/D.
            coverage_note = self._audit_coverage_scope(
                all_plugins=plugins,
                plugin_names=plugin_names,
                admin_base_url=admin_base_url,
            )

            notes: list[InfoNote] = [coverage_note, body_note]

            if findings:
                # Both notes are attached even on FAIL: coverage gaps and body validation
                # posture are orthogonal to the replay/algorithm violations and provide
                # independent architectural context for the analyst reading the report.
                return TestResult(
                    test_id=self.test_id,
                    status=TestStatus.FAIL,
                    message=(
                        f"hmac-auth plugin audit found {len(findings)} violation(s) "
                        f"(plugin id: {plugin_id}). "
                        "Misconfigured HMAC authentication exposes the Gateway to "
                        "replay attacks or signature forgery."
                    ),
                    findings=findings,
                    notes=notes,
                    transaction_log=list(self._transaction_log),
                    **self._metadata_kwargs(),
                )

            return self._make_pass(
                message=(
                    f"hmac-auth plugin (id: {plugin_id}) configuration is compliant: "
                    f"clock_skew <= {cfg.max_clock_skew_seconds} s and no forbidden "
                    "algorithms are configured."
                ),
                notes=notes,
            )

        except Exception as exc:  # noqa: BLE001
            log.exception("test_3_3_unexpected_error", error=str(exc))
            return self._make_error(exc)

    # ------------------------------------------------------------------
    # Sub-test A helpers: plugin discovery
    # ------------------------------------------------------------------

    def _fetch_plugins(self, admin_base_url: str) -> list[dict[str, Any]] | None:
        """
        Retrieve all plugins from the Kong Admin API.

        Wraps get_plugins() so that KongAdminError is converted to a structured
        log entry. Returns None on error so the caller can produce ERROR without
        re-catching the exception.

        Args:
            admin_base_url: Kong Admin API base URL without trailing slash.

        Returns:
            List of Kong plugin dicts (may be empty), or None on Admin API error.
        """
        try:
            plugins = get_plugins(admin_base_url)
            log.debug("test_3_3_plugins_fetched", total=len(plugins))
            return plugins
        except KongAdminError as exc:
            log.error(
                "test_3_3_admin_api_error",
                path="/plugins",
                status_code=exc.status_code,
                error=str(exc),
            )
            return None

    @staticmethod
    def _find_hmac_plugin(
        plugins: list[dict[str, Any]],
        plugin_names: list[str],
    ) -> dict[str, Any] | None:
        """
        Return the first plugin whose name appears in the plugin_names list, or None.

        Iterates the full plugin list from the Admin API and returns both enabled
        and disabled instances so the caller can distinguish "not installed" (None)
        from "installed but disabled" (dict with enabled=False).

        The check is case-insensitive to tolerate minor naming variations
        across gateway versions.

        Args:
            plugins:      Full plugin list from the Admin API.
            plugin_names: Ordered list of names to search for (from cfg.plugin_names).

        Returns:
            First plugin dict whose name matches any entry in plugin_names,
            or None if no matching plugin is installed.
        """
        normalised_names: set[str] = {n.lower() for n in plugin_names}
        for plugin in plugins:
            if plugin.get("name", "").lower() in normalised_names:
                return plugin
        return None

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

        return TestResult(
            test_id=self.test_id,
            status=TestStatus.SKIP,
            message=skip_reason,
            skip_reason=skip_reason,
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
            transaction_log=list(self._transaction_log),
            **self._metadata_kwargs(),
        )

    # ------------------------------------------------------------------
    # Sub-test E: coverage scope analysis
    # ------------------------------------------------------------------

    def _audit_coverage_scope(
        self,
        all_plugins: list[dict[str, Any]],
        plugin_names: list[str],
        admin_base_url: str,
    ) -> InfoNote:
        """
        Determine which services and routes are actually protected by HMAC.

        Kong allows a plugin to be scoped at three levels:
          - Global:  service=null AND route=null  →  applies to ALL traffic.
          - Service: service={"id": "..."}        →  applies to all routes of
                     that service only.
          - Route:   route={"id": "..."}          →  applies to that route only.

        A plugin that is correctly configured (compliant clock_skew and algorithms)
        but scoped to a single non-critical path still leaves the rest of the API
        traffic unprotected by HMAC.  This sub-test surfaces that gap.

        Algorithm:
          1. Filter all_plugins for enabled instances whose name matches plugin_names.
          2. If any instance is global (service=null AND route=null): emit a
             reassuring InfoNote — all traffic is covered, no gap analysis needed.
          3. Otherwise: fetch /services and /routes from the Admin API to build
             a complete inventory.  Map each plugin instance to its covered
             service or route.  Compute uncovered services (no direct plugin and
             no route-scope plugin covering any of their routes) and uncovered
             routes (not under a covered service and no direct route plugin).
          4. Emit a detailed InfoNote distinguishing covered vs uncovered entities.

        This method never raises.  Admin API errors during gap analysis produce a
        degraded InfoNote describing the limitation rather than a hard ERROR.

        Args:
            all_plugins:   Full plugin list from the Admin API (unfiltered).
            plugin_names:  Names to match when filtering HMAC plugins.
            admin_base_url: Kong Admin API base URL without trailing slash.

        Returns:
            InfoNote documenting the HMAC coverage scope.  Never a Finding.
        """
        normalised_names: set[str] = {n.lower() for n in plugin_names}
        enabled_hmac_plugins: list[dict[str, Any]] = [
            p
            for p in all_plugins
            if p.get("name", "").lower() in normalised_names and p.get("enabled", False)
        ]

        if not enabled_hmac_plugins:
            # Defensive guard: should not happen since caller already found a plugin.
            return InfoNote(
                title="HMAC Coverage Scope: No Enabled Instances Found",
                detail=(
                    "No enabled HMAC plugin instances were found during coverage "
                    "scope analysis.  This is unexpected because the primary plugin "
                    "lookup in Sub-test A already identified an active instance.  "
                    "This may indicate a race condition between the two Admin API calls.  "
                    "Re-run the assessment to confirm."
                ),
                references=_SCOPE_REFERENCES,
            )

        # Check for any global instance (service=null AND route=null).
        global_instances: list[dict[str, Any]] = [
            p for p in enabled_hmac_plugins if p.get("service") is None and p.get("route") is None
        ]

        if global_instances:
            global_ids: list[str] = [p.get("id", "<unknown>") for p in global_instances]
            instance_word: str = "instance" if len(global_ids) == 1 else "instances"
            log.debug(
                "test_3_3_coverage_scope_global",
                global_instance_ids=global_ids,
            )
            return InfoNote(
                title="HMAC Coverage: Global — All Traffic Protected",
                detail=(
                    f"The HMAC plugin {instance_word} "
                    f"{', '.join(repr(i) for i in global_ids)} "
                    f"{'is' if len(global_ids) == 1 else 'are'} applied globally "
                    "(service = null, route = null).  Every request reaching the "
                    "Gateway — regardless of path, method, or upstream service — "
                    "is subject to HMAC authentication.  No coverage gaps exist."
                    "\n\nA global plugin is the most protective scope.  If future "
                    "routes or services are added to this Gateway instance they will "
                    "automatically be covered without any plugin reconfiguration."
                ),
                references=_SCOPE_REFERENCES,
            )

        # All instances are scoped.  Perform gap analysis using /services and /routes.
        log.info(
            "test_3_3_coverage_scope_partial",
            enabled_instance_count=len(enabled_hmac_plugins),
        )

        try:
            services: list[dict[str, Any]] = get_services(admin_base_url)
            routes: list[dict[str, Any]] = get_routes(admin_base_url)
        except KongAdminError as exc:
            log.warning(
                "test_3_3_coverage_scope_fetch_error",
                error=str(exc),
            )
            # Degraded note: report what we know about the plugin scopes without
            # the full gap analysis, which requires the service/route inventories.
            scoped_summary: list[str] = self._summarise_plugin_scopes(enabled_hmac_plugins)
            return InfoNote(
                title="HMAC Coverage: Scoped — Gap Analysis Unavailable",
                detail=(
                    "The HMAC plugin is NOT applied globally.  All active instances "
                    "are scoped to specific services or routes, meaning traffic "
                    "outside those scopes is NOT protected by HMAC authentication.\n\n"
                    "Active plugin instances and their declared scopes:\n"
                    + "\n".join(f"  - {s}" for s in scoped_summary)
                    + "\n\n"
                    "A full gap analysis (listing uncovered services and routes) "
                    "was attempted but could not be completed because the Admin API "
                    f"returned an error when fetching the service/route inventory: "
                    f"{exc}\n\n"
                    "Verify manually that all intended traffic paths are covered by "
                    "an HMAC plugin instance."
                ),
                references=_SCOPE_REFERENCES,
            )

        # Build lookup maps: id → human-readable label.
        service_name_map: dict[str, str] = {
            s["id"]: (s.get("name") or s["id"]) for s in services if "id" in s
        }
        # For routes, use the paths list as the label (more informative than the UUID).
        route_label_map: dict[str, str] = {
            r["id"]: (", ".join(r.get("paths") or []) or r.get("name") or r["id"])
            for r in routes
            if "id" in r
        }
        # Map route id → parent service id (may be None for service-less routes).
        route_service_map: dict[str, str | None] = {
            r["id"]: (r.get("service") or {}).get("id") for r in routes if "id" in r
        }

        # Determine covered service IDs and covered route IDs from plugin scopes.
        covered_service_ids: set[str] = set()
        covered_route_ids: set[str] = set()

        for plugin in enabled_hmac_plugins:
            svc_scope = plugin.get("service")
            rte_scope = plugin.get("route")
            if svc_scope and svc_scope.get("id"):
                covered_service_ids.add(svc_scope["id"])
            if rte_scope and rte_scope.get("id"):
                covered_route_ids.add(rte_scope["id"])

        # A route is implicitly covered if its parent service has a service-scoped plugin.
        implicitly_covered_route_ids: set[str] = {
            rid for rid, sid in route_service_map.items() if sid in covered_service_ids
        }
        all_effectively_covered_route_ids: set[str] = (
            covered_route_ids | implicitly_covered_route_ids
        )

        all_service_ids: set[str] = set(service_name_map.keys())
        all_route_ids: set[str] = set(route_label_map.keys())

        uncovered_service_ids: set[str] = all_service_ids - covered_service_ids
        uncovered_route_ids: set[str] = all_route_ids - all_effectively_covered_route_ids

        log.info(
            "test_3_3_coverage_gap_summary",
            total_services=len(all_service_ids),
            covered_services=len(covered_service_ids),
            uncovered_services=len(uncovered_service_ids),
            total_routes=len(all_route_ids),
            covered_routes=len(all_effectively_covered_route_ids),
            uncovered_routes=len(uncovered_route_ids),
        )

        # Build human-readable detail sections.
        plugin_scope_lines: list[str] = self._summarise_plugin_scopes(
            enabled_hmac_plugins,
            service_name_map=service_name_map,
            route_label_map=route_label_map,
        )

        covered_svc_lines: list[str] = sorted(
            f"'{service_name_map.get(sid, sid)}' (id: {sid})" for sid in covered_service_ids
        )
        uncovered_svc_lines: list[str] = sorted(
            f"'{service_name_map.get(sid, sid)}' (id: {sid})" for sid in uncovered_service_ids
        )
        covered_rte_lines: list[str] = sorted(
            f"'{route_label_map.get(rid, rid)}' (id: {rid})"
            + (" [via parent service]" if rid in implicitly_covered_route_ids else "")
            for rid in all_effectively_covered_route_ids
        )
        uncovered_rte_lines: list[str] = sorted(
            f"'{route_label_map.get(rid, rid)}' (id: {rid})" for rid in uncovered_route_ids
        )

        has_gaps: bool = bool(uncovered_service_ids or uncovered_route_ids)
        title_suffix: str = (
            "Partial Coverage — Gaps Detected" if has_gaps else "Partial Scope — Full Coverage"
        )

        detail_parts: list[str] = [
            "The HMAC plugin is NOT applied globally.  All active instances are "
            "scoped to specific services or routes.  Traffic outside the covered "
            "scopes is NOT protected by HMAC authentication.\n",
            "Active plugin instances and their declared scopes:",
            *[f"  - {line}" for line in plugin_scope_lines],
        ]

        if covered_svc_lines:
            detail_parts += [
                "\nServices WITH HMAC coverage (direct service-scope plugin):",
                *[f"  + {line}" for line in covered_svc_lines],
            ]
        if uncovered_svc_lines:
            detail_parts += [
                "\nServices WITHOUT HMAC coverage:",
                *[f"  - {line}" for line in uncovered_svc_lines],
            ]
        if covered_rte_lines:
            detail_parts += [
                "\nRoutes WITH HMAC coverage (direct route-scope or via parent service):",
                *[f"  + {line}" for line in covered_rte_lines],
            ]
        if uncovered_rte_lines:
            detail_parts += [
                "\nRoutes WITHOUT HMAC coverage:",
                *[f"  - {line}" for line in uncovered_rte_lines],
            ]

        if has_gaps:
            detail_parts.append(
                "\nRecommended action: evaluate whether the uncovered services and "
                "routes require HMAC authentication.  If so, either add plugin "
                "instances scoped to each uncovered resource, or replace all "
                "scoped instances with a single global plugin instance "
                "(service = null, route = null)."
            )
        else:
            detail_parts.append(
                "\nAll registered services and routes are covered by at least one "
                "HMAC plugin instance (directly or via their parent service).  "
                "No traffic gaps were detected in the current Gateway configuration."
            )

        return InfoNote(
            title=f"HMAC Coverage Scope: {title_suffix}",
            detail="\n".join(detail_parts),
            references=_SCOPE_REFERENCES,
        )

    @staticmethod
    def _summarise_plugin_scopes(
        plugins: list[dict[str, Any]],
        service_name_map: dict[str, str] | None = None,
        route_label_map: dict[str, str] | None = None,
    ) -> list[str]:
        """
        Build a list of human-readable scope description strings, one per plugin instance.

        Used both in the full gap-analysis path (with name maps) and in the
        degraded path where the service/route inventories could not be fetched
        (maps are None, raw IDs are used as fallback labels).

        Args:
            plugins:          List of enabled HMAC plugin dicts.
            service_name_map: Map from service id to service name.  None in degraded mode.
            route_label_map:  Map from route id to route path label.  None in degraded mode.

        Returns:
            List of strings like
            "id: <uuid>, scope: service '<name>' (id: <uuid>)"
            "id: <uuid>, scope: route '<paths>' (id: <uuid>)"
            "id: <uuid>, scope: global"  ← should not appear here, but kept for safety.
        """
        lines: list[str] = []
        for plugin in plugins:
            pid: str = plugin.get("id", "<unknown>")
            svc_scope = plugin.get("service")
            rte_scope = plugin.get("route")

            if svc_scope and svc_scope.get("id"):
                sid: str = svc_scope["id"]
                label: str = (service_name_map or {}).get(sid, sid)
                lines.append(f"id: {pid!r}, scope: service '{label}' (id: {sid})")
            elif rte_scope and rte_scope.get("id"):
                rid: str = rte_scope["id"]
                label = (route_label_map or {}).get(rid, rid)
                lines.append(f"id: {pid!r}, scope: route '{label}' (id: {rid})")
            else:
                lines.append(f"id: {pid!r}, scope: global")

        return lines

    # ------------------------------------------------------------------
    # Sub-test B: clock_skew audit
    # ------------------------------------------------------------------

    def _audit_clock_skew(
        self,
        plugin_config: dict[str, Any],
        plugin_id: str,
        cfg: Any,  # RuntimeTest33Config -- typed as Any to avoid circular import  # noqa: ANN401
    ) -> Finding | None:
        """
        Validate the clock_skew field against the oracle threshold.

        The field name is read from cfg.field_clock_skew so the audit is
        agnostic to the gateway's JSON schema.  The sentinel value that
        represents "no limit configured" is read from cfg.clock_skew_unconfigured_value.

        Three conditions produce a Finding:
            1. The configured field name is absent from the plugin config object.
            2. The field value equals cfg.clock_skew_unconfigured_value (unlimited window).
            3. The field value exceeds cfg.max_clock_skew_seconds (window too wide).

        Args:
            plugin_config: The 'config' dict from the HMAC plugin object.
            plugin_id:     Plugin id string (for Finding detail context).
            cfg:           RuntimeTest33Config with the oracle threshold and field names.

        Returns:
            Finding if the clock_skew is non-compliant, None if compliant.
        """
        field_name: str = cfg.field_clock_skew
        raw_value = plugin_config.get(field_name)

        # Condition 1: field absent (unexpected but guard defensively).
        if raw_value is None:
            log.warning(
                "test_3_3_clock_skew_absent",
                plugin_id=plugin_id,
                field_name=field_name,
            )
            return Finding(
                title=(f"HMAC '{field_name}' Field Absent on Plugin '{plugin_id}'"),
                detail=(
                    f"The '{field_name}' field is absent from the HMAC plugin "
                    f"(id: {plugin_id}) configuration returned by the Admin API. "
                    "Expected an integer value in seconds controlling the replay-attack "
                    "window. This may indicate a gateway version incompatibility or "
                    "corrupted plugin configuration. Without this field, replay-attack "
                    "protection posture for HMAC authentication cannot be audited. "
                    f"Oracle: '{field_name}' must be > {cfg.clock_skew_unconfigured_value} "
                    f"and <= {cfg.max_clock_skew_seconds} s "
                    "(NIST SP 800-107 Rev. 1 Section 5.3.2). "
                    f"If the gateway uses a different field name, update "
                    "config.tests.domain_3.test_3_3.field_clock_skew accordingly."
                ),
                references=_REFERENCES,
                evidence_ref=None,
            )

        value_s = int(raw_value)

        # Condition 2: field equals the unconfigured sentinel (unlimited replay window).
        if value_s == cfg.clock_skew_unconfigured_value:
            log.warning(
                "test_3_3_clock_skew_unconfigured",
                plugin_id=plugin_id,
                field_name=field_name,
                value=value_s,
                sentinel=cfg.clock_skew_unconfigured_value,
            )
            return Finding(
                title=(
                    f"HMAC Replay Window Unlimited: '{field_name}' = "
                    f"{cfg.clock_skew_unconfigured_value} on Plugin '{plugin_id}'"
                ),
                detail=(
                    f"The HMAC plugin (id: {plugin_id}) has '{field_name}' = "
                    f"{cfg.clock_skew_unconfigured_value}, which disables "
                    "timestamp-based replay protection. An attacker who captures a valid "
                    "HMAC-signed request can replay it indefinitely — the gateway will "
                    "continue accepting it as authentic regardless of how much time has "
                    "elapsed. "
                    f"Oracle: '{field_name}' must be > {cfg.clock_skew_unconfigured_value} "
                    f"and <= {cfg.max_clock_skew_seconds} s "
                    "(NIST SP 800-107 Rev. 1 Section 5.3.2, 5-minute window). "
                    "Recommended action: set the field to a value between 60 and "
                    f"{cfg.max_clock_skew_seconds} seconds in the plugin configuration."
                ),
                references=_REFERENCES,
                evidence_ref=None,
            )

        # Condition 3: clock_skew exceeds oracle threshold.
        if value_s > cfg.max_clock_skew_seconds:
            log.warning(
                "test_3_3_clock_skew_too_wide",
                plugin_id=plugin_id,
                field_name=field_name,
                value=value_s,
                oracle_max_seconds=cfg.max_clock_skew_seconds,
            )
            return Finding(
                title=(
                    f"HMAC Replay Window Too Wide: '{field_name}' = {value_s} s "
                    f"on Plugin '{plugin_id}'"
                ),
                detail=(
                    f"The HMAC plugin (id: {plugin_id}) has '{field_name}' = {value_s} s "
                    f"({value_s / 60:.1f} min), which exceeds the oracle threshold of "
                    f"{cfg.max_clock_skew_seconds} s ({cfg.max_clock_skew_seconds / 60:.0f} min) "
                    "from NIST SP 800-107 Rev. 1 Section 5.3.2. "
                    f"A {value_s}-second window means an attacker who captures a signed "
                    f"request can replay it for up to {value_s / 60:.1f} minutes before the "
                    "gateway rejects it. Under targeted attack conditions (capture + immediate "
                    "replay), this window is sufficient to perform authenticated actions as "
                    "the legitimate caller. "
                    f"Recommended action: reduce '{field_name}' to "
                    f"<= {cfg.max_clock_skew_seconds} s in the plugin configuration."
                ),
                references=_REFERENCES,
                evidence_ref=None,
            )

        log.debug(
            "test_3_3_clock_skew_compliant",
            plugin_id=plugin_id,
            field_name=field_name,
            value=value_s,
            oracle_max_seconds=cfg.max_clock_skew_seconds,
        )
        return None

    # ------------------------------------------------------------------
    # Sub-test C: algorithm audit
    # ------------------------------------------------------------------

    def _audit_algorithms(
        self,
        plugin_config: dict[str, Any],
        plugin_id: str,
        cfg: Any,  # RuntimeTest33Config  # noqa: ANN401
    ) -> list[Finding]:
        """
        Check the algorithms list for any operator-forbidden algorithm.

        The field name is read from cfg.field_algorithms so the audit is agnostic
        to the gateway's JSON schema.  Produces one Finding per forbidden algorithm
        found. The Finding detail includes an algorithm-specific severity note
        (broken vs deprecated).

        Args:
            plugin_config: The 'config' dict from the HMAC plugin object.
            plugin_id:     Plugin id string (for Finding detail context).
            cfg:           RuntimeTest33Config with the forbidden_algorithms list
                           and the field_algorithms name.

        Returns:
            List of Findings (one per forbidden algorithm detected). Empty if clean.
        """
        field_name: str = cfg.field_algorithms
        raw_algorithms = plugin_config.get(field_name)

        if raw_algorithms is None:
            # Field absent: gateway uses its own default algorithm set.
            # We cannot determine what algorithms are active without the field.
            log.warning(
                "test_3_3_algorithms_field_absent",
                plugin_id=plugin_id,
                field_name=field_name,
            )
            return [
                Finding(
                    title=(f"HMAC '{field_name}' Field Absent on Plugin '{plugin_id}'"),
                    detail=(
                        f"The '{field_name}' field is absent from the HMAC plugin "
                        f"(id: {plugin_id}) configuration. Without this field the active "
                        "algorithm set defaults to the gateway's built-in list, which "
                        "historically includes 'hmac-sha1' and 'hmac-md5'. The actual "
                        "allowed algorithms cannot be audited. Configure the field explicitly "
                        "to restrict the allowed set to hmac-sha256, hmac-sha384, or "
                        "hmac-sha512. "
                        f"If the gateway uses a different field name, update "
                        "config.tests.domain_3.test_3_3.field_algorithms accordingly."
                    ),
                    references=_REFERENCES,
                    evidence_ref=None,
                )
            ]

        configured_algorithms: list[str] = [a.lower() for a in raw_algorithms]
        forbidden_set: list[str] = [a.lower() for a in cfg.forbidden_algorithms]

        findings: list[Finding] = []

        for forbidden_alg in forbidden_set:
            if forbidden_alg in configured_algorithms:
                severity_note = _ALGORITHM_SEVERITY_NOTES.get(
                    forbidden_alg, _ALGORITHM_SEVERITY_NOTE_DEFAULT
                )
                log.warning(
                    "test_3_3_forbidden_algorithm_found",
                    plugin_id=plugin_id,
                    algorithm=forbidden_alg,
                )
                findings.append(
                    Finding(
                        title=(
                            f"Forbidden HMAC Algorithm '{forbidden_alg}' Allowed "
                            f"on Plugin '{plugin_id}'"
                        ),
                        detail=(
                            f"The HMAC plugin (id: {plugin_id}) allows the algorithm "
                            f"'{forbidden_alg}' in its configured '{field_name}' list "
                            f"({configured_algorithms}). "
                            f"{severity_note} "
                            "Recommended action: remove this algorithm from the plugin's "
                            f"'{field_name}' list and ensure all consumers are migrated to "
                            "hmac-sha256 or stronger before the next key rotation."
                        ),
                        references=_REFERENCES,
                        evidence_ref=None,
                    )
                )
            else:
                log.debug(
                    "test_3_3_algorithm_not_found",
                    plugin_id=plugin_id,
                    algorithm=forbidden_alg,
                    configured=configured_algorithms,
                )

        return findings

    # ------------------------------------------------------------------
    # Sub-test D: body validation observability note
    # ------------------------------------------------------------------

    @staticmethod
    def _build_body_validation_note(
        plugin_config: dict[str, Any],
        plugin_id: str,
        field_validate_body: str,
    ) -> InfoNote:
        """
        Build an InfoNote describing the body validation posture of the plugin.

        This sub-test never fails. Its purpose is to surface whether the plugin
        is configured to include the request body in the HMAC signature. This
        is an architectural observation: the correct value is context-dependent
        and cannot be determined by the tool alone.

        The field name is passed explicitly via field_validate_body so the note
        reflects the gateway-specific configuration key.

        Args:
            plugin_config:       The 'config' dict from the HMAC plugin object.
            plugin_id:           Plugin id string (for note context).
            field_validate_body: JSON field name to read from plugin_config
                                 (from cfg.field_validate_body).

        Returns:
            InfoNote documenting the body validation posture.
        """
        raw_validate = plugin_config.get(field_validate_body)
        validate_body: bool = bool(raw_validate) if raw_validate is not None else False

        if validate_body:
            detail = (
                f"The HMAC plugin (id: {plugin_id}) has '{field_validate_body}' = true. "
                "The HMAC signature covers the full request body in addition to the headers, "
                "preventing body-swap attacks where an attacker intercepts a signed request "
                "and replaces the body with a malicious payload. This is the recommended "
                "configuration for APIs that accept POST, PUT, or PATCH requests with "
                "sensitive payloads."
            )
        else:
            body_field_note = (
                f"(field '{field_validate_body}' absent from config -- gateway defaults to false)"
                if raw_validate is None
                else f"'{field_validate_body}' = false"
            )
            detail = (
                f"The HMAC plugin (id: {plugin_id}) has {body_field_note}. "
                "The HMAC signature covers only the request headers (method, path, date, "
                "Authorization), not the body. An attacker who intercepts a signed request "
                "could replace the body with a malicious payload and the gateway would "
                "accept it as authentic. "
                "Whether this is acceptable depends on the API's usage pattern:\n"
                "  - GET-only APIs: body validation is irrelevant (no body to protect).\n"
                "  - POST/PUT/PATCH APIs handling sensitive operations: enabling "
                f"'{field_validate_body}' is strongly recommended.\n"
                "This note is informational. Enable body validation in the plugin "
                "configuration if body integrity is a requirement of your security policy."
            )

        return InfoNote(
            title=(
                f"HMAC Body Validation: '{field_validate_body}' = {validate_body} "
                f"on Plugin '{plugin_id}'"
            ),
            detail=detail,
            references=[
                "RFC-2104",
                "OWASP-ASVS-v5.0.0-V2.9.1",
            ],
        )
