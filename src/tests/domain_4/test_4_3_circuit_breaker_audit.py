"""
src/tests/domain_4/test_4_3_circuit_breaker_audit.py

Test 4.3 -- Circuit Breaker Configuration Audit: Graceful Degradation.

Guarantee (3_TOP_metodologia.md, Section 4.3):
    The Circuit Breaker pattern prevents cascading failure when a downstream
    service degrades. A correctly configured Gateway implements three states:

        CLOSED    -- normal operation; requests flow to the backend.
        OPEN      -- downstream failing; requests are rejected immediately
                     (with cached response or 503) without waiting for the
                     backend timeout. State entered after N consecutive
                     failures (failure_threshold).
        HALF-OPEN -- after a configured hold duration (timeout_duration),
                     a single probe request is forwarded; success closes
                     the circuit, failure re-opens it.

    Without a circuit breaker, a slow backend causes every in-flight request
    to block until the read_timeout expires. At 100 rps with a 30 s timeout,
    3 000 requests accumulate in 30 s, exhausting the thread pool and
    producing a full gateway outage from a single dependency failure.

Strategy: WHITE_BOX -- Configuration Audit.
    The methodology (section 4.3) prescribes "White Box - Audit di
    Configurazione": verify via Admin API whether circuit-breaker directives
    are present and correctly parameterised.

Priority: P1 -- resilience gap with business-critical impact.

Architecture: Dual-Check a 3 Livelli
---------------------------------------------------------------------------
This test follows a three-level fallback strategy specifically designed for
Kong OSS, which does not ship a native circuit-breaker plugin.

LEVEL 1 -- Native circuit-breaker plugin (Full Guarantee)
    Searches the Kong plugin registry for any plugin in accepted_cb_plugin_names.
    'response-ratelimiting' is intentionally excluded: it shapes request volumes
    but does NOT implement the CB state machine, does NOT detect downstream
    failures, and does NOT prevent cascading failure.

    Oracle:
        Plugin found, enabled, params in range   -> PASS (Full Guarantee)
        Plugin found, enabled, params out of range -> FAIL (param findings)
        Plugin found but disabled                -> FAIL (disabled finding)
        Plugin not found                         -> proceed to Level 2

LEVEL 2 -- Upstream passive healthcheck (Compensating Control)
    If no native CB plugin, inspects all Kong upstreams for a configured
    passive healthcheck (healthchecks.passive.unhealthy with at least one
    non-zero failure counter). Kong passive healthchecks mark a backend as
    unhealthy after N observed failures, removing it from the load-balancer
    pool -- this approximates CB behaviour at the upstream layer without
    implementing the full CLOSED/OPEN/HALF-OPEN state machine.

    A passive HC is considered "configured" when at least one of
    unhealthy.http_failures, unhealthy.tcp_failures, unhealthy.timeouts is > 0
    (Kong default is 0 for all = passive HCs disabled).

    A configured HC is "within safe thresholds" when all non-zero counters
    are <= the passive_hc_max_* values from config (default 10 each).

    Oracle:
        At least one upstream with valid passive HC -> PASS + informational Finding
        Upstreams exist but none have passive HC    -> proceed to Level 3
        No upstreams registered                     -> proceed to Level 3

LEVEL 3 -- No protection (Vulnerable)
    Neither native plugin nor upstream passive healthcheck found.
    Oracle: FAIL with a gap-documenting Finding.

FINDING SEPARATO -- Observability (always runs, independent of levels)
    Verifies whether the Kong /status endpoint exposes circuit-breaker metrics.
    Kong OSS /status does NOT expose these fields: this produces an
    informational Finding documenting the observability gap. This finding
    does not affect the test status.

EvidenceStore policy:
    WHITE_BOX configuration audit -- no requests to the target proxy.
    No _log_transaction() calls, evidence_ref=None on all Findings.
---------------------------------------------------------------------------

Kong OSS DB-less expected outcome:
    Level 1: no 'circuit-breaker' plugin found -> proceed to Level 2.
    Level 2: depends on upstream configuration:
        - Upstreams with passive HC configured -> PASS (compensating)
        - No passive HC configured             -> FAIL (Level 3)
    Observability: /status has no CB fields -> informational Finding appended.
"""  # noqa: N999

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import (
    Finding,
    InfoNote,
    RuntimeTest43Config,
    TestResult,
    TestStatus,
    TestStrategy,
)
from src.tests.base import BaseTest
from src.tests.helpers.kong_admin import KongAdminError, get_plugins, get_status, get_upstreams

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Field name aliases for failure_threshold across known Kong CB plugin variants.
# Evaluated in order; the first key found in the plugin config dict wins.
_FAILURE_THRESHOLD_ALIASES: tuple[str, ...] = (
    "failure_threshold",
    "consecutive_errors",
    "error_threshold_percentage",
)

# Field name aliases for Open-state hold duration (seconds).
_TIMEOUT_DURATION_ALIASES: tuple[str, ...] = (
    "timeout",
    "sleep_time",
    "recovery_time",
    "timeout_duration",
)

# OWASP/NIST references for Level 1 and Level 3 Findings.
_REFERENCES_CB: list[str] = [
    "OWASP-API4:2023",
    "OWASP-ASVS-v5.0.0-V16.5.2",
    "NIST-SP-800-204-Section-4.5.1",
    "CWE-400",
]

# References for the Level 2 compensating-control Finding.
_REFERENCES_PHC: list[str] = [
    "OWASP-ASVS-v5.0.0-V16.5.2",
    "NIST-SP-800-204-Section-4.5.1",
    "CWE-400",
]

# References for the observability Finding.
_REFERENCES_OBS: list[str] = [
    "OWASP-ASVS-v5.0.0-V16.5.2",
    "NIST-SP-800-204-Section-4.5.1",
]

# Kong /status top-level fields that would indicate CB observability.
# None of these exist in Kong OSS -- the check is intentionally defensive.
_CB_STATUS_INDICATORS: frozenset[str] = frozenset(
    {
        "circuit_breaker",
        "circuit_breakers",
        "cb_state",
    }
)


# ---------------------------------------------------------------------------
# Internal data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _PassiveHcSummary:
    """
    Evaluation result for the passive healthcheck of one Kong upstream.

    Attributes:
        upstream_name:     Kong upstream name (or upstream 'id' as fallback).
        is_active:         True if at least one failure counter > 0.
        within_thresholds: True if all active counters are <= config limits.
        http_failures:     Observed unhealthy.http_failures value (0 if absent).
        tcp_failures:      Observed unhealthy.tcp_failures value (0 if absent).
        timeouts:          Observed unhealthy.timeouts value (0 if absent).
        violation_details: Human-readable list of threshold violations (empty
                           when within_thresholds is True or is_active is False).
    """

    upstream_name: str
    is_active: bool
    within_thresholds: bool
    http_failures: int
    tcp_failures: int
    timeouts: int
    violation_details: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _Level1Result:
    """Outcome of the Level 1 native plugin check."""

    plugin_found: bool
    """True if any plugin from accepted_cb_plugin_names was found (enabled or not)."""
    plugin_name: str
    """Matched plugin name if found; empty string otherwise."""
    findings: list[Finding]
    """Empty on PASS (plugin found, enabled, in-range); non-empty on FAIL."""


@dataclass(frozen=True)
class _Level2Result:
    """Outcome of the Level 2 upstream passive healthcheck inspection."""

    has_valid_compensating_control: bool
    """True if at least one upstream has a valid passive HC within thresholds."""
    valid_upstream_count: int
    """Number of upstreams with a valid passive HC."""
    compensating_note: InfoNote | None
    """
    Informational InfoNote for PASS (compensating control); None on Level 3 path.

    Typed as InfoNote (not Finding) because the Level 2 PASS result carries no
    security violation: the note documents architectural context and the residual
    gap between a passive healthcheck and a true circuit breaker. This separation
    allows the TestResult model_validator invariant (PASS -> empty findings) to
    hold without modification.
    """


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------


class Test43CircuitBreakerAudit(BaseTest):
    """
    Test 4.3 -- Circuit Breaker Configuration Audit: Graceful Degradation.

    Implements a Dual-Check a 3 Livelli strategy via the Kong Admin API.
    See module docstring for the full level-by-level specification.
    """

    # ------------------------------------------------------------------
    # BaseTest class-level contract
    # ------------------------------------------------------------------

    test_id: ClassVar[str] = "4.3"
    test_name: ClassVar[str] = "Circuit Breaker Audit -- Dual-Check a 3 Livelli"
    domain: ClassVar[int] = 4
    priority: ClassVar[int] = 1
    strategy: ClassVar[TestStrategy] = TestStrategy.WHITE_BOX
    depends_on: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = [
        "availability",
        "resilience",
        "circuit-breaker",
        "cascading-failure",
        "passive-healthcheck",
        "white-box",
        "OWASP-API4",
    ]
    cwe_id: ClassVar[str] = "CWE-400"

    # ------------------------------------------------------------------
    # execute -- main entry point
    # ------------------------------------------------------------------

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Audit circuit-breaker protection via Dual-Check a 3 Livelli.

        Execution flow:
            1. Guard: skip if Admin API not configured.
            2. Level 1: detect native CB plugin.
               - Plugin found (enabled / disabled) -> PASS or FAIL (no Level 2).
               - Plugin not found -> Level 2.
            3. Level 2: inspect upstream passive healthchecks.
               - Valid passive HC found -> PASS with informational Finding.
               - None found -> Level 3.
            4. Level 3: FAIL (no protection).
            5. Observability check: append /status Finding (always, independent).

        Args:
            target:  Frozen TargetContext with URL and config references.
            context: Mutable TestContext (not used by this WHITE_BOX test).
            client:  SecurityClient (not used; Admin API calls use httpx directly).
            store:   EvidenceStore (not used; no proxy requests are made).

        Returns:
            TestResult with status PASS, FAIL, SKIP, or ERROR.
        """
        try:
            skip_guard = self._requires_admin_api(target)
            if skip_guard is not None:
                return skip_guard

            admin_base_url = target.admin_endpoint_base_url()
            assert admin_base_url is not None, (  # noqa: S101
                "admin_endpoint_base_url() returned None despite admin_api_available=True."
            )

            cfg = target.tests_config.test_4_3

            log.info(
                "test_4_3_starting",
                admin_base_url=admin_base_url,
                accepted_cb_plugin_names=cfg.accepted_cb_plugin_names,
            )

            # ----------------------------------------------------------
            # Level 1: native CB plugin detection
            # ----------------------------------------------------------
            plugins = self._fetch_plugins(admin_base_url)
            if plugins is None:
                return self._make_error(
                    RuntimeError(
                        "Kong Admin API GET /plugins failed. See structured log for details."
                    )
                )

            level1 = self._check_level1_plugin(plugins=plugins, cfg=cfg)

            if level1.plugin_found:
                # A recognised CB plugin was found (enabled or disabled).
                # Do NOT fall through to Level 2 regardless of the outcome.

                # The observability check always runs independently and always
                # produces an InfoNote (never a security Finding).
                observability_note = self._check_observability(admin_base_url)

                if not level1.findings:
                    # Plugin found, enabled, params in range -> Full Guarantee.
                    # Both branches are PASS: InfoNotes go into notes=, not findings=.
                    notes: list[InfoNote] = []
                    if observability_note is not None:
                        notes.append(observability_note)
                    return self._make_pass(
                        message=(
                            f"Level 1 (Full Guarantee): circuit-breaker plugin "
                            f"'{level1.plugin_name}' is enabled and configured "
                            "within methodology parameter ranges. The gateway is "
                            "protected against cascading failure."
                        ),
                        notes=notes,
                    )

                # Plugin found but disabled or out-of-range -> FAIL.
                # On FAIL the observability InfoNote is converted to a Finding so
                # that a single status type governs the findings list.
                fail_findings: list[Finding] = list(level1.findings)
                if observability_note is not None:
                    fail_findings.append(
                        Finding(
                            title=observability_note.title,
                            detail=observability_note.detail,
                            references=observability_note.references,
                            evidence_ref=None,
                        )
                    )
                return TestResult(
                    test_id=self.test_id,
                    status=TestStatus.FAIL,
                    message=(
                        f"Level 1: plugin '{level1.plugin_name}' found but "
                        f"has {len(level1.findings)} configuration issue(s). "
                        "See findings for details."
                    ),
                    findings=fail_findings,
                    transaction_log=list(self._transaction_log),
                    **self._metadata_kwargs(),
                )

            # Level 1 miss: log and continue.
            log.info(
                "test_4_3_level1_no_match_proceeding_to_level2",
                accepted_names=cfg.accepted_cb_plugin_names,
                total_plugins=len(plugins),
            )

            # ----------------------------------------------------------
            # Level 2: upstream passive healthchecks (compensating control)
            # ----------------------------------------------------------
            upstreams = self._fetch_upstreams(admin_base_url)
            if upstreams is None:
                return self._make_error(
                    RuntimeError(
                        "Kong Admin API GET /upstreams failed. See structured log for details."
                    )
                )

            level2 = self._check_level2_passive_hc(upstreams=upstreams, cfg=cfg)

            # Observability check is independent of level outcome.
            observability_note = self._check_observability(admin_base_url)

            if level2.has_valid_compensating_control:
                # Level 2 PASS: attach compensating control and observability
                # as InfoNotes, NOT as Findings. This preserves the model_validator
                # invariant (PASS -> empty findings list).
                assert level2.compensating_note is not None  # noqa: S101
                level2_notes: list[InfoNote] = [level2.compensating_note]
                if observability_note is not None:
                    level2_notes.append(observability_note)
                return self._make_pass(
                    message=(
                        "Level 2 (Compensating Control): no native circuit-breaker "
                        "plugin found, but "
                        f"{level2.valid_upstream_count} of {len(upstreams)} "
                        "upstream(s) have a passive healthcheck configured within "
                        "safe thresholds. Partial cascading-failure protection via "
                        "upstream health management. "
                        "See informational notes for architectural gaps."
                    ),
                    notes=level2_notes,
                )

            # ----------------------------------------------------------
            # Level 3: no protection at all -> FAIL
            # ----------------------------------------------------------
            # On FAIL, the observability InfoNote is converted to a Finding so
            # that all diagnostic information is co-located in findings.
            level3_findings: list[Finding] = [
                self._build_level3_finding(
                    accepted_plugin_names=cfg.accepted_cb_plugin_names,
                    upstream_count=len(upstreams),
                )
            ]
            if observability_note is not None:
                level3_findings.append(
                    Finding(
                        title=observability_note.title,
                        detail=observability_note.detail,
                        references=observability_note.references,
                        evidence_ref=None,
                    )
                )

            return TestResult(
                test_id=self.test_id,
                status=TestStatus.FAIL,
                message=(
                    "Level 3 (Vulnerable): no native circuit-breaker plugin and no "
                    "upstream passive healthcheck detected on this Kong gateway. "
                    f"Checked {len(plugins)} plugin(s) and {len(upstreams)} upstream(s). "
                    "See findings for remediation guidance."
                ),
                findings=level3_findings,
                transaction_log=list(self._transaction_log),
                **self._metadata_kwargs(),
            )

        except Exception as exc:  # noqa: BLE001
            log.exception("test_4_3_unexpected_error", error=str(exc))
            return self._make_error(exc)

    # ------------------------------------------------------------------
    # Level 1 helpers
    # ------------------------------------------------------------------

    def _fetch_plugins(self, admin_base_url: str) -> list[dict[str, Any]] | None:
        """
        Retrieve all Kong plugins from the Admin API.

        Wraps get_plugins() so that a KongAdminError produces a structured log
        entry and a None return; the caller converts None to ERROR status.

        Args:
            admin_base_url: Kong Admin API base URL without trailing slash.

        Returns:
            List of plugin dicts (possibly empty), or None on failure.
        """
        try:
            plugins = get_plugins(admin_base_url)
            log.debug("test_4_3_plugins_fetched", count=len(plugins))
            return plugins
        except KongAdminError as exc:
            log.error(
                "test_4_3_admin_api_error",
                path="/plugins",
                status_code=exc.status_code,
                error=str(exc),
            )
            return None

    def _check_level1_plugin(
        self,
        plugins: list[dict[str, Any]],
        cfg: RuntimeTest43Config,
    ) -> _Level1Result:
        """
        Search the plugin list for a native circuit-breaker plugin.

        Iterates accepted_cb_plugin_names in priority order and returns the
        first match. 'response-ratelimiting' is NOT in accepted_cb_plugin_names
        by design: it controls request volume, not downstream failure detection.

        Args:
            plugins: Full plugin list from Kong GET /plugins.
            cfg:     Test43AuditConfig with accepted names and oracle ranges.

        Returns:
            _Level1Result with plugin_found=False if nothing matched.
        """
        by_name: dict[str, dict[str, Any]] = {}
        for plugin in plugins:
            name: str = plugin.get("name", "")
            if name and name not in by_name:
                by_name[name] = plugin

        for candidate in cfg.accepted_cb_plugin_names:
            if candidate not in by_name:
                continue

            plugin = by_name[candidate]
            plugin_name: str = plugin.get("name", "<unknown>")
            is_enabled: bool = bool(plugin.get("enabled", False))

            log.info(
                "test_4_3_level1_plugin_matched",
                plugin_name=plugin_name,
                enabled=is_enabled,
            )

            if not is_enabled:
                return _Level1Result(
                    plugin_found=True,
                    plugin_name=plugin_name,
                    findings=[self._build_plugin_disabled_finding(plugin_name)],
                )

            param_findings = self._validate_plugin_parameters(plugin=plugin, cfg=cfg)
            return _Level1Result(
                plugin_found=True,
                plugin_name=plugin_name,
                findings=param_findings,
            )

        log.debug(
            "test_4_3_level1_no_match",
            searched=cfg.accepted_cb_plugin_names,
            present_plugins=list(by_name.keys()),
        )
        return _Level1Result(plugin_found=False, plugin_name="", findings=[])

    def _validate_plugin_parameters(
        self,
        plugin: dict[str, Any],
        cfg: RuntimeTest43Config,
    ) -> list[Finding]:
        """
        Validate failure_threshold and timeout_duration of an enabled CB plugin.

        Uses the module-level alias tuples to handle naming differences across
        Kong versions and Enterprise vs. OSS plugin configs.

        Args:
            plugin: Enabled Kong plugin dict (must have 'name' and 'config' keys).
            cfg:    Test43AuditConfig with Level 1 oracle ranges.

        Returns:
            List of Findings (empty when both parameters are compliant).
        """
        findings: list[Finding] = []
        plugin_name: str = plugin.get("name", "<unknown>")
        plugin_cfg: dict[str, Any] = plugin.get("config") or {}

        log.debug(
            "test_4_3_level1_validating_params",
            plugin_name=plugin_name,
            config_keys=list(plugin_cfg.keys()),
        )

        threshold_finding = self._validate_one_param(
            plugin_name=plugin_name,
            config=plugin_cfg,
            aliases=_FAILURE_THRESHOLD_ALIASES,
            label="failure_threshold",
            min_val=cfg.failure_threshold_min,
            max_val=cfg.failure_threshold_max,
            unit="consecutive failures",
        )
        if threshold_finding is not None:
            findings.append(threshold_finding)

        timeout_finding = self._validate_one_param(
            plugin_name=plugin_name,
            config=plugin_cfg,
            aliases=_TIMEOUT_DURATION_ALIASES,
            label="timeout_duration",
            min_val=cfg.timeout_duration_min_seconds,
            max_val=cfg.timeout_duration_max_seconds,
            unit="seconds",
        )
        if timeout_finding is not None:
            findings.append(timeout_finding)

        return findings

    def _validate_one_param(
        self,
        plugin_name: str,
        config: dict[str, Any],
        aliases: tuple[str, ...],
        label: str,
        min_val: int,
        max_val: int,
        unit: str,
    ) -> Finding | None:
        """
        Validate one numeric parameter of a Kong plugin config dict.

        Resolves the field name by iterating aliases in order; uses the first
        key found in the config dict.

        Three outcomes:
            Field not found under any alias  -> informational Finding.
            Value outside [min_val, max_val] -> FAIL Finding.
            Value within bounds              -> None (compliant, no Finding).

        Args:
            plugin_name: Plugin name for the Finding title.
            config:      Plugin config sub-dict from Admin API.
            aliases:     Field-name aliases to try, in priority order.
            label:       Human-readable parameter name for the Finding.
            min_val:     Inclusive minimum acceptable value.
            max_val:     Inclusive maximum acceptable value.
            unit:        Unit label (e.g. 'seconds', 'consecutive failures').

        Returns:
            Finding if the parameter is absent or out of range; else None.
        """
        resolved: str | None = next((a for a in aliases if a in config), None)

        if resolved is None:
            alias_list = ", ".join(f"'{a}'" for a in aliases)
            log.debug(
                "test_4_3_param_not_found",
                plugin_name=plugin_name,
                label=label,
                aliases=list(aliases),
            )
            return Finding(
                title=f"CB Parameter '{label}' Not Found in Plugin '{plugin_name}'",
                detail=(
                    f"The parameter '{label}' (searched under aliases: {alias_list}) "
                    f"is absent from plugin '{plugin_name}' config. "
                    "This may indicate a volume-rate controller rather than a true "
                    "circuit breaker, or an undocumented proprietary parameter name. "
                    f"Expected range: [{min_val}, {max_val}] {unit}."
                ),
                references=_REFERENCES_CB,
                evidence_ref=None,
            )

        raw_value = config[resolved]
        try:
            value = int(float(str(raw_value)))
        except (ValueError, TypeError):
            return Finding(
                title=f"CB Parameter '{label}' Non-Numeric in Plugin '{plugin_name}'",
                detail=(
                    f"Field '{resolved}' has value {raw_value!r}, which cannot be "
                    f"interpreted as a numeric threshold. "
                    f"Expected integer in [{min_val}, {max_val}] {unit}."
                ),
                references=_REFERENCES_CB,
                evidence_ref=None,
            )

        if min_val <= value <= max_val:
            log.debug(
                "test_4_3_param_compliant",
                plugin_name=plugin_name,
                field=resolved,
                value=value,
            )
            return None

        if value < min_val:
            direction = "below the minimum"
            impact = (
                f"A {label} of {value} {unit} is too sensitive: minor transient "
                "errors will trip the circuit prematurely, causing unnecessary "
                "service degradation (false positives / alert fatigue)."
            )
        else:
            direction = "above the maximum"
            impact = (
                f"A {label} of {value} {unit} allows too many failures before "
                "protection activates, exposing the system to cascading failure "
                "longer than the methodology tolerates."
            )

        log.warning(
            "test_4_3_param_out_of_range",
            plugin_name=plugin_name,
            field=resolved,
            value=value,
            expected_min=min_val,
            expected_max=max_val,
        )
        return Finding(
            title=(
                f"CB Parameter '{label}' Out of Range ({value} {unit}) in Plugin '{plugin_name}'"
            ),
            detail=(
                f"Plugin '{plugin_name}' field '{resolved}' = {value} {unit}, "
                f"which is {direction} of [{min_val}, {max_val}] {unit} "
                "(methodology section 4.3, Martin Fowler Circuit Breaker Pattern). "
                f"{impact} "
                f"Recommended: adjust '{resolved}' to a value in "
                f"[{min_val}, {max_val}] {unit}."
            ),
            references=_REFERENCES_CB,
            evidence_ref=None,
        )

    def _build_plugin_disabled_finding(self, plugin_name: str) -> Finding:
        """
        Build a Finding for a recognised CB plugin that is registered but disabled.

        A disabled plugin is functionally equivalent to an absent one: Kong
        skips disabled plugins during request processing, so the circuit-breaker
        state machine is inactive.

        Args:
            plugin_name: Kong plugin name string.

        Returns:
            FAIL Finding documenting the disabled-plugin gap.
        """
        return Finding(
            title=f"CB Plugin '{plugin_name}' Registered but Disabled",
            detail=(
                f"Plugin '{plugin_name}' is in the Kong plugin registry but its "
                "'enabled' field is false. Kong does not evaluate disabled plugins "
                "during request processing: circuit-breaker protection is inactive. "
                "This is functionally identical to the plugin being absent -- "
                "downstream service failures will not trigger the CB state machine. "
                "Remediation: set 'enabled: true' in the plugin configuration."
            ),
            references=_REFERENCES_CB,
            evidence_ref=None,
        )

    # ------------------------------------------------------------------
    # Level 2 helpers
    # ------------------------------------------------------------------

    def _fetch_upstreams(self, admin_base_url: str) -> list[dict[str, Any]] | None:
        """
        Retrieve all Kong upstreams from the Admin API.

        Args:
            admin_base_url: Kong Admin API base URL without trailing slash.

        Returns:
            List of upstream dicts (possibly empty), or None on failure.
        """
        try:
            upstreams = get_upstreams(admin_base_url)
            log.debug("test_4_3_upstreams_fetched", count=len(upstreams))
            return upstreams
        except KongAdminError as exc:
            log.error(
                "test_4_3_admin_api_error",
                path="/upstreams",
                status_code=exc.status_code,
                error=str(exc),
            )
            return None

    def _check_level2_passive_hc(
        self,
        upstreams: list[dict[str, Any]],
        cfg: RuntimeTest43Config,
    ) -> _Level2Result:
        """
        Inspect all Kong upstreams for a configured passive healthcheck.

        For each upstream, evaluates healthchecks.passive.unhealthy. An upstream
        is "active" when at least one failure counter (http_failures, tcp_failures,
        timeouts) is > 0. An active upstream is "within thresholds" when all
        non-zero counters are <= the respective passive_hc_max_* config value.

        Args:
            upstreams: Full upstream list from Kong GET /upstreams.
            cfg:       Test43AuditConfig with Level 2 oracle thresholds.

        Returns:
            _Level2Result indicating whether a valid compensating control exists.
        """
        if not upstreams:
            log.info("test_4_3_level2_no_upstreams_registered")
            return _Level2Result(
                has_valid_compensating_control=False,
                valid_upstream_count=0,
                compensating_note=None,
            )

        summaries: list[_PassiveHcSummary] = [
            self._evaluate_upstream_passive_hc(upstream=u, cfg=cfg) for u in upstreams
        ]

        for s in summaries:
            log.debug(
                "test_4_3_level2_upstream_evaluated",
                upstream_name=s.upstream_name,
                is_active=s.is_active,
                within_thresholds=s.within_thresholds,
                http_failures=s.http_failures,
                tcp_failures=s.tcp_failures,
                timeouts=s.timeouts,
                violations=s.violation_details,
            )

        valid = [s for s in summaries if s.is_active and s.within_thresholds]
        invalid_active = [s for s in summaries if s.is_active and not s.within_thresholds]
        inactive = [s for s in summaries if not s.is_active]

        log.info(
            "test_4_3_level2_summary",
            total_upstreams=len(upstreams),
            valid_count=len(valid),
            invalid_active_count=len(invalid_active),
            inactive_count=len(inactive),
        )

        if not valid:
            return _Level2Result(
                has_valid_compensating_control=False,
                valid_upstream_count=0,
                compensating_note=None,
            )

        compensating_note = self._build_compensating_control_note(
            valid=valid,
            invalid_active=invalid_active,
            inactive=inactive,
            total=len(upstreams),
        )
        return _Level2Result(
            has_valid_compensating_control=True,
            valid_upstream_count=len(valid),
            compensating_note=compensating_note,
        )

    def _evaluate_upstream_passive_hc(
        self,
        upstream: dict[str, Any],
        cfg: RuntimeTest43Config,
    ) -> _PassiveHcSummary:
        """
        Evaluate the passive healthcheck configuration of a single Kong upstream.

        Extracts healthchecks.passive.unhealthy and reads the three standard
        failure counters. An upstream is "active" if any counter > 0. The Kong
        default for all counters is 0 (passive healthcheck disabled).

        Args:
            upstream: Kong upstream dict from GET /upstreams.
            cfg:      Test43AuditConfig with passive_hc_max_* thresholds.

        Returns:
            _PassiveHcSummary describing the upstream's passive HC state.
        """
        upstream_name: str = upstream.get("name") or upstream.get("id") or "<unnamed>"

        healthchecks: dict[str, Any] = upstream.get("healthchecks") or {}
        passive: dict[str, Any] = healthchecks.get("passive") or {}
        unhealthy: dict[str, Any] = passive.get("unhealthy") or {}

        http_failures = int(unhealthy.get("http_failures") or 0)
        tcp_failures = int(unhealthy.get("tcp_failures") or 0)
        timeouts = int(unhealthy.get("timeouts") or 0)

        is_active = http_failures > 0 or tcp_failures > 0 or timeouts > 0

        violations: list[str] = []
        if is_active:
            if http_failures > 0 and http_failures > cfg.passive_hc_max_http_failures:
                violations.append(
                    f"http_failures={http_failures} exceeds max {cfg.passive_hc_max_http_failures}"
                )
            if tcp_failures > 0 and tcp_failures > cfg.passive_hc_max_tcp_failures:
                violations.append(
                    f"tcp_failures={tcp_failures} exceeds max {cfg.passive_hc_max_tcp_failures}"
                )
            if timeouts > 0 and timeouts > cfg.passive_hc_max_timeouts:
                violations.append(f"timeouts={timeouts} exceeds max {cfg.passive_hc_max_timeouts}")

        return _PassiveHcSummary(
            upstream_name=upstream_name,
            is_active=is_active,
            within_thresholds=is_active and not violations,
            http_failures=http_failures,
            tcp_failures=tcp_failures,
            timeouts=timeouts,
            violation_details=violations,
        )

    def _build_compensating_control_note(
        self,
        valid: list[_PassiveHcSummary],
        invalid_active: list[_PassiveHcSummary],
        inactive: list[_PassiveHcSummary],
        total: int,
    ) -> InfoNote:
        """
        Build an informational InfoNote documenting the Level 2 compensating control.

        This InfoNote is attached to a PASS result via TestResult.notes (not findings).
        Typed as InfoNote (not Finding) because Level 2 PASS implies no security
        violation: the note provides architectural context so the analyst understands
        the residual risk of relying on passive healthchecks vs. a true circuit breaker.

        On FAIL paths (Level 3), this method is not called. The observability
        check also returns an InfoNote that execute() converts to a Finding when
        the overall status is FAIL, so all diagnostic information remains co-located
        in the findings list for FAIL results.

        Args:
            valid:          Upstreams with active passive HC within thresholds.
            invalid_active: Upstreams with active passive HC but violating thresholds.
            inactive:       Upstreams with passive HC disabled (all counters = 0).
            total:          Total upstream count inspected.

        Returns:
            InfoNote for the PASS result's notes field.
        """
        valid_names = ", ".join(f"'{s.upstream_name}'" for s in valid)

        valid_detail_lines = [
            f"  - '{s.upstream_name}': http_failures={s.http_failures}, "
            f"tcp_failures={s.tcp_failures}, timeouts={s.timeouts}"
            for s in valid
        ]

        gap_lines: list[str] = []
        if inactive:
            inactive_names = ", ".join(f"'{s.upstream_name}'" for s in inactive)
            gap_lines.append(
                f"  - {len(inactive)} upstream(s) with passive HC DISABLED "
                f"({inactive_names}). Backends under these upstreams will NOT be "
                "ejected on failure: cascading-failure risk remains for their routes."
            )
        for s in invalid_active:
            gap_lines.append(
                f"  - Upstream '{s.upstream_name}': passive HC active but "
                f"threshold(s) out of range -- {'; '.join(s.violation_details)}."
            )

        detail_parts: list[str] = [
            "LEVEL 2 (Compensating Control -- Partial Guarantee)",
            "",
            "No native circuit-breaker plugin was found (Level 1 not satisfied). "
            f"However, {len(valid)} of {total} upstream(s) have a passive "
            "healthcheck configured with thresholds within methodology limits: "
            + valid_names
            + ".",
            "",
            "Upstream passive healthcheck configuration:",
        ]
        detail_parts.extend(valid_detail_lines)

        detail_parts += [
            "",
            "Architectural difference (passive HC vs. true circuit breaker):",
            "  - Passive HC operates at the load-balancer layer (backend ejection "
            "from pool), not at the request-dispatch layer.",
            "  - It does NOT implement CLOSED/OPEN/HALF-OPEN state machine.",
            "  - Requests to a degrading backend still time out until the backend "
            "is marked unhealthy; there is no instant fail-fast rejection.",
            "  - Recovery re-adds the backend after a TTL, not via a HALF-OPEN probe.",
            "",
            "Despite these limitations, passive healthchecks reduce cascading failure "
            "risk by eventually ejecting persistently failing backends. This is an "
            "accepted compensating control under OWASP ASVS V16.5.2 when a native "
            "CB plugin is unavailable (Kong OSS architectural constraint).",
        ]

        if gap_lines:
            detail_parts += [
                "",
                "Residual gaps identified (require remediation):",
            ]
            detail_parts.extend(gap_lines)
        else:
            detail_parts.append(
                "",
            )
            detail_parts.append(
                "All registered upstreams have a valid passive healthcheck configured."
            )

        detail_parts += [
            "",
            "Recommended remediation (eliminates the gap entirely):",
            "  1. Upgrade to Kong Gateway Enterprise and enable the native "
            "'circuit-breaker' plugin.",
            "  2. Implement CB at the service mesh layer (e.g., Istio "
            "DestinationRule.trafficPolicy.outlierDetection).",
        ]

        return InfoNote(
            title=(
                f"Level 2 (Compensating Control): Passive HC on "
                f"{len(valid)}/{total} Upstream(s) -- No Native CB Plugin"
            ),
            detail="\n".join(detail_parts),
            references=_REFERENCES_PHC,
        )

    # ------------------------------------------------------------------
    # Level 3 Finding
    # ------------------------------------------------------------------

    def _build_level3_finding(
        self,
        accepted_plugin_names: list[str],
        upstream_count: int,
    ) -> Finding:
        """
        Build a FAIL Finding documenting the complete absence of CB protection.

        Called when both Level 1 and Level 2 find no protection.

        Args:
            accepted_plugin_names: CB plugin names that were searched for.
            upstream_count:        Number of upstreams inspected at Level 2.

        Returns:
            FAIL Finding with remediation options.
        """
        names_quoted = ", ".join(f"'{n}'" for n in accepted_plugin_names)
        return Finding(
            title="Level 3 (Vulnerable): No Circuit-Breaker Protection Detected",
            detail=(
                "The Dual-Check a 3 Livelli found no cascading-failure protection "
                "on this Kong gateway.\n\n"
                f"Level 1 result: none of the accepted CB plugin names ({names_quoted}) "
                "are registered and enabled in the Kong plugin registry.\n\n"
                f"Level 2 result: {upstream_count} upstream(s) inspected; none have "
                "a passive healthcheck with at least one failure counter > 0 "
                "(Kong default is 0 for all counters = passive HC disabled).\n\n"
                "Impact: without a circuit breaker or compensating control, a single "
                "failing downstream service causes every request to block until "
                "read_timeout expires. At 100 rps with a 30 s read_timeout, 3 000 "
                "requests accumulate in 30 s, exhausting the worker pool and "
                "producing a full gateway outage from one dependency failure "
                "(cascading failure / thundering-herd pattern).\n\n"
                "Remediation options (in order of protection strength):\n"
                "  1. Kong Enterprise: enable the native 'circuit-breaker' plugin.\n"
                "  2. Kong OSS: configure passive healthchecks on ALL upstreams -- "
                "set unhealthy.http_failures, unhealthy.tcp_failures, and "
                "unhealthy.timeouts to non-zero values (e.g., 5, 5, 3).\n"
                "  3. Service mesh layer: Istio DestinationRule with "
                "trafficPolicy.outlierDetection (consecutive5xxErrors, interval, "
                "baseEjectionTime).\n"
                "  4. Custom Lua plugin implementing the CB state machine: add its "
                "name to accepted_cb_plugin_names in config.yaml."
            ),
            references=_REFERENCES_CB,
            evidence_ref=None,
        )

    # ------------------------------------------------------------------
    # Observability check (independent, always runs)
    # ------------------------------------------------------------------

    def _check_observability(self, admin_base_url: str) -> InfoNote | None:
        """
        Check whether the Kong /status endpoint exposes circuit-breaker metrics.

        Kong OSS /status reports only database connectivity and worker memory
        statistics. It does not expose CB state (OPEN/CLOSED/HALF-OPEN),
        failure counters, or rejection counts. This is expected on Kong OSS
        and produces an informational InfoNote documenting the observability gap.

        The InfoNote is attached to PASS results via TestResult.notes. On FAIL
        paths, execute() converts the InfoNote to a Finding so that all diagnostic
        information is co-located in the findings list for FAIL results.

        This check is independent of the Level 1/2/3 outcome and never changes
        the test status on its own.

        Args:
            admin_base_url: Kong Admin API base URL without trailing slash.

        Returns:
            Informational InfoNote if CB metrics are absent from /status.
            Returns None on KongAdminError (avoids masking the primary finding).
        """
        try:
            status_data = get_status(admin_base_url)
        except KongAdminError as exc:
            log.warning(
                "test_4_3_status_endpoint_unreachable",
                error=str(exc),
                status_code=exc.status_code,
            )
            return None

        status_keys: frozenset[str] = frozenset(status_data.keys())
        present_cb_keys = status_keys & _CB_STATUS_INDICATORS

        if present_cb_keys:
            log.info(
                "test_4_3_status_cb_fields_present",
                fields=list(present_cb_keys),
            )
            return None

        log.info(
            "test_4_3_status_no_cb_fields",
            present_keys=sorted(status_keys),
        )

        return InfoNote(
            title="Observability Gap: CB Metrics Absent from Kong /status",
            detail=(
                "The Kong Admin API GET /status response does not contain any "
                "circuit-breaker state fields "
                f"(checked: {', '.join(sorted(_CB_STATUS_INDICATORS))}). "
                f"Present fields: {', '.join(sorted(status_keys)) or '(none)'}.\n\n"
                "Kong OSS /status reports only database connectivity and worker "
                "memory statistics. It does not expose circuit-breaker or passive "
                "healthcheck state (OPEN/CLOSED/HALF-OPEN), failure counters, or "
                "backend ejection events. This is true regardless of whether a CB "
                "plugin or upstream passive healthcheck is configured.\n\n"
                "Impact: operators cannot detect a tripped circuit or an ejected "
                "backend in real time, cannot correlate client 503 errors with "
                "upstream failure events, and cannot verify that the compensating "
                "control is functioning correctly. The protection mechanism "
                "(whatever level it operates at) is operationally unmanageable "
                "during incidents without external observability.\n\n"
                "Remediation: deploy a Prometheus exporter or Datadog Kong "
                "integration to scrape upstream health metrics (targets with "
                "health: UNHEALTHY status), or upgrade to Kong Gateway Enterprise "
                "which exposes /status/circuit-breakers."
            ),
            references=_REFERENCES_OBS,
        )
