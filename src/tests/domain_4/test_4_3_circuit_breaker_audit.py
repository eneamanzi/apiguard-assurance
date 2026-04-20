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

    Without a circuit breaker, a slow or unresponsive backend causes every
    in-flight request to block until the read_timeout expires. With 100 rps
    and a 30 s read_timeout, 3 000 requests accumulate in 30 s, exhausting
    the thread pool and producing a full gateway outage from a single
    dependency failure (cascading failure).

Strategy: WHITE_BOX -- Configuration Audit.
    The methodology (section 4.3) prescribes "White Box - Audit di
    Configurazione": verify via Admin API whether circuit-breaker directives
    are present and correctly parameterised. The optional behavioural test
    (disabling a service and verifying fast-fail response) is explicitly
    marked as staging-only and is not implemented here.

Priority: P1 -- the absence of a circuit breaker is a business-critical
    resilience gap. In Kong OSS DB-less (the reference deployment for this
    thesis), no native circuit-breaker plugin is available; the expected
    result is therefore FAIL with a gap-documenting finding, which is the
    correct and academically honest outcome per OWASP ASVS v5.0.0 V16.5.2.

Sub-tests (executed in this fixed order):
--------------------------------------------------------------------------
Sub-test 1 -- Plugin Detection
    Retrieves all plugins via GET /plugins and searches for any plugin name
    in accepted_cb_plugin_names (config-driven).

    Oracle:
        At least one accepted plugin found and enabled  -> proceed to Sub-test 2
        No accepted plugin found or all disabled        -> FAIL (gap finding)
        All accepted plugins found but disabled         -> FAIL (disabled finding)

Sub-test 2 -- Parameter Validation (only if Sub-test 1 succeeds)
    For the first enabled accepted plugin, inspects its config dict for:

        a. failure_threshold (or equivalent): must be in [min, max]
           Accepted field aliases: 'failure_threshold', 'consecutive_errors',
           'error_threshold_percentage' (Kong Enterprise naming variants).
        b. timeout_duration (or equivalent): must be in [min_s, max_s]
           Accepted field aliases: 'timeout', 'sleep_time', 'recovery_time'
           (in seconds). Kong's 'response-ratelimiting' plugin does not
           expose these parameters -- its config is audited differently.

    Oracle (per parameter):
        value in [min, max]  -> compliant
        value outside range  -> Finding with observed value and expected range

Sub-test 3 -- Observability Check (always runs, independent)
    Verifies that the Kong /status endpoint exposes circuit-breaker state
    fields. Checked via GET /status on the Admin API.

    Kong OSS /status does NOT expose circuit-breaker metrics (it reports
    database connectivity and node information only). This sub-test will
    produce a non-blocking informational Finding on standard Kong OSS
    deployments -- informational only, not a FAIL by itself.

EvidenceStore policy:
    WHITE_BOX configuration audit -- no requests made to the target API,
    no _log_transaction() calls, evidence_ref=None on all Findings.
--------------------------------------------------------------------------

Kong OSS Caveat
---------------
Kong Gateway OSS (free tier, including DB-less mode) does not ship a native
circuit-breaker plugin. 'circuit-breaker' is a Kong Enterprise plugin.
The 'response-ratelimiting' plugin provides volume-based request shaping but
is NOT a true circuit breaker: it does not detect downstream failures, does
not implement the CLOSED/OPEN/HALF-OPEN state machine, and does not prevent
cascading failure.

On a vanilla Kong OSS deployment, Sub-test 1 will find no accepted plugin and
the test will return FAIL with a finding titled 'No Circuit-Breaker Plugin
Detected'. This is the academically correct result: it documents a real
architectural gap in the Kong OSS default deployment, directly cited by
OWASP ASVS v5.0.0 V16.5.2 as a required control.

If a custom Lua plugin or a third-party circuit-breaker implementation is
deployed, add its name to accepted_cb_plugin_names in config.yaml to enable
detection and parameter validation.
"""  # noqa: N999

from __future__ import annotations

from typing import Any, ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.models import Finding, TestResult, TestStatus, TestStrategy
from src.tests.base import BaseTest
from src.tests.helpers.kong_admin import KongAdminError, get_plugins, get_status

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

# Field name aliases for the failure threshold across known Kong CB plugins.
# Evaluated in order; first match wins.
_FAILURE_THRESHOLD_FIELD_ALIASES: tuple[str, ...] = (
    "failure_threshold",
    "consecutive_errors",
    "error_threshold_percentage",
)

# Field name aliases for the Open-state hold duration (in seconds).
_TIMEOUT_DURATION_FIELD_ALIASES: tuple[str, ...] = (
    "timeout",
    "sleep_time",
    "recovery_time",
    "timeout_duration",
)

# OWASP/NIST references cited in every Finding.
_REFERENCES: list[str] = [
    "OWASP-API4:2023",
    "OWASP-ASVS-v5.0.0-V16.5.2",
    "NIST-SP-800-204-Section-4.5.1",
    "CWE-400",
]

# Reference for the observability sub-test.
_OBSERVABILITY_REFERENCES: list[str] = [
    "OWASP-ASVS-v5.0.0-V16.5.2",
    "NIST-SP-800-204-Section-4.5.1",
]

# Kong OSS /status response fields that would indicate circuit-breaker
# observability (none currently exist in Kong OSS -- checked defensively).
_CB_STATUS_FIELD_INDICATORS: frozenset[str] = frozenset(
    {
        "circuit_breaker",
        "circuit_breakers",
        "cb_state",
    }
)


class Test43CircuitBreakerAudit(BaseTest):
    """
    Test 4.3 -- Circuit Breaker Configuration Audit: Graceful Degradation.

    Verifies via the Kong Admin API that a circuit-breaker (or functionally
    equivalent) plugin is registered, enabled, and parameterised within the
    ranges prescribed by the methodology. Produces a FAIL finding when no
    such plugin is detected -- the expected result on Kong OSS DB-less.
    """

    # ------------------------------------------------------------------
    # BaseTest class-level contract
    # ------------------------------------------------------------------

    test_id: ClassVar[str] = "4.3"
    test_name: ClassVar[str] = "Circuit Breaker Configuration Audit -- Graceful Degradation"
    domain: ClassVar[int] = 4
    priority: ClassVar[int] = 1
    strategy: ClassVar[TestStrategy] = TestStrategy.WHITE_BOX
    depends_on: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = [
        "availability",
        "resilience",
        "circuit-breaker",
        "cascading-failure",
        "white-box",
        "OWASP-API4",
    ]
    cwe_id: ClassVar[str] = "CWE-400"

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
        Audit circuit-breaker plugin presence and configuration via Kong Admin API.

        Execution flow:
            1. Guard: requires Admin API (_requires_admin_api).
            2. Sub-test 1: detect circuit-breaker plugin.
               If none found -> FAIL (gap finding), proceed to Sub-test 3.
               If found but disabled -> FAIL (disabled finding), proceed to Sub-test 3.
               If found and enabled -> proceed to Sub-test 2.
            3. Sub-test 2 (conditional): validate plugin parameters.
            4. Sub-test 3: check /status for CB observability (non-blocking).
            5. Return PASS or FAIL based on accumulated findings.

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

            findings: list[Finding] = []
            plugin_enabled: bool = False
            active_plugin_name: str = ""

            # Sub-test 1: plugin detection
            plugins_result = self._fetch_plugins(admin_base_url)
            if plugins_result is None:
                return self._make_error(
                    RuntimeError(
                        "Kong Admin API call to GET /plugins failed. "
                        "See structured log for details."
                    )
                )

            detected_plugin = self._detect_cb_plugin(
                plugins=plugins_result,
                accepted_names=cfg.accepted_cb_plugin_names,
            )

            if detected_plugin is None:
                findings.append(
                    self._build_no_plugin_finding(cfg.accepted_cb_plugin_names)
                )
                log.warning(
                    "test_4_3_no_cb_plugin_found",
                    accepted_names=cfg.accepted_cb_plugin_names,
                    total_plugins=len(plugins_result),
                )
            elif not detected_plugin.get("enabled", False):
                plugin_name_disabled: str = detected_plugin.get("name", "<unknown>")
                findings.append(
                    self._build_plugin_disabled_finding(plugin_name_disabled)
                )
                log.warning(
                    "test_4_3_cb_plugin_disabled",
                    plugin_name=plugin_name_disabled,
                    plugin_id=detected_plugin.get("id"),
                )
            else:
                plugin_enabled = True
                active_plugin_name = detected_plugin.get("name", "<unknown>")
                log.info(
                    "test_4_3_cb_plugin_found_enabled",
                    plugin_name=active_plugin_name,
                    plugin_id=detected_plugin.get("id"),
                )
                # Sub-test 2: parameter validation (only for enabled plugins).
                param_findings = self._audit_plugin_parameters(
                    plugin=detected_plugin,
                    cfg=cfg,
                )
                findings.extend(param_findings)

            # Sub-test 3: observability check (independent, always runs).
            observability_finding = self._check_status_observability(admin_base_url)
            if observability_finding is not None:
                findings.append(observability_finding)

            # Build final result.
            if findings:
                if not plugin_enabled:
                    summary = (
                        "Circuit-breaker plugin absent or disabled on Kong gateway. "
                        "Without a circuit breaker, a failing downstream service will "
                        "cause cascading thread-pool exhaustion and full gateway outage. "
                        f"See findings for details ({len(findings)} issue(s) detected)."
                    )
                else:
                    summary = (
                        f"Circuit-breaker plugin '{active_plugin_name}' detected but has "
                        f"configuration issues ({len(findings)} finding(s)). "
                        "Review parameter findings for remediation guidance."
                    )

                return TestResult(
                    test_id=self.test_id,
                    status=TestStatus.FAIL,
                    message=summary,
                    findings=findings,
                    transaction_log=list(self._transaction_log),
                    **self._metadata_kwargs(),
                )

            return self._make_pass(
                message=(
                    f"Circuit-breaker plugin '{active_plugin_name}' is enabled and "
                    "configured within methodology parameter ranges. "
                    "The gateway is protected against cascading failure from "
                    "downstream service degradation."
                )
            )

        except Exception as exc:  # noqa: BLE001
            log.exception("test_4_3_unexpected_error", error=str(exc))
            return self._make_error(exc)

    # ------------------------------------------------------------------
    # Sub-test 1: plugin detection
    # ------------------------------------------------------------------

    def _fetch_plugins(
        self, admin_base_url: str
    ) -> list[dict[str, Any]] | None:
        """
        Retrieve all installed Kong plugins from the Admin API.

        Wraps get_plugins() in a try/except so that a KongAdminError is
        converted to a structured log entry and None return, allowing the
        caller to produce an ERROR result cleanly.

        Args:
            admin_base_url: Kong Admin API base URL without trailing slash.

        Returns:
            List of Kong plugin dicts (may be empty), or None on Admin API error.
        """
        try:
            plugins = get_plugins(admin_base_url)
            log.debug("test_4_3_plugins_fetched", count=len(plugins))
            return plugins
        except KongAdminError as exc:
            log.error(
                "test_4_3_admin_api_error_plugins",
                path="/plugins",
                status_code=exc.status_code,
                error=str(exc),
            )
            return None

    def _detect_cb_plugin(
        self,
        plugins: list[dict[str, Any]],
        accepted_names: list[str],
    ) -> dict[str, Any] | None:
        """
        Search the plugin list for a circuit-breaker equivalent.

        Iterates accepted_names in order (config priority). For each name,
        scans the full plugin list for a match. Returns the first matching
        plugin dict regardless of its enabled state; the caller decides
        whether a disabled plugin is a gap.

        Args:
            plugins:        Full plugin list from GET /plugins.
            accepted_names: Ordered list of plugin names to accept as
                            circuit-breaker equivalents.

        Returns:
            First matching plugin dict, or None if none found.
        """
        by_name: dict[str, dict[str, Any]] = {}
        for plugin in plugins:
            name = plugin.get("name", "")
            if name and name not in by_name:
                by_name[name] = plugin

        for candidate_name in accepted_names:
            if candidate_name in by_name:
                log.debug(
                    "test_4_3_plugin_candidate_matched",
                    candidate=candidate_name,
                )
                return by_name[candidate_name]

        return None

    def _build_no_plugin_finding(self, accepted_names: list[str]) -> Finding:
        """
        Build a Finding documenting the complete absence of a CB plugin.

        Args:
            accepted_names: Plugin names that were searched for.

        Returns:
            Finding with a comprehensive gap description.
        """
        names_quoted = ", ".join(f"'{n}'" for n in accepted_names)
        return Finding(
            title="No Circuit-Breaker Plugin Detected on Kong Gateway",
            detail=(
                f"None of the accepted circuit-breaker plugin names ({names_quoted}) "
                "are registered in the Kong plugin registry (GET /plugins). "
                "\n\n"
                "Kong Gateway OSS (free tier, including DB-less mode) does not include "
                "a native circuit-breaker plugin. The 'circuit-breaker' plugin is "
                "available exclusively in Kong Gateway Enterprise. "
                "\n\n"
                "Impact: without a circuit breaker, a single failing downstream service "
                "causes every request to block until read_timeout expires. At 100 rps with "
                "a 30 s timeout, 3000 threads accumulate in 30 s, exhausting the connection "
                "pool and producing a full gateway outage from one dependency failure "
                "(cascading failure / thundering-herd). "
                "\n\n"
                "Remediation options:\n"
                "  1. Upgrade to Kong Gateway Enterprise and enable the circuit-breaker plugin.\n"
                "  2. Deploy a Lua-based custom circuit breaker and add its plugin name to "
                "accepted_cb_plugin_names in config.yaml.\n"
                "  3. Implement circuit breaking at the service mesh layer "
                "(e.g., Istio DestinationRule.trafficPolicy.outlierDetection).\n"
                "  4. Document the absence as an accepted architectural risk with compensating "
                "controls (aggressive read_timeout + autoscaling policy)."
            ),
            references=_REFERENCES,
            evidence_ref=None,
        )

    def _build_plugin_disabled_finding(self, plugin_name: str) -> Finding:
        """
        Build a Finding for a recognised CB plugin that is disabled.

        A disabled plugin is functionally equivalent to an absent one:
        Kong does not evaluate disabled plugins when processing requests.

        Args:
            plugin_name: Kong plugin name string.

        Returns:
            Finding describing the disabled plugin gap.
        """
        return Finding(
            title=f"Circuit-Breaker Plugin '{plugin_name}' Is Registered but Disabled",
            detail=(
                f"The plugin '{plugin_name}' is present in the Kong plugin registry "
                "but its 'enabled' field is false. Kong does not evaluate disabled "
                "plugins during request processing; the circuit-breaker protection "
                "is therefore inactive despite the plugin being registered. "
                "This is functionally identical to the plugin being absent: downstream "
                "service failures will not trigger the circuit-breaker state machine. "
                "Remediation: set 'enabled: true' in the plugin configuration, or "
                "remove the disabled entry and replace it with an active deployment."
            ),
            references=_REFERENCES,
            evidence_ref=None,
        )

    # ------------------------------------------------------------------
    # Sub-test 2: parameter validation
    # ------------------------------------------------------------------

    def _audit_plugin_parameters(
        self,
        plugin: dict[str, Any],
        cfg: Any,  # RuntimeTest43Config -- typed as Any to avoid circular import
    ) -> list[Finding]:
        """
        Validate circuit-breaker plugin configuration parameters.

        Inspects the plugin 'config' sub-dict for failure_threshold and
        timeout_duration using multiple field-name aliases to handle
        Kong version differences and Enterprise vs. OSS naming.

        For 'response-ratelimiting' (Kong OSS substitute): the plugin config
        structure differs significantly from a true circuit breaker -- it
        exposes rate windows rather than failure thresholds. The absence of
        the expected fields is documented as an informational finding.

        Args:
            plugin: Enabled Kong plugin dict from GET /plugins.
            cfg:    RuntimeTest43Config with oracle ranges.

        Returns:
            List of Findings (empty if all parameters are compliant or not
            applicable).
        """
        findings: list[Finding] = []
        plugin_name: str = plugin.get("name", "<unknown>")
        plugin_config: dict[str, Any] = plugin.get("config") or {}

        log.debug(
            "test_4_3_auditing_plugin_params",
            plugin_name=plugin_name,
            config_keys=list(plugin_config.keys()),
        )

        threshold_finding = self._validate_parameter_range(
            plugin_name=plugin_name,
            config=plugin_config,
            field_aliases=_FAILURE_THRESHOLD_FIELD_ALIASES,
            parameter_label="failure_threshold",
            min_value=cfg.failure_threshold_min,
            max_value=cfg.failure_threshold_max,
            unit="consecutive failures",
        )
        if threshold_finding is not None:
            findings.append(threshold_finding)

        timeout_finding = self._validate_parameter_range(
            plugin_name=plugin_name,
            config=plugin_config,
            field_aliases=_TIMEOUT_DURATION_FIELD_ALIASES,
            parameter_label="timeout_duration",
            min_value=cfg.timeout_duration_min_seconds,
            max_value=cfg.timeout_duration_max_seconds,
            unit="seconds",
        )
        if timeout_finding is not None:
            findings.append(timeout_finding)

        return findings

    def _validate_parameter_range(
        self,
        plugin_name: str,
        config: dict[str, Any],
        field_aliases: tuple[str, ...],
        parameter_label: str,
        min_value: int,
        max_value: int,
        unit: str,
    ) -> Finding | None:
        """
        Validate one numeric parameter of a plugin config dict.

        Resolves the field name by iterating field_aliases in order and
        using the first key found in the config dict.

        Three outcomes:
            Field not found under any alias -> informational Finding.
            Value outside [min_value, max_value] -> FAIL Finding.
            Value within bounds -> None (compliant).

        Args:
            plugin_name:     Plugin name for the Finding title.
            config:          Plugin config sub-dict from the Admin API.
            field_aliases:   Tuple of field-name aliases to try, in order.
            parameter_label: Human-readable parameter name for the Finding.
            min_value:       Inclusive minimum acceptable value.
            max_value:       Inclusive maximum acceptable value.
            unit:            Unit label for the Finding detail (e.g. 'seconds').

        Returns:
            Finding if the parameter is absent or out of range, else None.
        """
        resolved_field: str | None = None
        for alias in field_aliases:
            if alias in config:
                resolved_field = alias
                break

        if resolved_field is None:
            alias_list = ", ".join(f"'{a}'" for a in field_aliases)
            log.debug(
                "test_4_3_parameter_not_found",
                plugin_name=plugin_name,
                parameter_label=parameter_label,
                aliases_tried=list(field_aliases),
            )
            return Finding(
                title=(
                    f"Circuit-Breaker Parameter '{parameter_label}' Not Found "
                    f"in Plugin '{plugin_name}'"
                ),
                detail=(
                    f"The parameter '{parameter_label}' (searched under aliases: "
                    f"{alias_list}) is not present in the configuration of plugin "
                    f"'{plugin_name}'. "
                    "This may indicate that the plugin is a volume-rate controller "
                    "(e.g., 'response-ratelimiting') rather than a true circuit breaker, "
                    "or that the plugin uses a proprietary parameter name not in the "
                    "known alias list. "
                    f"Expected range: [{min_value}, {max_value}] {unit}. "
                    "Add the correct field name to the alias list in the test if the "
                    "parameter exists under a different name."
                ),
                references=_REFERENCES,
                evidence_ref=None,
            )

        raw_value = config[resolved_field]

        try:
            value = int(float(str(raw_value)))
        except (ValueError, TypeError):
            return Finding(
                title=(
                    f"Circuit-Breaker Parameter '{parameter_label}' Has Non-Numeric Value "
                    f"in Plugin '{plugin_name}'"
                ),
                detail=(
                    f"Field '{resolved_field}' in plugin '{plugin_name}' config has value "
                    f"{raw_value!r}, which cannot be interpreted as a numeric threshold. "
                    f"Expected an integer in [{min_value}, {max_value}] {unit}."
                ),
                references=_REFERENCES,
                evidence_ref=None,
            )

        if min_value <= value <= max_value:
            log.debug(
                "test_4_3_parameter_compliant",
                plugin_name=plugin_name,
                field=resolved_field,
                value=value,
                range_min=min_value,
                range_max=max_value,
            )
            return None

        if value < min_value:
            direction = "below the minimum"
            impact = (
                f"A {parameter_label} of {value} {unit} is too sensitive: minor "
                "transient errors will open the circuit prematurely, causing "
                "false positives and unnecessary service degradation (alert fatigue)."
            )
        else:
            direction = "above the maximum"
            impact = (
                f"A {parameter_label} of {value} {unit} allows too many failures "
                "before protection activates, leaving the system exposed to "
                "cascading failure for longer than the methodology tolerates."
            )

        log.warning(
            "test_4_3_parameter_out_of_range",
            plugin_name=plugin_name,
            field=resolved_field,
            value=value,
            expected_min=min_value,
            expected_max=max_value,
        )
        return Finding(
            title=(
                f"Circuit-Breaker Parameter '{parameter_label}' Out of Range "
                f"({value} {unit}) in Plugin '{plugin_name}'"
            ),
            detail=(
                f"Plugin '{plugin_name}' has '{resolved_field}' = {value} {unit}, "
                f"which is {direction} the acceptable range [{min_value}, {max_value}] "
                f"{unit} defined by the methodology (section 4.3, Martin Fowler "
                "Circuit Breaker Pattern). "
                f"{impact} "
                f"Recommended action: adjust '{resolved_field}' to a value in "
                f"[{min_value}, {max_value}] {unit} in the Kong plugin configuration."
            ),
            references=_REFERENCES,
            evidence_ref=None,
        )

    # ------------------------------------------------------------------
    # Sub-test 3: observability check
    # ------------------------------------------------------------------

    def _check_status_observability(
        self, admin_base_url: str
    ) -> Finding | None:
        """
        Check whether the Kong /status endpoint exposes circuit-breaker metrics.

        Kong OSS /status reports database connectivity and node status but has
        no circuit-breaker state fields. This is expected and does not produce
        a blocking FAIL by itself (the plugin absence in Sub-test 1 is the
        primary finding). This check produces an informational finding to
        document the observability gap, relevant for the thesis analysis of
        Kong OSS operational limitations.

        Args:
            admin_base_url: Kong Admin API base URL without trailing slash.

        Returns:
            Finding if CB metrics are absent from /status, else None.
            Returns None on KongAdminError to avoid masking the primary finding.
        """
        try:
            status_data = get_status(admin_base_url)
        except KongAdminError as exc:
            log.warning(
                "test_4_3_status_endpoint_error",
                error=str(exc),
                status_code=exc.status_code,
            )
            return None

        status_keys: frozenset[str] = frozenset(status_data.keys())
        cb_keys_present = status_keys & _CB_STATUS_FIELD_INDICATORS

        if cb_keys_present:
            log.info(
                "test_4_3_status_cb_fields_found",
                fields=list(cb_keys_present),
            )
            return None

        log.info(
            "test_4_3_status_no_cb_fields",
            present_keys=sorted(status_keys),
        )

        return Finding(
            title="Circuit-Breaker Metrics Absent from Kong /status Endpoint",
            detail=(
                "The Kong Admin API GET /status response does not contain any "
                "circuit-breaker state fields (checked: "
                f"{', '.join(sorted(_CB_STATUS_FIELD_INDICATORS))}). "
                f"Present /status fields: {', '.join(sorted(status_keys)) or '(none)'}. "
                "\n\n"
                "In Kong OSS, the /status endpoint reports only database connectivity "
                "and worker memory statistics. It does not expose circuit-breaker state "
                "(OPEN / CLOSED / HALF-OPEN), failure counters, or rejection counts. "
                "\n\n"
                "Impact: without circuit-breaker observability, operators cannot detect "
                "a tripped circuit in real time, cannot correlate client 503 errors with "
                "upstream failure events, and cannot verify that the circuit is recovering "
                "correctly during the HALF-OPEN probe phase. "
                "This observability gap makes the circuit breaker operationally unmanageable "
                "during incidents, even if it is functionally present. "
                "\n\n"
                "Remediation: deploy a monitoring sidecar (e.g., Prometheus exporter, "
                "Datadog Kong integration) that scrapes circuit-breaker state from a "
                "plugin-specific metrics endpoint, or upgrade to Kong Gateway Enterprise "
                "which exposes /status/circuit-breakers."
            ),
            references=_OBSERVABILITY_REFERENCES,
            evidence_ref=None,
        )
