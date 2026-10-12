"""
src/tests/domain_4/test_4_3_circuit_breaker_audit.py

Test 4.3 -- Circuit Breaker Configuration Audit: Graceful Degradation.

Guarantee (docs/knowledge/methodology/methodology.it.md, Section 4.3):
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
        At least one upstream with valid passive HC -> PASS + InfoNote
        Upstreams exist but none have passive HC    -> proceed to Level 3
        No upstreams registered                     -> proceed to Level 3

LEVEL 3 -- No protection (Vulnerable)
    Neither native plugin nor upstream passive healthcheck found.
    Oracle: FAIL with a gap-documenting Finding.

FINDING SEPARATO -- Observability (always runs, independent of levels)
    Verifies that the live health of the backend targets can be read (gateway
    concept "live target health"; Kong /upstreams/{name}/health). When it
    cannot, an InfoNote says why (a Finding on FAIL paths); it never changes
    the test status on its own.

Gateway access:
    The levels read the gateway concepts circuit breakers, health checks and
    live target health (src/core/gateway/concepts.py) through the adapter;
    which Kong plugin names count as circuit breakers comes from
    accepted_cb_plugin_names, passed to the Kong adapter. A health checks
    concept not supported or not accessible gives SKIP; circuit breakers not
    accessible give SKIP when the verdict would be Level 3 (absence not
    proven), a note when Level 2 holds.

EvidenceStore policy:
    No request to the target proxy. Each concept read is stored as an artifact
    (BaseTest._record_gateway_concept); findings point to the concept they
    are based on (evidence_ref).
---------------------------------------------------------------------------

Kong OSS DB-less expected outcome:
    Level 1: no 'circuit-breaker' plugin found -> proceed to Level 2.
    Level 2: depends on upstream configuration:
        - Upstreams with passive HC configured -> PASS (compensating)
        - No passive HC configured             -> FAIL (Level 3)
    Observability: the upstream health is readable -> no note.
"""  # noqa: N999

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import ClassVar

import structlog

from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.gateway.base import (
    CONCEPT_CIRCUIT_BREAKERS,
    CONCEPT_HEALTH_CHECKS,
    CONCEPT_TARGET_HEALTH,
)
from src.core.gateway.concepts import (
    CircuitBreaker,
    ConceptRead,
    ConceptStatus,
    HealthCheck,
    TargetHealth,
)
from src.core.models import (
    Finding,
    InfoNote,
    TestResult,
    TestStrategy,
)
from src.test_config.domain_4 import Test43AuditConfig
from src.tests.base import BaseTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

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
    requires_pass: ClassVar[list[str]] = []
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
        Audit circuit breaking and health checks through the gateway adapter.

        Reads three gateway concepts (circuit breakers, health checks, live
        target health), stores each as evidence, and applies the three levels:
            Level 1: a circuit breaker (the first one, in the configured
                     priority order) enabled and with parameters in range.
            Level 2: otherwise, at least one backend with a passive health
                     check within thresholds (compensating control).
            Level 3: otherwise, FAIL.
        Observability: the live health of the targets must be readable; when
        it is not, a note (a finding on FAIL) says why.
        A concept the gateway does not support or that cannot be read: SKIP
        when the verdict depends on it, a note otherwise.

        Returns:
            TestResult with status PASS, FAIL, SKIP, or ERROR.
        """
        try:
            skip_guard = self._requires_admin_api(target)
            if skip_guard is not None:
                return skip_guard

            gateway = target.gateway
            assert gateway is not None  # noqa: S101

            cfg = target.tests_config.test_4_3
            log.info(
                "test_4_3_starting",
                gateway_adapter=gateway.adapter_name,
                accepted_cb_plugin_names=cfg.accepted_cb_plugin_names,
            )

            breakers = gateway.circuit_breakers()
            breakers_ref = self._record_gateway_concept(
                target, store, CONCEPT_CIRCUIT_BREAKERS, breakers
            )
            health = gateway.target_health()
            health_ref = self._record_gateway_concept(target, store, CONCEPT_TARGET_HEALTH, health)
            observability_note = self._check_observability(health, health_ref)

            level1 = self._check_level1_plugin(breakers.items, cfg, breakers_ref)
            if level1.plugin_found:
                if not level1.findings:
                    notes: list[InfoNote] = []
                    if observability_note is not None:
                        notes.append(observability_note)
                    return self._make_pass(
                        message=(
                            f"Level 1 (Full Guarantee): circuit breaker "
                            f"'{level1.plugin_name}' is enabled and configured "
                            "within methodology parameter ranges. The gateway is "
                            "protected against cascading failure."
                        ),
                        notes=notes,
                    )
                fail_findings: list[Finding] = list(level1.findings)
                if observability_note is not None:
                    fail_findings.append(self._note_as_finding(observability_note, health_ref))
                return self._make_fail_multi(
                    message=(
                        f"Level 1: circuit breaker '{level1.plugin_name}' found but "
                        f"has {len(level1.findings)} configuration issue(s). "
                        "See findings for details."
                    ),
                    findings=fail_findings,
                )

            log.info(
                "test_4_3_level1_no_match_proceeding_to_level2",
                accepted_names=cfg.accepted_cb_plugin_names,
                breakers_status=breakers.status.value,
            )

            checks = gateway.health_checks()
            checks_ref = self._record_gateway_concept(target, store, CONCEPT_HEALTH_CHECKS, checks)
            if checks.status != ConceptStatus.READ:
                return self._skip_for_concept(CONCEPT_HEALTH_CHECKS, checks, checks_ref)

            level2 = self._check_level2_passive_hc(checks.items, cfg)
            if level2.has_valid_compensating_control:
                assert level2.compensating_note is not None  # noqa: S101
                level2_notes: list[InfoNote] = [level2.compensating_note]
                breakers_note = self._unread_breakers_note(breakers, breakers_ref)
                if breakers_note is not None:
                    level2_notes.append(breakers_note)
                if observability_note is not None:
                    level2_notes.append(observability_note)
                return self._make_pass(
                    message=(
                        "Level 2 (Compensating Control): no native circuit-breaker "
                        "plugin found, but "
                        f"{level2.valid_upstream_count} of {len(checks.items)} "
                        "upstream(s) have a passive healthcheck configured within "
                        "safe thresholds. Partial cascading-failure protection via "
                        "upstream health management. "
                        "See informational notes for architectural gaps."
                    ),
                    notes=level2_notes,
                )

            # Level 3 needs to know that no circuit breaker exists: if the
            # breakers could not be read, the absence is not proven.
            if breakers.status == ConceptStatus.NOT_ACCESSIBLE:
                return self._skip_for_concept(CONCEPT_CIRCUIT_BREAKERS, breakers, breakers_ref)

            level3_findings: list[Finding] = [
                self._build_level3_finding(
                    accepted_plugin_names=cfg.accepted_cb_plugin_names,
                    upstream_count=len(checks.items),
                    evidence_ref=checks_ref,
                )
            ]
            if observability_note is not None:
                level3_findings.append(self._note_as_finding(observability_note, health_ref))
            return self._make_fail_multi(
                message=(
                    "Level 3 (Vulnerable): no circuit breaker and no backend passive "
                    "healthcheck detected on this gateway. "
                    f"Checked {len(checks.items)} upstream(s). "
                    "See findings for remediation guidance."
                ),
                findings=level3_findings,
            )

        except Exception as exc:  # noqa: BLE001
            log.exception("test_4_3_unexpected_error", error=str(exc))
            return self._make_error(exc)

    @staticmethod
    def _note_as_finding(note: InfoNote, evidence_ref: str) -> Finding:
        """Turn an InfoNote into a Finding (FAIL paths keep diagnostics with the findings)."""
        return Finding(
            title=note.title,
            detail=note.detail,
            references=note.references,
            evidence_ref=evidence_ref,
        )

    @staticmethod
    def _unread_breakers_note(
        breakers: ConceptRead[CircuitBreaker], evidence_ref: str
    ) -> InfoNote | None:
        """Return a note when the circuit breakers could not be read (Level 1 unknown)."""
        if breakers.status == ConceptStatus.READ:
            return None
        return InfoNote(
            title="Level 1 Not Verified: Circuit Breakers Not Read",
            detail=(
                f"The gateway's circuit breakers could not be read ({breakers.status.value}: "
                f"{breakers.reason}). The verdict rests on Level 2 only. Evidence: {evidence_ref}."
            ),
            references=_REFERENCES_CB,
        )

    # ------------------------------------------------------------------
    # Level 1 helpers
    # ------------------------------------------------------------------

    def _check_level1_plugin(
        self,
        breakers: tuple[CircuitBreaker, ...],
        cfg: Test43AuditConfig,
        evidence_ref: str,
    ) -> _Level1Result:
        """
        Take the first circuit breaker read and validate it.

        The adapter returns the breakers in the configured priority order
        (accepted_cb_plugin_names on Kong), first instance of each, so the
        first item is the one the test judges.

        Args:
            breakers:     Circuit breakers read from the gateway.
            cfg:          Test43AuditConfig with the oracle ranges.
            evidence_ref: Evidence record of the concept read.

        Returns:
            _Level1Result with plugin_found=False if there is none.
        """
        if not breakers:
            log.debug("test_4_3_level1_no_match", searched=cfg.accepted_cb_plugin_names)
            return _Level1Result(plugin_found=False, plugin_name="", findings=[])
        breaker = breakers[0]
        log.info("test_4_3_level1_plugin_matched", plugin=breaker.source, enabled=breaker.enabled)
        if not breaker.enabled:
            return _Level1Result(
                plugin_found=True,
                plugin_name=breaker.source,
                findings=[self._build_plugin_disabled_finding(breaker.source, evidence_ref)],
            )
        return _Level1Result(
            plugin_found=True,
            plugin_name=breaker.source,
            findings=self._validate_plugin_parameters(breaker, cfg, evidence_ref),
        )

    def _validate_plugin_parameters(
        self,
        breaker: CircuitBreaker,
        cfg: Test43AuditConfig,
        evidence_ref: str,
    ) -> list[Finding]:
        """
        Validate the failure threshold and the open duration of an enabled breaker.

        Args:
            breaker:      The circuit breaker read from the gateway.
            cfg:          Test43AuditConfig with Level 1 oracle ranges.
            evidence_ref: Evidence record of the concept read.

        Returns:
            List of Findings (empty when both parameters are compliant).
        """
        findings: list[Finding] = []
        open_seconds = None if breaker.open_seconds is None else int(breaker.open_seconds)
        for value, label, min_val, max_val, unit in (
            (
                breaker.failure_threshold,
                "failure_threshold",
                cfg.failure_threshold_min,
                cfg.failure_threshold_max,
                "consecutive failures",
            ),
            (
                open_seconds,
                "timeout_duration",
                cfg.timeout_duration_min_seconds,
                cfg.timeout_duration_max_seconds,
                "seconds",
            ),
        ):
            finding = self._validate_one_param(
                plugin_name=breaker.source,
                value=value,
                label=label,
                min_val=min_val,
                max_val=max_val,
                unit=unit,
                evidence_ref=evidence_ref,
            )
            if finding is not None:
                findings.append(finding)
        return findings

    def _validate_one_param(
        self,
        plugin_name: str,
        value: int | None,
        label: str,
        min_val: int,
        max_val: int,
        unit: str,
        evidence_ref: str,
    ) -> Finding | None:
        """
        Validate one numeric parameter of a circuit breaker.

        Two outcomes produce a Finding:
            Value not stated by the gateway  -> informational Finding.
            Value outside [min_val, max_val] -> FAIL Finding.

        Args:
            plugin_name:  The breaker's source, for the Finding title.
            value:        The parameter's value, or None if not stated.
            label:        Parameter name for the Finding.
            min_val:      Inclusive minimum acceptable value.
            max_val:      Inclusive maximum acceptable value.
            unit:         Unit label (e.g. 'seconds', 'consecutive failures').
            evidence_ref: Evidence record of the concept read.

        Returns:
            Finding if the parameter is absent or out of range; else None.
        """
        if value is None:
            log.debug("test_4_3_param_not_found", plugin_name=plugin_name, label=label)
            return Finding(
                title=f"CB Parameter '{label}' Not Found in Plugin '{plugin_name}'",
                detail=(
                    f"The gateway does not state the parameter '{label}' of '{plugin_name}' "
                    "(absent, or not a number). This may indicate a volume-rate controller "
                    "rather than a true circuit breaker, or an undocumented proprietary "
                    f"parameter name. Expected range: [{min_val}, {max_val}] {unit}."
                ),
                references=_REFERENCES_CB,
                evidence_ref=evidence_ref,
            )

        if min_val <= value <= max_val:
            log.debug("test_4_3_param_compliant", plugin_name=plugin_name, label=label, value=value)
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

        log.info(
            "test_4_3_param_out_of_range",
            plugin_name=plugin_name,
            label=label,
            value=value,
            expected_min=min_val,
            expected_max=max_val,
        )
        return Finding(
            title=(
                f"CB Parameter '{label}' Out of Range ({value} {unit}) in Plugin '{plugin_name}'"
            ),
            detail=(
                f"'{plugin_name}' {label} = {value} {unit}, "
                f"which is {direction} of [{min_val}, {max_val}] {unit} "
                "(methodology section 4.3, Martin Fowler Circuit Breaker Pattern). "
                f"{impact} "
                f"Recommended: adjust {label} to a value in [{min_val}, {max_val}] {unit}."
            ),
            references=_REFERENCES_CB,
            evidence_ref=evidence_ref,
        )

    def _build_plugin_disabled_finding(self, plugin_name: str, evidence_ref: str) -> Finding:
        """
        Build a Finding for a recognised CB plugin that is registered but disabled.

        A disabled plugin is functionally equivalent to an absent one: Kong
        skips disabled plugins during request processing, so the circuit-breaker
        state machine is inactive.

        Args:
            plugin_name:  The breaker's source (plugin name and id on Kong).
            evidence_ref: Evidence record of the concept read.

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
            evidence_ref=evidence_ref,
        )

    # ------------------------------------------------------------------
    # Level 2 helpers
    # ------------------------------------------------------------------

    def _check_level2_passive_hc(
        self,
        upstreams: tuple[HealthCheck, ...],
        cfg: Test43AuditConfig,
    ) -> _Level2Result:
        """
        Inspect all Kong upstreams for a configured passive healthcheck.

        For each upstream, evaluates healthchecks.passive.unhealthy. An upstream
        is "active" when at least one failure counter (http_failures, tcp_failures,
        timeouts) is > 0. An active upstream is "within thresholds" when all
        non-zero counters are <= the respective passive_hc_max_* config value.

        Args:
            upstreams: Health checks of each backend, read from the gateway.
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
        upstream: HealthCheck,
        cfg: Test43AuditConfig,
    ) -> _PassiveHcSummary:
        """
        Evaluate the passive healthcheck configuration of a single Kong upstream.

        Extracts healthchecks.passive.unhealthy and reads the three standard
        failure counters. An upstream is "active" if any counter > 0. The Kong
        default for all counters is 0 (passive healthcheck disabled).

        Args:
            upstream: Health checks of one backend.
            cfg:      Test43AuditConfig with passive_hc_max_* thresholds.

        Returns:
            _PassiveHcSummary describing the upstream's passive HC state.
        """
        upstream_name: str = upstream.name
        passive = upstream.passive
        http_failures = (passive.http_failures or 0) if passive is not None else 0
        tcp_failures = (passive.tcp_failures or 0) if passive is not None else 0
        timeouts = (passive.timeouts or 0) if passive is not None else 0

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
        accepted_plugin_names: Sequence[str],
        upstream_count: int,
        evidence_ref: str,
    ) -> Finding:
        """
        Build a FAIL Finding documenting the complete absence of CB protection.

        Called when both Level 1 and Level 2 find no protection.

        Args:
            accepted_plugin_names: CB plugin names that were searched for.
            upstream_count:        Number of upstreams inspected at Level 2.
            evidence_ref:          Evidence record of the health checks read.

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
            evidence_ref=evidence_ref,
        )

    # ------------------------------------------------------------------
    # Observability check (independent, always runs)
    # ------------------------------------------------------------------

    def _check_observability(
        self,
        health: ConceptRead[TargetHealth],
        evidence_ref: str,
    ) -> InfoNote | None:
        """
        Check that the live health of the backend targets can be read.

        A tripped circuit or an excluded backend must be visible in real time
        (the gateway concept "live target health": Kong /upstreams/{name}/health,
        APISIX Control API). When it can be read there is no gap; when the
        gateway does not support it or it cannot be read, an InfoNote says why
        (execute() turns it into a Finding on FAIL paths). This check never
        changes the test status on its own.

        Args:
            health:       The adapter's answer for the live target health.
            evidence_ref: Evidence record of that answer.

        Returns:
            None when the live health is readable, else an InfoNote.
        """
        if health.status == ConceptStatus.READ:
            log.info("test_4_3_live_health_readable", targets=len(health.items))
            return None
        log.info("test_4_3_live_health_not_readable", status=health.status.value)
        return InfoNote(
            title="Observability Gap: Backend Health State Not Readable",
            detail=(
                f"The live health of the backend targets could not be read "
                f"({health.status.value}: {health.reason}). Evidence: {evidence_ref}.\n\n"
                "Impact: operators cannot detect a tripped circuit or an ejected "
                "backend in real time, cannot correlate client 503 errors with "
                "upstream failure events, and cannot verify that the compensating "
                "control is functioning correctly.\n\n"
                "Remediation: expose the gateway's backend health state to the "
                "monitoring (e.g. a Prometheus exporter), and give the assessment "
                "read access to it."
            ),
            references=_REFERENCES_OBS,
        )
