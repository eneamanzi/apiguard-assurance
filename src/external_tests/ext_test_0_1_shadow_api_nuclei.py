"""
src/external_tests/ext_test_0_1_shadow_api_nuclei.py

ExtTest01ShadowApiNuclei: external test for shadow API discovery via nuclei.

Relationship with Test 0.1 (native):
    Test 0.1 (src/tests/domain_0/test_0_1_shadow_api_discovery.py) covers the
    PYTHON-native parts of Garanzia 0.1:
        - Path fuzzing from the internal shadow_wordlists.py wordlist via
          SecurityClient (httpx), comparing active paths against the OpenAPI spec.
        - HTTP method discovery (OPTIONS vs spec-declared methods).
        - Versioning completeness check (active version variants vs documented).

    This external test extends coverage with a CONNECTOR-managed nuclei scan:
        - Template-based detection of known exposure patterns:
          Swagger/OpenAPI UI endpoints, admin panels, debug paths,
          API misconfigurations catalogued in nuclei-templates.
        - The key distinction: nuclei templates encode community-curated
          knowledge of "paths that should not be publicly reachable", whereas
          the native test cross-references paths against the project's own
          OpenAPI spec.  The two approaches are complementary: native catches
          spec drift; nuclei catches known-bad exposure patterns.

    The split follows the HYBRID pattern defined in Z-CHECKLIST.md:
        Native part   -> spec-diff-based shadow API discovery
        External part -> template-based known-exposure detection (this file)

Test ID:
    "ext.0.1" -- NOT "0.1" to avoid collision with the native Test 0.1 in the
    engine's test_lookup dict.  The "ext." prefix is the project convention for
    all ExternalToolTest subclasses (matches the file prefix "ext_test_").

Oracle (Garanzia 0.1, OWASP API9:2023 Improper Inventory Management,
        CWE-200 Exposure of Sensitive Information):
    CRITICAL, HIGH, MEDIUM severity finding -> FAIL with one Finding per item.
        Rationale: any medium-or-above exposure detected by a community-curated
        template represents an endpoint that is reachable but should not be, or
        is reachable in a way that exposes sensitive information.  These are
        unambiguous FAIL conditions under the methodology.
    LOW or INFO severity finding -> PASS with one InfoNote per item.
        Rationale: LOW/INFO findings (e.g. Swagger UI at /api/swagger on Forgejo)
        represent informational detections rather than exploitable exposures.
        They are surfaced as structured InfoNote cards for analyst review but do
        not constitute a security guarantee failure on their own.
    No findings (results=[]) -> PASS.
        Rationale: nuclei found no templates matching the scan target.  This is
        the normal, expected result on a well-configured API gateway.

    Severity values confirmed against nuclei v3.8.0 / templates v10.4.3:
        "critical", "high", "medium", "low", "info"  (all lowercase in JSON).

    nuclei severity is nested: item["info"]["severity"] -- NOT item["severity"].
    FAIL_SEVERITIES and NOTE_SEVERITIES use lowercase exact match (not .upper()
    normalization) because nuclei consistently emits lowercase severity values.

Timeout source:
    target.external_tools.nuclei.timeout_seconds is the canonical total
    wall-clock scan timeout.  NucleiConfig.per_request_timeout controls the
    per-HTTP-request timeout passed to nuclei via -timeout.

DAG placement:
    depends_on = [] -- Phase A, no prerequisites.  The native Test 0.1 also
    has no prerequisites; both tests collect evidence independently before
    any authenticated tests run.

Dependency rule:
    Imports from: stdlib, structlog, src.connectors, src.external_tests.base,
                  src.core.context, src.core.models, src.core.evidence.
    Must never import from: tests/, config/loader.py, discovery/, report/,
    or engine.py.
"""

from __future__ import annotations

from typing import Any, ClassVar

import structlog

from src.connectors import NucleiConnector
from src.connectors.base import BaseConnector, ConnectorResult
from src.core.context import TargetContext
from src.core.models import Finding, InfoNote, TestStrategy
from src.core.models.results import TestResult
from src.external_tests.base import ExternalToolTest

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Oracle severity sets
# Derived from Step B.0 reconnaissance (nuclei v3.8.0 / templates v10.4.3).
# nuclei emits severity values in lowercase in the JSON export.
# ---------------------------------------------------------------------------

# Findings at these severities directly violate Garanzia 0.1 and produce FAIL.
FAIL_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium"})

# Findings at these severities are surfaced as structured InfoNote cards (not FAIL).
# Analyst review is recommended but the guarantee is considered satisfied.
NOTE_SEVERITIES: frozenset[str] = frozenset({"low", "info"})

# Any severity value not in FAIL_SEVERITIES or NOTE_SEVERITIES is logged as
# a warning (unexpected value, likely a new severity added in a future nuclei
# version) and treated as a note (conservative: does not produce FAIL).

# Standards references included in every Finding and InfoNote this test produces.
# Defined here (not inside helper methods) so both _finding_from_nuclei_item()
# and _note_from_nuclei_item() share the same canonical tuple without duplication.
_REFERENCES: tuple[str, ...] = (
    "OWASP API9:2023 Improper Inventory Management",
    "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
)

# Analyst guidance appended to every InfoNote detail.
# Defined as a constant to avoid verbatim repetition and make wording easy to tune.
_NOTE_ANALYST_SUFFIX: str = (
    "Low/info severity: below the FAIL threshold for Garanzia 0.1. "
    "Analyst review recommended."
)


# ---------------------------------------------------------------------------
# ExtTest01ShadowApiNuclei
# ---------------------------------------------------------------------------


class ExtTest01ShadowApiNuclei(ExternalToolTest):  # noqa: N801
    """
    External test for Garanzia 0.1 (Shadow API Discovery) using nuclei.

    Invokes NucleiConnector with the tag filter defined in
    target.external_tools.nuclei.tags (default: api, exposure, misconfig, panel)
    and partitions nuclei findings into FAIL / NOTE / ignored buckets using
    FAIL_SEVERITIES and NOTE_SEVERITIES.

    A FAIL means nuclei detected a known exposure pattern on the target that
    constitutes an undocumented or improperly secured API surface -- the core
    of what Garanzia 0.1 aims to prevent.

    NOTE items (low/info) are surfaced as structured InfoNote cards in the
    HTML report: they record template matches below the FAIL threshold so the
    analyst can review them without misclassifying them as security violations.
    """

    # --- ClassVar attributes (required by BaseTest / ExternalToolTest) ------

    test_id: ClassVar[str] = "ext.0.1"
    test_name: ClassVar[str] = "Shadow API Discovery via nuclei (template-based exposure detection)"
    priority: ClassVar[int] = 0
    domain: ClassVar[int] = 0
    strategy: ClassVar[TestStrategy] = TestStrategy.BLACK_BOX
    depends_on: ClassVar[list[str]] = []
    tags: ClassVar[list[str]] = [
        "shadow-api",
        "discovery",
        "exposure",
        "OWASP-API9",
        "nuclei",
    ]
    cwe_id: ClassVar[str] = "CWE-200"
    tool_name: ClassVar[str] = "nuclei"

    # ------------------------------------------------------------------
    # ExternalToolTest abstract method implementations
    # ------------------------------------------------------------------

    def _build_connector(self) -> BaseConnector:
        """
        Instantiate NucleiConnector.

        Pure object construction -- zero I/O.  Discovery of the binary
        path (shutil.which, local tools directory) is deferred to
        NucleiConnector.is_available(), called by _check_and_skip()
        in ExternalToolTest._run().

        Returns:
            NucleiConnector: Uninitialised connector ready for _check_and_skip().
        """
        return NucleiConnector()

    def _invoke_connector(
        self,
        connector: BaseConnector,
        target: TargetContext,
        target_url: str,
    ) -> ConnectorResult:
        """
        Build invocation parameters from TargetContext and call connector.run().

        All runtime parameters are read from target.external_tools.nuclei so
        that no values are hardcoded in this method.  The operator controls
        the scan via config.yaml.

        Args:
            connector:  Active NucleiConnector instance (already confirmed
                        available by _check_and_skip()).
            target:     Frozen TargetContext with external_tools.nuclei config.
            target_url: Resolved base URL passed by ExternalToolTest._run().
                        Canonical source for the scan target; takes precedence
                        over any URL derived internally.

        Returns:
            ConnectorResult: Raw nuclei output, unfiltered.

        Raises:
            ExternalToolError: Propagated from NucleiConnector.run() on
                               template directory missing, subprocess timeout,
                               or fatal nuclei error.
        """
        nuclei_cfg = target.external_tools.nuclei

        # timeout_seconds is mandatory when enabled=True (enforced by Pydantic
        # validator in NucleiConfig).  The cast is safe here.
        timeout_seconds: int = nuclei_cfg.timeout_seconds  # type: ignore[assignment]

        log.info(
            "ext_test_0_1_invoke_connector",
            target_url=target_url,
            template_dir=nuclei_cfg.template_dir,
            tags=nuclei_cfg.tags,
            per_request_timeout=nuclei_cfg.per_request_timeout,
            rate_limit_rps=nuclei_cfg.rate_limit_rps,
            timeout_seconds=timeout_seconds,
        )

        return connector.run(  # type: ignore[return-value]
            target_url=target_url,
            timeout_seconds=timeout_seconds,
            template_dir=nuclei_cfg.template_dir,
            tags=nuclei_cfg.tags,
            per_request_timeout=nuclei_cfg.per_request_timeout,
            rate_limit_rps=nuclei_cfg.rate_limit_rps,
            extra_flags=nuclei_cfg.extra_flags,
        )

    def _evaluate(
        self,
        result: ConnectorResult,
        artifact_ref: str,
    ) -> TestResult:
        """
        Apply the oracle to nuclei findings and produce a TestResult.

        Partitions ConnectorResult.raw_output["results"] into three buckets:
            fail_items  -- severity in FAIL_SEVERITIES (critical, high, medium)
            note_items  -- severity in NOTE_SEVERITIES (low, info)
            unknown     -- severity not in either set (logged as warning, treated as note)

        Severity field path (nuclei-specific):
            nuclei nests severity under item["info"]["severity"], unlike testssl.sh
            which places it at the top level as item["severity"].  The .lower()
            normalisation matches FAIL_SEVERITIES and NOTE_SEVERITIES which use
            lowercase values confirmed from real nuclei v3.8.0 output.

        Outcome:
            len(fail_items) > 0  -> FAIL, one Finding per item; note_items
                                    attached as InfoNote objects alongside.
            len(fail_items) == 0 -> PASS; note_items surfaced as InfoNote cards
                                    for analyst review.

        Note items are always converted to structured InfoNote objects and
        passed via notes= to _make_pass() / _make_fail().  This ensures they
        appear as blue cards in the HTML report detail panel -- not as raw text
        embedded in the message string.

        Args:
            result:       ConnectorResult from NucleiConnector.run().
            artifact_ref: Evidence record ID from store.pin_artifact() in _run().

        Returns:
            TestResult with status PASS or FAIL and a structured message.
        """
        results: list[dict[str, Any]] = result.raw_output.get("results", [])
        total_count: int = result.raw_output.get("all_count", len(results))

        if not results:
            log.info(
                "ext_test_0_1_evaluate_pass",
                reason="no_findings",
                total_count=total_count,
            )
            return self._make_pass(
                message=(
                    "nuclei found no template matches on the target. "
                    "No known shadow API exposures detected via template-based scan."
                ),
            )

        # Partition findings by severity.
        # nuclei severity is nested under item["info"]["severity"] and always lowercase.
        fail_items: list[dict[str, Any]] = []
        note_items: list[dict[str, Any]] = []

        for item in results:
            severity = str(item.get("info", {}).get("severity", "")).lower()

            if severity in FAIL_SEVERITIES:
                fail_items.append(item)
            elif severity in NOTE_SEVERITIES:
                note_items.append(item)
            else:
                # Unexpected severity value: treat conservatively as note,
                # but log a warning so the analyst is aware.
                log.warning(
                    "ext_test_0_1_unknown_severity",
                    template_id=item.get("template-id", "unknown"),
                    severity=severity,
                    detail=(
                        "Unexpected severity value not in FAIL_SEVERITIES or "
                        "NOTE_SEVERITIES.  Treated as informational note.  "
                        "Update the oracle if this severity is intentional in "
                        f"nuclei-templates v{result.tool_version or 'unknown'}."
                    ),
                )
                note_items.append(item)

        log.info(
            "ext_test_0_1_evaluate_partitioned",
            total=total_count,
            fail_count=len(fail_items),
            note_count=len(note_items),
        )

        # Build InfoNote objects for all NOTE bucket items (low/info).
        # Constructed before the FAIL/PASS branch so both paths share the same
        # list without duplicating InfoNote construction logic.
        all_notes: list[InfoNote] = [
            self._note_from_nuclei_item(item) for item in note_items
        ]

        # ------------------------------------------------------------------
        # FAIL path: at least one medium/high/critical finding.
        # ------------------------------------------------------------------
        if fail_items:
            findings: list[Finding] = [
                self._finding_from_nuclei_item(item, artifact_ref) for item in fail_items
            ]
            log.info(
                "ext_test_0_1_evaluate_fail",
                fail_count=len(fail_items),
                note_count=len(note_items),
            )
            return self._make_fail(
                message=(
                    f"nuclei detected {len(fail_items)} shadow API exposure(s) "
                    f"at severity medium/high/critical out of {total_count} "
                    "total finding(s)."
                ),
                findings=findings,
                notes=all_notes,
            )

        # ------------------------------------------------------------------
        # PASS path: only low/info findings (informational).
        # ------------------------------------------------------------------
        log.info(
            "ext_test_0_1_evaluate_pass",
            reason="only_informational_findings",
            note_count=len(note_items),
        )
        return self._make_pass(
            message=(
                f"nuclei found {len(note_items)} informational finding(s) "
                "(low/info severity -- no security guarantee violated). "
                "Analyst review recommended."
            ),
            notes=all_notes,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _finding_from_nuclei_item(item: dict[str, Any], artifact_ref: str) -> Finding:
        """
        Convert a single nuclei finding dict to a Finding model.

        All field accesses use .get() with safe defaults to guard against
        schema changes in future nuclei-templates versions.  The oracle in
        _evaluate() uses only the fields confirmed in Step B.0 reconnaissance
        (nuclei v3.8.0 / templates v10.4.3, 2026-05-11).

        nuclei finding field mapping (Step B.0 confirmed fields):
            template-id          -> used in Finding.title
            info.name            -> used in Finding.title
            info.severity        -> used in Finding.detail
            matched-at           -> used in Finding.detail (the discovered URL)
            info.classification.cwe-id -> used in Finding.references

        Args:
            item:         Single finding dict from nuclei raw_output["results"].
            artifact_ref: Evidence record ID for cross-referencing in the report.

        Returns:
            Finding: Structured finding for the TestResult.
        """
        info: dict[str, Any] = item.get("info", {})
        classification: dict[str, Any] = info.get("classification", {}) or {}

        template_id: str = item.get("template-id", "unknown-template")
        name: str = info.get("name", "Unknown nuclei finding")
        severity: str = info.get("severity", "unknown").upper()
        matched_at: str = item.get("matched-at", "unknown")

        # CWE IDs: nuclei emits a list (e.g. ["cwe-200"]) or null.
        cwe_raw: list[str] | None = classification.get("cwe-id")
        cwe_references: list[str] = [cwe.upper() for cwe in cwe_raw] if cwe_raw else []

        return Finding(
            title=f"[nuclei:{template_id}] {name}",
            detail=(
                f"Severity: {severity}. "
                f"nuclei template '{template_id}' matched at '{matched_at}'. "
                "This endpoint is reachable and matches a known exposure "
                "pattern catalogued in nuclei-templates.  Verify whether "
                "this path is documented in the OpenAPI specification and "
                "subject to the same authentication and rate-limiting policy "
                "as documented endpoints."
            ),
            references=[*_REFERENCES, *cwe_references],
            evidence_ref=artifact_ref,
        )

    @staticmethod
    def _note_from_nuclei_item(item: dict[str, Any]) -> InfoNote:
        """
        Convert a single nuclei low/info finding dict to an InfoNote.

        Mirrors the field access pattern of _finding_from_nuclei_item() but
        produces an InfoNote rather than a Finding: the item is below the FAIL
        threshold and does not constitute a security guarantee violation.  The
        InfoNote is surfaced as a blue card in the HTML report detail panel so
        the analyst can review the match without misclassifying it as a failure.

        nuclei finding field mapping (same as _finding_from_nuclei_item):
            template-id          -> InfoNote.title suffix
            info.name            -> InfoNote.title
            info.severity        -> InfoNote.title prefix
            matched-at           -> InfoNote.detail (the matched URL)
            info.classification.cwe-id -> InfoNote.references

        Args:
            item: Single finding dict from nuclei raw_output["results"].

        Returns:
            InfoNote: Structured informational annotation for the HTML report.
        """
        info: dict[str, Any] = item.get("info", {})
        classification: dict[str, Any] = info.get("classification", {}) or {}

        template_id: str = item.get("template-id", "unknown-template")
        name: str = info.get("name", "Unknown nuclei finding")
        severity: str = info.get("severity", "unknown").upper()
        matched_at: str = item.get("matched-at", "unknown")

        cwe_raw: list[str] | None = classification.get("cwe-id")
        cwe_references: list[str] = [cwe.upper() for cwe in cwe_raw] if cwe_raw else []

        return InfoNote(
            title=f"[{severity}] {name}",
            detail=(
                f"nuclei template '{template_id}' matched at '{matched_at}'. "
                f"{_NOTE_ANALYST_SUFFIX}"
            ),
            references=[*_REFERENCES, *cwe_references],
        )
