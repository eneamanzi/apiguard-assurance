"""
src/external_tests/base.py

ExternalToolTest: abstract base class for tests that wrap an external binary.

Relationship with tests/base.py (BaseTest):
    ExternalToolTest does NOT inherit from BaseTest.  The two hierarchies are
    intentionally kept separate because their execution contracts differ:

        BaseTest.execute()         -> receives (TargetContext, TestContext,
                                                SecurityClient, EvidenceStore)
        ExternalToolTest.execute() -> same signature, but internally invokes a
                                      BaseConnector rather than SecurityClient.

    Both return TestResult.  The engine treats them identically -- it sees only
    the TestResult contract, not the implementation hierarchy.

    The `source` ClassVar is set to "external" here and propagated to every
    TestResult via _metadata_kwargs() (same mechanism as BaseTest).

Responsibility split:

    ExternalToolTest is responsible for:
        1. Checking tool availability (_check_and_skip).
        2. Calling connector.run() with the correct parameters.
        3. Evaluating ConnectorResult against the test oracle (_evaluate).
        4. Calling store.pin_artifact() to persist the raw output.
        5. Building the correct TestResult (PASS / FAIL / SKIP / ERROR).

    BaseConnector is responsible for:
        1. Discovering the binary (shutil.which or env var or importlib).
        2. Invoking the subprocess / library with the correct flags.
        3. Parsing JSON output.
        4. Returning ConnectorResult or raising ExternalToolError.

    EvidenceStore.pin_artifact() is responsible for:
        1. Sanitizing credentials from raw_output before persistence.

DA-2 -- Connector lifecycle (dependency injection):
    ExternalTestRegistry may inject a pre-built, shared connector instance
    before execute() is called.  This avoids re-initialising the same connector
    for each test that uses the same external tool, and -- more importantly --
    collapses N "connector_not_available" log entries into a single registry-
    level WARNING.

    Two instance attributes manage this lifecycle:

        _injected_connector: BaseConnector | None
            Set by ExternalTestRegistry._inject_connectors() when the tool IS
            available.  _run() uses it via _get_connector(); _check_and_skip()
            skips the is_available() call because the registry already confirmed
            availability.

        _skip_reason_from_registry: str | None
            Set by ExternalTestRegistry._inject_connectors() when the tool is
            NOT available.  _run() detects it as the first step and returns a
            SKIP immediately, before building any connector.

    The fallback (_injected_connector is None, _skip_reason_from_registry is
    None) preserves full backward compatibility: _get_connector() calls
    _build_connector() and _check_and_skip() calls is_available() as before.

Dependency rule:
    Imports from: stdlib, pydantic, structlog, src.core.*, src.connectors.base.
    Must never import from: tests/, config/loader.py, discovery/, report/, engine.py.
"""

from __future__ import annotations

import json
import traceback
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, ClassVar, Literal, TypedDict

import structlog

from src.connectors.base import BaseConnector, ConnectorResult
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import ExternalToolError
from src.core.models import TestStatus, TestStrategy
from src.core.models.results import Finding, InfoNote, TestResult

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# _REQUIRED_RAW_OUTPUT_KEYS -- ConnectorRawOutput contract enforcement
# ---------------------------------------------------------------------------
# These four keys are mandated by the ConnectorRawOutput contract defined in
# connectors/base.py.  _validate_raw_output() checks their presence before
# _evaluate() is called, converting a silent broken-report scenario into an
# explicit ERROR TestResult with a diagnostic message pointing to the contract.
#
# Rationale for a module-level constant (not a local variable in the method):
#   - Frozen sets are evaluated once at import time -- zero per-call overhead.
#   - The constant is visible to grep / tooling as a canonical list without
#     reading the _validate_raw_output() body.
#   - New connectors can scan this constant during code review to verify
#     they satisfy the contract before running the full assessment.
_REQUIRED_RAW_OUTPUT_KEYS: frozenset[str] = frozenset(
    {"command", "command_json", "results", "all_count"}
)

# ---------------------------------------------------------------------------
# _DEV_CACHE_UNSAFE_CHARS -- filename sanitisation for dev mode cache lookup
# ---------------------------------------------------------------------------
# Characters that EvidenceStore._persist_tool_artifact() replaces with
# underscores when constructing the on-disk artifact filename.  Reproduced
# here so that _load_dev_cache() can reconstruct the exact same filename
# without importing the private constant from src/core/evidence.py.
#
# Invariant: must stay in sync with _ARTIFACT_FILENAME_UNSAFE_CHARS in
# src/core/evidence.py.  Both strings encode the same set of characters;
# the duplication is intentional to avoid coupling external_tests/ to a
# private evidence module constant (unidirectional dependency rule).
#
# Characters: dot, forward slash, backslash, space.
_DEV_CACHE_UNSAFE_CHARS: str = "./\\ "

# ---------------------------------------------------------------------------
# _ExternalTestMetadataKwargs -- TypedDict for type-safe TestResult construction
# ---------------------------------------------------------------------------
# Mirrors _MetadataKwargs in tests/base.py.  Both TypedDicts are intentionally
# kept private to their respective modules: external_tests/ must not import from
# tests/ (unidirectional dependency rule).  Duplication is acceptable because
# the types are an implementation detail of the _make_*() helper methods and
# not part of any public interface.  Sharing via core/ would expose an internal
# construction detail; keeping them local makes each module self-contained and
# independently refactorable.


class _ExternalTestMetadataKwargs(TypedDict):
    """TypedDict for the metadata keyword arguments passed to TestResult.

    Provides Pylance with exact type information for each key so that
    **self._metadata_kwargs() is verified as type-safe at the call site.
    All fields correspond to TestResult metadata fields declared in
    src/core/models/results.py.
    """

    test_name: str
    domain: int
    priority: int
    strategy: str
    tags: list[str]
    cwe_id: str
    source: Literal["native", "external"]
    tool_name: str


# ---------------------------------------------------------------------------
# ExternalToolTest -- ABC
# ---------------------------------------------------------------------------


class ExternalToolTest(ABC):
    """
    Abstract base class for security tests that delegate to an external binary.

    Concrete subclasses implement two methods:
        _build_connector()  -- instantiate and return the correct BaseConnector.
        _evaluate()         -- inspect ConnectorResult and return TestResult.

    The execute() method orchestrates the complete lifecycle:
        1. (DA-2 fast-path) return SKIP if registry marked the tool absent.
        2. check tool availability -> SKIP if missing (fallback path).
        3. call connector.run() -> ConnectorResult or ExternalToolError.
        4. call _evaluate() -> TestResult (PASS / FAIL / SKIP).
        5. on ExternalToolError -> TestResult(ERROR).
        6. on unexpected exception -> TestResult(ERROR) -- never propagates.

    ClassVar attributes (required on every concrete subclass):

        test_id   : str        -- unique identifier, e.g. "ext.tls.1.5".
        test_name : str        -- human-readable name for the HTML report.
        domain    : int        -- domain number (0-7) matching the methodology.
        priority  : int        -- 0-3 (P0-P3), used by ExternalTestRegistry filter.
        strategy  : TestStrategy -- always BLACK_BOX for external scanners.
        depends_on: list[str]    -- test_ids this test must run after.
        tags      : list[str]    -- free-form tags for report classification.
        cwe_id    : str          -- primary CWE reference for the vulnerability.
        tool_name : str          -- name of the external binary this test uses
                                    (e.g. "testssl.sh", "ffuf", "nuclei").
                                    Must match the key used in ExternalToolsConfig
                                    so that ExternalTestRegistry._apply_filters()
                                    can call ExternalToolsConfig.is_tool_enabled().

    The `source` ClassVar is fixed at "external" and must NOT be overridden
    by concrete subclasses -- it is the architectural invariant that separates
    external results from native results in the report builder.
    """

    # --- Orchestrator metadata (same role as in BaseTest) ---
    test_id: ClassVar[str]
    test_name: ClassVar[str]
    domain: ClassVar[int]
    priority: ClassVar[int]
    strategy: ClassVar[TestStrategy]
    depends_on: ClassVar[list[str]]
    tags: ClassVar[list[str]]
    cwe_id: ClassVar[str]

    # --- External tool identifier -- used by ExternalTestRegistry for per-tool filtering ---
    # Must match the key that ExternalToolsConfig.is_tool_enabled() recognises:
    # "testssl", "ffuf", "nuclei" (or any future tool key added to the config schema).
    tool_name: ClassVar[str]

    # --- Result origin -- fixed, must not be overridden ---
    source: ClassVar[Literal["native", "external"]] = "external"

    # ------------------------------------------------------------------
    # DA-2 -- Connector lifecycle (dependency injection hook)
    # ------------------------------------------------------------------
    # These two instance attributes are set by ExternalTestRegistry._inject_connectors()
    # before execute() is called.  They are NOT ClassVars: they are per-instance
    # so that two parallel assessment runs (if ever introduced) remain isolated.
    #
    # Invariant: at most ONE of the two is non-None for any given test instance.
    #   _injected_connector is set  <-> tool IS available, registry injected it.
    #   _skip_reason_from_registry is set <-> tool is NOT available, skip immediately.
    #   Both None <-> registry has not run (backward-compatible fallback mode).

    _injected_connector: BaseConnector | None = None
    _skip_reason_from_registry: str | None = None

    # ------------------------------------------------------------------
    # Public interface (called by engine.py)
    # ------------------------------------------------------------------

    def execute(
        self,
        target: TargetContext,
        context: TestContext,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Orchestrate the external tool execution lifecycle.

        Note: SecurityClient is intentionally NOT a parameter here.  External
        tool tests do not make HTTP requests via httpx; they invoke subprocesses.
        The engine passes (target, context, store) to ExternalToolTest.execute()
        and (target, context, client, store) to BaseTest.execute().

        Args:
            target:  Frozen TargetContext with target URL, credentials, surface.
            context: Mutable TestContext accumulating assessment state.
            store:   EvidenceStore for persisting tool output as artifacts.

        Returns:
            TestResult: Always returns a result -- never raises.
        """
        store.begin_test(self.test_id)
        try:
            result = self._run(target, context, store)
        except Exception as exc:  # noqa: BLE001 -- top-level catch by design
            result = self._make_error(exc)
        finally:
            store.end_test()
        return result

    def _run(
        self,
        target: TargetContext,
        context: TestContext,
        store: EvidenceStore,
    ) -> TestResult:
        """
        Internal run method -- called by execute() inside try/except.

        Separating _run() from execute() keeps the top-level exception handler
        in execute() clean while allowing _run() to use early returns freely.

        Execution paths:

            DA-2 fast-path A (registry absent):
                _skip_reason_from_registry is set -> SKIP immediately.

            Dev mode fast-path (cache hit):
                dev_mode=True in config AND cache file exists at
                outputs/tools/<label>_output.json -> ConnectorResult is
                reconstructed from disk, subprocess is skipped entirely,
                _check_and_skip() and _warn_if_version_mismatch() are NOT
                called (the binary may not be installed at all).

            Dev mode first run (cache miss):
                dev_mode=True but no cache file found -> falls through to the
                normal path.  The binary runs, pin_artifact() writes the cache,
                and the next run will hit the fast-path.

            Normal path:
                dev_mode=False or store.tools_dir is None -> full pipeline:
                availability check, version warning, subprocess invocation.

        DA-2 fast-path B remains in _check_and_skip(): if _injected_connector
        is set (registry confirmed availability), is_available() is skipped.
        This fast-path is only reached when the dev mode path did not return
        early (cache miss or dev_mode=False).

        Args:
            target:  Frozen TargetContext.
            context: Mutable TestContext.
            store:   EvidenceStore (provides tools_dir for cache lookup).

        Returns:
            TestResult: PASS, FAIL, SKIP, or ERROR.

        Raises:
            ExternalToolError: Propagated from connector.run(); caught by execute().
            Any other exception: Propagated to execute() top-level handler.
        """
        # --- DA-2 fast-path A: registry pre-determined tool is absent ---
        # The registry calls is_available() once per tool and sets this string
        # on every test in the group when the tool is missing.  We return SKIP
        # here without building a connector or calling is_available() again.
        if self._skip_reason_from_registry is not None:
            log.debug(
                "external_test_skip_from_registry",
                test_id=self.test_id,
                reason=self._skip_reason_from_registry,
            )
            return self._make_skip(self._skip_reason_from_registry)

        # --- Get connector (injected or freshly built) ---
        connector = self._get_connector()

        # --- Compute artifact label early ---
        # Moved before _invoke_connector() so that the same label string is
        # available to both the dev mode cache lookup and pin_artifact().
        # Formula mirrors _persist_tool_artifact()'s naming convention so
        # the cache file reconstructed here is the same file written by the
        # prior live run.  Example: test_id="ext.0.1.nuclei"
        # -> artifact_label="ext.0.1.nuclei"
        # -> cache file: outputs/tools/ext_0_1_nuclei_output.json
        # The test_id already carries the tool name (ext.X.Y.toolname convention),
        # so appending TOOL_NAME again would produce duplicate suffixes.
        artifact_label: str = self.test_id

        # --- Dev mode: attempt cache load before touching the binary ---
        # _is_dev_mode() reads the per-tool dev_mode flag from config.yaml.
        # _load_dev_cache() returns None on cache miss (file absent / corrupt).
        # On cache hit, connector_result is fully reconstructed and the normal
        # path (availability check + subprocess) is skipped entirely, so the
        # binary does not need to be installed.
        dev_mode: bool = self._is_dev_mode(target)
        connector_result: ConnectorResult | None = None
        cache_hit: bool = False

        if dev_mode and store.tools_dir is not None:
            connector_result = self._load_dev_cache(
                connector=connector,
                artifact_label=artifact_label,
                tools_dir=store.tools_dir,
            )
            cache_hit = connector_result is not None

        # --- Normal path: executed only when cache did not supply a result ---
        if connector_result is None:
            # Step 1: availability check (DA-2 fast-path B inside _check_and_skip).
            skip_result = self._check_and_skip(connector)
            if skip_result is not None:
                return skip_result

            # Step 1b: version compatibility check.
            # Emits a structured WARNING if the installed binary version does
            # not match external_tools.<tool>.expected_version in config.yaml.
            # Does NOT skip or error -- the test proceeds, but the analyst is
            # alerted that oracle field names may have changed across versions.
            self._warn_if_version_mismatch(connector, target)

            # Step 2: retrieve target URL for external binary.
            # Connectors use effective_endpoint_base_url(), not endpoint_base_url(),
            # so Docker Compose service names are used when APIGUARD_TARGET_EFFECTIVE_URL
            # is set in the environment (ADR-001 §6).
            target_url = target.effective_endpoint_base_url()

            # Step 3: execute binary.
            try:
                connector_result = self._invoke_connector(connector, target, target_url)
            except ExternalToolError as exc:
                if exc.timed_out:
                    return self._make_error(
                        exc,
                        message_override=(
                            f"External tool '{exc.tool_name}' timed out. "
                            "Increase timeout_seconds in config.yaml external_tools section."
                        ),
                    )
                return self._make_error(exc)

        # --- Step 3b: validate ConnectorRawOutput contract ---
        # Applies to both cache-hit and live-run results.  The cache file was
        # written from a previously valid ConnectorResult, so this check should
        # always pass on cache hits; it is kept here as a safety net against
        # manually edited or truncated cache files.
        # Raises ExternalToolError (caught by execute()'s top-level handler) if
        # any of the four required keys are absent from raw_output.
        self._validate_raw_output(connector_result)

        # --- Step 4: build enriched artifact, then pin to evidence store ---
        #
        # The enriched artifact extends raw_output with three _apiguard_meta_*
        # keys that carry connector-level metadata useful for reproducibility:
        #
        #   _apiguard_meta_tool_version     -- binary version string or None on cache hits.
        #   _apiguard_meta_execution_time_ms -- subprocess wall-clock time; 0 on cache hits.
        #   _apiguard_meta_dev_mode_cache_hit -- True when the result came from disk cache.
        #
        # Namespace rationale: the "_apiguard_meta_" prefix guarantees no collision
        # with tool-native output keys and makes these fields trivially greppable.
        #
        # The enriched artifact is what pin_artifact() writes to both evidence.json
        # and outputs/tools/<label>_output.json, so the on-disk file and the HTML
        # report modal download are structurally identical.  On a dev mode cache
        # hit, pin_artifact() re-writes the enriched data with the current run's
        # meta values (cache_hit=True, tool_version=None, execution_time_ms=0),
        # keeping the evidence trail accurate for this assessment run.
        enriched_artifact: dict[str, Any] = {
            **connector_result.raw_output,
            "_apiguard_meta_tool_version": connector_result.tool_version,
            "_apiguard_meta_execution_time_ms": connector_result.execution_time_ms,
            "_apiguard_meta_dev_mode_cache_hit": cache_hit,
        }

        artifact_ref = store.pin_artifact(
            label=artifact_label,
            data=enriched_artifact,
        )

        log.info(
            "external_test_connector_complete",
            test_id=self.test_id,
            tool=connector.TOOL_NAME,
            exit_code=connector_result.exit_code,
            execution_time_ms=connector_result.execution_time_ms,
            timed_out=connector_result.timed_out,
            artifact_ref=artifact_ref,
            dev_mode_cache_hit=cache_hit,
        )

        # --- Step 5: oracle evaluation (subclass responsibility) ---
        result = self._evaluate(connector_result, artifact_ref)

        return result.model_copy(
            update={
                "tool_artifact": enriched_artifact,
                # Expose the label and record_id used by pin_artifact() so the
                # HTML report's Tool Output modal can reconstruct the on-disk
                # filename (outputs/tools/<label_safe>_output.json) for the
                # browser download and embed the record_id in the envelope for
                # cross-referencing with evidence.json.
                "tool_artifact_label": artifact_label,
                "tool_artifact_record_id": artifact_ref,
            }
        )

    # ------------------------------------------------------------------
    # Dev mode helpers
    # ------------------------------------------------------------------

    def _is_dev_mode(self, target: TargetContext) -> bool:
        """Return True if dev_mode is enabled for this test's tool in config.yaml.

        Reads ``external_tools.<tool_name>.dev_mode`` from the frozen
        TargetContext.  Returns False for any of these conditions:
            - The tool_name ClassVar is not present in ExternalToolsConfig
              (e.g. a new tool not yet declared in the schema).
            - The per-tool config object does not have a dev_mode attribute
              (e.g. a tool that predates BaseExternalToolConfig.dev_mode).
            - dev_mode is explicitly set to False in config.yaml.

        The double getattr() with False defaults ensures this method never
        raises, matching the defensive convention used by _warn_if_version_mismatch().

        Args:
            target: Frozen TargetContext exposing target.external_tools.

        Returns:
            bool: True only if the per-tool dev_mode flag is True.
        """
        tool_cfg = getattr(target.external_tools, self.tool_name, None)
        return bool(getattr(tool_cfg, "dev_mode", False))

    def _load_dev_cache(
        self,
        connector: BaseConnector,
        artifact_label: str,
        tools_dir: Path,
    ) -> ConnectorResult | None:
        """Load a cached ConnectorResult from a prior live run if dev_mode is active.

        EvidenceStore._persist_tool_artifact() writes each external tool's
        raw_output to disk in an envelope structure:

            {
                "source_test_id": "...",
                "label": "...",
                "record_id": "...",
                "generated_at_utc": "...",
                "data": { <sanitized raw_output> }
            }

        This method reconstructs a ConnectorResult from that envelope, using
        the ``data`` key as raw_output.  The resulting ConnectorResult is
        structurally identical to one produced by a live connector.run() call,
        so _validate_raw_output() and _evaluate() receive the same type they
        always do -- the cache is fully transparent to subclass oracle logic.

        Filename reconstruction:
            The cache file is named ``<safe_label>_output.json``, where
            safe_label is artifact_label with each character in
            _DEV_CACHE_UNSAFE_CHARS replaced by an underscore.  This
            reproduces the exact transformation applied by
            EvidenceStore._persist_tool_artifact(), ensuring this method
            looks for the file at the same path it was written to.

            Example: artifact_label="ext.0.1.nuclei"
                     safe_label="ext_0_1_nuclei"
                     file path: tools_dir/ext_0_1_nuclei_output.json

        Fields in the reconstructed ConnectorResult:
            tool_name          -- from connector.TOOL_NAME (live value, not cached)
            tool_version       -- None (get_version() is not called on cache hits)
            raw_output         -- envelope["data"] (the cached payload)
            exit_code          -- 0 (no subprocess ran; exit_code is not stored)
            execution_time_ms  -- 0 (no subprocess ran; wall-clock is meaningless)
            timed_out          -- False

        The None tool_version and 0 execution_time_ms are surfaced in the
        HTML report via _apiguard_meta_* keys injected by _run(), making the
        dev mode origin visible to analysts without requiring report template
        changes.

        Args:
            connector:      Active connector (provides TOOL_NAME for the result).
            artifact_label: Label string as computed by _run() before invocation
                            (e.g. "ext.0.1_nuclei").
            tools_dir:      Root tool artifact directory from store.tools_dir
                            (e.g. Path("outputs/tools")).

        Returns:
            ConnectorResult: Reconstructed from the cache file on hit.
            None: On cache miss (file absent) or cache corruption (JSON error,
                  missing envelope keys).  The caller falls through to the
                  normal subprocess path on None.
        """
        # Reproduce _persist_tool_artifact()'s safe_label transformation.
        safe_label: str = artifact_label
        for char in _DEV_CACHE_UNSAFE_CHARS:
            safe_label = safe_label.replace(char, "_")
        cache_path: Path = tools_dir / f"{safe_label}_output.json"

        if not cache_path.exists():
            log.info(
                "dev_mode_cache_miss",
                test_id=self.test_id,
                tool=connector.TOOL_NAME,
                cache_path=str(cache_path),
                detail=(
                    "Cache file not found -- running tool live and saving result "
                    "for the next run.  Delete outputs/tools/ to force a fresh "
                    "scan on any subsequent run."
                ),
            )
            return None

        # Load and parse the envelope written by _persist_tool_artifact().
        try:
            envelope: dict[str, Any] = json.loads(cache_path.read_text(encoding="utf-8"))
            raw_output: dict[str, Any] = envelope["data"]
        except (json.JSONDecodeError, KeyError, OSError) as exc:
            log.warning(
                "dev_mode_cache_load_failed",
                test_id=self.test_id,
                tool=connector.TOOL_NAME,
                cache_path=str(cache_path),
                error=str(exc),
                detail=(
                    "Cache file is corrupt or missing the 'data' envelope key. "
                    "Falling through to a live tool run.  "
                    "Delete the file to suppress this warning."
                ),
            )
            return None

        log.warning(
            "dev_mode_cache_hit",
            test_id=self.test_id,
            tool=connector.TOOL_NAME,
            cache_path=str(cache_path),
            cached_at=envelope.get("generated_at_utc", "unknown"),
            detail=(
                "DEV MODE: _evaluate() will receive cached tool output. "
                "The binary was NOT invoked.  "
                "Set dev_mode: false before running a production assessment."
            ),
        )
        return ConnectorResult(
            tool_name=connector.TOOL_NAME,
            # tool_version is not stored in the cache envelope; set to None so
            # _apiguard_meta_tool_version in the enriched artifact is explicit
            # about the fact that version info is unavailable for this run.
            tool_version=None,
            raw_output=raw_output,
            # exit_code and execution_time_ms are not meaningful for a cached
            # result (no subprocess ran).  Set to sentinel values that the
            # report template can detect via _apiguard_meta_dev_mode_cache_hit.
            exit_code=0,
            execution_time_ms=0,
            timed_out=False,
        )

    def _warn_if_version_mismatch(
        self,
        connector: BaseConnector,
        target: TargetContext,
    ) -> None:
        """Emit a structured WARNING if the binary version differs from expected_version.

        Compares the output of ``<binary> --version`` against the
        ``expected_version`` field declared in
        ``external_tools.<tool_name>.expected_version`` of config.yaml.

        Decision table:
            expected_version is None  -> no check, return silently.
                Rationale: the operator has not pinned a version; any binary is
                acceptable.  This is the safe default for environments where
                version pinning is not yet configured.

            connector.get_version() returns None -> WARNING("version_unknown").
                Rationale: the binary exists (is_available() passed) but does
                not support --version.  We cannot confirm compatibility; an
                explicit WARNING is safer than silent acceptance.

            expected in actual (substring match) -> OK, return silently.
                Rationale: version output varies by tool:
                    nuclei  emits "nuclei v3.8.0 (github.com/...)"
                    testssl emits "testssl 3.2.3 from ..."
                Matching the expected string ("3.8.0") as a substring of the
                actual output handles both formats without regex fragility.

            expected NOT in actual -> WARNING("version_mismatch").
                Rationale: the oracle in _evaluate() was written against a
                specific version's JSON schema.  A different version may emit
                renamed, retyped, or removed fields, producing silent wrong
                results rather than explicit errors.

        This method NEVER raises, NEVER returns a value, and NEVER skips
        the test.  Its sole effect is the structured log entry.

        Version pinning rationale (for thesis documentation):
            ExternalToolTest._evaluate() is an oracle tightly coupled to the
            JSON output schema of a specific binary version.  The Version
            Pinning pattern (expected_version in config.yaml + TOOL_VERSION in
            install_tools.sh + ARG in Dockerfile) ensures that the binary
            version that produced an assessment report is always traceable.
            A mismatch during execution means the tool and the oracle have
            diverged -- the result of the assessment for this test MUST be
            reviewed manually before being trusted.

        License note (for thesis documentation):
            Each external tool carries its own open-source license.
            testssl.sh is distributed under GPLv2; nuclei under MIT.
            APIGuard does not bundle or redistribute these binaries -- it
            invokes them as separate processes and documents which version
            it has been validated against via expected_version.  This
            "invocation-only" model is the standard approach used by security
            frameworks (e.g. Metasploit modules calling system binaries) to
            avoid license contamination of the wrapper codebase.

        Args:
            connector: The active connector whose binary version to check.
            target:    Frozen TargetContext exposing target.external_tools
                       for per-tool configuration access.
        """
        # Retrieve the expected version from per-tool config.
        # target.external_tools is the ExternalToolsConfig Pydantic model.
        # getattr with None default handles tools not yet declared in the schema
        # (e.g. a test for a future tool before its Config class is added).
        tool_cfg = getattr(target.external_tools, self.tool_name, None)
        if tool_cfg is None:
            # Tool not in ExternalToolsConfig -- version check not applicable.
            return

        expected: str | None = getattr(tool_cfg, "expected_version", None)
        if expected is None:
            # Operator has not pinned a version: no check.
            return

        actual: str | None = connector.get_version()

        if actual is None:
            log.warning(
                "external_tool_version_unknown",
                test_id=self.test_id,
                tool=self.tool_name,
                expected_version=expected,
                detail=(
                    "Binary is available but '--version' returned no output. "
                    "Cannot confirm version compatibility with the oracle. "
                    "Verify the installed binary manually."
                ),
            )
            return

        # Normalize: strip leading 'v' from expected to handle both "3.8.0"
        # and "v3.8.0" configured values against actual output like
        # "nuclei v3.8.0 (github.com/projectdiscovery/nuclei)".
        expected_normalized = expected.lstrip("v")
        if expected_normalized not in actual:
            log.warning(
                "external_tool_version_mismatch",
                test_id=self.test_id,
                tool=self.tool_name,
                expected_version=expected,
                actual_version=actual,
                detail=(
                    f"The installed '{self.tool_name}' version does not match "
                    f"expected_version='{expected}' in config.yaml. "
                    "The oracle in _evaluate() was written and validated against "
                    f"v{expected_normalized}. Field names or JSON structure may "
                    "have changed in the installed version, producing incorrect "
                    "or incomplete findings. "
                    "To resolve: reinstall the tool at the pinned version via "
                    "install_tools.sh, or update expected_version in config.yaml "
                    "and review _evaluate() for compatibility with the new version."
                ),
            )
        else:
            log.debug(
                "external_tool_version_ok",
                test_id=self.test_id,
                tool=self.tool_name,
                version=actual,
            )

    def _check_and_skip(self, connector: BaseConnector) -> TestResult | None:
        """
        Return a SKIP TestResult if the connector binary is not available.

        Returns None if the tool IS available (execution should proceed normally).
        Returns a SKIP TestResult if the tool is not found via either discovery
        channel (shutil.which or SERVICE_ENV_VAR or importlib.find_spec).

        DA-2 fast-path B: if _injected_connector is not None, the registry has
        already confirmed availability.  We skip the is_available() call entirely
        and return None immediately, eliminating one syscall per test.

        This method must NEVER raise.  A tool that is not installed is an
        expected operational condition -- the correct status is SKIP, not ERROR.

        Args:
            connector: The connector whose availability to check.

        Returns:
            TestResult | None: SKIP result if unavailable, None to proceed.
        """
        # DA-2 fast-path B: injected connector implies confirmed availability.
        if self._injected_connector is not None:
            return None

        # Fallback path: no injection -- check availability now.
        try:
            available = connector.is_available()
        except Exception as exc:  # noqa: BLE001 -- is_available() must not raise
            log.warning(
                "connector_availability_check_failed",
                test_id=self.test_id,
                tool=connector.TOOL_NAME,
                error=str(exc),
            )
            available = False

        if not available:
            reason = (
                f"External tool '{connector.TOOL_NAME}' is not available. "
                "Install it in PATH or configure its discovery env variable. "
                f"Test '{self.test_id}' ({self.test_name}) requires this tool."
            )
            log.info(
                "external_test_skipped_tool_not_found",
                test_id=self.test_id,
                tool=connector.TOOL_NAME,
            )
            return self._make_skip(reason)

        return None

    # ------------------------------------------------------------------
    # DA-2 -- Connector accessor
    # ------------------------------------------------------------------

    def _get_connector(self) -> BaseConnector:
        """Return the active connector for this test execution.

        If the ExternalTestRegistry has injected a shared connector instance
        (DA-2 lifecycle optimisation), return it.  Otherwise, call
        _build_connector() to create a fresh instance.

        Concrete subclasses must NOT override this method.  They implement
        _build_connector() (the factory) and _invoke_connector() (the call).

        Returns:
            BaseConnector: The connector to use for this test execution.
        """
        if self._injected_connector is not None:
            return self._injected_connector
        return self._build_connector()

    # ------------------------------------------------------------------
    # Abstract methods -- implemented by concrete subclasses
    # ------------------------------------------------------------------

    @abstractmethod
    def _build_connector(self) -> BaseConnector:
        """
        Instantiate and return the concrete BaseConnector for this test.

        Called once per execute() invocation when no injected connector exists.
        Subclasses must not perform I/O or discovery here -- only object construction.

        Example:
            def _build_connector(self) -> BaseConnector:
                return TestsslConnector()

        Returns:
            BaseConnector: A concrete connector instance ready to run.
        """
        ...

    @abstractmethod
    def _invoke_connector(
        self,
        connector: BaseConnector,
        target: TargetContext,
        target_url: str,
    ) -> ConnectorResult:
        """
        Call connector.run() with the correct tool-specific parameters.

        This method is the bridge between the generic ExternalToolTest lifecycle
        and the specific CLI interface of each tool.  It reads tool-specific
        parameters from target.tests_config (populated from config.yaml) and
        passes them to connector.run() as named keyword arguments.

        Example (testssl):
            def _invoke_connector(self, connector, target, target_url):
                return connector.run(
                    target_url=target_url,
                    timeout_seconds=target.tests_config.external_testssl_timeout,
                    extra_flags=target.tests_config.external_testssl_flags,
                )

        Args:
            connector:   The connector returned by _build_connector().
            target:      Frozen TargetContext (for reading tests_config parameters).
            target_url:  String URL for the tool's CLI target argument.

        Returns:
            ConnectorResult: Parsed tool output.

        Raises:
            ExternalToolError: Propagated to _run() which handles it.
        """
        ...

    @abstractmethod
    def _evaluate(
        self,
        result: ConnectorResult,
        artifact_ref: str,
    ) -> TestResult:
        """
        Evaluate ConnectorResult against the test oracle and return TestResult.

        This is where the security logic lives for external tests.  The subclass
        inspects result.raw_output, applies the oracle from the methodology, and
        constructs a TestResult with appropriate Findings.

        The artifact_ref is the record_id returned by store.pin_artifact() in
        _run().  It must be attached to every Finding.evidence_ref so the HTML
        report can cross-reference findings to the raw tool output.

        Rules (same as BaseTest):
            - FAIL must include at least one Finding.
            - PASS has an empty findings list.
            - SKIP is permitted if the oracle detects an inapplicable condition
              discovered only after examining the output (not a missing tool --
              that is handled by _check_and_skip).

        Args:
            result:       ConnectorResult from the connector.
            artifact_ref: Evidence record ID from store.pin_artifact().

        Returns:
            TestResult: PASS, FAIL, or SKIP -- never ERROR (errors are handled
                        by execute()'s top-level handler).
        """
        ...

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # ConnectorResult validation
    # ------------------------------------------------------------------

    def _validate_raw_output(self, result: ConnectorResult) -> None:
        """
        Verify that ConnectorResult.raw_output satisfies the ConnectorRawOutput contract.

        Checks that all four keys required by ConnectorRawOutput (defined in
        connectors/base.py) are present in result.raw_output.  Raises
        ExternalToolError if any are missing so that execute()'s top-level
        handler converts the failure into a TestResult(ERROR) with a
        diagnostic message -- rather than silently producing dashes in the
        HTML report via the Jinja2 ``default_dash`` filter.

        Call site: invoked in _run() after connector.run() returns and BEFORE
        store.pin_artifact() / _evaluate().  This ordering ensures that a
        contract violation is detected before any artifact is written to the
        evidence store, keeping evidence.json free of incomplete records.

        This method never returns a value; it either completes silently or
        raises.  The ExternalToolError propagates to execute()'s BLE001 handler.

        Args:
            result: ConnectorResult whose raw_output to validate.

        Raises:
            ExternalToolError: If one or more required keys are absent.
        """
        missing: frozenset[str] = _REQUIRED_RAW_OUTPUT_KEYS - result.raw_output.keys()
        if missing:
            raise ExternalToolError(
                message=(
                    f"ConnectorResult.raw_output from '{result.tool_name}' is missing "
                    f"required ConnectorRawOutput keys: {sorted(missing)}. "
                    "Check the ConnectorRawOutput contract in src/connectors/base.py "
                    "and ensure the connector's run() method populates all four "
                    "mandatory keys (command, command_json, results, all_count)."
                ),
                tool_name=result.tool_name,
                exit_code=result.exit_code,
            )

    # Result constructors -- mirror BaseTest helpers
    # ------------------------------------------------------------------

    def _metadata_kwargs(self) -> _ExternalTestMetadataKwargs:
        """Build metadata dict for type-safe TestResult construction.

        Mirrors BaseTest._metadata_kwargs() exactly, including the source field
        which is always "external" for ExternalToolTest subclasses.

        The getattr() calls with fallback defaults guard against concrete
        subclasses that omit a ClassVar declaration.  The TestRegistry logs a
        WARNING for missing ClassVar attributes before execute() is ever called.

        Returns:
            _ExternalTestMetadataKwargs: Keyword arguments for TestResult constructor.
        """
        return _ExternalTestMetadataKwargs(
            test_name=str(getattr(self.__class__, "test_name", "")),
            domain=int(getattr(self.__class__, "domain", -1)),
            priority=int(getattr(self.__class__, "priority", 0)),
            strategy=str(getattr(self.__class__, "strategy", TestStrategy.BLACK_BOX).value),
            tags=list(getattr(self.__class__, "tags", [])),
            cwe_id=str(getattr(self.__class__, "cwe_id", "")),
            source="external",
            tool_name=str(getattr(self.__class__, "tool_name", "")),
        )

    def _make_pass(self, message: str, notes: list[InfoNote] | None = None) -> TestResult:
        """
        Construct a PASS TestResult with no findings.

        The optional ``notes`` parameter allows a PASS result to carry
        informational annotations (InfoNote objects) that are semantically
        distinct from Findings.  Notes are rendered as blue cards in the HTML
        report and do NOT affect the test status, exit code, or finding count.

        Primary use case for external tests:
            Tool findings below the FAIL threshold (e.g. testssl.sh MEDIUM/WARN
            severities that do not trigger FAIL per the oracle) can be surfaced
            as notes so they are visible in the report without being
            misclassified as security violations.

        Args:
            message: Human-readable description of why the test passed.
            notes:   Optional list of InfoNote objects for informational context.
                     None (default) produces an empty notes list.

        Returns:
            TestResult: status=PASS, empty findings list, notes as provided.
        """
        return TestResult(
            test_id=self.test_id,
            status=TestStatus.PASS,
            message=message,
            findings=[],
            notes=notes or [],
            **self._metadata_kwargs(),
        )

    def _make_fail(
        self,
        message: str,
        findings: list[Finding],
        notes: list[InfoNote] | None = None,
    ) -> TestResult:
        """
        Construct a FAIL TestResult with at least one Finding.

        The optional ``notes`` parameter allows a FAIL result to carry
        informational annotations alongside the violation findings.  This is
        semantically correct: a test can simultaneously have HIGH-severity
        violations (Findings) and MEDIUM/WARN observations (InfoNotes) from
        the same tool run.  Without this parameter, notes built during
        _evaluate() would be silently discarded when findings are present.

        Args:
            message:  Human-readable summary of the failure.
            findings: Non-empty list of Finding objects documenting the violation.
            notes:    Optional list of InfoNote objects for informational context.
                      None (default) produces an empty notes list.

        Returns:
            TestResult: status=FAIL with findings attached and optional notes.
        """
        return TestResult(
            test_id=self.test_id,
            status=TestStatus.FAIL,
            message=message,
            findings=findings,
            notes=notes or [],
            **self._metadata_kwargs(),
        )

    def _make_skip(self, reason: str) -> TestResult:
        """
        Construct a SKIP TestResult.

        Used by _check_and_skip() when the connector binary is not available,
        by _run() when _skip_reason_from_registry is set (DA-2 fast-path), and
        by _evaluate() for oracle-level inapplicability discovered post-execution.

        The skip_reason field is required by the TestResult model_validator --
        omitting it raises a Pydantic ValidationError.

        Args:
            reason: Human-readable explanation of why the test was skipped.

        Returns:
            TestResult: status=SKIP, empty findings list, skip_reason=reason.
        """
        return TestResult(
            test_id=self.test_id,
            status=TestStatus.SKIP,
            message=reason,
            skip_reason=reason,  # required by model_validator (TestStatus.SKIP invariant)
            findings=[],
            **self._metadata_kwargs(),
        )

    def _make_error(
        self,
        exc: Exception,
        message_override: str | None = None,
    ) -> TestResult:
        """
        Construct an ERROR TestResult from any unexpected exception.

        Called by execute()'s top-level handler and by _run() for ExternalToolError.
        The full traceback is logged at WARNING level for operator debugging.
        The TestResult message is kept concise for the HTML report.

        Args:
            exc:              The exception that caused the ERROR.
            message_override: If provided, used as message instead of str(exc).

        Returns:
            TestResult: status=ERROR, empty findings list.
        """
        log.warning(
            "external_test_error",
            test_id=self.test_id,
            error_type=type(exc).__name__,
            error=str(exc),
            traceback=traceback.format_exc(),
        )
        message = message_override or f"[{type(exc).__name__}] {exc}"
        return TestResult(
            test_id=self.test_id,
            status=TestStatus.ERROR,
            message=message,
            findings=[],
            **self._metadata_kwargs(),
        )
