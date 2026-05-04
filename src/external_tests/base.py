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

import traceback
from abc import ABC, abstractmethod
from typing import ClassVar, Literal, TypedDict

import structlog

from src.connectors.base import BaseConnector, ConnectorResult
from src.core.context import TargetContext, TestContext
from src.core.evidence import EvidenceStore
from src.core.exceptions import ExternalToolError
from src.core.models import TestStrategy
from src.core.models.results import Finding, TestResult, TestStatus

log: structlog.BoundLogger = structlog.get_logger(__name__)

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

    # ------------------------------------------------------------------
    # Internal orchestration
    # ------------------------------------------------------------------

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

        DA-2 fast-paths (evaluated before any connector work):
            Fast-path A: if _skip_reason_from_registry is set, the registry
                         already determined the tool is absent.  Return SKIP
                         immediately -- zero connector overhead.
            Fast-path B: _check_and_skip() skips is_available() when
                         _injected_connector is not None (already confirmed by
                         registry).

        Args:
            target:  Frozen TargetContext.
            context: Mutable TestContext.
            store:   EvidenceStore.

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

        # --- Step 1: availability check (skipped if registry injected connector) ---
        skip_result = self._check_and_skip(connector)
        if skip_result is not None:
            return skip_result

        # --- Step 2: retrieve target URL for external binary ---
        # Connectors use effective_endpoint_base_url(), not endpoint_base_url(),
        # so Docker Compose service names are used when APIGUARD_TARGET_EFFECTIVE_URL
        # is set in the environment (ADR-001 §6).
        target_url = target.effective_endpoint_base_url()

        # --- Step 3: execute binary ---
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

        # --- Step 4: pin raw artifact to evidence store ---
        artifact_ref = store.pin_artifact(
            label=f"{self.test_id}_{connector.TOOL_NAME.replace('.', '_')}",
            data=connector_result.raw_output,
        )

        log.info(
            "external_test_connector_complete",
            test_id=self.test_id,
            tool=connector.TOOL_NAME,
            exit_code=connector_result.exit_code,
            execution_time_ms=connector_result.execution_time_ms,
            timed_out=connector_result.timed_out,
            artifact_ref=artifact_ref,
        )

        # --- Step 5: oracle evaluation (subclass responsibility) ---
        return self._evaluate(connector_result, artifact_ref)

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
        )

    def _make_pass(self, message: str) -> TestResult:
        """
        Construct a PASS TestResult with no findings.

        Args:
            message: Human-readable description of why the test passed.

        Returns:
            TestResult: status=PASS, empty findings list.
        """
        return TestResult(
            test_id=self.test_id,
            status=TestStatus.PASS,
            message=message,
            findings=[],
            **self._metadata_kwargs(),
        )

    def _make_fail(self, message: str, findings: list[Finding]) -> TestResult:
        """
        Construct a FAIL TestResult with at least one Finding.

        Args:
            message:  Human-readable summary of the failure.
            findings: Non-empty list of Finding objects documenting the violation.

        Returns:
            TestResult: status=FAIL with findings attached.
        """
        return TestResult(
            test_id=self.test_id,
            status=TestStatus.FAIL,
            message=message,
            findings=findings,
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
