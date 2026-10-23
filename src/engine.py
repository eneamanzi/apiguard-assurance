"""
src/engine.py

Assessment pipeline orchestrator for the APIGuard Assurance tool.

The engine is the only module with full visibility across all components.
Its responsibility is exclusively orchestrative: it calls the right modules
in the right order, passes the right objects, and records the results.

The engine contains NO domain logic, NO test interpretation, NO decisions
about what to test. Every such decision is delegated to the appropriate
component:
    - What to test:        TestRegistry + DAGScheduler
    - How to test:         BaseTest.execute() implementations
    - What HTTP to send:   SecurityClient
    - What to record:      EvidenceStore (populated by tests)
    - What to report:      report/builder.py + report/renderer.py

Pipeline phases (docs/04-architecture/01-overview.md, "Pipeline"):

    Phase 1 -- Initialization:
        Load and validate config.yaml via config/loader.py.
        Raises ConfigurationError on failure [BLOCKS STARTUP].

    Phase 2 -- OpenAPI Discovery:
        Resolve the spec source via SpecificationConfig.get_source().
        This returns either an HTTP/HTTPS URL or a local filesystem path,
        depending on which field is set in config.yaml. The distinction is
        transparent to the rest of the engine: load_openapi_spec() accepts
        both formats natively.
        Fetch or read, dereference, and validate the OpenAPI spec.
        Build AttackSurface from the dereferenced spec.
        Raises OpenAPILoadError on failure [BLOCKS STARTUP].

    Phase 3 -- Context Construction:
        Build TargetContext (frozen) from ToolConfig + AttackSurface.
        Propagates both openapi_spec_url and openapi_spec_path from
        SpecificationConfig to TargetContext (exactly one will be non-None).
        Build TestContext (mutable, empty).
        Build EvidenceStore (streaming JSONL, unbounded capacity).

    Phase 4 -- Test Discovery and Scheduling:
        TestRegistry discovers and filters active tests.
        DAGScheduler builds the topological execution order.
        Raises DAGCycleError on dependency cycle [BLOCKS STARTUP].

    Phase 5 -- Execution:
        For each ScheduledBatch in topological order:
            For each test in the batch (sequential):
                Call test.execute(target, context, client, store).
                Add TestResult to ResultSet.
                Check fail-fast condition.

    Phase 6 -- Teardown (Best-Effort):
        Drain TestContext resource registry in LIFO order.
        DELETE each registered resource via SecurityClient.
        Log TeardownError as WARNING; continue on failure.

    Phase 7 -- Report Generation:
        Serialize EvidenceStore to config.output.evidence_path via merge_and_finalize().
        Aggregate ResultSet statistics via report/builder.py -> ReportData.
        Render HTML report to config.output.report_path via report/renderer.py.
        Write JSON report via ReportData.model_dump_json().
        Compute and return exit code.

Dependency rule:
    engine.py imports from all src/ layers (config/, core/, discovery/,
    tests/, report/). It is the only module permitted to do so.
    No other module imports from engine.py.
"""

from __future__ import annotations

import ssl
import time
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import structlog
from pydantic import BaseModel, Field

from src import __version__
from src.config.config_used import config_used_yaml
from src.config.loader import closest_match, read_config
from src.config.schema import ToolConfig
from src.config.tests_section import validate_tests_section
from src.core.assessment_test import NEEDED_TO_RUN, REFERS_TO_RESOURCE, AssessmentTest, has_marker
from src.core.auth_placement import CredentialPlacement, resolve_placement
from src.core.client import SecurityClient
from src.core.context import TargetContext, TestContext
from src.core.dag import DAGScheduler, ScheduledBatch, prerequisite_skip_reason
from src.core.evidence import EvidenceStore
from src.core.exceptions import (
    AuthenticationSetupError,
    ConfigurationError,
    DAGCycleError,
    OpenAPILoadError,
    SecurityClientError,
    TeardownError,
    TestDefinitionError,
    raise_for_test_definition_problems,
)
from src.core.gateway import GATEWAY_ADAPTERS
from src.core.models import (
    AttackSurface,
    ExitCode,
    NotRunEntry,
    NotRunReason,
    ResultSet,
    TestResult,
    TestStatus,
)
from src.core.redaction import SecretRegistry
from src.core.references import ReferenceResponses
from src.core.test_metadata import EFFECT_RANK, Need, is_external_test_id, section_keys
from src.core.test_needs import NEED_ROLES, ConfigurationFacts, unmet_needs
from src.core.tls import (
    GATEWAY_ADMIN_TLS,
    GATEWAY_HEALTH_TLS,
    SPECIFICATION_TLS,
    TARGET_TLS,
    build_ssl_context,
    certificate_answer,
    certificate_failure,
    tls_warnings,
)
from src.discovery.derivation import derive_knowledge
from src.discovery.openapi import load_openapi_spec
from src.discovery.surface import build_attack_surface
from src.external_tests.base import ExternalToolTest
from src.external_tests.registry import ExternalTestRegistry
from src.report.builder import ReportData, build_report_data
from src.report.renderer import render_html_report
from src.tests.base import BaseTest
from src.tests.helpers.auth import acquire_tokens
from src.tests.registry import TestRegistry

log: structlog.BoundLogger = structlog.get_logger(__name__)

# Similarity threshold for suggesting a test ID in place of an unknown one.
# Higher than for configuration keys (0.6): test IDs are short and close to
# each other, so 0.6 would suggest "1.6" for "1.7"; 0.8 keeps real typos
# ("ext.1.5.sslyzee" -> "ext.1.5.sslyze", "ext.0.1.nucle" -> "ext.0.1.nuclei").
_TEST_ID_SUGGESTION_CUTOFF: float = 0.8


class ConnectionContexts(BaseModel):
    """The TLS context of each connection, built once at startup (src/core/tls.py)."""

    model_config = {"frozen": True, "arbitrary_types_allowed": True}

    target: ssl.SSLContext = Field(description="Requests to the API.")
    specification: ssl.SSLContext = Field(description="The specification download.")
    admin: ssl.SSLContext | None = Field(
        description="The gateway's Admin API; None without gateway."
    )
    health: ssl.SSLContext | None = Field(description="The gateway's health API; None without it.")


def build_connection_contexts(config: ToolConfig) -> ConnectionContexts:
    """
    Build the TLS context of every connection and log the warnings about them.

    Called at startup by the run and by validate-config, so that a broken tls
    block stops the tool before any test.

    Args:
        config: The validated configuration.

    Returns:
        The contexts.

    Raises:
        ConfigurationError: A tls block whose files cannot be used (not PEM,
            certificate and key not matching, encrypted key).
    """
    gateway = config.gateway
    health = gateway.health if gateway is not None else None
    blocks = [
        (TARGET_TLS, config.target.tls, str(config.target.base_url)),
        (
            SPECIFICATION_TLS,
            config.specification.tls,
            str(config.specification.url) if config.specification.url is not None else None,
        ),
    ]
    if gateway is not None:
        blocks.append((GATEWAY_ADMIN_TLS, gateway.admin.tls, str(gateway.admin.url)))
    if health is not None:
        blocks.append((GATEWAY_HEALTH_TLS, health.tls, str(health.url)))
    for where, settings, url in blocks:
        for warning in tls_warnings(settings, url, where):
            log.warning("tls_configuration_warning", detail=warning)
    return ConnectionContexts(
        target=build_ssl_context(config.target.tls, TARGET_TLS),
        specification=build_ssl_context(config.specification.tls, SPECIFICATION_TLS),
        admin=(
            build_ssl_context(gateway.admin.tls, GATEWAY_ADMIN_TLS) if gateway is not None else None
        ),
        health=(build_ssl_context(health.tls, GATEWAY_HEALTH_TLS) if health is not None else None),
    )


# Test ID the preflight request is recorded under in the evidence.
_PREFLIGHT_TEST_ID: str = "preflight"
_PREFLIGHT_PATH: str = "/"


def _preflight(client: SecurityClient, store: EvidenceStore) -> None:
    """
    Send one request to the API before any test and record it in the evidence.

    A TLS failure (certificate not trusted, wrong name, expired, client
    certificate refused) stops the run with a clear message, once, and so does
    a TLS problem the server reports with an HTTP answer (nginx's pages: client
    certificate missing or not accepted, plain HTTP to an HTTPS port,
    src/core/tls.py); any other HTTP answer, of any status, lets it go on.
    Other transport failures are left to the tests, as before.

    Args:
        client: The SecurityClient of the run (target.tls).
        store:  The evidence store.

    Raises:
        ConfigurationError: On a TLS failure.
    """
    store.begin_test(_PREFLIGHT_TEST_ID)
    try:
        response, record = client.request(
            method="GET", path=_PREFLIGHT_PATH, test_id=_PREFLIGHT_TEST_ID
        )
        store.pin_evidence(record)
        log.info("pipeline_preflight_completed", status_code=record.response_status_code)
    except SecurityClientError as exc:
        reason = certificate_failure(exc, TARGET_TLS)
        if reason is not None:
            raise ConfigurationError(
                f"Connection to the API failed before any test: {reason}",
                config_path=TARGET_TLS,
            ) from exc
        log.warning("pipeline_preflight_transport_failure", detail=str(exc))
        return
    finally:
        store.end_test()
    answer_reason = certificate_answer(response.status_code, response.text, TARGET_TLS)
    if answer_reason is not None:
        raise ConfigurationError(
            f"Connection to the API failed before any test: {answer_reason}",
            config_path=TARGET_TLS,
        )


def _write_config_used(
    config: ToolConfig, written: dict[str, object], test_params: dict[str, BaseModel]
) -> None:
    """
    Write config_used.yaml, the configuration the run used, among the outputs.

    Written before the run contacts the target, so it exists even when the run
    stops later (src/config/config_used.py). A failure to write it is logged
    and does not stop the run, like a report that cannot be written.

    Args:
        config:      The validated configuration.
        written:     The file as written.
        test_params: Test ID -> its validated parameters.
    """
    path = config.output.config_used_path
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            config_used_yaml(config, written, test_params, __version__), encoding="utf-8"
        )
    except OSError as exc:
        log.error("config_used_write_failed", output_path=str(path), detail=str(exc))
        return
    log.info("config_used_written", output_path=str(path))


def check_tests(config: ToolConfig) -> dict[str, BaseModel]:
    """
    Check the test declarations, execution.test_ids and the tests section.

    Called by the engine right after Phase 1, before any contact with the
    target, and by ``apiguard validate-config``. Three checks, in order:

    1. Test declarations (src/core/test_discovery.py): both registries are
       scanned, native and external (even with external tools disabled), and
       the problems of both are listed together, including a prerequisite
       (depends_on, requires_pass) that names no existing test.
    2. execution.test_ids content (its format is checked by the
       configuration schema): an entry is rejected when no test has that ID
       (with the closest ID as a suggestion), or when it is an external test
       whose tool is disabled (master switch or per-tool switch): test_ids
       chooses among available tests and never enables a tool.
    3. The tests section, against the parameter model each test declares
       (src/config/tests_section.py): an unknown test or parameter, or a
       value out of range, is rejected like any configuration key.

    Args:
        config: The validated configuration.

    Returns:
        Test ID -> validated parameters, for every test that declares a model
        (TargetContext.test_params).

    Raises:
        TestDefinitionError: Listing every declaration problem.
        ConfigurationError: Listing every rejected test_ids entry, or every
            problem of the tests section.
    """
    definition_problems: list[str] = []
    native_tests: list[BaseTest] = []
    external_tests: list[ExternalToolTest] = []
    try:
        native_tests = TestRegistry().list_tests()
    except TestDefinitionError as exc:
        definition_problems.extend(exc.problems)
    try:
        external_tests = ExternalTestRegistry().list_tests()
    except TestDefinitionError as exc:
        definition_problems.extend(exc.problems)
    native_ids = {t.info.id for t in native_tests}
    external_tools = {t.info.id: t.tool_name for t in external_tests}
    all_ids = native_ids | set(external_tools)
    for test in [*native_tests, *external_tests]:
        cls = test.__class__
        for field, prerequisites in (
            ("depends_on", test.info.depends_on),
            ("requires_pass", test.info.requires_pass),
        ):
            for prerequisite in prerequisites:
                if prerequisite not in all_ids:
                    definition_problems.append(
                        f"{cls.__name__} ({cls.__module__}): info.{field} names "
                        f"{prerequisite!r}, which is not a test"
                    )
    raise_for_test_definition_problems(definition_problems)

    _check_test_ids(config, native_ids, external_tools)
    models = {t.info.id: type(t).params_model for t in [*native_tests, *external_tests]}
    return validate_tests_section(config.tests, models, config.resources)


def select_tests(
    config: ToolConfig,
) -> tuple[list[BaseTest | ExternalToolTest], list[NotRunEntry]]:
    """
    The tests the run executes, and those the filters exclude.

    Applies execution.test_ids, or else min_priority and strategies, and the
    external tools' switches, as Phase 4 does (also for validate-config).

    Args:
        config: The validated configuration.

    Returns:
        (selected tests, native then external; tests excluded by the filters,
        by test ID).
    """
    # --- Split execution.test_ids by registry ---
    # None: no test_ids, normal filters. A set (possibly empty): run only
    # these IDs; an empty part means no test of that kind.
    native_allowed_ids: set[str] | None = None
    external_allowed_ids: set[str] | None = None
    if config.execution.test_ids:
        requested_ids = set(config.execution.test_ids)
        external_allowed_ids = {tid for tid in requested_ids if is_external_test_id(tid)}
        native_allowed_ids = requested_ids - external_allowed_ids

    # --- Native test discovery ---
    registry = TestRegistry()
    native_tests: list[BaseTest] = registry.discover(
        min_priority=config.execution.min_priority,
        enabled_strategies=set(config.execution.strategies),
        allowed_ids=native_allowed_ids,
    )

    # --- External test discovery ---
    ext_registry = ExternalTestRegistry()
    external_tests: list[ExternalToolTest] = ext_registry.discover(
        external_tools_config=config.external_tools,
        min_priority=config.execution.min_priority,
        enabled_strategies=set(config.execution.strategies),
        allowed_ids=external_allowed_ids,
    )

    # --- Merge both lists ---
    selected: list[BaseTest | ExternalToolTest] = [*native_tests, *external_tests]
    not_run = sorted([*registry.not_run, *ext_registry.not_run], key=lambda e: e.test_id)
    return selected, not_run


def configuration_facts(config: ToolConfig) -> ConfigurationFacts:
    """
    What the tests' needs are checked against, from the configuration.

    Args:
        config: The validated configuration.

    Returns:
        The facts (credentials, gateway, resources).
    """
    return ConfigurationFacts(
        credentials=config.credentials,
        gateway_configured=config.gateway is not None,
        resources=config.resources,
    )


def target_facts(target: TargetContext) -> ConfigurationFacts:
    """
    The same facts as configuration_facts, from the run's TargetContext.

    Args:
        target: The run's TargetContext.

    Returns:
        The facts (credentials, gateway, resources).
    """
    return ConfigurationFacts(
        credentials=target.credentials,
        gateway_configured=target.gateway is not None,
        resources=target.resources,
    )


def unmet_needs_by_test(
    tests: Sequence[AssessmentTest[Any]],
    test_params: Mapping[str, BaseModel],
    facts: ConfigurationFacts,
) -> dict[str, list[str]]:
    """
    The tests that cannot run with the configuration, with the reasons.

    Args:
        tests:       The tests to check.
        test_params: Every test's validated parameters (check_tests).
        facts:       The configuration facts.

    Returns:
        Test ID -> reasons (src/core/test_needs.py), only for the tests that
        have an unmet need, in ID order.
    """
    unmet: dict[str, list[str]] = {}
    for test in sorted(tests, key=lambda t: t.info.id):
        reasons = unmet_needs(test.info, test_params.get(test.info.id), facts)
        if reasons:
            unmet[test.info.id] = reasons
    return unmet


def describe_tests(config: ToolConfig | None = None) -> list[dict[str, Any]]:
    """
    Every test with its declaration, for ``apiguard list-tests``.

    Without a configuration: what each test is (its TestInfo), what it needs,
    and the JSON Schema of its parameters. With one (already loaded and
    valid): also whether the run selects it and, if it cannot run, why.

    Args:
        config: A validated configuration, or None.

    Returns:
        One JSON-ready mapping per test, native then external, in ID order.

    Raises:
        TestDefinitionError: When a test cannot be used.
        ConfigurationError: When the configuration's test selection or tests
            section is invalid (as check_tests).
    """
    tests = sorted(
        [*TestRegistry().list_tests(), *ExternalTestRegistry().list_tests()],
        key=lambda t: (t.info.is_external, t.info.id),
    )
    selected_ids: set[str] = set()
    unmet: dict[str, list[str]] = {}
    if config is not None:
        test_params = check_tests(config)
        selected, _ = select_tests(config)
        selected_ids = {t.info.id for t in selected}
        unmet = unmet_needs_by_test(tests, test_params, configuration_facts(config))
    described: list[dict[str, Any]] = []
    for test in tests:
        info = test.info
        model = type(test).params_model
        domain_key, test_key = section_keys(info.id)
        entry: dict[str, Any] = {
            **info.model_dump(mode="json"),
            "domain": info.domain,
            "source": test.source,
            "parameters_key": f"tests.{domain_key}.{test_key}" if model is not None else None,
            "needed_parameters": [
                name
                for name, field in (model.model_fields.items() if model is not None else ())
                if has_marker(field, NEEDED_TO_RUN)
            ],
            "parameters_schema": model.model_json_schema() if model is not None else None,
        }
        if config is not None:
            entry["selected"] = info.id in selected_ids
            entry["unmet_needs"] = unmet.get(info.id, [])
        described.append(entry)
    return described


def test_parameter_models() -> dict[str, type[BaseModel] | None]:
    """
    The parameter model of every test, native and external, by test ID.

    For tools that need the complete configuration schema (the tests section
    is known only from the tests: scripts/check_config_keys.py).

    Returns:
        Test ID -> its parameter model (None: the test has none).

    Raises:
        TestDefinitionError: When a test cannot be used (as check_tests).
    """
    tests = [*TestRegistry().list_tests(), *ExternalTestRegistry().list_tests()]
    return {t.info.id: type(t).params_model for t in tests}


def _check_test_ids(
    config: ToolConfig, native_ids: set[str], external_tools: dict[str, str]
) -> None:
    """
    Reject an execution.test_ids entry that names no test or a disabled tool.

    Args:
        config:         The validated configuration.
        native_ids:     IDs of the native tests.
        external_tools: ID -> tool of the external tests.

    Raises:
        ConfigurationError: Listing every rejected entry.
    """
    requested = config.execution.test_ids
    if not requested:
        return
    known_ids = sorted(native_ids | set(external_tools))

    problems: list[str] = []
    for test_id in requested:
        if test_id in native_ids:
            continue
        tool_name = external_tools.get(test_id)
        if tool_name is None:
            suggestion = closest_match(test_id, known_ids, _TEST_ID_SUGGESTION_CUTOFF)
            hint = f" (did you mean '{suggestion}'?)" if suggestion is not None else ""
            problems.append(f"unknown test '{test_id}'{hint}")
        elif not config.external_tools.is_tool_enabled(tool_name):
            switch = (
                f"external_tools.{tool_name}.enabled is false"
                if config.external_tools.enabled
                else "external_tools.enabled is false"
            )
            problems.append(f"'{test_id}' cannot run: {switch}")

    if problems:
        raise ConfigurationError(
            message=(
                f"Test selection invalid with {len(problems)} error(s):\n"
                + "\n".join(f"  - execution.test_ids: {problem}" for problem in problems)
            ),
            config_path="execution.test_ids",
        )


def check_credentials(config: ToolConfig) -> CredentialPlacement | None:
    """
    Check that the credentials determine where and how they are sent.

    The same resolution the run makes after Phase 2 (resolve_placement), for
    validate-config: it reads the specification (download or local file, as
    the run does) only when credentials are configured, since only then the
    declared security schemes matter.

    Args:
        config: The validated configuration.

    Returns:
        The placement, or None when no credentials are configured (nothing
        read).

    Raises:
        ConfigurationError: When the configuration and the specification do not
            determine one placement.
        OpenAPILoadError: When the specification cannot be read.
    """
    if config.credentials.auth_type is None:
        return None
    spec_source = config.specification.get_source()
    spec, dialect = load_openapi_spec(
        spec_source,
        timeout_seconds=config.specification.timeout,
        tls_context=build_ssl_context(config.specification.tls, SPECIFICATION_TLS),
    )
    surface = build_attack_surface(spec, dialect, source_url=spec_source)
    return resolve_placement(config.credentials, surface.security_schemes)


def specification_connection(config: ToolConfig) -> tuple[str, float, ssl.SSLContext]:
    """
    Return the specification source of a configuration and how to download it.

    For the generate-seed command run with a configuration file.

    Args:
        config: The validated configuration.

    Returns:
        The source (URL or absolute path), the timeout and the TLS context.

    Raises:
        ConfigurationError: A specification.tls block whose files cannot be used.
    """
    return (
        config.specification.get_source(),
        config.specification.timeout,
        build_ssl_context(config.specification.tls, SPECIFICATION_TLS),
    )


def _resource_references(params: BaseModel) -> list[str]:
    """
    The resource names a test's parameters refer to (fields marked REFERS_TO_RESOURCE).

    Nested parameter models are searched too (7.2's url_accepting_endpoint.resource).

    Args:
        params: A test's validated parameters, or one of their nested models.

    Returns:
        The names set, in field order.
    """
    names: list[str] = []
    for name, field in type(params).model_fields.items():
        value = getattr(params, name)
        if isinstance(value, BaseModel):
            names += _resource_references(value)
        elif has_marker(field, REFERS_TO_RESOURCE) and isinstance(value, str):
            names.append(value)
        elif has_marker(field, REFERS_TO_RESOURCE) and isinstance(value, list | tuple):
            names += [item for item in value if isinstance(item, str)]
    return names


def describe_resources(config: ToolConfig, test_params: dict[str, BaseModel]) -> str:
    """
    Describe the prepared resources and who uses them, for validate-config.

    A test uses a resource when one of its parameters marked REFERS_TO_RESOURCE
    (src/core/assessment_test.py), at any depth, names it.

    Args:
        config:      The validated configuration.
        test_params: Every test's validated parameters (check_tests).

    Returns:
        E.g. "repository (tests.domain_7.test_7_2), forgejo-token (credentials,
        login)"; a resource nobody uses is marked "(not used)".
    """
    users: dict[str, list[str]] = {name: [] for name in config.resources}
    if config.credentials.login_resource in users:
        users[config.credentials.login_resource].append("credentials, login")
    for test_id, params in sorted(test_params.items()):
        domain_key, test_key = section_keys(test_id)
        for value in _resource_references(params):
            if value in users:
                users[value].append(f"tests.{domain_key}.{test_key}")
    return ", ".join(
        f"{name} ({'; '.join(used) if used else 'not used'})" for name, used in users.items()
    )


# ---------------------------------------------------------------------------
# Run observer (progress for an interface such as the console)
# ---------------------------------------------------------------------------


class RunPlan(BaseModel):
    """What a run is about to do: emitted once, after Phase 4."""

    model_config = {"frozen": True}

    target_url: str = Field(description="Base URL of the assessed API.")
    spec_title: str = Field(description="Title of the OpenAPI specification.")
    spec_version: str = Field(description="Version of the OpenAPI specification.")
    endpoint_count: int = Field(description="Endpoints in the attack surface.")
    selected_ids: list[str] = Field(description="IDs of the tests scheduled for execution.")
    not_run: list[NotRunEntry] = Field(description="Tests not run, with the reason.")
    min_priority: int = Field(description="execution.min_priority.")
    strategies: list[str] = Field(description="execution.strategies.")
    test_ids: list[str] = Field(description="execution.test_ids (empty: not set).")


class RunObserver(Protocol):
    """
    Receives the progress of a run, for an interface (the console of the CLI).

    The engine calls it at fixed points; it never changes what the run does.
    """

    def run_planned(self, plan: RunPlan) -> None:
        """Phase 4 done: what will run and what will not."""

    def test_started(
        self, position: int, total: int, test_id: str, test_name: str, timeout_seconds: int | None
    ) -> None:
        """A test is about to execute (timeout_seconds: external tool limit, if any)."""

    def test_finished(self, position: int, total: int, result: TestResult) -> None:
        """A test has returned its result."""

    def cleanup_started(self) -> None:
        """Phase 6 starts (after the last test, or on an interruption)."""

    def cleanup_finished(self, removed: int, failed: int) -> None:
        """Phase 6 done: resources removed from the target, and failures."""

    def run_finished(self, result_set: ResultSet, exit_code: int, report_paths: list[Path]) -> None:
        """Phase 7 done: final results, exit code and the reports written."""

    def run_stopped(self, reason: str) -> None:
        """The run stopped before any verdict (exit 10): the reason, in full."""


# ---------------------------------------------------------------------------
# AssessmentEngine
# ---------------------------------------------------------------------------


class AssessmentEngine:
    """
    Orchestrator for the APIGuard Assurance assessment pipeline.

    One AssessmentEngine instance is created per pipeline run by cli.py.
    The run() method executes all seven phases sequentially and returns
    the process exit code.

    The engine is intentionally not reusable across multiple runs: each
    run creates fresh instances of all shared state objects (TargetContext,
    TestContext, EvidenceStore, ResultSet). Reusing an engine instance would
    risk contaminating results from a previous run.
    """

    def __init__(self, config_path: Path, observer: RunObserver | None = None) -> None:
        """
        Initialize the engine with the path to the configuration file.

        Does not load the configuration or perform any I/O at construction
        time. All I/O begins in run() Phase 1.

        Args:
            config_path: Path to the config.yaml file.
            observer:    Receives the progress of the run (the console of the
                         CLI), or None.
        """
        self._config_path: Path = config_path
        self._run_id: str = _generate_run_id()
        self._observer: RunObserver | None = observer

        log.info(
            "assessment_engine_initialized",
            run_id=self._run_id,
            config_path=str(config_path),
        )

    def run(self) -> int:
        """
        Execute the complete assessment pipeline and return the exit code.

        Returns:
            int: Process exit code (an ExitCode member): 0, 1, 3 or 10.
        """
        log.info("assessment_pipeline_started", run_id=self._run_id)
        wall_start = time.monotonic()

        try:
            exit_code = self._run_pipeline()
        except (ConfigurationError, OpenAPILoadError, DAGCycleError, TestDefinitionError) as exc:
            log.error(
                "assessment_pipeline_infrastructure_failure",
                run_id=self._run_id,
                exc_type=type(exc).__name__,
                detail=str(exc),
            )
            exit_code = ExitCode.INFRASTRUCTURE
            if self._observer is not None:
                self._observer.run_stopped(str(exc))
        except Exception as exc:  # noqa: BLE001
            log.error(
                "assessment_pipeline_unexpected_engine_error",
                run_id=self._run_id,
                exc_type=type(exc).__name__,
                detail=str(exc),
            )
            exit_code = ExitCode.INFRASTRUCTURE
            if self._observer is not None:
                self._observer.run_stopped(
                    f"unexpected error in the engine ({type(exc).__name__}): {exc}"
                )

        elapsed = time.monotonic() - wall_start
        log.info(
            "assessment_pipeline_completed",
            run_id=self._run_id,
            exit_code=int(exit_code),
            elapsed_seconds=round(elapsed, 2),
        )

        return exit_code

    # ------------------------------------------------------------------
    # Internal pipeline runner
    # ------------------------------------------------------------------

    def _run_pipeline(self) -> int:
        """
        Execute all seven pipeline phases and return the exit code.

        Phases 1-4 are blocking: exceptions propagate to run() which converts
        them to ExitCode.INFRASTRUCTURE. Phases 5-7 are non-blocking.
        """
        config, connections, config_as_written = self._phase_1_initialize()
        test_params = check_tests(config)
        _write_config_used(config, config_as_written, test_params)
        attack_surface = self._phase_2_openapi_discovery(config, connections)
        target, context, store = self._phase_3_build_contexts(
            config=config,
            attack_surface=attack_surface,
            connections=connections,
            test_params=test_params,
        )
        scheduled_batches, active_tests, not_run = self._phase_4_discover_and_schedule(
            config, test_params
        )
        if self._observer is not None:
            self._observer.run_planned(
                RunPlan(
                    target_url=str(config.target.base_url),
                    spec_title=attack_surface.spec_title,
                    spec_version=attack_surface.spec_version,
                    endpoint_count=attack_surface.total_endpoint_count,
                    selected_ids=sorted(t.info.id for t in active_tests),
                    not_run=not_run,
                    min_priority=config.execution.min_priority,
                    strategies=[s.value for s in config.execution.strategies],
                    test_ids=list(config.execution.test_ids),
                )
            )

        result_set = ResultSet(not_run=not_run)

        with SecurityClient(
            base_url=target.endpoint_base_url(),
            connect_timeout=config.target.connect_timeout,
            read_timeout=config.target.read_timeout,
            max_retry_attempts=config.target.max_retry_attempts,
            tls_context=target.tls_context,
            secrets=context.secrets,
        ) as client:
            # One request before any test: a TLS problem (certificate not
            # trusted, client certificate missing) stops the run once (exit 10)
            # instead of failing every test.
            _preflight(client, store)

            # The run's reference responses (calibration, positive control):
            # one object, through the run's client and store, reached by the
            # tests through context.references (src/core/references.py).
            context.attach_references(ReferenceResponses(client, store))

            # Phase 6 (teardown) MUST run even if Phase 5 is interrupted by
            # KeyboardInterrupt (Ctrl+C) or terminated by an unexpected
            # exception.  Tests in Phase 5 register real resources on the
            # target (Forgejo tokens, repos, gateway routes) via
            # context.register_resource_for_teardown(); skipping Phase 6
            # would leave those resources dangling on the target and could
            # conflict with subsequent runs.
            #
            # The try/finally guarantees teardown is always attempted; the
            # teardown loop itself swallows individual TeardownError instances
            # (logged as WARNING with manual_cleanup_required=True), so a
            # single resource failure cannot abort the cleanup of the rest.
            try:
                self._phase_5_execute(
                    scheduled_batches=scheduled_batches,
                    active_tests=active_tests,
                    target=target,
                    context=context,
                    client=client,
                    store=store,
                    result_set=result_set,
                    config=config,
                )
            finally:
                if self._observer is not None:
                    self._observer.cleanup_started()
                removed, failed = self._phase_6_teardown(
                    context=context,
                    client=client,
                    target=target,
                )
                if self._observer is not None:
                    self._observer.cleanup_finished(removed=removed, failed=failed)

        result_set.completed_at = datetime.now(UTC)
        not_run_by_reason: dict[str, int] = {}
        for entry in result_set.not_run:
            not_run_by_reason[entry.reason.value] = not_run_by_reason.get(entry.reason.value, 0) + 1
        log.info(
            "pipeline_tests_not_run",
            not_run_count=len(result_set.not_run),
            by_reason=not_run_by_reason,
        )

        self._phase_7_report(
            result_set=result_set,
            store=store,
            config=config,
            attack_surface=attack_surface,
            secrets=context.secrets,
            references=context.references,
        )

        exit_code = result_set.compute_exit_code()
        if self._observer is not None:
            written = [
                path
                for path in (
                    config.output.report_path,
                    config.output.json_report_path,
                    config.output.evidence_path,
                    config.output.config_used_path,
                )
                if path.is_file()
            ]
            self._observer.run_finished(result_set, int(exit_code), written)
        return exit_code

    # ------------------------------------------------------------------
    # Phase 1 -- Initialization
    # ------------------------------------------------------------------

    def _phase_1_initialize(self) -> tuple[ToolConfig, ConnectionContexts, dict[str, object]]:
        """
        Load and validate config.yaml, and build the TLS context of every connection.

        Returns:
            Frozen ToolConfig instance, the connections' TLS contexts, and the
            file as written (for config_used.yaml).

        Raises:
            ConfigurationError: If config.yaml is missing, unreadable,
                                 contains unresolved env vars, or fails
                                 Pydantic validation.
        """
        log.info("pipeline_phase_1_initialization_started")

        loaded = read_config(self._config_path)
        config = loaded.config
        # Every tls block is usable, or the run stops here (exit 10).
        connections = build_connection_contexts(config)

        log.info(
            "pipeline_phase_1_initialization_completed",
            base_url=str(config.target.base_url),
            openapi_source=config.specification.get_source(),
            openapi_source_type="local_path" if config.specification.is_local else "url",
            min_priority=config.execution.min_priority,
            strategies=[s.value for s in config.execution.strategies],
            fail_fast=config.execution.fail_fast,
            output_directory=str(config.output.directory),
            specification_timeout=config.specification.timeout,
        )

        return config, connections, loaded.written

    # ------------------------------------------------------------------
    # Phase 2 -- OpenAPI Discovery
    # ------------------------------------------------------------------

    def _phase_2_openapi_discovery(
        self, config: ToolConfig, connections: ConnectionContexts
    ) -> AttackSurface:
        """
        Fetch or read the OpenAPI spec and build the AttackSurface.

        The spec source is resolved via SpecificationConfig.get_source(),
        which returns either an HTTP/HTTPS URL or an absolute filesystem path
        depending on which config field is set. load_openapi_spec() accepts
        both formats; the distinction is handled transparently inside that
        function, including a pre-flight existence check for local paths.

        For local files the network timeout still applies but is never the
        limiting factor: file I/O completes well within any reasonable budget.

        Returns:
            Populated AttackSurface instance.

        Raises:
            OpenAPILoadError: If the spec cannot be fetched/read, dereferenced,
                              validated, or if a network fetch times out.
        """
        log.info("pipeline_phase_2_openapi_discovery_started")

        spec_source: str = config.specification.get_source()

        log.info(
            "pipeline_phase_2_openapi_source_resolved",
            spec_source=spec_source,
            source_type="local_path" if config.specification.is_local else "url",
        )

        spec, dialect = load_openapi_spec(
            spec_source,
            timeout_seconds=config.specification.timeout,
            tls_context=connections.specification,
        )
        attack_surface = build_attack_surface(spec, dialect, source_url=spec_source)
        # What the tool derives from the specification before any test runs
        # (src/discovery/derivation.py): no request, the specification only.
        attack_surface = derive_knowledge(spec, attack_surface)

        log.info(
            "pipeline_phase_2_openapi_discovery_completed",
            spec_title=attack_surface.spec_title,
            spec_version=attack_surface.spec_version,
            dialect=attack_surface.dialect,
            total_endpoints=attack_surface.total_endpoint_count,
            unique_paths=attack_surface.unique_path_count,
            derived_facts=len(attack_surface.derived),
        )

        return attack_surface

    # ------------------------------------------------------------------
    # Phase 3 -- Context Construction
    # ------------------------------------------------------------------

    def _phase_3_build_contexts(
        self,
        config: ToolConfig,
        attack_surface: AttackSurface,
        connections: ConnectionContexts,
        test_params: dict[str, BaseModel],
    ) -> tuple[TargetContext, TestContext, EvidenceStore]:
        """
        Construct the three shared state objects for the pipeline run.

        TargetContext is frozen and populated from config + attack_surface.
        Both openapi_spec_url and openapi_spec_path are propagated from
        SpecificationConfig; exactly one will be non-None, preserving the source
        type information for test_0_1's shadow-API exclusion set builder
        and for the HTML report header.

        TestContext is mutable and starts empty.

        EvidenceStore is initialized with:
            tmp_dir:   streaming JSONL directory for per-test evidence files.
            tools_dir: optional directory where pin_artifact() writes a
                       standalone JSON copy of each external tool's raw output.
                       Set to config.output.directory / "tools" so that tool
                       outputs are directly inspectable without parsing
                       evidence.json.

        Args:
            config:         The validated configuration.
            attack_surface: The AttackSurface built in Phase 2.
            connections:    The TLS contexts built in Phase 1.
            test_params:    Every test's validated parameters (check_tests).

        Returns:
            Tuple of (TargetContext, TestContext, EvidenceStore).
        """
        log.info("pipeline_phase_3_context_construction_started")

        # Instantiate the gateway adapter when configured.
        # Injected into TargetContext so that WHITE_BOX tests access the admin plane
        # via the neutral concept readers (target.gateway.backend_timeouts() etc.).
        # The adapter is chosen by gateway.adapter in GATEWAY_ADAPTERS
        # (src/core/gateway/__init__.py). It receives the Admin API headers, the
        # address of a separate health interface (gateway.health.url, for a
        # gateway that keeps live backend health outside the Admin API) and the
        # TLS contexts; which plugins hold a concept is the adapter's own
        # knowledge (no test parameter reaches it).
        gateway = None
        gateway_config = config.gateway
        if gateway_config is not None:
            admin = gateway_config.admin
            gateway = GATEWAY_ADAPTERS[gateway_config.adapter](
                admin_base_url=str(admin.url).rstrip("/"),
                connect_timeout=admin.connect_timeout,
                read_timeout=admin.read_timeout,
                admin_headers=admin.headers,
                health_api_url=(
                    str(gateway_config.health.url) if gateway_config.health is not None else None
                ),
                admin_tls_context=connections.admin,
                health_tls_context=connections.health,
            )
            log.info(
                "pipeline_phase_3_gateway_adapter_instantiated",
                adapter=gateway.adapter_name,
                admin_base_url=str(admin.url).rstrip("/"),
            )

        # Where and how credentials are sent: the configuration completed by the
        # security schemes of the specification. A configuration that does not
        # determine it raises ConfigurationError here, before any test (exit 10).
        credential_placement = resolve_placement(
            config.credentials, attack_surface.security_schemes
        )
        if credential_placement is not None:
            log.info(
                "pipeline_phase_3_credential_placement_resolved",
                auth_type=str(config.credentials.auth_type),
                location=credential_placement.location.value,
                name=credential_placement.name,
                source=credential_placement.source,
            )

        target = TargetContext(
            base_url=config.target.base_url,
            openapi_spec_url=config.specification.url,
            openapi_spec_path=(
                config.specification.path.resolve()
                if config.specification.path is not None
                else None
            ),
            admin_api_url=gateway_config.admin.url if gateway_config is not None else None,
            attack_surface=attack_surface,
            credentials=config.credentials,
            resources=dict(config.resources),
            credential_placement=credential_placement,
            test_params=test_params,
            path_seed=dict(config.target.path_seed),
            tls_ca_bundle=config.target.tls.ca_bundle if config.target.tls is not None else None,
            tls_context=connections.target,
            external_tools=config.external_tools,
            gateway=gateway,
        )

        context = TestContext()
        # The Admin API header values are credentials: masked in every output.
        admin_headers = gateway_config.admin.headers if gateway_config is not None else {}
        for header_name, header_value in admin_headers.items():
            context.register_secret(header_value, f"admin API header {header_name}")

        # FIX: tools_dir receives config.output.directory / "tools" so that
        # pin_artifact() writes a standalone JSON copy of each external tool's
        # raw output to outputs/tools/<label>.json alongside the main report.
        store = EvidenceStore(
            tmp_dir=config.output.evidence_tmp_path,
            tools_dir=config.output.directory / "tools",
        )

        log.info(
            "pipeline_phase_3_context_construction_completed",
            admin_api_available=target.admin_api_available,
            openapi_source=target.get_openapi_source(),
            is_local_spec=target.is_local_spec,
            path_seed_param_count=len(target.path_seed),
            path_seed_param_names=sorted(target.path_seed.keys()),
        )

        return target, context, store

    # ------------------------------------------------------------------
    # Phase 4 -- Test Discovery and Scheduling
    # ------------------------------------------------------------------

    def _phase_4_discover_and_schedule(
        self,
        config: ToolConfig,
        test_params: dict[str, BaseModel],
    ) -> tuple[list[ScheduledBatch], list[BaseTest | ExternalToolTest], list[NotRunEntry]]:
        """
        Discover active tests (native + external) and build the topological schedule.

        Also returns the tests excluded by the filters, with the reason
        (NotRunEntry, from both registries), for the report section not_run.

        Merges two independent discovery passes:
            1. TestRegistry         -> list[BaseTest]          (native Python tests)
            2. ExternalTestRegistry -> list[ExternalToolTest]  (binary-wrapper tests)

        The two lists are merged before being passed to DAGScheduler.  Both
        hierarchies declare their ID and prerequisites in info (TestInfo);
        both kinds of prerequisite order the run.  Cross-hierarchy
        prerequisites are supported: an ExternalToolTest may name a BaseTest
        test_id.

        Selection by execution.test_ids:
            Not set: each registry receives allowed_ids=None and applies its
            normal filters (priority, strategy, tool enablement).
            Set: only the listed tests run.  IDs prefixed with "ext." go to
            ExternalTestRegistry, the others to TestRegistry; each registry
            receives its part as a set, possibly empty, and an empty set
            means "no test of this kind" (not "no filter").  A listed test
            of a disabled external tool still does not run.

        Returns:
            Tuple of (list[ScheduledBatch], combined list BaseTest | ExternalToolTest,
            tests excluded by the filters sorted by test_id).

        Raises:
            DAGCycleError: If a circular dependency is detected.
        """
        log.info("pipeline_phase_4_discovery_and_scheduling_started")

        all_tests, not_run = select_tests(config)

        # A run that checks nothing must not end CLEAN (exit 0): stop with
        # INFRASTRUCTURE (no verdict). With test_ids every entry was already
        # checked to be runnable, so this is reached only through the filters.
        if not all_tests:
            raise ConfigurationError(
                message=(
                    "No test selected: no test matches execution.min_priority="
                    f"{config.execution.min_priority} and execution.strategies="
                    f"{[s.value for s in config.execution.strategies]} with the "
                    "enabled external tools. Widen the filters or list the tests "
                    "in execution.test_ids."
                ),
                config_path="execution",
            )

        # Both kinds of prerequisite order the run; whether a prerequisite is
        # met is decided in Phase 5 (prerequisite_skip_reason).
        dependency_map: dict[str, list[str]] = {
            t.info.id: list(t.info.prerequisites) for t in all_tests
        }

        scheduler = DAGScheduler()
        active_test_ids = {t.info.id for t in all_tests}
        scheduled_batches = scheduler.build_schedule(
            dependencies=dependency_map,
            active_test_ids=active_test_ids,
            order_rank={t.info.id: EFFECT_RANK[t.info.effect] for t in all_tests},
        )

        # Tests whose needs the configuration does not meet: said before any test
        # runs; Phase 5 records them as SKIP with the same reason.
        unmet = unmet_needs_by_test(all_tests, test_params, configuration_facts(config))
        for test_id, reasons in unmet.items():
            log.warning("test_will_skip_unmet_needs", test_id=test_id, reason=" ".join(reasons))

        total_scheduled = sum(b.size for b in scheduled_batches)
        log.info(
            "pipeline_phase_4_discovery_and_scheduling_completed",
            native_tests=sum(1 for t in all_tests if not t.info.is_external),
            external_tests=sum(1 for t in all_tests if t.info.is_external),
            total_active=len(all_tests),
            batch_count=len(scheduled_batches),
            total_scheduled=total_scheduled,
        )

        return scheduled_batches, all_tests, not_run

    # ------------------------------------------------------------------
    # Phase 5 -- Execution
    # ------------------------------------------------------------------

    def _phase_5_execute(
        self,
        scheduled_batches: list[ScheduledBatch],
        active_tests: list[BaseTest | ExternalToolTest],
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
        result_set: ResultSet,
        config: ToolConfig,
    ) -> None:
        """
        Execute all scheduled tests (native + external) in topological order.

        For each ScheduledBatch, iterates over test_ids sequentially.
        Each test is located by test_id in the active_tests list, then
        executed via test.execute(). The TestResult is added to result_set.

        Prerequisites (docs/04-architecture/03-assessment-model.md, "Dependencies
        between tests"): before a test runs, its depends_on and requires_pass
        are checked against the results so far; an unmet prerequisite gives a
        SKIP result with the reason, and the test is not executed.

        Fail-fast condition (docs/04-architecture/03-assessment-model.md, "Fail-fast"):
            If config.execution.fail_fast is True and a P0 test returns
            FAIL, ERROR or INCONCLUSIVE, execution stops immediately.
        """
        log.info(
            "pipeline_phase_5_execution_started",
            batch_count=len(scheduled_batches),
        )

        test_lookup: dict[str, BaseTest | ExternalToolTest] = {t.info.id: t for t in active_tests}
        fail_fast_triggered = False
        fail_fast_result: TestResult | None = None
        # Position of the test in the run, logged as "<position>/<total>".
        position = 0
        total = len(active_tests)

        for batch in scheduled_batches:
            if fail_fast_triggered:
                break

            log.debug(
                "pipeline_phase_5_batch_starting",
                batch_index=batch.batch_index,
                batch_size=batch.size,
                test_ids=batch.test_ids,
            )

            for test_id in batch.test_ids:
                if fail_fast_triggered:
                    break

                test = test_lookup.get(test_id)
                if test is None:
                    log.error(
                        "pipeline_phase_5_test_id_not_in_lookup",
                        test_id=test_id,
                        detail=(
                            "A test_id appeared in the scheduled batch but has "
                            "no corresponding test instance (BaseTest or ExternalToolTest) "
                            "in the active tests lookup. This indicates a DAGScheduler / "
                            "TestRegistry inconsistency."
                        ),
                    )
                    continue

                position += 1
                skip_reason = prerequisite_skip_reason(
                    depends_on=list(test.info.depends_on),
                    requires_pass=list(test.info.requires_pass),
                    statuses={r.test_id: r.status for r in result_set.results},
                )
                if skip_reason is None:
                    needs = unmet_needs(
                        test.info, target.test_params.get(test_id), target_facts(target)
                    )
                    skip_reason = " ".join(needs) if needs else None
                if skip_reason is not None:
                    result = test._skip(skip_reason)  # noqa: SLF001
                    log.info(
                        "test_skipped_prerequisite_not_met",
                        progress=f"{position}/{total}",
                        test_id=test_id,
                        reason=skip_reason,
                    )
                else:
                    timeout_seconds = self._external_timeout_seconds(test, config)
                    if self._observer is not None:
                        self._observer.test_started(
                            position,
                            total,
                            test_id,
                            test.info.name,
                            timeout_seconds,
                        )
                    result = self._execute_single_test(
                        test=test,
                        target=target,
                        context=context,
                        client=client,
                        store=store,
                        progress=f"{position}/{total}",
                        timeout_seconds=timeout_seconds,
                    )
                result_set.add_result(result)
                if self._observer is not None:
                    self._observer.test_finished(position, total, result)

                if config.execution.fail_fast:
                    fail_fast_triggered = self._check_fail_fast(
                        result=result,
                        test=test,
                    )
                    if fail_fast_triggered:
                        fail_fast_result = result

            log.debug(
                "pipeline_phase_5_batch_completed",
                batch_index=batch.batch_index,
            )

        if fail_fast_result is not None:
            self._record_fail_fast_not_run(
                scheduled_batches=scheduled_batches,
                test_lookup=test_lookup,
                result_set=result_set,
                trigger=fail_fast_result,
            )
            log.warning(
                "pipeline_phase_5_fail_fast_triggered",
                results_recorded=result_set.total_count,
                detail=(
                    "Execution aborted by fail-fast condition. A P0 test returned FAIL, ERROR "
                    "or INCONCLUSIVE."
                ),
            )

        log.info(
            "pipeline_phase_5_execution_completed",
            total_results=result_set.total_count,
            pass_count=result_set.pass_count,
            fail_count=result_set.fail_count,
            skip_count=result_set.skip_count,
            error_count=result_set.error_count,
        )

    @staticmethod
    def _external_timeout_seconds(
        test: BaseTest | ExternalToolTest,
        config: ToolConfig,
    ) -> int | None:
        """
        Return the configured timeout of an external test's tool, else None.

        Args:
            test:   The test about to run.
            config: The validated configuration (external_tools.<tool>).

        Returns:
            external_tools.<tool>.timeout_seconds, or None for a native test.
        """
        if not isinstance(test, ExternalToolTest):
            return None
        tool_config = getattr(config.external_tools, test.tool_name, None)
        timeout: int | None = getattr(tool_config, "timeout_seconds", None)
        return timeout

    @staticmethod
    def _record_fail_fast_not_run(
        scheduled_batches: list[ScheduledBatch],
        test_lookup: dict[str, BaseTest | ExternalToolTest],
        result_set: ResultSet,
        trigger: TestResult,
    ) -> None:
        """
        Add the scheduled tests that fail-fast prevented from running to not_run.

        Args:
            scheduled_batches: The Phase 4 schedule.
            test_lookup:       test_id -> test instance.
            result_set:        The run's results (not_run is extended and re-sorted).
            trigger:           The result that triggered fail-fast.
        """
        executed = {r.test_id for r in result_set.results}
        detail = (
            f"execution.fail_fast: the run stopped after {trigger.test_id} "
            f"returned {trigger.status.value}"
        )
        for batch in scheduled_batches:
            for test_id in batch.test_ids:
                test = test_lookup.get(test_id)
                if test is None or test_id in executed:
                    continue
                result_set.not_run.append(
                    NotRunEntry(
                        test_id=test_id,
                        test_name=test.info.name,
                        source=test.source,
                        reason=NotRunReason.FAIL_FAST,
                        detail=detail,
                    )
                )
        result_set.not_run.sort(key=lambda e: e.test_id)

    def _execute_single_test(
        self,
        test: BaseTest | ExternalToolTest,
        target: TargetContext,
        context: TestContext,
        client: SecurityClient,
        store: EvidenceStore,
        progress: str,
        timeout_seconds: int | None,
    ) -> TestResult:
        """
        Execute a single test (native or external) and return its TestResult.

        The start log carries progress ("5/18") and, for an external test,
        the tool's timeout_seconds, so that a long run shows where it is and
        how long the current test may take.

        Dispatch logic:
            - BaseTest:         calls test.execute(target, context, client, store)
                                SecurityClient is required for HTTP requests.
            - ExternalToolTest: calls test.execute(target, context, store)
                                SecurityClient is intentionally absent -- external
                                tests invoke subprocesses, not httpx.

        The store.begin_test() / end_test() lifecycle is managed by each
        hierarchy's execute() method, not here -- to avoid double-calling.
        This method only measures wall-clock time and attaches duration_ms.
        """
        test_id = test.info.id
        test_name = test.info.name
        source = test.source

        timeout_field: dict[str, int] = (
            {"timeout_seconds": timeout_seconds} if timeout_seconds is not None else {}
        )
        log.info(
            "test_execution_started",
            progress=progress,
            test_id=test_id,
            test_name=test_name,
            priority=test.info.priority,
            strategy=test.info.strategy,
            source=source,
            **timeout_field,
        )

        # The gateway reaches only the tests that declare it (Need.GATEWAY,
        # required or optional): what a test declares is what it can use
        # (docs/project/test-review.md, phase 0c piece 1b; 0.1).
        if not test.info.uses(Need.GATEWAY) and target.gateway is not None:
            target = target.model_copy(update={"gateway": None})

        # The credential of every account a test declares is obtained before it
        # runs, as the gateway is given to it: a declared need is provided, so
        # no test logs in for itself (group B, 2026-10-22). The login happens
        # once per role and is reused by every later test; a role whose login
        # does not work makes this test ERROR with the reason, and the others go
        # on. Without any such need nothing is sent, so a run of tests that
        # need no account never logs in.
        roles = frozenset(role for need, role in NEED_ROLES.items() if test.info.uses(need))
        if roles:
            try:
                acquire_tokens(target, context, client, required_roles=roles)
            except (AuthenticationSetupError, SecurityClientError) as exc:
                log.error(
                    "test_account_not_available",
                    test_id=test_id,
                    roles=sorted(roles),
                    error=str(exc),
                )
                return test._error(exc)  # noqa: SLF001

        wall_start = time.monotonic()

        if isinstance(test, ExternalToolTest):
            result = test.execute(target, context, client, store)
        else:
            store.begin_test(test_id)
            try:
                result = test.execute(target, context, client, store)
            finally:
                store.end_test()

        elapsed_ms = (time.monotonic() - wall_start) * 1000.0
        result = result.model_copy(update={"duration_ms": round(elapsed_ms, 2)})

        log.info(
            "test_execution_completed",
            test_id=test_id,
            status=result.status.value,
            finding_count=len(result.findings),
            duration_ms=round(elapsed_ms, 2),
            source=source,
        )

        return result

    @staticmethod
    def _check_fail_fast(result: TestResult, test: BaseTest | ExternalToolTest) -> bool:
        """
        Determine whether the fail-fast condition is triggered.

        Condition: test has priority P0 AND status is FAIL, ERROR or
        INCONCLUSIVE. All three are blocking for P0 tests: a FAIL violates a
        critical guarantee, an ERROR or an INCONCLUSIVE means its verification
        did not complete (the same grouping as exit code 3) -- proceeding would
        produce an assessment without foundation.
        """
        is_p0 = test.info.priority == 0
        is_blocking_status = result.status in (
            TestStatus.FAIL,
            TestStatus.ERROR,
            TestStatus.INCONCLUSIVE,
        )

        if is_p0 and is_blocking_status:
            log.warning(
                "fail_fast_condition_met",
                test_id=test.info.id,
                status=result.status.value,
                priority=test.info.priority,
            )
            return True

        return False

    # ------------------------------------------------------------------
    # Phase 6 -- Teardown
    # ------------------------------------------------------------------

    def _phase_6_teardown(
        self,
        context: TestContext,
        client: SecurityClient,
        target: TargetContext,
    ) -> tuple[int, int]:
        """
        Delete all resources registered during Phase 5 in LIFO order.

        Each DELETE request is attempted via SecurityClient. Failures are
        caught, logged as WARNING, and execution continues. A teardown failure
        does not affect the ResultSet or the exit code.

        Returns:
            (resources removed, resources whose removal failed).
        """
        log.info(
            "pipeline_phase_6_teardown_started",
            pending_resources=context.registered_resource_count(),
        )

        resources = context.drain_resources()

        if not resources:
            log.info("pipeline_phase_6_teardown_completed_no_resources")
            return 0, 0

        success_count = 0
        failure_count = 0
        acceptable_codes = {200, 204, 404}

        for method, path, teardown_headers in resources:
            try:
                response, _ = client.request(
                    method=method,
                    path=path,
                    test_id="teardown",
                    headers=teardown_headers if teardown_headers else None,
                )
                if response.status_code not in acceptable_codes:
                    raise TeardownError(
                        message=(
                            f"DELETE {path} returned unexpected status "
                            f"{response.status_code}. "
                            f"Expected one of: {sorted(acceptable_codes)}."
                        ),
                        resource_method=method,
                        resource_path=path,
                        failed_status_code=response.status_code,
                    )
                success_count += 1
                log.debug(
                    "teardown_resource_deleted",
                    method=method,
                    path=path,
                    status_code=response.status_code,
                )

            except TeardownError as exc:
                failure_count += 1
                log.warning(
                    "teardown_resource_deletion_failed",
                    method=exc.resource_method,
                    path=exc.resource_path,
                    failed_status_code=exc.failed_status_code,
                    detail=exc.message,
                    manual_cleanup_required=True,
                )

            except Exception as exc:  # noqa: BLE001
                failure_count += 1
                log.warning(
                    "teardown_resource_unexpected_error",
                    method=method,
                    path=path,
                    exc_type=type(exc).__name__,
                    detail=str(exc),
                    manual_cleanup_required=True,
                )

        log.info(
            "pipeline_phase_6_teardown_completed",
            total_resources=len(resources),
            success_count=success_count,
            failure_count=failure_count,
        )
        return success_count, failure_count

    # ------------------------------------------------------------------
    # Phase 7 -- Report Generation
    # ------------------------------------------------------------------

    def _phase_7_report(
        self,
        result_set: ResultSet,
        store: EvidenceStore,
        config: ToolConfig,
        attack_surface: AttackSurface,
        secrets: SecretRegistry,
        references: ReferenceResponses,
    ) -> None:
        """
        Serialize evidence and generate the HTML assessment report.

        Every output is redacted with secrets (src/core/redaction.py): the
        evidence file as it is written, the report data once, before both
        the HTML and the JSON report are produced from it.

        Errors during report generation are logged as ERROR but do not
        change the exit code: assessment results are correct regardless of
        whether the report was successfully written to disk.
        """
        evidence_path = config.output.evidence_path
        report_path = config.output.report_path
        json_report_path = config.output.json_report_path

        log.info(
            "pipeline_phase_7_report_generation_started",
            total_results=result_set.total_count,
            evidence_records=store.record_count,
            evidence_path=str(evidence_path),
            report_path=str(report_path),
        )

        try:
            records_written = store.merge_and_finalize(
                evidence_path, tool_version=__version__, redact=secrets.redact
            )
            log.info(
                "pipeline_phase_7_evidence_serialized",
                output_path=str(evidence_path),
                records_written=records_written,
            )
        except OSError as exc:
            log.error(
                "pipeline_phase_7_evidence_serialization_failed",
                output_path=str(evidence_path),
                detail=str(exc),
            )

        try:
            report_data = build_report_data(
                result_set=result_set,
                run_id=self._run_id,
                config=config,
                spec_title=attack_surface.spec_title,
                spec_version=attack_surface.spec_version,
                references=references,
                derived=attack_surface.derived,
            )
            # Secrets learned after their capture (e.g. a token in the
            # response that creates it) are replaced in the whole report.
            report_data = ReportData.model_validate_json(
                secrets.redact(report_data.model_dump_json())
            )
        except Exception as exc:  # noqa: BLE001
            log.error(
                "pipeline_phase_7_report_data_build_failed",
                exc_type=type(exc).__name__,
                detail=str(exc),
            )
            return

        try:
            render_html_report(
                report_data=report_data,
                output_path=report_path,
            )
            log.info(
                "pipeline_phase_7_html_report_rendered",
                output_path=str(report_path),
            )
        except Exception as exc:  # noqa: BLE001
            log.error(
                "pipeline_phase_7_html_report_render_failed",
                exc_type=type(exc).__name__,
                detail=str(exc),
            )

        try:
            json_report_path.parent.mkdir(parents=True, exist_ok=True)
            json_report_path.write_text(
                report_data.model_dump_json(indent=2),
                encoding="utf-8",
            )
            log.info(
                "pipeline_phase_7_json_report_written",
                output_path=str(json_report_path),
                size_bytes=json_report_path.stat().st_size,
            )
        except OSError as exc:
            log.error(
                "pipeline_phase_7_json_report_write_failed",
                output_path=str(json_report_path),
                detail=str(exc),
            )

        log.info("pipeline_phase_7_report_generation_completed")


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def _generate_run_id() -> str:
    """
    Generate a unique run identifier for this pipeline execution.

    Format: 'apiguard-{YYYYMMDD}-{HHMMSS}-{microseconds}'
    Example: 'apiguard-20260328-142305-123456'

    Timestamp-based rather than UUID: human-readable in log output
    and chronologically sortable.
    """
    now = datetime.now(UTC)
    return f"apiguard-{now.strftime('%Y%m%d-%H%M%S')}-{now.microsecond:06d}"
