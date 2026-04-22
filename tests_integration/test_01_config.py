"""
tests_integration/test_01_config.py

Integration tests for Phase 1 — Initialization (config/loader.py + config/schema.py).

Executable Documentation contract
----------------------------------
These tests specify the exact behaviour of the configuration layer under every
class of input that the system must handle. Reading this file answers the
question: "What does the config loader accept, what does it reject, and what
state does it produce for a valid input?"

Phase 1 contract (from engine.py docstring):
    Load and validate config.yaml via config/loader.py.
    Raises ConfigurationError on failure [BLOCKS STARTUP].

Test organisation
-----------------
Section A — Happy path: a valid config produces the expected ToolConfig state.
Section B — Environment variable interpolation: ${VAR} substitution semantics.
Section C — Validation failures: each class of invalid input raises ConfigurationError
            with a meaningful message.
Section D — OutputConfig: computed properties and default path construction.
Section E — CredentialsConfig: pair-validation invariant.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError
from src.config.loader import load_config
from src.config.schema import OutputConfig, ToolConfig
from src.core.exceptions import ConfigurationError
from src.core.models import TestStrategy

# ===========================================================================
# Section A — Happy path
# ===========================================================================


class TestValidConfigLoading:
    """
    Phase 1 loads a syntactically and semantically valid config.yaml and returns
    a frozen ToolConfig that reflects every field declared in the file.

    These tests verify that no silent defaults silently override explicit values
    and that the returned object is immediately usable by the rest of the pipeline.
    """

    def test_returns_tool_config_instance(self, minimal_config_file: Path) -> None:
        """
        load_config() must return a ToolConfig, not raise, for a valid file.

        If this test fails, Phase 1 cannot complete and the entire pipeline
        is blocked regardless of the validity of the target.
        """
        config = load_config(minimal_config_file)
        assert isinstance(config, ToolConfig)

    def test_target_base_url_is_preserved(self, minimal_config_file: Path) -> None:
        """
        target.base_url must exactly match the value declared in config.yaml.

        TargetContext is built from this URL in Phase 3; a mangled URL would
        silently redirect all HTTP traffic to the wrong host.
        """
        config = load_config(minimal_config_file)
        assert str(config.target.base_url).rstrip("/") == "http://localhost:8000"

    def test_execution_strategy_filter_is_honoured(self, minimal_config_file: Path) -> None:
        """
        execution.strategies must contain exactly the values listed in the file.

        TestRegistry uses this list in Phase 4 to decide which tests to include.
        A strategy missing from the list means an entire class of tests is silently
        skipped without any indication to the operator.
        """
        config = load_config(minimal_config_file)
        assert config.execution.strategies == [TestStrategy.BLACK_BOX]

    def test_execution_min_priority_is_honoured(self, minimal_config_file: Path) -> None:
        """
        execution.min_priority must carry the value from config.yaml into ToolConfig.

        min_priority=3 means all test priorities (0-3) are included.
        If this value is silently coerced, lower-priority tests may be incorrectly
        excluded or included.
        """
        config = load_config(minimal_config_file)
        assert config.execution.min_priority == 3

    def test_output_directory_is_path_object(self, minimal_config_file: Path) -> None:
        """
        output.directory must be a pathlib.Path, not a raw string.

        The engine calls output.evidence_path and output.report_path — both
        Path properties. If directory were stored as a string, these properties
        would not exist and Phase 7 would crash with an AttributeError.
        """
        config = load_config(minimal_config_file)
        assert isinstance(config.output.directory, Path)

    def test_config_is_frozen_after_load(self, minimal_config_file: Path) -> None:
        """
        ToolConfig must be immutable (frozen) after load_config() returns.

        The frozen guarantee is the architectural contract that makes it safe
        to share a single ToolConfig across all pipeline phases without
        synchronisation. Any mutation attempt must raise an exception.
        """
        config = load_config(minimal_config_file)
        with pytest.raises(ValidationError):
            config.execution = config.execution  # type: ignore[misc]

    def test_admin_api_url_defaults_to_none(self, minimal_config_file: Path) -> None:
        """
        When admin_api_url is absent from config.yaml, it must default to None.

        A None admin_api_url causes all WHITE_BOX tests to SKIP. This is the
        correct behaviour for a Black Box assessment. A missing key must never
        silently produce an invalid URL.
        """
        config = load_config(minimal_config_file)
        assert config.target.admin_api_url is None


# ===========================================================================
# Section B — Environment variable interpolation
# ===========================================================================


class TestEnvVarInterpolation:
    """
    loader.py resolves ${VAR_NAME} placeholders before YAML parsing.

    The interpolation is a pre-processing step, not a Pydantic feature.
    These tests verify the exact contract of Phase B in load_config's
    internal loading pipeline.
    """

    def test_env_var_is_substituted_into_url(self, tmp_path: Path) -> None:
        """
        A ${VAR_NAME} placeholder in a URL field must be replaced with the
        corresponding environment variable value before Pydantic validates the URL.

        Without this, operators cannot safely manage credentials via CI/CD
        environment injection.
        """
        config_content = """\
target:
  base_url: "http://${TARGET_HOST}:8000"
  openapi_spec_url: "http://localhost:3000/swagger.v1.json"
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(config_content, encoding="utf-8")

        os.environ["TARGET_HOST"] = "testserver"
        try:
            config = load_config(config_path)
            assert "testserver" in str(config.target.base_url)
        finally:
            del os.environ["TARGET_HOST"]

    def test_missing_env_var_raises_configuration_error(self, tmp_path: Path) -> None:
        """
        A ${VAR_NAME} with no corresponding environment variable must raise
        ConfigurationError — not KeyError, not ValueError, not a Pydantic error.

        The ConfigurationError type is what the engine catches in Phase 1 to
        produce a structured startup-failure log entry with the variable name.
        Any other exception type would propagate as an unhandled crash.
        """
        config_content = """\
target:
  base_url: "http://localhost:8000"
  openapi_spec_url: "http://localhost:3000/swagger.v1.json"
credentials:
  admin_username: "${DEFINITELY_UNSET_VAR_XYZ_12345}"
  admin_password: "${DEFINITELY_UNSET_VAR_XYZ_12345}"
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(config_content, encoding="utf-8")

        os.environ.pop("DEFINITELY_UNSET_VAR_XYZ_12345", None)

        with pytest.raises(ConfigurationError):
            load_config(config_path)


# ===========================================================================
# Section C — Validation failures
# ===========================================================================


class TestConfigValidationFailures:
    """
    load_config() must raise ConfigurationError for every class of invalid input.

    Each test here documents one specific invalid configuration scenario and
    the contract that it must produce a ConfigurationError rather than a
    silent misconfiguration or an unhandled Python exception.
    """

    def test_missing_file_raises_configuration_error(self, tmp_path: Path) -> None:
        """
        A path that does not exist must raise ConfigurationError immediately.

        The engine must fail loudly in Phase 1 rather than proceeding with
        an empty or default configuration that would produce nonsensical results.
        """
        nonexistent = tmp_path / "does_not_exist.yaml"
        with pytest.raises(ConfigurationError):
            load_config(nonexistent)

    def test_missing_target_section_raises_configuration_error(self, tmp_path: Path) -> None:
        """
        A config.yaml that omits the required 'target' section must raise
        ConfigurationError with a message pointing to the missing field.

        'target' contains the base_url that every test uses to construct HTTP
        requests. Without it, the pipeline cannot function at all.
        """
        config_content = """\
execution:
  min_priority: 0
  strategies:
    - BLACK_BOX
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(config_content, encoding="utf-8")

        with pytest.raises(ConfigurationError):
            load_config(config_path)

    def test_invalid_url_raises_configuration_error(self, tmp_path: Path) -> None:
        """
        A base_url that is not a valid HTTP URL must raise ConfigurationError.

        Pydantic's AnyHttpUrl validator catches this, but the error must be
        wrapped in ConfigurationError before it reaches the caller — the engine
        only catches ConfigurationError in Phase 1, not ValidationError.
        """
        config_content = """\
target:
  base_url: "not-a-url"
  openapi_spec_url: "http://localhost:3000/swagger.v1.json"
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(config_content, encoding="utf-8")

        with pytest.raises(ConfigurationError):
            load_config(config_path)

    def test_empty_strategies_raises_configuration_error(self, tmp_path: Path) -> None:
        """
        An empty execution.strategies list must raise ConfigurationError.

        An empty list would cause TestRegistry to discover zero tests, resulting
        in a pipeline run that produces no results — a silent false-negative.
        The validator rejects this at load time rather than allowing a vacuous run.
        """
        config_content = """\
target:
  base_url: "http://localhost:8000"
  openapi_spec_url: "http://localhost:3000/swagger.v1.json"
execution:
  strategies: []
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(config_content, encoding="utf-8")

        with pytest.raises(ConfigurationError):
            load_config(config_path)

    def test_invalid_yaml_syntax_raises_configuration_error(self, tmp_path: Path) -> None:
        """
        A config.yaml with a YAML syntax error must raise ConfigurationError.

        The error must identify the problem as a YAML issue, not a Python
        exception from the yaml library leaking through the API boundary.
        """
        config_content = "target: {base_url: [unclosed bracket"
        config_path = tmp_path / "config.yaml"
        config_path.write_text(config_content, encoding="utf-8")

        with pytest.raises(ConfigurationError):
            load_config(config_path)

    def test_empty_file_raises_configuration_error(self, tmp_path: Path) -> None:
        """
        An empty config.yaml must raise ConfigurationError before any parsing.

        An empty file with no content cannot represent a valid configuration.
        The loader detects this during Phase A (raw file read) to provide a
        cleaner error message than the one Pydantic would emit for an empty dict.
        """
        config_path = tmp_path / "config.yaml"
        config_path.write_text("", encoding="utf-8")

        with pytest.raises(ConfigurationError):
            load_config(config_path)


# ===========================================================================
# Section D — OutputConfig computed properties
# ===========================================================================


class TestOutputConfig:
    """
    OutputConfig.evidence_path and OutputConfig.report_path are computed
    properties that the engine reads in Phase 7. Their correctness is a
    prerequisite for writing any output files.
    """

    def test_evidence_path_is_inside_output_directory(self, tmp_path: Path) -> None:
        """
        evidence_path must be a child of the configured directory.

        Phase 7 calls output.evidence_path to determine where to write
        the evidence JSON. If the path points outside the output directory,
        files would be scattered across the filesystem.
        """
        out = OutputConfig(directory=tmp_path)
        assert out.evidence_path.parent == tmp_path

    def test_report_path_is_inside_output_directory(self, tmp_path: Path) -> None:
        """
        report_path must be a child of the configured directory.

        Same constraint as evidence_path, but for the HTML report.
        """
        out = OutputConfig(directory=tmp_path)
        assert out.report_path.parent == tmp_path

    def test_evidence_path_has_json_extension(self) -> None:
        """
        evidence_path must have a .json extension.

        The evidence file is parsed as JSON by downstream tooling. A wrong
        extension would confuse file associations and break CI artefact collectors.
        """
        out = OutputConfig()
        assert out.evidence_path.suffix == ".json"

    def test_report_path_has_html_extension(self) -> None:
        """
        report_path must have a .html extension.

        The report is an HTML document opened in a browser. A wrong extension
        prevents automatic browser association and breaks CI report publishers.
        """
        out = OutputConfig()
        assert out.report_path.suffix == ".html"

    def test_default_directory_is_outputs(self) -> None:
        """
        When no directory is specified, OutputConfig defaults to Path('outputs').

        This is the convention documented in config.yaml comments and in the
        .gitignore. Changing the default would silently break the .gitignore
        exclusion, causing output files to be committed to version control.
        """
        out = OutputConfig()
        assert out.directory == Path("outputs")


# ===========================================================================
# Section E — CredentialsConfig pair validation
# ===========================================================================


class TestCredentialPairValidation:
    """
    CredentialsConfig enforces that username and password for each role are
    provided together or not at all. A username without a password (or vice
    versa) is a misconfigured environment variable setup that must be caught
    at startup, not silently produce a runtime authentication failure.
    """

    def test_username_without_password_raises_configuration_error(self, tmp_path: Path) -> None:
        """
        Providing admin_username without admin_password must raise ConfigurationError.

        A half-configured credential pair is always a configuration mistake.
        The error message must name the incomplete pair so the operator knows
        which environment variable to set.
        """
        config_content = """\
target:
  base_url: "http://localhost:8000"
  openapi_spec_url: "http://localhost:3000/swagger.v1.json"
credentials:
  admin_username: "admin"
"""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(config_content, encoding="utf-8")

        with pytest.raises(ConfigurationError):
            load_config(config_path)
