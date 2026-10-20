"""
src/config/tests_section.py

The ``tests:`` section of config.yaml, checked against the tests that exist.

Each test declares its own parameter model in its class
(``class Test21...(BaseTest[Test21Params])``, docs/04-architecture/05-design-decisions.md,
D8), so the section can only be checked once the tests are discovered: the
engine collects the models (``engine.check_tests``, right after Phase 1 and
in ``apiguard validate-config``) and passes them here. The keys are derived
from the test IDs: test ``2.1`` is ``tests.domain_2.test_2_1``, an external
test ``ext.1.5.testssl`` would be ``tests.domain_1.ext_1_5_testssl`` (test
IDs cannot be YAML keys: YAML reads ``2.10`` as the number 2.1).

The section is validated with one model built from the declared models, so
an unknown test or parameter gets the same message as any unknown key, with
the closest name (``loader.describe_validation_errors``). The validation
context carries what a parameter model may check against the rest of the
configuration: the names and values of ``resources`` (test 7.2).

A domain or a test written empty (every line under it commented) takes its
defaults, as everywhere in config.yaml (loader.without_empty_blocks).

Dependency rule: imports from pydantic, the stdlib, src.config.loader and
src.core; never from tests/ (the models are passed in).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, create_model

from src.config.loader import describe_validation_errors, without_empty_blocks
from src.config.schema import ToolConfig
from src.core.assessment_test import PARAMS_CONTEXT_RESOURCES, NoParams
from src.core.exceptions import ConfigurationError
from src.core.test_metadata import section_keys

# Dotted name of the section in config.yaml.
TESTS_SECTION: str = "tests"

_MODEL_CONFIG: ConfigDict = ConfigDict(frozen=True, extra="forbid")


def tests_section_model(models: Mapping[str, type[BaseModel] | None]) -> type[BaseModel]:
    """
    The model of the tests section, built from the tests' parameter models.

    Args:
        models: Test ID -> its parameter model (None: the test has none).

    Returns:
        A frozen model with one field per domain and, in each, one field per
        test, every field optional (its defaults).
    """
    domains: dict[str, dict[str, Any]] = {}
    for test_id in sorted(models):
        domain_key, test_key = section_keys(test_id)
        model = models[test_id] or NoParams
        domains.setdefault(domain_key, {})[test_key] = (model, Field(default_factory=model))
    fields: dict[str, Any] = {}
    for domain_key, test_fields in sorted(domains.items()):
        domain_model = create_model(
            f"TestsSection_{domain_key}", __config__=_MODEL_CONFIG, **test_fields
        )
        fields[domain_key] = (domain_model, Field(default_factory=domain_model))
    return create_model("TestsSection", __config__=_MODEL_CONFIG, **fields)


def config_model(models: Mapping[str, type[BaseModel] | None]) -> type[BaseModel]:
    """
    ToolConfig with its tests section as the tool checks it (one model per test).

    The whole schema of config.yaml, for what walks every key: the example
    check (scripts/check_config_keys.py) and the configuration a run used
    (src/config/config_used.py).

    Args:
        models: Test ID -> its parameter model (None: the test has none).

    Returns:
        A model with ToolConfig's fields and the tests section's model.
    """
    section = tests_section_model(models)
    fields: dict[str, Any] = {TESTS_SECTION: (section, Field(default_factory=section))}
    return create_model("CompleteConfig", __base__=ToolConfig, **fields)


def validate_tests_section(
    raw: Mapping[str, Any],
    models: Mapping[str, type[BaseModel] | None],
    resources: Mapping[str, Any],
) -> dict[str, BaseModel]:
    """
    Validate the tests section and return each test's parameters.

    Args:
        raw:       config.tests as written in config.yaml.
        models:    Test ID -> its parameter model (None: the test has none).
        resources: config.resources, for the models that check against it.

    Returns:
        Test ID -> validated parameters, for every test that has a model
        (its defaults when the section does not mention it).

    Raises:
        ConfigurationError: Listing every problem, each with its dotted key.
    """
    section = tests_section_model(models)
    try:
        validated = section.model_validate(
            without_empty_blocks(dict(raw), section), context={PARAMS_CONTEXT_RESOURCES: resources}
        )
    except ValidationError as exc:
        lines = describe_validation_errors(exc, section, f"{TESTS_SECTION}.")
        raise ConfigurationError(
            message=(
                f"Configuration validation failed with {exc.error_count()} error(s):\n"
                + "\n".join(f"  - {line}" for line in lines)
            ),
            config_path=TESTS_SECTION,
        ) from exc
    params: dict[str, BaseModel] = {}
    for test_id, model in models.items():
        if model is None:
            continue
        domain_key, test_key = section_keys(test_id)
        params[test_id] = getattr(getattr(validated, domain_key), test_key)
    return params
