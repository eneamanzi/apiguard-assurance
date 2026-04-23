"""
src/config/schema/domain_1.py

Pydantic v2 configuration models for Domain 1 (Identity and Authentication) tests.

This module is part of the config/schema/ package refactoring. It owns all
per-test tuning parameters for tests 1.x. Each test that requires operator-
configurable parameters gets its own model (Test1XConfig); the domain-level
aggregator (TestDomain1Config) collects them all and is the only symbol
exported to tests_config.py.

Dependency rule: imports only from pydantic and the stdlib.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TEST_11_MAX_ENDPOINTS_CAP_DEFAULT: int = 0
TEST_11_MAX_ENDPOINTS_CAP_MIN: int = 0

# ---------------------------------------------------------------------------
# Per-test configs
# ---------------------------------------------------------------------------


class Test11Config(BaseModel):
    """
    Tuning parameters for Test 1.1 (Authentication Required).

    Controls how many protected endpoints Test 1.1 will probe in a single
    assessment run. The default value of 0 signals 'probe all endpoints',
    which is the academically complete behaviour. A positive integer caps
    the scan when the target enforces strict rate limiting that would cause
    429 responses during a full run, or when a time-bounded assessment is
    required.
    """

    model_config = {"frozen": True}

    max_endpoints_cap: Annotated[int, Field(ge=TEST_11_MAX_ENDPOINTS_CAP_MIN)] = Field(
        default=TEST_11_MAX_ENDPOINTS_CAP_DEFAULT,
        description=(
            "Maximum number of protected endpoints that Test 1.1 will probe. "
            "0 means test ALL protected endpoints declared in the OpenAPI spec "
            "(recommended for complete academic coverage). "
            "Set to a positive integer only when the target API enforces strict "
            "rate limiting that would cause 429 responses during a full scan, "
            "or when the operator requires a time-bounded assessment."
        ),
    )


# ---------------------------------------------------------------------------
# Domain-level aggregator
# ---------------------------------------------------------------------------


class TestDomain1Config(BaseModel):
    """
    Aggregator for all Domain 1 (Identity and Authentication) test configs.

    One field per test in the domain. tests_config.py imports only this class.
    Adding a new Domain 1 test requires:
        1. Defining a Test1XConfig model above.
        2. Adding a field here.
        3. Adding the corresponding RuntimeTest1XConfig in core/models/runtime.py.
        4. Populating it in engine.py Phase 3.
    """

    model_config = {"frozen": True}

    test_1_1: Test11Config = Field(
        default_factory=Test11Config,
        description="Tuning parameters for Test 1.1 (Authentication Required).",
    )
