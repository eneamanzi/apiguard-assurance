"""
src/config/schema/tests_config.py

Pydantic v2 aggregator for all per-domain test tuning configurations.

TestsConfig is the single object that ToolConfig (in tool_config.py) exposes
as its 'tests' field. It imports one aggregator per domain (TestDomain1Config,
TestDomain4Config, ...) and exposes them as typed fields.

Scaling convention:
    Adding a new domain requires:
        1. Creating src/config/schema/domain_N.py with TestDomainNConfig.
        2. Importing TestDomainNConfig here and adding a field.
        3. Exporting it via __init__.py.
    No other files in this package need to change.

Dependency rule: imports only from pydantic, the stdlib, and sibling domain
modules within this package. Must never import from tool_config.py (that
would create a circular dependency: tool_config imports tests_config).
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from src.config.schema.domain_1 import TestDomain1Config
from src.config.schema.domain_4 import TestDomain4Config
from src.config.schema.domain_6 import TestDomain6Config
from src.config.schema.domain_7 import TestDomain7Config

# ---------------------------------------------------------------------------
# TestsConfig
# ---------------------------------------------------------------------------


class TestsConfig(BaseModel):
    """
    Container for all per-domain test tuning parameters.

    Populated by config.yaml under the 'tests:' top-level key and stored
    (after propagation through engine.py Phase 3) in TargetContext.tests_config
    as a RuntimeTestsConfig instance.

    Default values are defined in each domain's individual model (e.g.
    Test41ProbeConfig) and require no operator override for a standard assessment.
    """

    model_config = {"frozen": True}

    domain_1: TestDomain1Config = Field(
        default_factory=TestDomain1Config,
        description="Tuning parameters for Domain 1 (Identity and Authentication) tests.",
    )
    domain_4: TestDomain4Config = Field(
        default_factory=TestDomain4Config,
        description="Tuning parameters for Domain 4 (Availability and Resilience) tests.",
    )
    domain_6: TestDomain6Config = Field(
        default_factory=TestDomain6Config,
        description="Tuning parameters for Domain 6 (Configuration and Hardening) tests.",
    )
    domain_7: TestDomain7Config = Field(
        default_factory=TestDomain7Config,
        description="Tuning parameters for Domain 7 (Business Logic and Sensitive Flows) tests.",
    )
