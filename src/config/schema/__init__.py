"""
src/config/schema/__init__.py

Public API facade for the config/schema package.

This file re-exports every public symbol from the sub-modules so that
existing import statements remain valid unchanged:

    from src.config.schema import ToolConfig           # still works
    from src.config.schema import Test41ProbeConfig    # new, also works
    from src.config.schema import TestsConfig          # still works

Internal modules import directly from the sub-module that owns the symbol
(e.g. ``from src.config.schema.domain_4 import Test41ProbeConfig``) to
keep import paths explicit and avoid hidden coupling through the facade.
The facade exists for external consumers (engine.py, loader.py, cli.py,
tests_e2e/) that should not need to know the internal package layout.

Symbol inventory by source module:

    tool_config.py      TargetConfig, CredentialsConfig, ExecutionConfig,
                        OutputConfig, ToolConfig

    domain_1.py         Test11Config, TestDomain1Config

    domain_4.py         Test41ProbeConfig, Test42AuditConfig,
                        Test43AuditConfig, TestDomain4Config

    domain_6.py         Test62AuditConfig, Test64AuditConfig,
                        TestDomain6Config

    tests_config.py     TestsConfig
"""

from __future__ import annotations

from src.config.schema.domain_1 import Test11Config, TestDomain1Config
from src.config.schema.domain_4 import (
    Test41ProbeConfig,
    Test42AuditConfig,
    Test43AuditConfig,
    TestDomain4Config,
)
from src.config.schema.domain_6 import (
    Test62AuditConfig,
    Test64AuditConfig,
    TestDomain6Config,
)
from src.config.schema.tests_config import TestsConfig
from src.config.schema.tool_config import (
    CredentialsConfig,
    ExecutionConfig,
    OutputConfig,
    TargetConfig,
    ToolConfig,
)

__all__ = [
    # tool_config.py
    "TargetConfig",
    "CredentialsConfig",
    "ExecutionConfig",
    "OutputConfig",
    "ToolConfig",
    # domain_1.py
    "Test11Config",
    "TestDomain1Config",
    # domain_4.py
    "Test41ProbeConfig",
    "Test42AuditConfig",
    "Test43AuditConfig",
    "TestDomain4Config",
    # domain_6.py
    "Test62AuditConfig",
    "Test64AuditConfig",
    "TestDomain6Config",
    # tests_config.py
    "TestsConfig",
]
