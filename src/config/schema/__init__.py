"""
src/config/schema/__init__.py

Public API facade for the config/schema package.

This file re-exports every public symbol from the sub-modules so that
existing import statements remain valid unchanged:

    from src.config.schema import ToolConfig           # still works
    from src.config.schema import Test41ProbeConfig    # new, also works
    from src.config.schema import TestsConfig          # still works

The per-test models live in ``src/test_config/`` (one module per domain,
the single definition used by both the configuration and the tests).
Internal modules import directly from the module that owns the symbol
(e.g. ``from src.test_config.domain_4 import Test41ProbeConfig``) to
keep import paths explicit and avoid hidden coupling through the facade.
The facade exists for external consumers (engine.py, loader.py, cli.py,
tests_e2e/) that should not need to know the internal package layout.

Symbol inventory by source module (domain_*.py are in src/test_config/):

    tool_config.py      TargetConfig, CredentialsConfig, ExecutionConfig,
                        OutputConfig, ToolConfig

    domain_0.py         Test02ProbeConfig, TestDomain0Config

    domain_1.py         Test11Config, Test14Config, TestDomain1Config,
                        Test15Config, Test16Config

    domain_2.py         Test21Config, TestDomain2Config

    domain_3.py         Test33Config, TestDomain3Config

    domain_4.py         Test41ProbeConfig, Test42AuditConfig,
                        Test43AuditConfig, TestDomain4Config

    domain_6.py         Test62AuditConfig, Test64AuditConfig,
                        TestDomain6Config

    domain_7.py         Test72SSRFConfig, TestDomain7Config

    tests_config.py     TestsConfig
"""

from __future__ import annotations

from src.config.schema.tests_config import TestsConfig
from src.config.schema.tool_config import (
    CredentialsConfig,
    ExecutionConfig,
    OutputConfig,
    TargetConfig,
    ToolConfig,
)
from src.test_config.domain_0 import Test02ProbeConfig, TestDomain0Config
from src.test_config.domain_1 import (
    Test11Config,
    Test14Config,
    Test15Config,
    Test16Config,
    TestDomain1Config,
)
from src.test_config.domain_2 import Test21Config, TestDomain2Config
from src.test_config.domain_3 import Test33Config, TestDomain3Config
from src.test_config.domain_4 import (
    Test41ProbeConfig,
    Test42AuditConfig,
    Test43AuditConfig,
    TestDomain4Config,
)
from src.test_config.domain_6 import (
    Test62AuditConfig,
    Test64AuditConfig,
    TestDomain6Config,
)
from src.test_config.domain_7 import Test72SSRFConfig, TestDomain7Config

__all__ = [
    # tool_config.py
    "TargetConfig",
    "CredentialsConfig",
    "ExecutionConfig",
    "OutputConfig",
    "ToolConfig",
    # domain_0.py
    "Test02ProbeConfig",
    "TestDomain0Config",
    # domain_1.py
    "Test11Config",
    "Test14Config",
    "TestDomain1Config",
    "Test15Config",
    "Test16Config",
    # domain_2.py
    "Test21Config",
    "TestDomain2Config",
    # domain_3.py
    "Test33Config",
    "TestDomain3Config",
    # domain_4.py
    "Test41ProbeConfig",
    "Test42AuditConfig",
    "Test43AuditConfig",
    "TestDomain4Config",
    # domain_6.py
    "Test62AuditConfig",
    "Test64AuditConfig",
    "TestDomain6Config",
    # domain_7.py
    "Test72SSRFConfig",
    "TestDomain7Config",
    # tests_config.py
    "TestsConfig",
]
