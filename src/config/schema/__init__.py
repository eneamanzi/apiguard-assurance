"""
src/config/schema/__init__.py

Public API facade for the config/schema package.

This file re-exports the public models of the configuration schema:

    from src.config.schema import ToolConfig

The tests' parameter models are not here: each test declares its own in its
module (``class Test21...(BaseTest[Test21Params])``), and the tests section is
checked once the tests are discovered (src/config/tests_section.py).

Symbol inventory:

    tool_config.py      TargetConfig, SpecificationConfig, GatewayConfig,
                        GatewayAdminConfig, GatewayHealthConfig, ExecutionConfig,
                        OutputConfig, ToolConfig
                        (credentials: src/core/models/runtime.py, RuntimeCredentials)
"""

from __future__ import annotations

from src.config.schema.tool_config import (
    ExecutionConfig,
    GatewayAdminConfig,
    GatewayConfig,
    GatewayHealthConfig,
    OutputConfig,
    SpecificationConfig,
    TargetConfig,
    ToolConfig,
)

__all__ = [
    "TargetConfig",
    "SpecificationConfig",
    "GatewayConfig",
    "GatewayAdminConfig",
    "GatewayHealthConfig",
    "ExecutionConfig",
    "OutputConfig",
    "ToolConfig",
]
