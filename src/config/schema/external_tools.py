"""
src/config/schema/external_tools.py

Re-export shim.  The authoritative definitions live in src/core/models/external_tools.py
so that TargetContext (in core/) can hold ExternalToolsConfig without violating the
unidirectional dependency rule (core/ must not import from config/).

All callers that import from this module continue to work unchanged.
"""

from src.core.models.external_tools import (
    BaseExternalToolConfig,
    ExternalToolsConfig,
    NucleiConfig,
    TestsslConfig,
)

__all__ = [
    "BaseExternalToolConfig",
    "ExternalToolsConfig",
    "NucleiConfig",
    "TestsslConfig",
]
