"""
src/connectors/__init__.py

Public API re-exports for the connectors package.

Importing from this package surface rather than directly from sub-modules
keeps import paths stable if the internal layout changes, and signals
explicitly what is part of the public interface vs internal implementation.

Usage in connector subclasses:
    from src.connectors import BaseSubprocessConnector, ConnectorResult

Usage in external_tests/:
    from src.connectors import BaseConnector, ConnectorResult
"""

from src.connectors.base import (
    BaseConnector,
    BaseLibraryConnector,
    BaseSubprocessConnector,
    ConnectorResult,
)

__all__ = [
    "BaseConnector",
    "BaseSubprocessConnector",
    "BaseLibraryConnector",
    "ConnectorResult",
]
