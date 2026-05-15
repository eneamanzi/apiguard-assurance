"""
src/connectors/types/__init__.py

Shared type definitions used by families of connectors and by the
``ExternalToolTest`` subclasses that consume their output.

These are NOT connector implementations — they describe the SHAPE of raw
output dicts produced by external tools (TypedDict contracts).  Pydantic
domain models (e.g. ``Finding``, ``TestResult``) live in ``src/core/models/``;
generic per-connector raw-output contracts (``ConnectorRawOutput``) live in
``src/connectors/base.py``; this module hosts the TLS-specific (and future
JWT-specific, load-metrics-specific, …) sub-shapes shared between connector
producers and external-test consumers.

Re-exports the public types so callers can write::

    from src.connectors.types import TlsFinding
"""

from __future__ import annotations

from src.connectors.types.tls_findings import TlsFinding

__all__ = ["TlsFinding"]
