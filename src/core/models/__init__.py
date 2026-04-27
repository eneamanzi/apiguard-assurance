"""
src/core/models/__init__.py

Public API facade for the core/models package.

This file re-exports every public symbol from the sub-modules so that
existing import statements remain valid unchanged:

    from src.core.models import TestResult, Finding, ...   # still works
    from src.core.models import TransactionSummary         # still works
    from src.core.models import AttackSurface              # still works

Internal modules import directly from the sub-module that owns the symbol
(e.g. ``from src.core.models.enums import TestStatus``) to keep import
paths explicit and avoid hidden coupling through the facade. The facade
exists for external consumers (engine.py, context.py, evidence.py,
report/builder.py, tests/, cli.py, config/loader.py) that should not
need to know the internal package layout.

Symbol inventory by source module:

    enums.py        TestStatus, TestStrategy, SpecDialect

    http.py         EvidenceRecord, TransactionSummary

    surface.py      ParameterInfo, EndpointRecord, AttackSurface

    results.py      Finding, InfoNote, TestResult, ResultSet

    runtime.py      RuntimeCredentials,
                    RuntimeTest11Config,
                    RuntimeTest41Config, RuntimeTest42Config, RuntimeTest43Config,
                    RuntimeTest62Config, RuntimeTest64Config,
                    RuntimeTest72Config,
                    RuntimeTestsConfig
"""

from __future__ import annotations

from src.core.models.enums import SpecDialect, TestStatus, TestStrategy
from src.core.models.http import EvidenceRecord, TransactionSummary
from src.core.models.results import Finding, InfoNote, ResultSet, TestResult
from src.core.models.runtime import (
    RuntimeCredentials,
    RuntimeTest11Config,
    RuntimeTest41Config,
    RuntimeTest42Config,
    RuntimeTest43Config,
    RuntimeTest62Config,
    RuntimeTest64Config,
    RuntimeTest72Config,
    RuntimeTestsConfig,
)
from src.core.models.surface import AttackSurface, EndpointRecord, ParameterInfo

__all__ = [
    # enums.py
    "TestStatus",
    "TestStrategy",
    "SpecDialect",
    # http.py
    "EvidenceRecord",
    "TransactionSummary",
    # surface.py
    "ParameterInfo",
    "EndpointRecord",
    "AttackSurface",
    # results.py
    "Finding",
    "InfoNote",
    "TestResult",
    "ResultSet",
    # runtime.py
    "RuntimeCredentials",
    "RuntimeTest11Config",
    "RuntimeTest41Config",
    "RuntimeTest42Config",
    "RuntimeTest43Config",
    "RuntimeTest62Config",
    "RuntimeTest64Config",
    "RuntimeTest72Config",
    "RuntimeTestsConfig",
]
