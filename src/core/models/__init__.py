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

    enums.py           TestStatus, TestStrategy, SpecDialect, ExitCode, NotRunReason

    http.py            EvidenceFile, EvidenceRecord, TransactionSummary

    surface.py         ParameterInfo, EndpointRecord, AttackSurface,
                       SecuritySchemeRecord, SecuritySchemeType

    results.py         Finding, InfoNote, TestResult, ResultSet, NotRunEntry

    runtime.py         RuntimeCredentials, SendAs, AuthType, CredentialLocation
                       (per-test parameters: in each test's module)

    resources.py       ResourceConfig, CreateRequest, DeleteRequest, ResourceAuth,
                       CREDENTIAL_VALUE, FIXED_PLACEHOLDERS, PLACEHOLDER_USERNAME,
                       PLACEHOLDER_PASSWORD, PLACEHOLDER_RANDOM

    tls.py             TlsSettings

    external_tools.py  BaseExternalToolConfig, TestsslConfig, NucleiConfig,
                       ExternalToolsConfig
"""

from __future__ import annotations

from src.core.models.enums import ExitCode, NotRunReason, SpecDialect, TestStatus, TestStrategy
from src.core.models.external_tools import (
    BaseExternalToolConfig,
    ExternalToolsConfig,
    NucleiConfig,
    TestsslConfig,
)
from src.core.models.http import EvidenceFile, EvidenceRecord, TransactionSummary
from src.core.models.resources import (
    CREDENTIAL_VALUE,
    FIXED_PLACEHOLDERS,
    PLACEHOLDER_PASSWORD,
    PLACEHOLDER_RANDOM,
    PLACEHOLDER_USERNAME,
    CreateRequest,
    DeleteRequest,
    ResourceAuth,
    ResourceConfig,
)
from src.core.models.results import Finding, InfoNote, NotRunEntry, ResultSet, TestResult
from src.core.models.runtime import AuthType, CredentialLocation, RuntimeCredentials, SendAs
from src.core.models.surface import (
    AttackSurface,
    EndpointRecord,
    ParameterInfo,
    SecuritySchemeRecord,
    SecuritySchemeType,
)
from src.core.models.tls import TlsSettings

__all__ = [
    # enums.py
    "TestStatus",
    "TestStrategy",
    "SpecDialect",
    "ExitCode",
    "NotRunReason",
    # http.py
    "EvidenceFile",
    "EvidenceRecord",
    "TransactionSummary",
    # surface.py
    "ParameterInfo",
    "EndpointRecord",
    "AttackSurface",
    "SecuritySchemeRecord",
    "SecuritySchemeType",
    # results.py
    "Finding",
    "InfoNote",
    "TestResult",
    "ResultSet",
    "NotRunEntry",
    # runtime.py
    "RuntimeCredentials",
    "SendAs",
    "AuthType",
    "CredentialLocation",
    # resources.py
    "ResourceConfig",
    "CreateRequest",
    "DeleteRequest",
    "ResourceAuth",
    "CREDENTIAL_VALUE",
    "FIXED_PLACEHOLDERS",
    "PLACEHOLDER_USERNAME",
    "PLACEHOLDER_PASSWORD",
    "PLACEHOLDER_RANDOM",
    # tls.py
    "TlsSettings",
    # external_tools.py
    "BaseExternalToolConfig",
    "TestsslConfig",
    "NucleiConfig",
    "ExternalToolsConfig",
]
