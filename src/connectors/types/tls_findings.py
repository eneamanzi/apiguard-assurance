"""
src/connectors/types/tls_findings.py

Shared shape for TLS findings produced by the TLS-class connectors
(``TestsslConnector``, ``SslyzeConnector``).  Both connectors normalise their
tool-specific output into a list of ``TlsFinding`` dicts, which the
``ext_test_1_5_tls_analysis`` oracle then consumes uniformly.

Required fields are the three the oracle needs to partition findings into
FAIL / NOTE / IGNORE buckets:

    id        -- finding identifier (e.g. "cert_chain_of_trust", "heartbleed")
    severity  -- one of CRITICAL / HIGH / MEDIUM / WARN / OK / INFO / LOW
    finding   -- human-readable description of what was detected

Optional fields capture metadata that some tools include and the oracle
opportunistically surfaces (CVE/CWE references in the report, IP/port for
testssl's per-host findings):

    cve, cwe  -- standards references when present
    ip, port  -- target identifiers (testssl only; sslyze omits them)

The TypedDict is structural, not nominal: connectors construct plain dicts
that conform to this shape; mypy validates the access pattern downstream.

Dependency rule:
    Imports from: typing only.
    Must never import from: tests/, external_tests/, config/, discovery/,
                             report/, engine.py.
"""

from __future__ import annotations

from typing import NotRequired, TypedDict


class TlsFinding(TypedDict):
    """Common shape for TLS findings produced by testssl.sh and sslyze."""

    id: str
    severity: str
    finding: str
    cve: NotRequired[str]
    cwe: NotRequired[str]
    ip: NotRequired[str]
    port: NotRequired[str]
