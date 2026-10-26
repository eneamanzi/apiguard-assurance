"""
src/connectors/schemathesis.py

SchemathesisConnector: subprocess connector for Schemathesis, a schema-driven
API testing tool. It generates valid and invalid requests from the OpenAPI
specification and runs checks; this connector runs the `schemathesis run` CLI
and parses its JUnit XML output into findings.

Checks run (the ones that answer guarantee 3.1, input validation):
    not_a_server_error           an input must not cause a 500 (the bad input
                                 reached the logic);
    negative_data_rejection      an invalid input must be rejected (a 4xx), not
                                 accepted;
    response_schema_conformance  the response matches the schema the spec
                                 declares.

A failing operation (a <testcase> with a <failure> in the JUnit output) is
returned as a finding; the calling test's oracle decides the outcome.

The tool is run unauthenticated (no credential is injected): its write requests
are refused, so nothing is created; a deep authenticated run is a deferred
follow-up (the backlog in docs/project/roadmap.md).

Discovery: `schemathesis` on PATH (installed by the `[schemathesis]` extra).

Dependency rule:
    Imports from stdlib, structlog, src.connectors.base, src.core.exceptions.
    Must never import from tests/, external_tests/, config/, discovery/, report/.
"""

from __future__ import annotations

import os
import tempfile
import time
import xml.etree.ElementTree as ET  # noqa: S405  # nosec B405 -- our own tool's output
from pathlib import Path
from typing import Any, ClassVar

import structlog

from src.connectors.base import BaseSubprocessConnector, ConnectorResult
from src.core.exceptions import ExternalToolError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# The checks that answer guarantee 3.1 (input validation).
_CHECKS: str = "not_a_server_error,negative_data_rejection,response_schema_conformance"

# Exit codes of a completed run: 0 (all passed), 1 (failures found). Anything
# else is an execution error.
_SUCCESS_EXIT_CODES: frozenset[int] = frozenset({0, 1})

# How long one generated request may take before Schemathesis gives up on it.
_REQUEST_TIMEOUT_MS: int = 5000


class SchemathesisConnector(BaseSubprocessConnector):
    """Subprocess connector for the `schemathesis run` CLI (tier: subprocess)."""

    TOOL_NAME: ClassVar[str] = "schemathesis"
    BINARY_NAME: ClassVar[str] = "schemathesis"
    DEFAULT_TIMEOUT_SECONDS: ClassVar[int] = 600

    def run(
        self,
        target_url: str,
        timeout_seconds: int,
        *,
        schema_source: str = "",
        ca_bundle: Path | None = None,
        max_examples: int = 5,
    ) -> ConnectorResult:
        """
        Run Schemathesis against the specification and return the failing operations.

        Args:
            target_url:     The base URL of the API (`--base-url`).
            timeout_seconds: Wall-clock limit for the whole run.
            schema_source:  The OpenAPI specification: a URL or a local file path.
            ca_bundle:      target.tls.ca_bundle, for `--request-tls-verify`.
            max_examples:   Hypothesis examples per operation (kept low to bound the run).

        Returns:
            ConnectorResult with raw_output['results'] = one dict per failing
            operation ({id, finding}).

        Raises:
            ExternalToolError: on timeout, a bad exit code, or unreadable output.
        """
        if not schema_source:
            raise ExternalToolError(
                message="schemathesis needs the OpenAPI schema source (schema_source).",
                tool_name=self.TOOL_NAME,
                exit_code=None,
            )
        binary = self._resolve_binary_path() or self.BINARY_NAME
        tls_verify = str(ca_bundle) if ca_bundle is not None else "true"
        cmd: list[str] = [
            binary,
            "run",
            schema_source,
            "--base-url",
            target_url,
            "--checks",
            _CHECKS,
            "--request-tls-verify",
            tls_verify,
            "--hypothesis-max-examples",
            str(max_examples),
            "--request-timeout",
            str(_REQUEST_TIMEOUT_MS),
            "--exclude-deprecated",
            "--no-color",
        ]
        fd, junit_path = tempfile.mkstemp(suffix=".xml", prefix="apiguard_schemathesis_")
        os.close(fd)
        display = [*cmd]
        if ca_bundle is not None:
            display[display.index(tls_verify)] = self._relativize_display_path(tls_verify)
        command, command_json = self._build_reproducible_commands(
            cmd_prefix=display, scan_target="", json_output_args=["--junit-xml", "schemathesis.xml"]
        )
        log.info("schemathesis_run_starting", base_url=target_url, schema=schema_source)
        start_ms = int(time.monotonic() * 1000)
        try:
            stdout, exit_code = self._run_subprocess(
                cmd=[*cmd, "--junit-xml", junit_path],
                timeout_seconds=timeout_seconds,
                tool_name=self.TOOL_NAME,
            )
            execution_ms = int(time.monotonic() * 1000) - start_ms
            if exit_code not in _SUCCESS_EXIT_CODES:
                preview = (stdout or "")[:300].replace("\n", " ")
                raise ExternalToolError(
                    message=(
                        f"schemathesis exited with code {exit_code}. Output: {preview!r}. "
                        "Check the schema URL is reachable and the base URL is correct."
                    ),
                    tool_name=self.TOOL_NAME,
                    exit_code=exit_code,
                )
            results = _parse_junit(junit_path)
        except ExternalToolError:
            raise
        except Exception as exc:  # noqa: BLE001 -- re-wrapped with context
            raise ExternalToolError(
                message=f"schemathesis connector unexpected error: {exc}",
                tool_name=self.TOOL_NAME,
                exit_code=None,
            ) from exc
        finally:
            self._cleanup(junit_path)

        raw_output: dict[str, Any] = {
            "command": command,
            "command_json": command_json,
            "results": results,
            "all_count": len(results),
        }
        log.info("schemathesis_run_complete", failures=len(results), execution_time_ms=execution_ms)
        return ConnectorResult(
            tool_name=self.TOOL_NAME,
            tool_version=self.get_version(),
            raw_output=raw_output,
            exit_code=exit_code,
            execution_time_ms=execution_ms,
            timed_out=False,
        )

    def _cleanup(self, path: str) -> None:
        """Delete the temp JUnit file, ignoring errors."""
        try:
            os.unlink(path)
        except OSError as exc:
            log.debug("schemathesis_temp_cleanup_failed", path=path, error=str(exc))


def _parse_junit(path: str) -> list[dict[str, str]]:
    """
    The failing operations in a Schemathesis JUnit file.

    Each <testcase name="METHOD /path"> with a <failure> child is one failing
    operation; its failure message is kept (truncated).

    Args:
        path: The JUnit XML file written by `--junit-xml`.

    Returns:
        One dict {id, finding} per failing operation (empty when all passed).

    Raises:
        ExternalToolError: when the file is missing or not valid XML.
    """
    try:
        tree = ET.parse(path)  # noqa: S314  # nosec B314 -- our own tool's output, a temp file we control
    except (OSError, ET.ParseError) as exc:
        raise ExternalToolError(
            message=f"schemathesis JUnit output could not be read from '{path}': {exc}",
            tool_name="schemathesis",
            exit_code=0,
        ) from exc
    findings: list[dict[str, str]] = []
    for testcase in tree.iter("testcase"):
        failure = testcase.find("failure")
        if failure is None:
            continue
        name = testcase.get("name", "unknown operation")
        message = (failure.get("message") or failure.text or "check failed").strip()
        findings.append({"id": name, "finding": message[:500]})
    return findings
