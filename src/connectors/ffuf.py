"""
src/connectors/ffuf.py

FfufConnector: subprocess connector for ffuf, the path search of test
ext.0.1.ffuf.

Responsibility (connector layer):
    Run ffuf once per job (a base URL and its words), read each JSON output
    and return every response ffuf kept, unfiltered, in one ConnectorResult.
    It does not decide what a path means: the test re-verifies each one with
    the tool's client and judges it.

One run per base URL:
    ffuf's calibration (-ac) learns what "not found" looks like with random
    words in place of FUZZ, once per run. The services behind one gateway
    answer an unknown path differently (crAPI, 2026-10-21: identity 401 with
    49 bytes, community 404 with 19, workshop 404 with 179), so a single run
    over several base paths keeps hundreds of false candidates (627 of 836);
    one run per base path calibrates each.

Requests: unauthenticated GET only. ffuf never verifies TLS certificates
(InsecureSkipVerify in pkg/runner/simple.go of v2.3.0, no option to change
it), so the connector never passes the run's credentials or headers to it.

ffuf JSON output (-of json -o <file>), checked on ffuf v2.3.0 on the labs:

    {"commandline": "...", "time": "...", "config": {...},
     "results": [{"input": {"FUZZ": "user"}, "position": 1, "status": 401,
                  "length": 75, "words": 3, "lines": 1,
                  "content-type": "application/json", "redirectlocation": "",
                  "duration": 1234567, "url": "https://host/api/v1/user",
                  "host": "host", ...}]}

raw_output contract (ConnectorRawOutput keys):
    command       the ffuf commands, one per job, joined by " ; ", local
                  paths relativized and the temporary files shown as
                  ffuf_wordlist.txt and ffuf_result.json;
    command_json  the same;
    results       every result of every job, with "base_url" added;
    all_count     len(results);
    base_urls     the base URL of every job, in order (also those with no result).

Hardcoded flags (architectural invariants):
    -ac              ffuf's own calibration, per run.
    -mc all          every status is kept: the test decides, not a list of codes.
    -noninteractive  no interactive console.
    -s               silent: no banner or progress on the output.

Dependency rule:
    Imports from stdlib, structlog, src.connectors.base, src.core.exceptions
    only. Must never import from tests/, external_tests/, config/, or report/.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

import structlog

from src.connectors.base import BaseSubprocessConnector, ConnectorResult
from src.core.exceptions import ExternalToolError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# Flags hardcoded as architectural invariants (see module docstring).
_HARDCODED_FLAGS: list[str] = ["-ac", "-mc", "all", "-noninteractive", "-s"]

# The keyword ffuf replaces with each word.
_FUZZ_KEYWORD: str = "FUZZ"

# ffuf exits 0 when the search completed, whatever it found.
_FFUF_SUCCESS_EXIT_CODE: int = 0

# Seconds the subprocess may run after its own -maxtime before it is killed:
# ffuf stops itself at -maxtime and still writes its output.
_MAXTIME_GRACE_SECONDS: int = 15

# The flag that prints ffuf's version ("ffuf version: 2.3.0"); ffuf has no --version.
_VERSION_FLAG: str = "-V"
_VERSION_TIMEOUT_SECONDS: int = 10

# Clean names of the temporary files in the displayed commands.
_DISPLAY_WORDLIST: str = "ffuf_wordlist.txt"
_DISPLAY_RESULT: str = "ffuf_result.json"
_COMMAND_SEPARATOR: str = " ; "


@dataclass(frozen=True)
class FfufJob:
    """One ffuf run: the base URL (ending with '/') and the words tried under it."""

    base_url: str
    words: tuple[str, ...]


class FfufConnector(BaseSubprocessConnector):
    """
    Subprocess connector for ffuf (one run per base URL).

    Usage (called by the test's _invoke_connector()):
        result = connector.run(
            jobs=[FfufJob("https://host/api/v1/", ("users", "admin")), ...],
            timeout_seconds=600,
            per_request_timeout=10,
            rate_limit_rps=30,
        )
    """

    TOOL_NAME: ClassVar[str] = "ffuf"
    BINARY_NAME: ClassVar[str] = "ffuf"
    LOCAL_TOOLS_SUBDIR: ClassVar[str] = "ffuf"

    def get_version(self) -> str | None:
        """
        The version line of ffuf ("ffuf version: 2.3.0"), from ``ffuf -V``.

        ffuf has no ``--version`` flag (the base implementation's), so this
        override asks with ``-V``.

        Returns:
            str | None: The version line, or None if ffuf cannot be run.
        """
        binary_cmd = self._resolve_binary_path()
        if binary_cmd is None:
            return None
        try:
            result = subprocess.run(  # noqa: S603 -- [resolved binary path, static flag]
                [binary_cmd, _VERSION_FLAG],
                capture_output=True,
                text=True,
                timeout=_VERSION_TIMEOUT_SECONDS,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            log.debug("ffuf_version_discovery_failed", error=str(exc))
            return None
        for line in (result.stdout or result.stderr or "").splitlines():
            if line.strip():
                return line.strip()
        return None

    def run(  # type: ignore[override]
        self,
        jobs: list[FfufJob],
        timeout_seconds: int,
        per_request_timeout: int,
        rate_limit_rps: int,
    ) -> ConnectorResult:
        """
        Run ffuf once per job and return every response it kept.

        The time limit is shared by the jobs: each runs with ffuf's -maxtime
        set to what is left; when nothing is left, the search stops with a
        timeout.

        Args:
            jobs:                The base URLs and their words (FfufJob).
            timeout_seconds:     Wall-clock limit of the whole search.
            per_request_timeout: Timeout of each request (-timeout).
            rate_limit_rps:      Requests per second (-rate).

        Returns:
            ConnectorResult whose raw_output["results"] holds every result,
            each with the "base_url" of its job.

        Raises:
            ExternalToolError: ffuf not found, a run failed or produced no
                               readable output, or the time limit was reached.
        """
        binary_cmd = self._resolve_binary_path()
        if binary_cmd is None:
            raise ExternalToolError(
                message="ffuf binary not found. Run install_tools.sh or add ffuf to PATH.",
                tool_name=self.TOOL_NAME,
                exit_code=-1,
            )
        display_binary = self._relativize_display_path(binary_cmd)
        common = [
            "-rate",
            str(rate_limit_rps),
            "-timeout",
            str(per_request_timeout),
            *_HARDCODED_FLAGS,
        ]
        results: list[dict[str, Any]] = []
        commands: list[str] = []
        deadline = time.monotonic() + timeout_seconds
        start_ms = int(time.monotonic() * 1000)
        log.info(
            "ffuf_connector_start",
            jobs=len(jobs),
            words=sum(len(job.words) for job in jobs),
            rate_limit_rps=rate_limit_rps,
            timeout_seconds=timeout_seconds,
        )
        with tempfile.TemporaryDirectory(prefix="apiguard_ffuf_") as temp_dir_str:
            temp_dir = Path(temp_dir_str)
            for index, job in enumerate(jobs):
                remaining = int(deadline - time.monotonic())
                if remaining <= 0:
                    raise ExternalToolError(
                        message=(
                            f"ffuf reached the time limit of {timeout_seconds}s after "
                            f"{index} of {len(jobs)} base paths. Increase "
                            "'external_tools.ffuf.timeout_seconds' in config.yaml."
                        ),
                        tool_name=self.TOOL_NAME,
                        timed_out=True,
                    )
                wordlist = temp_dir / f"words_{index}.txt"
                wordlist.write_text("\n".join(job.words) + "\n", encoding="utf-8")
                output = temp_dir / f"result_{index}.json"
                url = job.base_url + _FUZZ_KEYWORD
                cmd = [
                    binary_cmd,
                    "-u",
                    url,
                    "-w",
                    str(wordlist),
                    *common,
                    "-maxtime",
                    str(remaining),
                    "-of",
                    "json",
                    "-o",
                    str(output),
                ]
                _stdout, exit_code = self._run_subprocess(
                    cmd=cmd,
                    timeout_seconds=remaining + _MAXTIME_GRACE_SECONDS,
                    tool_name=self.TOOL_NAME,
                )
                if exit_code != _FFUF_SUCCESS_EXIT_CODE:
                    raise ExternalToolError(
                        message=f"ffuf exited with code {exit_code} on {url}.",
                        tool_name=self.TOOL_NAME,
                        exit_code=exit_code,
                    )
                for item in self._read_output(output):
                    results.append({**item, "base_url": job.base_url})
                commands.append(
                    " ".join(
                        [display_binary, "-u", url, "-w", _DISPLAY_WORDLIST, *common]
                        + ["-of", "json", "-o", _DISPLAY_RESULT]
                    )
                )
        execution_time_ms = int(time.monotonic() * 1000) - start_ms
        log.info(
            "ffuf_connector_complete",
            results=len(results),
            execution_time_ms=execution_time_ms,
        )
        command = _COMMAND_SEPARATOR.join(commands)
        return ConnectorResult(
            tool_name=self.TOOL_NAME,
            tool_version=self.get_version(),
            raw_output={
                "command": command,
                "command_json": command,
                "results": results,
                "all_count": len(results),
                "base_urls": [job.base_url for job in jobs],
            },
            exit_code=_FFUF_SUCCESS_EXIT_CODE,
            execution_time_ms=execution_time_ms,
            timed_out=False,
        )

    def _read_output(self, output: Path) -> list[dict[str, Any]]:
        """
        The results of one ffuf run, from its JSON output file.

        Args:
            output: The file passed to ffuf with -o.

        Returns:
            The "results" list of the file.

        Raises:
            ExternalToolError: The file is missing or not ffuf's JSON output.
        """
        try:
            data = json.loads(output.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ExternalToolError(
                message=f"ffuf output could not be read: {exc}",
                tool_name=self.TOOL_NAME,
                exit_code=0,
            ) from exc
        found = data.get("results") if isinstance(data, dict) else None
        if not isinstance(found, list):
            raise ExternalToolError(
                message=(
                    "ffuf output has no results list: the ffuf version may differ from "
                    "external_tools.ffuf.expected_version."
                ),
                tool_name=self.TOOL_NAME,
                exit_code=0,
            )
        return found
