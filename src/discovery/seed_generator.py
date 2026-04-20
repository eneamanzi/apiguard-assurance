"""
src/discovery/seed_generator.py

Path-seed template generator for the APIGuard Assurance tool.

Responsibility
--------------
This module provides the logic behind the ``apiguard generate-seed`` CLI command.
Given an OpenAPI specification source (HTTP URL or local filesystem path), it:

    1. Fetches or reads the raw specification text.
    2. Parses the JSON or YAML into a Python dict.
    3. Traverses the ``paths`` object and collects all unique ``{param}`` names
       declared across every path template.
    4. Returns a sorted, deduplicated list of parameter names.

The caller (``cli.py``) renders these names into a YAML template with
``FILL_ME`` placeholders that the operator can paste under the ``target:``
section of ``config.yaml``.

Design constraints
------------------
- This module does NOT use ``prance`` for ``$ref`` dereferencing.  Path
  template strings are top-level keys in the ``paths`` mapping and are never
  embedded inside ``$ref`` entries, so full dereferencing is unnecessary.
  This keeps the command fast and removes the dependency on the target being
  reachable for spec validation purposes.

- The module does NOT perform OpenAPI spec validation.  The ``generate-seed``
  command is intended to run before the full assessment, potentially before all
  target infrastructure is up.  A malformed spec produces a clear parse error
  via the standard ``json`` / ``yaml`` module exception chain.

- Fetch timeout is configurable and defaults to a conservative value that
  avoids hanging on unresponsive spec URLs.

Dependency rule
---------------
This module imports from stdlib (``json``, ``re``, ``pathlib``) and third-party
``httpx`` and ``yaml``.  It must never import from ``src.config``, ``src.core``,
``src.tests``, ``src.report``, or ``src.engine``.

The ``src.tests.helpers.path_resolver`` module shares the ``{param}`` extraction
regex but is not imported here to preserve the strict one-way dependency rule:
``discovery/`` must not import from ``tests/``.  The regex is defined locally.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

import httpx
import structlog
import yaml

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Default HTTP fetch timeout for remote spec sources.
SPEC_FETCH_TIMEOUT_DEFAULT_SECONDS: float = 30.0

# Regex to extract path parameter names from OpenAPI path template strings.
# Mirrors the pattern in src/tests/helpers/path_resolver.py; defined locally
# to avoid importing from tests/ (dependency rule violation).
_PARAM_PATTERN: re.Pattern[str] = re.compile(r"\{([^}]+)\}")

# Key name for the ``paths`` object in both Swagger 2.0 and OpenAPI 3.x.
_SPEC_PATHS_KEY: str = "paths"


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def extract_path_param_names(
    spec_source: str,
    timeout_seconds: float = SPEC_FETCH_TIMEOUT_DEFAULT_SECONDS,
) -> list[str]:
    """
    Fetch or read an OpenAPI specification and return all unique path parameter names.

    The ``spec_source`` argument is interpreted as:
        - An HTTP/HTTPS URL if it starts with ``http://`` or ``https://``.
        - A local filesystem path otherwise.

    Only path template strings (the keys of the ``paths`` object) are scanned.
    Response/request body schemas are not inspected: they do not contain path
    parameters.

    Parameter names are extracted using the same colon-split logic as the
    ``resolve_path_with_seed`` helper: ``{id:[0-9]+}`` normalises to ``"id"``.

    Args:
        spec_source:     URL or local path string pointing to the OpenAPI spec.
        timeout_seconds: HTTP fetch timeout in seconds (applies only to URL
                         sources).  Default: ``SPEC_FETCH_TIMEOUT_DEFAULT_SECONDS``.

    Returns:
        Sorted, deduplicated list of parameter name strings extracted from all
        path templates in the specification.  Empty list if the specification
        declares no parametric paths.

    Raises:
        SeedGeneratorFetchError:  If the spec cannot be retrieved (network
                                   error, HTTP error status, file not found).
        SeedGeneratorParseError:  If the spec text cannot be parsed as JSON
                                   or YAML, or if the parsed object has no
                                   ``paths`` mapping.
    """
    log.info(
        "seed_generator_extraction_started",
        spec_source=spec_source,
        timeout_seconds=timeout_seconds,
    )

    raw_text = _fetch_spec_text(spec_source, timeout_seconds)
    spec_dict = _parse_spec_text(raw_text, spec_source)
    param_names = _collect_param_names(spec_dict, spec_source)

    log.info(
        "seed_generator_extraction_completed",
        unique_param_count=len(param_names),
        params=param_names,
    )

    return param_names


def render_seed_template(
    param_names: list[str],
    spec_source: str,
) -> str:
    """
    Render a YAML path_seed template from a list of parameter names.

    Produces a YAML string that the operator can paste directly under the
    ``target:`` section of ``config.yaml``.  Every parameter name is listed
    with the placeholder value ``"FILL_ME"``.

    Args:
        param_names:  Ordered list of parameter name strings (e.g.
                      ``["owner", "repo", "id"]``).
        spec_source:  Original spec source string, included in the header
                      comment for traceability.

    Returns:
        YAML string containing the ``path_seed`` block and guidance comments.
        Empty parameter list produces a ``path_seed: {}`` block with a note.
    """
    header_lines: list[str] = [
        "# APIGuard path_seed template",
        f"# Generated from: {spec_source}",
        "#",
        "# Instructions:",
        "#   1. Replace every FILL_ME value with a real resource identifier on your target.",
        "#   2. Paste the path_seed block under the 'target:' section of config.yaml.",
        "#   3. Re-run the assessment to resolve parametric paths using real values.",
        "#",
        "# Why this matters:",
        "#   Without real values, parametric paths (e.g. /repos/{owner}/{repo})",
        "#   resolve to generic placeholders like /repos/1/1, which return 404",
        "#   before reaching the authentication middleware. The probe result is",
        "#   classified as INCONCLUSIVE_PARAMETRIC instead of ENFORCED or BYPASS.",
        "#",
    ]

    if not param_names:
        header_lines.append(
            "# No path parameters found in this specification. path_seed can be left empty."
        )
        body = "path_seed: {}"
        return "\n".join(header_lines) + "\n" + body + "\n"

    seed_lines: list[str] = ["path_seed:"]
    for name in param_names:
        seed_lines.append(f'  {name}: "FILL_ME"')

    return "\n".join(header_lines) + "\n" + "\n".join(seed_lines) + "\n"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _fetch_spec_text(spec_source: str, timeout_seconds: float) -> str:
    """
    Retrieve the raw text of the OpenAPI specification.

    Routes the request to the appropriate transport based on the scheme of
    ``spec_source``.  URL sources use ``httpx``; path sources use ``pathlib``.

    Args:
        spec_source:     URL or filesystem path string.
        timeout_seconds: Timeout for HTTP requests (ignored for local files).

    Returns:
        Raw specification text string (JSON or YAML, not yet parsed).

    Raises:
        SeedGeneratorFetchError: On network failure, HTTP error, or missing file.
    """
    parsed = urlparse(spec_source)
    is_url = parsed.scheme in ("http", "https")

    if is_url:
        return _fetch_from_url(spec_source, timeout_seconds)
    return _read_from_path(spec_source)


def _fetch_from_url(url: str, timeout_seconds: float) -> str:
    """
    Fetch the raw specification text over HTTP/HTTPS.

    Args:
        url:             HTTP/HTTPS URL string.
        timeout_seconds: Request timeout.

    Returns:
        Response body text.

    Raises:
        SeedGeneratorFetchError: On connection error or non-2xx HTTP status.
    """
    log.debug("seed_generator_fetching_url", url=url, timeout_seconds=timeout_seconds)

    try:
        response = httpx.get(url, timeout=timeout_seconds, follow_redirects=True)
        response.raise_for_status()
    except httpx.TimeoutException as exc:
        raise SeedGeneratorFetchError(
            spec_source=url,
            reason=f"HTTP request timed out after {timeout_seconds}s: {exc}",
        ) from exc
    except httpx.HTTPStatusError as exc:
        raise SeedGeneratorFetchError(
            spec_source=url,
            reason=(
                f"HTTP {exc.response.status_code} received when fetching spec. "
                f"Verify that the spec URL is correct and the server is reachable."
            ),
        ) from exc
    except httpx.RequestError as exc:
        raise SeedGeneratorFetchError(
            spec_source=url,
            reason=f"Connection error: {exc}",
        ) from exc

    log.debug(
        "seed_generator_url_fetched",
        url=url,
        status_code=response.status_code,
        content_length=len(response.text),
    )
    return response.text


def _read_from_path(path_str: str) -> str:
    """
    Read the raw specification text from a local filesystem path.

    Args:
        path_str: Absolute or relative filesystem path string.

    Returns:
        File content as a text string.

    Raises:
        SeedGeneratorFetchError: If the file does not exist or cannot be read.
    """
    spec_path = Path(path_str).resolve()
    log.debug("seed_generator_reading_local_file", resolved_path=str(spec_path))

    if not spec_path.exists():
        raise SeedGeneratorFetchError(
            spec_source=path_str,
            reason=f"File not found at resolved path: {spec_path}",
        )

    if not spec_path.is_file():
        raise SeedGeneratorFetchError(
            spec_source=path_str,
            reason=f"Path exists but is not a regular file: {spec_path}",
        )

    try:
        content = spec_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SeedGeneratorFetchError(
            spec_source=path_str,
            reason=f"File read error: {exc}",
        ) from exc

    log.debug("seed_generator_local_file_read", content_length=len(content))
    return content


def _parse_spec_text(raw_text: str, spec_source: str) -> dict[str, object]:
    """
    Parse raw JSON or YAML specification text into a Python dict.

    Attempts JSON first (faster and unambiguous).  Falls back to YAML if JSON
    parsing fails, since YAML is a superset of JSON and handles both formats.

    Args:
        raw_text:    Raw specification text.
        spec_source: Original source identifier, used in error messages.

    Returns:
        Parsed specification dict.

    Raises:
        SeedGeneratorParseError: If both JSON and YAML parsing fail, or if the
                                  parsed value is not a mapping type.
    """
    spec_dict: object

    # Try JSON first: it is unambiguous and faster than YAML.
    try:
        spec_dict = json.loads(raw_text)
        log.debug("seed_generator_parsed_as_json")
    except json.JSONDecodeError:
        # Not JSON. Try YAML (handles both YAML and JSON-as-YAML).
        try:
            spec_dict = yaml.safe_load(raw_text)
            log.debug("seed_generator_parsed_as_yaml")
        except yaml.YAMLError as exc:
            raise SeedGeneratorParseError(
                spec_source=spec_source,
                reason=f"Specification is neither valid JSON nor valid YAML: {exc}",
            ) from exc

    if not isinstance(spec_dict, dict):
        raise SeedGeneratorParseError(
            spec_source=spec_source,
            reason=(
                f"Parsed specification root is not a mapping (got {type(spec_dict).__name__}). "
                "A valid OpenAPI specification must be a YAML/JSON object at the root level."
            ),
        )

    return spec_dict


def _collect_param_names(
    spec_dict: dict[str, object],
    spec_source: str,
) -> list[str]:
    """
    Traverse the ``paths`` object and collect all unique path parameter names.

    Only path template strings (the dict keys of the ``paths`` mapping) are
    scanned.  No deep traversal into operation objects is performed.

    Args:
        spec_dict:   Parsed specification dict.
        spec_source: Original source identifier, used in warning messages.

    Returns:
        Sorted, deduplicated list of parameter name strings.

    Raises:
        SeedGeneratorParseError: If the ``paths`` key is absent or not a mapping.
    """
    paths = spec_dict.get(_SPEC_PATHS_KEY)

    if paths is None:
        raise SeedGeneratorParseError(
            spec_source=spec_source,
            reason=(
                "The specification has no 'paths' key. "
                "Verify that the source is a valid OpenAPI 2.0 or 3.x specification "
                "and not a different YAML/JSON document."
            ),
        )

    if not isinstance(paths, dict):
        raise SeedGeneratorParseError(
            spec_source=spec_source,
            reason=(
                f"The 'paths' key is present but contains a {type(paths).__name__} "
                "instead of a mapping. Cannot extract path parameters."
            ),
        )

    seen: set[str] = set()

    for raw_path in paths:
        path_str = str(raw_path)
        if "{" not in path_str:
            continue

        for match in _PARAM_PATTERN.finditer(path_str):
            full_content: str = match.group(1)
            param_name: str = full_content.split(":")[0].strip()
            if param_name:
                seen.add(param_name)

    total_paths = len(paths)
    parametric_paths = sum(1 for p in paths if "{" in str(p))
    log.debug(
        "seed_generator_path_scan_complete",
        total_paths=total_paths,
        parametric_paths=parametric_paths,
        unique_params_found=len(seen),
    )

    return sorted(seen)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class SeedGeneratorFetchError(Exception):
    """
    Raised when the OpenAPI specification cannot be retrieved.

    Covers network failures, HTTP error statuses, and missing local files.
    """

    def __init__(self, spec_source: str, reason: str) -> None:
        self.spec_source = spec_source
        self.reason = reason
        super().__init__(f"Cannot fetch spec from '{spec_source}': {reason}")


class SeedGeneratorParseError(Exception):
    """
    Raised when the retrieved specification text cannot be parsed into a valid dict.

    Covers JSON/YAML parse failures and structural issues (missing ``paths`` key).
    """

    def __init__(self, spec_source: str, reason: str) -> None:
        self.spec_source = spec_source
        self.reason = reason
        super().__init__(f"Cannot parse spec from '{spec_source}': {reason}")
