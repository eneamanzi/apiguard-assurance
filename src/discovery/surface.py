"""
src/discovery/surface.py

AttackSurface builder: translates a dereferenced spec dict into the
structured AttackSurface object consumed by test implementations.

This module is the boundary between the raw spec representation (a nested
Python dict from prance) and the tool's typed domain model (AttackSurface,
EndpointRecord, ParameterInfo from src.core.models).

Dialect-aware extraction
------------------------
The module adapts its extraction logic based on the SpecDialect passed in
from openapi.py. The two dialects differ in three areas:

    1. Base path resolution:
        Swagger 2.0   -- a global ``basePath`` key (e.g. "/api/v1") defines
                         the URL prefix shared by all operations. Path entries
                         in the ``paths`` object are *relative* to this prefix
                         (e.g. "/repos/search"). The canonical absolute path
                         is ``basePath + path`` (e.g. "/api/v1/repos/search").
                         This join is performed by _resolve_absolute_path().
        OpenAPI 3.x   -- the ``paths`` object already contains absolute paths.
                         Server-level prefixes live in ``servers[].url`` and
                         are intentionally not applied here: our tests send
                         requests to the Gateway base URL and rely on Kong's
                         route matching, not on path construction from the spec.

    2. Parameter schema location:
        OpenAPI 3.x   -- type/format are nested under ``param.schema.type``
                         and ``param.schema.format``.
        Swagger 2.0   -- type/format are declared directly on the parameter
                         object (``param.type``, ``param.format``) for
                         path/query/header/cookie params. ``in: body`` params
                         carry a ``schema`` child (used only for body
                         extraction, not ParameterInfo).

    3. Request body representation:
        OpenAPI 3.x   -- dedicated ``requestBody`` key on the operation object.
        Swagger 2.0   -- ``parameters`` entries with ``in: body`` (JSON body)
                         or ``in: formData`` (form fields). Content type comes
                         from operation-level or global ``consumes``.

    All other aspects (HTTP methods, security inheritance, tags,
    operationId, deprecated, path-level parameter inheritance) are identical
    between dialects.

What this module does NOT do:
    - Make HTTP requests.
    - Validate the spec structure (that is openapi.py's responsibility).
    - Apply server-level prefixes from OpenAPI 3.x ``servers`` objects.

Dependency rule:
    This module imports from stdlib, structlog, src.core.models, and
    src.core.exceptions only. It must never import from config/, tests/,
    report/, or engine.py.
"""

from __future__ import annotations

import posixpath
from collections.abc import Sequence

import structlog

from src.core.exceptions import OpenAPILoadError
from src.core.models import AttackSurface, EndpointRecord, ParameterInfo, SpecDialect

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OPENAPI_HTTP_METHODS: frozenset[str] = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
)

# Valid ``in`` values for ParameterInfo (both dialects).
OPENAPI_PARAMETER_LOCATIONS: frozenset[str] = frozenset({"path", "query", "header", "cookie"})

# Swagger 2.0 ``in`` values that represent the request body rather than a
# discrete parameter. These are extracted as body metadata and excluded from
# the ParameterInfo list.
_SWAGGER2_BODY_LOCATIONS: frozenset[str] = frozenset({"body", "formdata"})

# Default content types for Swagger 2.0 when ``consumes`` is absent.
_SWAGGER2_DEFAULT_CONSUMES_BODY: list[str] = ["application/json"]
_SWAGGER2_DEFAULT_CONSUMES_FORMDATA: list[str] = ["multipart/form-data"]

# Swagger 2.0 global spec keys.
_KEY_BASE_PATH: str = "basePath"

# Spec keys accessed during surface construction.
_KEY_PATHS: str = "paths"
_KEY_INFO: str = "info"
_KEY_TITLE: str = "title"
_KEY_VERSION: str = "version"
_KEY_SECURITY: str = "security"
_KEY_PARAMETERS: str = "parameters"
_KEY_OPERATION_ID: str = "operationId"
_KEY_TAGS: str = "tags"
_KEY_DEPRECATED: str = "deprecated"
_KEY_REQUEST_BODY: str = "requestBody"
_KEY_REQUIRED: str = "required"
_KEY_CONTENT: str = "content"
_KEY_SCHEMA: str = "schema"
_KEY_TYPE: str = "type"
_KEY_FORMAT: str = "format"
_KEY_NAME: str = "name"
_KEY_IN: str = "in"
_KEY_CONSUMES: str = "consumes"


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def build_attack_surface(
    spec: dict[str, object],
    dialect: SpecDialect,
    source_url: str | None = None,
) -> AttackSurface:
    """
    Translate a fully dereferenced spec dict into an AttackSurface.

    Called once by engine.py immediately after load_openapi_spec() returns.
    The returned AttackSurface is stored in TargetContext and remains
    immutable for the entire pipeline run.

    Args:
        spec: Fully dereferenced Swagger 2.0 or OpenAPI 3.x spec dict, as
              returned by src.discovery.openapi.load_openapi_spec().
              Must not contain any remaining $ref entries.
        dialect: Detected spec dialect (SWAGGER_2 or OPENAPI_3). Controls
                 how base paths and parameters are extracted.

    Returns:
        A frozen AttackSurface instance populated with one EndpointRecord
        per (path, method) pair declared in the spec.

    Raises:
        OpenAPILoadError: If the spec's paths object is missing or malformed
                          in a way that prevents surface construction.
    """
    log.debug("attack_surface_build_started", dialect=dialect)

    spec_title, spec_version = _extract_spec_metadata(spec)

    global_security: list[object] = _extract_global_security(spec)
    global_requires_auth: bool = _security_array_requires_auth(global_security)

    log.debug(
        "attack_surface_global_security_extracted",
        global_requires_auth=global_requires_auth,
        global_security_scheme_count=len(global_security),
    )

    # Extract the Swagger 2.0 basePath prefix (empty string for OpenAPI 3.x).
    base_path_prefix: str = _extract_base_path(spec, dialect)

    if base_path_prefix:
        log.debug(
            "attack_surface_swagger2_base_path_detected",
            base_path=base_path_prefix,
            detail=(
                "All Swagger 2.0 path entries are relative to this prefix. "
                "Absolute paths will be resolved as: basePath + path_entry."
            ),
        )

    # Global ``consumes`` is Swagger 2.0-only; empty list for OpenAPI 3.x.
    global_consumes: list[str] = _extract_global_consumes(spec, dialect)

    paths = spec.get(_KEY_PATHS)
    if not isinstance(paths, dict):
        raise OpenAPILoadError(
            message=(
                "Cannot build AttackSurface: 'paths' key is missing or not a "
                "mapping in the dereferenced spec. This indicates a spec that "
                "passed validation but has an unexpected structure."
            ),
            source_url=source_url,
        )

    endpoints: list[EndpointRecord] = []

    for raw_path, path_item in paths.items():
        raw_path_str = str(raw_path)

        if not isinstance(path_item, dict):
            log.warning(
                "attack_surface_skipping_malformed_path_item",
                path=raw_path_str,
                reason="path item is not a dict",
            )
            continue

        # Resolve the absolute path using dialect-appropriate logic.
        absolute_path: str = _resolve_absolute_path(
            raw_path=raw_path_str,
            base_path_prefix=base_path_prefix,
        )

        path_level_parameters: list[object] = _extract_raw_parameters(path_item)

        records = _build_records_for_path(
            path=absolute_path,
            path_item=path_item,
            path_level_parameters=path_level_parameters,
            global_requires_auth=global_requires_auth,
            global_consumes=global_consumes,
            dialect=dialect,
        )
        endpoints.extend(records)

    surface = AttackSurface(
        spec_title=spec_title,
        spec_version=spec_version,
        dialect=dialect,
        endpoints=endpoints,
    )

    log.info(
        "attack_surface_build_completed",
        spec_title=spec_title,
        spec_version=spec_version,
        dialect=dialect,
        total_endpoints=surface.total_endpoint_count,
        unique_paths=surface.unique_path_count,
        authenticated_endpoints=len(surface.get_authenticated_endpoints()),
        public_endpoints=len(surface.get_public_endpoints()),
        deprecated_endpoints=surface.deprecated_count,
        base_path_prefix=base_path_prefix if base_path_prefix else "(none)",
    )

    return surface


# ---------------------------------------------------------------------------
# Base path resolution — the core fix for Swagger 2.0 relative paths
# ---------------------------------------------------------------------------


def _extract_base_path(
    spec: dict[str, object],
    dialect: SpecDialect,
) -> str:
    """
    Extract the Swagger 2.0 ``basePath`` global prefix from the spec root.

    In Swagger 2.0, ``basePath`` is the URL segment shared by all operations.
    Path entries in the ``paths`` object are relative to this prefix.
    The canonical absolute path for an operation is ``basePath + path_entry``.

    This key is Swagger 2.0-specific. OpenAPI 3.x uses ``servers[].url`` to
    express the same concept, but we deliberately do not apply server-level
    prefixes for OpenAPI 3.x: test requests are sent to the Gateway base URL
    and rely on Kong's route matching, not on paths constructed from the spec.

    The returned value is normalized:
        - Leading slash is guaranteed.
        - Trailing slash is stripped to avoid double-slash when joining with
          a path entry that itself starts with "/".
        - The root basePath "/" is normalized to "" (empty string) so that
          joining it with any path entry is a no-op.

    Args:
        spec: Fully dereferenced spec dict.
        dialect: Detected spec dialect.

    Returns:
        Normalized basePath string (e.g. "/api/v1"), or empty string if
        the dialect is not SWAGGER_2 or if basePath is absent/root-only.
    """
    if dialect is not SpecDialect.SWAGGER_2:
        return ""

    raw_base_path = spec.get(_KEY_BASE_PATH)
    if not isinstance(raw_base_path, str) or not raw_base_path.strip():
        return ""

    # Normalize: ensure leading slash, strip trailing slash.
    normalized = "/" + raw_base_path.strip("/")

    # A basePath of "/" (root) is semantically equivalent to no prefix.
    if normalized == "/":
        return ""

    return normalized


def _resolve_absolute_path(
    raw_path: str,
    base_path_prefix: str,
) -> str:
    """
    Join a raw spec path entry with the basePath prefix into an absolute path.

    This function implements the double-prefix guard described in the module
    docstring: if ``raw_path`` already starts with ``base_path_prefix``, the
    prefix is not applied again. This prevents the ``/api/v1/api/v1/repos``
    corruption that would occur if a future spec provided absolute paths while
    also declaring a basePath.

    The join uses ``posixpath.join`` followed by slash normalization to handle
    edge cases such as double slashes at the join boundary. The result always
    starts with "/" because both ``base_path_prefix`` (if non-empty) and
    ``raw_path`` (per OpenAPI spec) must begin with "/".

    Decision table:
        base_path_prefix=""      + raw_path="/repos"        -> "/repos"
        base_path_prefix="/api/v1" + raw_path="/repos"      -> "/api/v1/repos"
        base_path_prefix="/api/v1" + raw_path="/api/v1/repos" -> "/api/v1/repos"
        base_path_prefix="/api"  + raw_path="/api/v1/repos" -> "/api/api/v1/repos"
            (intentional: prefix "/api" != prefix of raw_path "/api/v1")

    The last case is intentional because the guard compares the *full* prefix
    string, not a partial match. If the spec declares basePath="/api" but
    path entries begin with "/api/v1/...", this indicates a malformed spec and
    it is more honest to produce a slightly wrong path than to silently guess.

    Args:
        raw_path: Path entry from the spec's ``paths`` object (e.g. "/repos").
        base_path_prefix: Normalized basePath from _extract_base_path().

    Returns:
        Absolute API path string starting with "/".
    """
    if not base_path_prefix:
        # No prefix to apply: return the raw path as-is, ensuring leading slash.
        return "/" + raw_path.lstrip("/")

    # Double-prefix guard: do not prepend if the path is already absolute
    # and already starts with the full basePath prefix.
    if raw_path.startswith(base_path_prefix):
        return _normalize_slashes(raw_path)

    # Standard case: join prefix + relative path.
    joined = posixpath.join(base_path_prefix, raw_path.lstrip("/"))
    return _normalize_slashes(joined)


def _normalize_slashes(path: str) -> str:
    """
    Collapse any consecutive slashes in a path into a single slash.

    Preserves the leading slash that OpenAPI paths require. Does not alter
    the trailing character (some OpenAPI specs intentionally use trailing
    slashes to distinguish resource collections from individual resources,
    though this is uncommon).

    Args:
        path: A URL path string, possibly containing consecutive slashes.

    Returns:
        Path with all consecutive slashes collapsed to one.
    """
    # Split on "/" and filter out empty segments that arise from double slashes,
    # then rejoin. The leading "/" is restored explicitly.
    segments = [segment for segment in path.split("/") if segment]
    normalized = "/" + "/".join(segments)

    # Preserve trailing slash if the original had one (and it's not just "/").
    if path.endswith("/") and normalized != "/":
        normalized += "/"

    return normalized


# ---------------------------------------------------------------------------
# Metadata extraction
# ---------------------------------------------------------------------------


def _extract_spec_metadata(spec: dict[str, object]) -> tuple[str, str]:
    """Extract (title, version) from the spec info object. Dialect-independent."""
    info = spec.get(_KEY_INFO)
    if not isinstance(info, dict):
        return "Unknown", "Unknown"
    title = info.get(_KEY_TITLE)
    version = info.get(_KEY_VERSION)
    return (
        str(title) if title is not None else "Unknown",
        str(version) if version is not None else "Unknown",
    )


def _extract_global_security(spec: dict[str, object]) -> list[object]:
    """
    Extract the global security array from the spec root.

    Both Swagger 2.0 and OpenAPI 3.x use the same top-level ``security``
    array structure, so this function is dialect-independent.
    """
    security = spec.get(_KEY_SECURITY)
    if not isinstance(security, list):
        return []
    return security


def _extract_global_consumes(
    spec: dict[str, object],
    dialect: SpecDialect,
) -> list[str]:
    """
    Extract the global ``consumes`` array (Swagger 2.0 only).

    Returns an empty list for OpenAPI 3.x without inspecting the spec.
    For Swagger 2.0, this provides the default content type for operations
    that do not declare their own ``consumes`` field.
    """
    if dialect is not SpecDialect.SWAGGER_2:
        return []
    consumes = spec.get(_KEY_CONSUMES)
    if not isinstance(consumes, list):
        return []
    return [str(c) for c in consumes if c is not None]


# ---------------------------------------------------------------------------
# Per-path operation building
# ---------------------------------------------------------------------------


def _build_records_for_path(
    path: str,
    path_item: dict[str, object],
    path_level_parameters: list[object],
    global_requires_auth: bool,
    global_consumes: list[str],
    dialect: SpecDialect,
) -> list[EndpointRecord]:
    """Build all EndpointRecord objects for a single path item."""
    records: list[EndpointRecord] = []

    for key, operation in path_item.items():
        method = key.lower()
        if method not in OPENAPI_HTTP_METHODS:
            continue

        if not isinstance(operation, dict):
            log.warning(
                "attack_surface_skipping_malformed_operation",
                path=path,
                method=method.upper(),
                reason="operation is not a dict",
            )
            continue

        record = _build_single_record(
            path=path,
            method=method,
            operation=operation,
            path_level_parameters=path_level_parameters,
            global_requires_auth=global_requires_auth,
            global_consumes=global_consumes,
            dialect=dialect,
        )
        records.append(record)

    return records


def _build_single_record(
    path: str,
    method: str,
    operation: dict[str, object],
    path_level_parameters: list[object],
    global_requires_auth: bool,
    global_consumes: list[str],
    dialect: SpecDialect,
) -> EndpointRecord:
    """
    Build a single EndpointRecord from a spec operation object.

    Dialect differences handled here:

        OpenAPI 3.x:
            - All ``in`` values are path/query/header/cookie.
            - type/format extracted from ``param.schema.type / .format``.
            - Request body from dedicated ``requestBody`` key.

        Swagger 2.0:
            - ``in: body`` and ``in: formData`` represent the request body.
              They do NOT appear in EndpointRecord.parameters.
            - type/format extracted directly from ``param.type / .format``
              for path/query/header/cookie params.
            - Request body inferred from body/formData params + ``consumes``.

    Security inheritance is identical in both dialects.
    """
    # --- operationId ---
    operation_id_raw = operation.get(_KEY_OPERATION_ID)
    operation_id: str | None = str(operation_id_raw) if operation_id_raw is not None else None

    # --- tags ---
    tags_raw = operation.get(_KEY_TAGS)
    tags: list[str] = (
        [str(t) for t in tags_raw if t is not None] if isinstance(tags_raw, list) else []
    )

    # --- deprecated ---
    is_deprecated: bool = operation.get(_KEY_DEPRECATED) is True

    # --- requires_auth ---
    # OpenAPI security inheritance rule (identical in both dialects):
    #   - If the operation declares 'security' (even empty []), use it.
    #   - Otherwise inherit global security.
    operation_security_raw = operation.get(_KEY_SECURITY)
    if isinstance(operation_security_raw, list):
        requires_auth = _security_array_requires_auth(operation_security_raw)
    else:
        requires_auth = global_requires_auth

    # --- parameters ---
    operation_level_parameters = _extract_raw_parameters(operation)
    merged_all = _merge_parameters(
        path_level=path_level_parameters,
        operation_level=operation_level_parameters,
    )

    if dialect is SpecDialect.SWAGGER_2:
        # Split: body/formData params go to body extraction; the rest to ParameterInfo.
        regular_params = [
            p
            for p in merged_all
            if isinstance(p, dict)
            and str(p.get(_KEY_IN, "")).lower() not in _SWAGGER2_BODY_LOCATIONS
        ]
        body_params = [
            p
            for p in merged_all
            if isinstance(p, dict) and str(p.get(_KEY_IN, "")).lower() in _SWAGGER2_BODY_LOCATIONS
        ]
    else:
        regular_params = [p for p in merged_all if isinstance(p, dict)]
        body_params = []

    valid_parameters: list[ParameterInfo] = [
        p
        for p in (
            _build_parameter_info(param, dialect)
            for param in regular_params
            if isinstance(param, dict)
        )
        if p is not None
    ]

    # --- request body ---
    if dialect is SpecDialect.SWAGGER_2:
        request_body_required, request_body_content_types = _extract_request_body_swagger2(
            operation, body_params, global_consumes
        )
    else:
        request_body_required, request_body_content_types = _extract_request_body_oas3(operation)

    return EndpointRecord(
        path=path,
        method=method.upper(),
        operation_id=operation_id,
        tags=tags,
        requires_auth=requires_auth,
        is_deprecated=is_deprecated,
        parameters=valid_parameters,
        request_body_required=request_body_required,
        request_body_content_types=request_body_content_types,
    )


# ---------------------------------------------------------------------------
# Security resolution
# ---------------------------------------------------------------------------


def _security_array_requires_auth(security_array: list[object]) -> bool:
    """
    Return True if the security array implies authentication is required.

    Both dialects share the same semantics: empty list = no requirement,
    non-empty list = at least one scheme required.
    """
    return bool(security_array)


# ---------------------------------------------------------------------------
# Parameter extraction and merging
# ---------------------------------------------------------------------------


def _extract_raw_parameters(obj: dict[str, object]) -> list[object]:
    """Extract the raw parameters list from a path item or operation object."""
    params = obj.get(_KEY_PARAMETERS)
    if not isinstance(params, list):
        return []
    return params


def _merge_parameters(
    path_level: list[object],
    operation_level: list[object],
) -> list[object]:
    """
    Merge path-level and operation-level parameter lists.

    Operation-level parameters override path-level ones with the same
    (name, ``in``) combination. This rule is identical in both dialects.
    """
    merged: dict[tuple[str, str], object] = {}

    for param in path_level:
        if not isinstance(param, dict):
            continue
        name = str(param.get(_KEY_NAME, ""))
        location = str(param.get(_KEY_IN, ""))
        if name and location:
            merged[(name, location)] = param

    for param in operation_level:
        if not isinstance(param, dict):
            continue
        name = str(param.get(_KEY_NAME, ""))
        location = str(param.get(_KEY_IN, ""))
        if name and location:
            merged[(name, location)] = param

    return list(merged.values())


def _build_parameter_info(
    raw_param: dict[str, object],
    dialect: SpecDialect,
) -> ParameterInfo | None:
    """
    Build a ParameterInfo from a raw parameter object dict.

    Schema location by dialect:
        OpenAPI 3.x  -- type/format under ``param.schema.type / .format``.
        Swagger 2.0  -- type/format directly on the param object
                        (``param.type``, ``param.format``). If a ``schema``
                        child is present it takes precedence (consistent with
                        the OAS3 branch — some Swagger 2.0 tools emit it).

    Returns None if the parameter lacks a name or location.
    """
    name_raw = raw_param.get(_KEY_NAME)
    location_raw = raw_param.get(_KEY_IN)

    if not name_raw or not location_raw:
        log.warning(
            "attack_surface_skipping_malformed_parameter",
            raw_param_keys=list(raw_param.keys()),
            reason="missing 'name' or 'in' field",
        )
        return None

    name = str(name_raw).strip()
    location = str(location_raw).strip().lower()

    if location not in OPENAPI_PARAMETER_LOCATIONS:
        log.warning(
            "attack_surface_unknown_parameter_location",
            param_name=name,
            location=location,
            known_locations=sorted(OPENAPI_PARAMETER_LOCATIONS),
        )

    required_raw = raw_param.get(_KEY_REQUIRED)
    is_required: bool = (required_raw is True) or (location == "path")

    schema_type: str | None = None
    schema_format: str | None = None

    schema = raw_param.get(_KEY_SCHEMA)
    if isinstance(schema, dict):
        # Nested schema object: present in OAS3 always, and in Swagger 2.0
        # body/allOf params (which should already be filtered out before
        # this function is called, but safe to handle here too).
        type_raw = schema.get(_KEY_TYPE)
        format_raw = schema.get(_KEY_FORMAT)
        schema_type = str(type_raw) if type_raw is not None else None
        schema_format = str(format_raw) if format_raw is not None else None
    elif dialect is SpecDialect.SWAGGER_2:
        # Swagger 2.0 path/query/header/cookie params carry type/format directly.
        type_raw = raw_param.get(_KEY_TYPE)
        format_raw = raw_param.get(_KEY_FORMAT)
        schema_type = str(type_raw) if type_raw is not None else None
        schema_format = str(format_raw) if format_raw is not None else None

    return ParameterInfo(
        name=name,
        location=location,
        required=is_required,
        schema_type=schema_type,
        schema_format=schema_format,
    )


# ---------------------------------------------------------------------------
# Request body extraction — OpenAPI 3.x
# ---------------------------------------------------------------------------


def _extract_request_body_oas3(
    operation: dict[str, object],
) -> tuple[bool, list[str]]:
    """
    Extract request body metadata from an OpenAPI 3.x operation.

    OAS3 requestBody structure::

        requestBody:
          required: true
          content:
            application/json:
              schema: {...}
    """
    request_body = operation.get(_KEY_REQUEST_BODY)
    if not isinstance(request_body, dict):
        return False, []

    is_required: bool = request_body.get(_KEY_REQUIRED) is True
    content = request_body.get(_KEY_CONTENT)
    content_types: list[str] = list(content.keys()) if isinstance(content, dict) else []

    return is_required, content_types


# ---------------------------------------------------------------------------
# Request body extraction — Swagger 2.0
# ---------------------------------------------------------------------------


def _extract_request_body_swagger2(
    operation: dict[str, object],
    body_params: Sequence[object],
    global_consumes: list[str],
) -> tuple[bool, list[str]]:
    """
    Extract request body metadata from Swagger 2.0 body/formData parameters.

    Swagger 2.0 request body encoding:
        ``in: body``     -- single JSON (or other type) body parameter.
        ``in: formData`` -- one or more form fields constituting the body.

    Content-type resolution order:
        1. Operation-level ``consumes`` (most specific).
        2. Global ``consumes`` from the spec root.
        3. Hard-coded defaults: ``application/json`` for body, ``multipart/form-data``
           for formData.

    Args:
        operation: Operation object dict.
        body_params: Pre-filtered params with ``in: body`` or ``in: formData``.
        global_consumes: Global ``consumes`` from the spec root (may be empty).

    Returns:
        Tuple of (is_required, content_types).
    """
    if not body_params:
        return False, []

    is_required: bool = any(
        isinstance(p, dict) and p.get(_KEY_REQUIRED) is True for p in body_params
    )

    op_consumes_raw = operation.get(_KEY_CONSUMES)
    if isinstance(op_consumes_raw, list) and op_consumes_raw:
        content_types = [str(c) for c in op_consumes_raw if c is not None]
    elif global_consumes:
        content_types = global_consumes
    else:
        has_formdata = any(
            isinstance(p, dict) and str(p.get(_KEY_IN, "")).lower() == "formdata"
            for p in body_params
        )
        content_types = (
            _SWAGGER2_DEFAULT_CONSUMES_FORMDATA if has_formdata else _SWAGGER2_DEFAULT_CONSUMES_BODY
        )

    return is_required, content_types
