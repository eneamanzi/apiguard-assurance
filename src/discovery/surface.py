"""
src/discovery/surface.py

AttackSurface builder: translates a dereferenced OpenAPI spec dict into the
structured AttackSurface object consumed by test implementations.

This module is the boundary between the raw OpenAPI representation (a nested
Python dict from prance) and the tool's typed domain model (AttackSurface,
EndpointRecord, ParameterInfo from src.core.models).

After this module runs, no other component in the tool accesses the raw
OpenAPI dict. All endpoint knowledge is accessed through AttackSurface's
typed filter methods.

Translation responsibilities:
    - Iterate over all (path, method) operation pairs in the spec.
    - Derive requires_auth from OpenAPI security declarations, respecting
      the OpenAPI 3.x inheritance rule: operation-level security overrides
      global security; an empty security array means public (no auth).
    - Extract and type ParameterInfo from the parameters array of each operation.
    - Extract deprecation status, operationId, tags, and request body metadata.
    - Populate AttackSurface.spec_title and spec_version from the info object.

What this module does NOT do:
    - Substitute path template parameters ({owner}, {repo}) with real values.
      That is the test's responsibility at request time.
    - Validate the spec structure. That is openapi.py's responsibility.
    - Make HTTP requests. All information is derived from the static spec.

Dependency rule:
    This module imports from stdlib, structlog, src.core.models, and
    src.core.exceptions only. It must never import from config/, tests/,
    report/, or engine.py.
"""

from __future__ import annotations

import structlog

from src.core.exceptions import OpenAPILoadError
from src.core.models import AttackSurface, EndpointRecord, ParameterInfo

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# HTTP methods recognized as OpenAPI operation keys within a path item object.
# Other keys in a path item ('summary', 'description', 'parameters', 'servers')
# are not operations and must be excluded from endpoint enumeration.
OPENAPI_HTTP_METHODS: frozenset[str] = frozenset(
    {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "trace",
    }
)

# OpenAPI parameter location values (the 'in' field of a parameter object).
OPENAPI_PARAMETER_LOCATIONS: frozenset[str] = frozenset(
    {
        "path",
        "query",
        "header",
        "cookie",
    }
)

# Keys in the OpenAPI spec accessed during surface construction.
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


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def build_attack_surface(spec: dict[str, object]) -> AttackSurface:
    """
    Translate a fully dereferenced OpenAPI spec dict into an AttackSurface.

    This function is called once by engine.py immediately after
    openapi.load_openapi_spec() returns, during Phase 2 (OpenAPI Discovery).
    The returned AttackSurface is stored in TargetContext and remains
    immutable for the entire pipeline run.

    The function performs a single pass over the spec's paths object,
    extracting one EndpointRecord per (path, method) operation pair.
    The global security declaration is extracted first and used as the
    default for all operations that do not declare their own security array.

    Args:
        spec: Fully dereferenced OpenAPI 3.x specification dict, as returned
              by src.discovery.openapi.load_openapi_spec(). Must not contain
              any remaining $ref entries.

    Returns:
        A frozen AttackSurface instance populated with one EndpointRecord
        per (path, method) pair declared in the spec.

    Raises:
        OpenAPILoadError: If the spec's paths object is missing or malformed
                          in a way that prevents surface construction. This
                          should not occur if openapi.py's validation passed,
                          but is guarded against defensively.
    """
    log.debug("attack_surface_build_started")

    # Extract metadata from the info object.
    spec_title, spec_version = _extract_spec_metadata(spec)

    # Extract the global security declaration.
    # Used as default for operations without an explicit security array.
    global_security: list[object] = _extract_global_security(spec)
    global_requires_auth: bool = _security_array_requires_auth(global_security)

    log.debug(
        "attack_surface_global_security_extracted",
        global_requires_auth=global_requires_auth,
        global_security_scheme_count=len(global_security),
    )

    # Extract all paths.
    paths = spec.get(_KEY_PATHS)
    if not isinstance(paths, dict):
        raise OpenAPILoadError(
            message=(
                "Cannot build AttackSurface: 'paths' key is missing or not a "
                "mapping in the dereferenced spec. This indicates a spec that "
                "passed validation but has an unexpected structure."
            ),
        )

    # Build one EndpointRecord per (path, method) operation pair.
    endpoints: list[EndpointRecord] = []

    for raw_path, path_item in paths.items():
        path = str(raw_path)

        if not isinstance(path_item, dict):
            log.warning(
                "attack_surface_skipping_malformed_path_item",
                path=path,
                reason="path item is not a dict",
            )
            continue

        # Path-level parameters declared in the path item object.
        # These are inherited by all operations under this path unless
        # overridden at the operation level (OpenAPI 3.x spec, Section 4.7.9).
        path_level_parameters: list[object] = _extract_raw_parameters(path_item)

        records = _build_records_for_path(
            path=path,
            path_item=path_item,
            path_level_parameters=path_level_parameters,
            global_requires_auth=global_requires_auth,
        )
        endpoints.extend(records)

    surface = AttackSurface(
        spec_title=spec_title,
        spec_version=spec_version,
        endpoints=endpoints,
    )

    log.info(
        "attack_surface_build_completed",
        spec_title=spec_title,
        spec_version=spec_version,
        total_endpoints=surface.total_endpoint_count,
        unique_paths=surface.unique_path_count,
        authenticated_endpoints=len(surface.get_authenticated_endpoints()),
        public_endpoints=len(surface.get_public_endpoints()),
        deprecated_endpoints=surface.deprecated_count,
    )

    return surface


# ---------------------------------------------------------------------------
# Metadata extraction
# ---------------------------------------------------------------------------


def _extract_spec_metadata(spec: dict[str, object]) -> tuple[str, str]:
    """
    Extract the spec title and version from the OpenAPI info object.

    Both fields are used in the HTML report header and in structured logs.
    Defaults to "Unknown" if the info object is absent or incomplete,
    rather than raising — missing metadata does not affect assessment correctness.

    Args:
        spec: Root-level dereferenced spec dict.

    Returns:
        Tuple of (title, version) as strings.
    """
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
    Extract the global security array from the root of the spec.

    The global security array defines the default security requirements
    for all operations that do not declare their own security field.

    OpenAPI 3.x global security format:
        security:
          - bearerAuth: []
          - apiKeyAuth: []

    Each element is a Security Requirement Object (a dict mapping scheme
    names to scope lists). An empty list means no global security is declared.

    Args:
        spec: Root-level dereferenced spec dict.

    Returns:
        The security array as a list, or an empty list if absent.
    """
    security = spec.get(_KEY_SECURITY)
    if not isinstance(security, list):
        return []
    return security


# ---------------------------------------------------------------------------
# Per-path operation building
# ---------------------------------------------------------------------------


def _build_records_for_path(
    path: str,
    path_item: dict[str, object],
    path_level_parameters: list[object],
    global_requires_auth: bool,
) -> list[EndpointRecord]:
    """
    Build all EndpointRecord objects for a single OpenAPI path item.

    Iterates over all keys in the path item dict. Keys matching
    OPENAPI_HTTP_METHODS are operation objects; all other keys are
    path item metadata and are skipped.

    Args:
        path: The API path string, e.g. '/api/v1/repos/{owner}/{repo}'.
        path_item: The path item object dict from the spec.
        path_level_parameters: Parameters declared at path level,
                                inherited by all operations under this path.
        global_requires_auth: Default auth requirement from global security.

    Returns:
        List of EndpointRecord, one per HTTP method declared in the path item.
    """
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
        )
        records.append(record)

    return records


def _build_single_record(
    path: str,
    method: str,
    operation: dict[str, object],
    path_level_parameters: list[object],
    global_requires_auth: bool,
) -> EndpointRecord:
    """
    Build a single EndpointRecord from an OpenAPI operation object.

    Extracts all fields required by EndpointRecord:
        - operationId, tags, deprecated from the operation object.
        - requires_auth from operation-level or global security declaration.
        - parameters by merging path-level and operation-level parameters,
          with operation-level taking precedence (OpenAPI override semantics).
        - request body metadata (required, content types).

    Args:
        path: API path string.
        method: HTTP method, lowercase.
        operation: Operation object dict from the spec.
        path_level_parameters: Parameters inherited from the path item.
        global_requires_auth: Default auth requirement.

    Returns:
        A fully populated, frozen EndpointRecord.
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
    deprecated_raw = operation.get(_KEY_DEPRECATED)
    is_deprecated: bool = deprecated_raw is True

    # --- requires_auth ---
    # OpenAPI 3.x security inheritance rule:
    #   1. If the operation declares 'security' (even an empty list), use it.
    #   2. Otherwise, inherit the global security declaration.
    # An empty 'security: []' at the operation level explicitly marks the
    # operation as public, overriding even a global security requirement.
    operation_security_raw = operation.get(_KEY_SECURITY)
    if isinstance(operation_security_raw, list):
        # Operation has an explicit security declaration — use it.
        requires_auth = _security_array_requires_auth(operation_security_raw)
    else:
        # No operation-level security — inherit from global.
        requires_auth = global_requires_auth

    # --- parameters ---
    # Merge path-level and operation-level parameters.
    # Operation-level parameters override path-level ones with the same
    # (name, in) combination (OpenAPI 3.x spec, Section 4.8.12).
    operation_level_parameters = _extract_raw_parameters(operation)
    merged_parameters = _merge_parameters(
        path_level=path_level_parameters,
        operation_level=operation_level_parameters,
    )
    parameter_infos = [
        _build_parameter_info(raw_param)
        for raw_param in merged_parameters
        if isinstance(raw_param, dict)
    ]
    # Filter out None results from malformed parameter objects.
    valid_parameters: list[ParameterInfo] = [p for p in parameter_infos if p is not None]

    # --- request body ---
    request_body_required, request_body_content_types = _extract_request_body_info(operation)

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
    Determine whether a security array implies authentication is required.

    OpenAPI 3.x semantics:
        - Empty list []  -> no security requirement -> requires_auth = False
        - Non-empty list -> at least one scheme required -> requires_auth = True
        - Each element is a Security Requirement Object (dict). An element
          with all empty scope lists still counts as a security requirement.

    Args:
        security_array: The 'security' array from a spec level (global or
                        operation). Must be a list (not None).

    Returns:
        True if the array contains at least one non-empty Security Requirement
        Object, False if the array is empty.
    """
    if not security_array:
        return False

    # At least one element: authentication is declared as required.
    # We do not inspect the content of individual requirement objects here:
    # the presence of any element is sufficient to declare auth required.
    # The specific scheme (bearer, apiKey, etc.) is not relevant to the
    # tool's auth bypass tests, which operate at the HTTP level.
    return True


# ---------------------------------------------------------------------------
# Parameter extraction and merging
# ---------------------------------------------------------------------------


def _extract_raw_parameters(obj: dict[str, object]) -> list[object]:
    """
    Extract the raw parameters list from a path item or operation object.

    Returns an empty list if 'parameters' is absent or not a list,
    rather than raising — malformed parameters are logged at WARNING level
    and skipped, not treated as fatal.

    Args:
        obj: A path item or operation object dict.

    Returns:
        The parameters list, or an empty list.
    """
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

    Per OpenAPI 3.x Section 4.8.12, operation-level parameters override
    path-level parameters with the same (name, 'in') combination.
    Parameters unique to either level are included as-is.

    Merging strategy:
        1. Build a dict keyed by (name, in) from path-level parameters.
        2. For each operation-level parameter, insert or overwrite the entry.
        3. Return the values of the merged dict.

    Args:
        path_level: Parameters declared at the path item level.
        operation_level: Parameters declared at the operation level.

    Returns:
        Merged list of raw parameter objects, with duplicates resolved.
    """
    # Key: (name, location) tuple for deduplication.
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


def _build_parameter_info(raw_param: dict[str, object]) -> ParameterInfo | None:
    """
    Build a ParameterInfo from a raw OpenAPI parameter object dict.

    Returns None if the parameter lacks a name or location, logging a
    WARNING. These are required fields per OpenAPI 3.x; their absence
    indicates a malformed spec that passed validation (lenient validator)
    or a prance dereferencing artifact.

    Args:
        raw_param: A single parameter object dict from the spec.

    Returns:
        A ParameterInfo instance, or None if the parameter is malformed.
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

    # Path parameters are always required per OpenAPI 3.x.
    required_raw = raw_param.get(_KEY_REQUIRED)
    is_required: bool = (required_raw is True) or (location == "path")

    # Extract schema type and format from the nested schema object.
    schema_type: str | None = None
    schema_format: str | None = None

    schema = raw_param.get(_KEY_SCHEMA)
    if isinstance(schema, dict):
        type_raw = schema.get(_KEY_TYPE)
        format_raw = schema.get(_KEY_FORMAT)
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
# Request body extraction
# ---------------------------------------------------------------------------


def _extract_request_body_info(
    operation: dict[str, object],
) -> tuple[bool, list[str]]:
    """
    Extract request body metadata from an operation object.

    OpenAPI 3.x requestBody structure:
        requestBody:
          required: true
          content:
            application/json:
              schema: {...}
            application/xml:
              schema: {...}

    Args:
        operation: Operation object dict.

    Returns:
        Tuple of (is_required, content_types) where:
            is_required: True if requestBody.required is true.
            content_types: List of declared media type strings,
                           e.g. ['application/json', 'application/xml'].
    """
    request_body = operation.get(_KEY_REQUEST_BODY)
    if not isinstance(request_body, dict):
        return False, []

    required_raw = request_body.get(_KEY_REQUIRED)
    is_required: bool = required_raw is True

    content = request_body.get(_KEY_CONTENT)
    content_types: list[str] = list(content.keys()) if isinstance(content, dict) else []

    return is_required, content_types
