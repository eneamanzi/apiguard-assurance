"""
src/discovery/openapi.py

OpenAPI specification fetcher, dereferencer, and validator.

This module implements Phase 2 (OpenAPI Discovery) of the assessment pipeline.
It produces a fully dereferenced OpenAPI specification as a plain Python dict,
suitable for consumption by discovery/surface.py without further parsing.

Three sequential operations are performed:

    Phase 2a — Fetch and dereference:
        Download the OpenAPI spec from the configured URL or local path.
        Resolve all $ref pointers (including remote HTTP references) using
        prance.UnresolvingParser, producing a fully inline specification
        with no remaining $ref entries. This is required because test logic
        must be able to access any schema fragment without a resolver object.

    Phase 2b — Structural validation:
        Validate the dereferenced spec against the OpenAPI 3.x meta-schema
        using openapi-spec-validator. This catches malformed specs that
        prance accepted syntactically but that do not conform to the
        OpenAPI standard (missing required fields, invalid type values, etc.).

    Phase 2c — Content sanity checks:
        Verify that the spec contains at least one path with at least one
        operation. An empty spec is technically valid OpenAPI but produces
        an AttackSurface with zero endpoints, making the entire assessment
        meaningless. Surfacing this as a fatal error in Phase 2 is more
        useful than producing a report with 26 SKIP results.

Dependency rule:
    This module imports from stdlib, prance, openapi-spec-validator,
    structlog, src.core.exceptions, and src.core.models only.
    It must never import from config/, tests/, report/, or engine.py.
"""

from __future__ import annotations

import structlog
from openapi_spec_validator import OpenAPIV30SpecValidator, OpenAPIV31SpecValidator
from prance import ResolvingParser  # type: ignore[import-untyped]
from prance.util.url import ResolutionError as PranceResolutionError  # type: ignore[import-untyped]

from src.core.exceptions import OpenAPILoadError

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Minimum number of paths required for a meaningful attack surface.
# A spec with zero paths is valid OpenAPI but produces no testable endpoints.
MINIMUM_PATH_COUNT: int = 1

# Minimum number of operations (path + method pairs) across all paths.
MINIMUM_OPERATION_COUNT: int = 1

# Supported OpenAPI major versions. prance handles both; we validate
# with the appropriate validator class based on the detected version.
SUPPORTED_OPENAPI_MAJOR_VERSIONS: frozenset[str] = frozenset({"3"})

# The key in the dereferenced spec dict that holds the paths mapping.
OPENAPI_PATHS_KEY: str = "paths"
OPENAPI_INFO_KEY: str = "info"
OPENAPI_VERSION_KEY: str = "openapi"


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def load_openapi_spec(source_url: str) -> dict[str, object]:
    """
    Fetch, dereference, and validate an OpenAPI specification.

    This is the single public function of this module. It is called once by
    engine.py during Phase 2 (OpenAPI Discovery) and returns a fully
    dereferenced specification dict ready for surface.py to parse.

    The function is deterministic and idempotent: calling it twice with the
    same source_url on the same target produces an identical dict (assuming
    the target has not changed its spec between calls).

    Args:
        source_url: URL or local filesystem path of the OpenAPI specification.
                    HTTP/HTTPS URLs are fetched via prance's HTTP transport.
                    Filesystem paths must be absolute or relative to the
                    working directory. Both JSON and YAML formats are supported.
                    Example: "http://localhost:8000/api/swagger"
                    Example: "/etc/apiguard/local_spec.yaml"

    Returns:
        A fully dereferenced OpenAPI specification as a nested Python dict.
        All $ref entries have been resolved inline. The dict is a plain
        data structure with no prance or jsonschema objects embedded.

    Raises:
        OpenAPILoadError: For any of the following conditions:
            - Network error fetching the spec (connection refused, DNS failure).
            - HTTP error from the spec endpoint (404, 401, 500).
            - $ref resolution failure (circular reference, unreachable remote ref).
            - The spec does not conform to OpenAPI 3.x (validation failure).
            - The spec contains no paths or no operations.
            - The spec declares an unsupported OpenAPI version (e.g., 2.x Swagger).
    """
    log.info(
        "openapi_discovery_started",
        source_url=source_url,
    )

    # Phase 2a: fetch and dereference.
    dereferenced_spec = _fetch_and_dereference(source_url)

    # Check OpenAPI version before validation to provide a clear error
    # if the spec is Swagger 2.x rather than a validator-level failure.
    _assert_supported_version(dereferenced_spec, source_url)

    # Phase 2b: structural validation.
    _validate_spec_structure(dereferenced_spec, source_url)

    # Phase 2c: content sanity checks.
    _assert_spec_has_operations(dereferenced_spec, source_url)

    spec_info = dereferenced_spec.get(OPENAPI_INFO_KEY, {})
    if not isinstance(spec_info, dict):
        spec_info = {}

    paths_obj = dereferenced_spec.get(OPENAPI_PATHS_KEY, {})
    path_count = len(paths_obj) if isinstance(paths_obj, dict) else 0

    log.info(
        "openapi_discovery_completed",
        source_url=source_url,
        spec_title=spec_info.get("title", "Unknown"),
        spec_version=spec_info.get("version", "Unknown"),
        openapi_version=dereferenced_spec.get(OPENAPI_VERSION_KEY, "Unknown"),
        path_count=path_count,
    )

    return dereferenced_spec


# ---------------------------------------------------------------------------
# Phase 2a — Fetch and dereference
# ---------------------------------------------------------------------------


def _fetch_and_dereference(source_url: str) -> dict[str, object]:
    """
    Fetch the OpenAPI spec and resolve all $ref pointers into a flat dict.

    prance.ResolvingParser handles both HTTP URLs and local file paths.
    It fetches the root document, discovers all $ref entries recursively,
    fetches any remote references, and produces a single dict where every
    schema fragment is inlined. The result contains no $ref keys.

    Error handling strategy:
        prance raises different exception types depending on the failure mode
        and the transport layer (HTTP vs filesystem). Rather than listing
        every possible prance exception, we catch the two most specific
        prance types (PranceResolutionError for $ref failures) and then
        fall back to a broad Exception catch for transport-level failures.
        All cases are normalized to OpenAPILoadError.

        This broad catch is intentional and documented: it is the only
        location in the codebase where Exception is caught, and it exists
        specifically because prance's exception surface is not fully stable
        across versions. The caught exception's string representation is
        stored in OpenAPILoadError.underlying_error for diagnostics.

    Args:
        source_url: URL or filesystem path of the OpenAPI spec.

    Returns:
        Fully dereferenced spec as a nested dict.

    Raises:
        OpenAPILoadError: On any fetch or dereferencing failure.
    """
    log.debug(
        "openapi_fetching_spec",
        source_url=source_url,
    )

    try:
        parser = ResolvingParser(
            source_url,
            lazy=False,
            strict=False,
        )
    except PranceResolutionError as exc:
        raise OpenAPILoadError(
            message=(
                f"Failed to resolve one or more $ref pointers in the OpenAPI spec "
                f"at '{source_url}'. This may indicate a circular reference, an "
                f"unreachable remote $ref, or a malformed $ref path. "
                f"Underlying error: {exc}"
            ),
            source_url=source_url,
            underlying_error=str(exc),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        # Intentional broad catch: prance raises heterogeneous exception types
        # for network failures depending on the installed transport (requests vs
        # httpx) and prance version. All are normalized to OpenAPILoadError.
        # The noqa suppresses Ruff BLE001 (blind exception) at this specific line.
        raise OpenAPILoadError(
            message=(
                f"Failed to fetch or parse the OpenAPI spec from '{source_url}'. "
                f"Verify that the URL is reachable and returns a valid "
                f"OpenAPI 3.x JSON or YAML document. "
                f"Underlying error: {type(exc).__name__}: {exc}"
            ),
            source_url=source_url,
            underlying_error=f"{type(exc).__name__}: {exc}",
        ) from exc

    spec = parser.specification
    if not isinstance(spec, dict):
        raise OpenAPILoadError(
            message=(
                f"OpenAPI spec at '{source_url}' did not produce a dict after "
                f"dereferencing. Got: {type(spec).__name__}. "
                "Ensure the spec root is a YAML/JSON mapping, not a list or scalar."
            ),
            source_url=source_url,
        )

    log.debug(
        "openapi_spec_dereferenced",
        source_url=source_url,
        top_level_keys=sorted(spec.keys()),
    )

    return spec  # pyright: ignore[reportReturnType]


# ---------------------------------------------------------------------------
# Version guard
# ---------------------------------------------------------------------------


def _assert_supported_version(
    spec: dict[str, object],
    source_url: str,
) -> None:
    """
    Verify that the spec declares a supported OpenAPI major version.

    We support OpenAPI 3.x only. Swagger 2.x (identified by a top-level
    'swagger' key rather than 'openapi') is explicitly rejected with a
    clear message, because the Forgejo API spec is OpenAPI 3.x and the
    tool's path/parameter parsing assumes 3.x semantics.

    Args:
        spec: Dereferenced spec dict.
        source_url: Original source URL, used only for error messages.

    Raises:
        OpenAPILoadError: If the spec is Swagger 2.x or declares an
                          unsupported OpenAPI 3.x sub-version.
    """
    # Swagger 2.x uses a 'swagger' key at the root.
    if "swagger" in spec:
        swagger_version = spec.get("swagger", "2.x")
        raise OpenAPILoadError(
            message=(
                f"The spec at '{source_url}' appears to be Swagger {swagger_version} "
                "(OpenAPI 2.x), which is not supported by this tool. "
                "The tool requires OpenAPI 3.x. If the target exposes both versions, "
                "configure openapi_spec_url to point to the 3.x endpoint."
            ),
            source_url=source_url,
        )

    openapi_field = spec.get(OPENAPI_VERSION_KEY)
    if not isinstance(openapi_field, str):
        raise OpenAPILoadError(
            message=(
                f"The spec at '{source_url}' does not declare an 'openapi' version "
                "field at the root level. This is required by the OpenAPI 3.x spec. "
                "Ensure the document is a valid OpenAPI 3.x specification."
            ),
            source_url=source_url,
        )

    major_version = openapi_field.split(".")[0]
    if major_version not in SUPPORTED_OPENAPI_MAJOR_VERSIONS:
        raise OpenAPILoadError(
            message=(
                f"Unsupported OpenAPI version '{openapi_field}' in spec at "
                f"'{source_url}'. Supported major versions: "
                f"{sorted(SUPPORTED_OPENAPI_MAJOR_VERSIONS)}."
            ),
            source_url=source_url,
            underlying_error=f"openapi field value: {openapi_field!r}",
        )

    log.debug(
        "openapi_version_supported",
        openapi_version=openapi_field,
        major_version=major_version,
    )


# ---------------------------------------------------------------------------
# Phase 2b — Structural validation
# ---------------------------------------------------------------------------


def _validate_spec_structure(
    spec: dict[str, object],
    source_url: str,
) -> None:
    """
    Validate the dereferenced spec against the OpenAPI 3.x meta-schema.

    Uses openapi-spec-validator, which implements the official OpenAPI
    Initiative JSON Schema validators for both 3.0.x and 3.1.x.
    The validator is selected based on the declared 'openapi' version field.

    Validation is performed on the dereferenced spec (all $ref resolved)
    rather than the raw spec. This ensures that referenced schemas are
    also validated, not just the root document.

    openapi-spec-validator raises openapi_spec_validator.OpenAPIValidationError
    (a subclass of jsonschema.ValidationError) on failure. We catch it and
    convert to OpenAPILoadError with the validator's human-readable message.

    Args:
        spec: Fully dereferenced spec dict.
        source_url: Original source URL, used only for error messages.

    Raises:
        OpenAPILoadError: If the spec fails OpenAPI 3.x structural validation.
    """
    openapi_version: str = str(spec.get(OPENAPI_VERSION_KEY, "3.0.0"))

    validator_class: type[OpenAPIV31SpecValidator] | type[OpenAPIV30SpecValidator]

    # Select the appropriate validator based on the minor version.
    # OpenAPI 3.1.x has a different meta-schema from 3.0.x.
    if openapi_version.startswith("3.1"):
        validator_class = OpenAPIV31SpecValidator
        version_label = "3.1.x"
    else:
        validator_class = OpenAPIV30SpecValidator
        version_label = "3.0.x"

    log.debug(
        "openapi_validating_spec",
        source_url=source_url,
        openapi_version=openapi_version,
        validator=version_label,
    )

    try:
        validator = validator_class(spec)
        validator.validate()
    except Exception as exc:  # noqa: BLE001
        # openapi-spec-validator raises jsonschema.ValidationError or its
        # own OpenAPIValidationError. Both carry a human-readable message
        # in str(exc). Broad catch is intentional here for the same reason
        # as in _fetch_and_dereference: the exception hierarchy depends on
        # the installed version of openapi-spec-validator and jsonschema.
        raise OpenAPILoadError(
            message=(
                f"OpenAPI spec at '{source_url}' failed {version_label} structural "
                f"validation. The spec is syntactically valid YAML/JSON but does not "
                f"conform to the OpenAPI {version_label} schema. "
                f"Validation error: {exc}"
            ),
            source_url=source_url,
            underlying_error=str(exc),
        ) from exc

    log.debug(
        "openapi_structural_validation_passed",
        source_url=source_url,
        validator=version_label,
    )


# ---------------------------------------------------------------------------
# Phase 2c — Content sanity checks
# ---------------------------------------------------------------------------


def _assert_spec_has_operations(
    spec: dict[str, object],
    source_url: str,
) -> None:
    """
    Verify that the spec declares at least one path with at least one operation.

    An OpenAPI spec with an empty or absent 'paths' object is technically
    valid per the OpenAPI 3.x schema (paths is not required in 3.1.x),
    but produces an AttackSurface with zero endpoints. Running an assessment
    against such a surface would yield 26 SKIP results with no informational
    value. Surfacing this as a fatal error here is more honest.

    We count operations (path + method pairs) rather than just paths, because
    a spec with one path and no operations under it is equally meaningless.

    Args:
        spec: Fully dereferenced and validated spec dict.
        source_url: Original source URL, used only for error messages.

    Raises:
        OpenAPILoadError: If the spec has no paths or no HTTP operations.
    """
    # HTTP methods recognized as OpenAPI operations.
    # 'parameters', 'summary', 'description', 'servers' are non-operation keys.
    http_methods: frozenset[str] = frozenset(
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

    paths = spec.get(OPENAPI_PATHS_KEY)

    if not isinstance(paths, dict) or len(paths) < MINIMUM_PATH_COUNT:
        raise OpenAPILoadError(
            message=(
                f"OpenAPI spec at '{source_url}' declares no paths. "
                "An assessment against a spec with no endpoints produces no "
                "testable attack surface. Verify that the spec URL points to "
                "the correct document and that the 'paths' key is present."
            ),
            source_url=source_url,
        )

    total_operations = 0
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        total_operations += sum(1 for key in path_item if key.lower() in http_methods)

    if total_operations < MINIMUM_OPERATION_COUNT:
        raise OpenAPILoadError(
            message=(
                f"OpenAPI spec at '{source_url}' declares {len(paths)} path(s) "
                "but no HTTP operations (GET, POST, PUT, etc.) under any of them. "
                "Verify that the spec is complete and not a stub."
            ),
            source_url=source_url,
        )

    log.debug(
        "openapi_content_sanity_check_passed",
        source_url=source_url,
        path_count=len(paths),
        operation_count=total_operations,
    )
