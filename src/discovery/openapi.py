"""
src/discovery/openapi.py

OpenAPI / Swagger specification fetcher, dereferencer, and validator.

This module implements Phase 2 (OpenAPI Discovery) of the assessment pipeline.
It produces a fully dereferenced specification as a plain Python dict and a
SpecDialect tag, both consumed by discovery/surface.py.

Supported dialects
------------------
    SWAGGER_2   Swagger 2.0  (top-level ``swagger: "2.0"`` key)
    OPENAPI_3   OpenAPI 3.x  (top-level ``openapi: "3.x"`` key, minor 0 or 1)

Design: detect-and-adapt
------------------------
The function does NOT reject Swagger 2.0 specs. Instead it detects the
dialect from the parsed root document and routes validation to the
appropriate validator class. Downstream modules (surface.py) receive the
dialect tag and apply matching extraction logic.

Three sequential phases
-----------------------
    Phase 2a — Fetch and dereference (with timeout watchdog):
        Download the spec and resolve all $ref pointers using
        _NonValidatingResolvingParser, a thin subclass of prance.ResolvingParser
        that overrides _validate() to perform $ref resolution only, skipping
        prance's backend validation step.

        Timeout implementation
        ----------------------
        Prance uses the requests library internally. requests has no default
        timeout (it waits indefinitely). To prevent the pipeline from hanging
        on an unresponsive spec URL, _fetch_and_dereference() runs the entire
        prance operation in a background thread via concurrent.futures and
        waits for it with an explicit timeout_seconds parameter. If the thread
        does not complete within the deadline, a TimeoutError is converted to
        OpenAPILoadError. The background thread may continue running briefly
        after abandonment (Python threads cannot be killed), but since the
        main thread raises immediately and the CLI process exits shortly after,
        this is acceptable for a CLI tool. It would NOT be acceptable in a
        long-running server context.

        Why subclassing prance is necessary
        ------------------------------------
        prance.ResolvingParser._validate() does two things in sequence:
          1. Resolves all $ref pointers via prance.util.resolver.RefResolver.
          2. Calls BaseParser._validate(), which invokes openapi-spec-validator
             on the fully-resolved spec.

        Step 2 fails for Swagger 2.0 specs because those specs can declare
        ``type: file`` on upload parameters. This is valid Swagger 2.0 syntax
        but is not a JSON Schema Draft 4 type. The subclass skips step 2;
        our own dialect-aware validation in Phase 2b replaces it.

    Phase 2b — Dialect detection and structural validation:
        Detect the dialect from the root-level version key and validate with
        the appropriate openapi-spec-validator class.

    Phase 2c — Content sanity checks:
        Verify that the spec contains at least one path with at least one
        operation.

Dependency rule:
    This module imports from stdlib, prance, openapi-spec-validator,
    structlog, src.core.exceptions, and src.core.models only.
    It must never import from config/, tests/, report/, or engine.py.
"""

from __future__ import annotations

import concurrent.futures

import structlog
from openapi_spec_validator import OpenAPIV30SpecValidator, OpenAPIV31SpecValidator
from prance import ResolvingParser  # type: ignore[import-untyped]
from prance.util.resolver import RefResolver  # type: ignore[import-untyped]
from prance.util.url import ResolutionError as PranceResolutionError  # type: ignore[import-untyped]

from src.core.exceptions import OpenAPILoadError
from src.core.models import SpecDialect

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MINIMUM_PATH_COUNT: int = 1
MINIMUM_OPERATION_COUNT: int = 1

_SWAGGER_KEY: str = "swagger"
_OPENAPI_KEY: str = "openapi"

_SUPPORTED_SWAGGER_MAJOR: str = "2"
_SUPPORTED_OPENAPI_MAJOR: str = "3"

OPENAPI_PATHS_KEY: str = "paths"
OPENAPI_INFO_KEY: str = "info"

# Default timeout used when load_openapi_spec() is called without an explicit
# timeout argument (e.g. from tests or scripts that bypass the config layer).
_DEFAULT_FETCH_TIMEOUT_SECONDS: float = 60.0


# ---------------------------------------------------------------------------
# prance subclass — $ref resolution without backend validation
# ---------------------------------------------------------------------------


class _NonValidatingResolvingParser(ResolvingParser):  # type: ignore[misc]
    """
    prance.ResolvingParser that resolves $refs but skips backend validation.

    Overrides _validate() to perform $ref resolution (step 1) only.
    Step 2 (backend validation) is intentionally omitted: dialect-aware
    validation is performed explicitly in Phase 2b of load_openapi_spec()
    using the correct validator class for the detected dialect.

    This is necessary because prance's default backend (openapi-spec-validator)
    rejects Swagger 2.0 specs that use ``type: file`` for upload parameters.
    ``type: file`` is valid Swagger 2.0 but is not a JSON Schema Draft 4 type.
    The workaround parameters ``validate_spec=False`` and ``backend=None`` do
    not work (silently ignored / ValueError). Overriding _validate() is the
    only reliable approach without adding new dependencies or duplicating
    prance's fetch/parse logic.

    Coupling risk: this subclass accesses _ResolvingParser__reference_cache
    via Python name-mangling. The prance dependency is pinned to an exact
    version in pyproject.toml to guard against this breaking silently.
    """

    def _validate(self) -> None:
        """Resolve $refs in-place; skip backend validation."""
        forward_arg_names = (
            "encoding",
            "recursion_limit",
            "recursion_limit_handler",
            "resolve_types",
            "resolve_method",
            "strict",
        )
        forward_args = {k: v for k, v in self.options.items() if k in forward_arg_names}

        ref_cache: dict[object, object] = self._ResolvingParser__reference_cache  # pyright: ignore[reportAttributeAccessIssue]

        resolver = RefResolver(
            self.specification,  # type: ignore[has-type]
            self.url,
            reference_cache=ref_cache,
            **forward_args,
        )
        resolver.resolve_references()
        self.specification = resolver.specs
        # Intentionally skip BaseParser._validate().


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def load_openapi_spec(
    source_url: str,
    timeout_seconds: float = _DEFAULT_FETCH_TIMEOUT_SECONDS,
) -> tuple[dict[str, object], SpecDialect]:
    """
    Fetch, dereference, and validate an API specification.

    Supports both Swagger 2.0 and OpenAPI 3.x documents. The dialect is
    detected automatically from the root-level version key and returned
    alongside the dereferenced spec dict so that downstream modules can
    apply dialect-appropriate parsing logic.

    The entire prance fetch + dereference operation runs in a background
    thread. If it does not complete within timeout_seconds, an
    OpenAPILoadError is raised immediately and the thread is abandoned.

    Args:
        source_url: URL or local filesystem path of the specification.
                    HTTP/HTTPS URLs are fetched via prance's HTTP transport.
                    Both JSON and YAML formats are supported.
        timeout_seconds: Maximum wall-clock time in seconds for the fetch
                         and dereference step. Defaults to 60.0 seconds.
                         Set via config.execution.openapi_fetch_timeout_seconds.

    Returns:
        A tuple (spec, dialect) where:
            spec    -- Fully dereferenced specification as a nested Python dict.
            dialect -- SpecDialect.SWAGGER_2 or SpecDialect.OPENAPI_3.

    Raises:
        OpenAPILoadError: For any failure condition during fetch, validation,
                          or content sanity checks — including timeout.
    """
    log.info("openapi_discovery_started", source_url=source_url, timeout_seconds=timeout_seconds)

    # Phase 2a: fetch and dereference (skip prance backend validation).
    dereferenced_spec = _fetch_and_dereference(source_url, timeout_seconds)

    # Phase 2b: detect dialect, then validate against the correct schema.
    dialect = _detect_dialect(dereferenced_spec, source_url)
    _validate_spec_structure(dereferenced_spec, dialect, source_url)

    # Phase 2c: content sanity checks (dialect-independent).
    _assert_spec_has_operations(dereferenced_spec, source_url)

    spec_info = dereferenced_spec.get(OPENAPI_INFO_KEY, {})
    if not isinstance(spec_info, dict):
        spec_info = {}

    paths_obj = dereferenced_spec.get(OPENAPI_PATHS_KEY, {})
    path_count = len(paths_obj) if isinstance(paths_obj, dict) else 0

    log.info(
        "openapi_discovery_completed",
        source_url=source_url,
        dialect=dialect,
        spec_title=spec_info.get("title", "Unknown"),
        spec_version=spec_info.get("version", "Unknown"),
        path_count=path_count,
    )

    return dereferenced_spec, dialect


# ---------------------------------------------------------------------------
# Phase 2a — Fetch and dereference (with timeout watchdog)
# ---------------------------------------------------------------------------


def _prance_worker(source_url: str) -> dict[str, object]:
    """
    Worker function executed in a background thread by _fetch_and_dereference.

    Runs the full prance fetch + $ref resolution pipeline and returns the
    dereferenced spec dict. Any exception raised here is propagated back
    to the calling thread via concurrent.futures.Future.result().

    This function is intentionally isolated so that the threading boundary
    is explicit and the main thread's exception handling is clean.

    Args:
        source_url: URL or filesystem path of the spec to fetch.

    Returns:
        Fully dereferenced spec as a nested dict.

    Raises:
        PranceResolutionError: On $ref resolution failure.
        Exception: Any other prance / requests / YAML parse error.
    """
    parser = _NonValidatingResolvingParser(
        source_url,
        lazy=False,
        strict=False,
        recursion_limit=10,
        recursion_limit_handler=lambda *args, **kwargs: {},
    )
    return parser.specification  # type: ignore[no-any-return]


def _fetch_and_dereference(source_url: str, timeout_seconds: float) -> dict[str, object]:
    """
    Fetch the spec and resolve all $ref pointers with an explicit timeout.

    Runs _prance_worker in a ThreadPoolExecutor with a single worker thread.
    Waits for the future to complete within timeout_seconds. If the deadline
    is exceeded, OpenAPILoadError is raised immediately.

    The abandoned background thread may continue running briefly (Python
    threads cannot be forcibly terminated), but this is acceptable in the
    CLI context where the process exits after raising the error.

    Args:
        source_url: URL or filesystem path of the spec.
        timeout_seconds: Maximum time to wait for the prance operation.

    Returns:
        Fully dereferenced spec as a nested dict.

    Raises:
        OpenAPILoadError: On timeout, $ref resolution failure, or any
                          other transport / parse failure.
    """
    log.debug(
        "openapi_fetching_spec",
        source_url=source_url,
        timeout_seconds=timeout_seconds,
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_prance_worker, source_url)

        try:
            spec = future.result(timeout=timeout_seconds)

        except concurrent.futures.TimeoutError as exc:
            raise OpenAPILoadError(
                message=(
                    f"Timed out after {timeout_seconds}s waiting for the OpenAPI spec "
                    f"to be fetched and dereferenced from '{source_url}'. "
                    "Verify that the spec URL is reachable and that the document "
                    "does not contain an excessive number of remote $ref entries. "
                    "Increase 'execution.openapi_fetch_timeout_seconds' in config.yaml "
                    "if the spec is large and the network is slow."
                ),
                source_url=source_url,
                underlying_error="concurrent.futures.TimeoutError",
            ) from exc

        except PranceResolutionError as exc:
            raise OpenAPILoadError(
                message=(
                    f"Failed to resolve one or more $ref pointers in the spec "
                    f"at '{source_url}'. This may indicate a circular reference, an "
                    f"unreachable remote $ref, or a malformed $ref path. "
                    f"Underlying error: {exc}"
                ),
                source_url=source_url,
                underlying_error=str(exc),
            ) from exc

        except Exception as exc:  # noqa: BLE001
            raise OpenAPILoadError(
                message=(
                    f"Failed to fetch or parse the spec from '{source_url}'. "
                    f"Verify that the URL is reachable and returns a valid "
                    f"Swagger 2.0 or OpenAPI 3.x JSON/YAML document. "
                    f"Underlying error: {type(exc).__name__}: {exc}"
                ),
                source_url=source_url,
                underlying_error=f"{type(exc).__name__}: {exc}",
            ) from exc

    if not isinstance(spec, dict):
        raise OpenAPILoadError(
            message=(
                f"Spec at '{source_url}' did not produce a dict after "
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
# Phase 2b — Dialect detection
# ---------------------------------------------------------------------------


def _detect_dialect(
    spec: dict[str, object],
    source_url: str,
) -> SpecDialect:
    """
    Detect the spec dialect from the root-level version key.

    Args:
        spec: Dereferenced spec dict.
        source_url: Original source URL, used only for error messages.

    Returns:
        SpecDialect.SWAGGER_2 or SpecDialect.OPENAPI_3.

    Raises:
        OpenAPILoadError: If the spec declares an unknown or unsupported version.
    """
    # --- Swagger 2.0 ---
    if _SWAGGER_KEY in spec:
        swagger_version = str(spec.get(_SWAGGER_KEY, ""))
        major = swagger_version.split(".")[0]
        if major == _SUPPORTED_SWAGGER_MAJOR:
            log.debug(
                "openapi_dialect_detected",
                source_url=source_url,
                dialect=SpecDialect.SWAGGER_2,
                version_field=swagger_version,
            )
            return SpecDialect.SWAGGER_2
        raise OpenAPILoadError(
            message=(
                f"Spec at '{source_url}' declares Swagger version '{swagger_version}', "
                f"which is not supported. Supported Swagger major version: "
                f"{_SUPPORTED_SWAGGER_MAJOR}."
            ),
            source_url=source_url,
            underlying_error=f"swagger field value: {swagger_version!r}",
        )

    # --- OpenAPI 3.x ---
    openapi_field = spec.get(_OPENAPI_KEY)
    if isinstance(openapi_field, str):
        major = openapi_field.split(".")[0]
        if major == _SUPPORTED_OPENAPI_MAJOR:
            log.debug(
                "openapi_dialect_detected",
                source_url=source_url,
                dialect=SpecDialect.OPENAPI_3,
                version_field=openapi_field,
            )
            return SpecDialect.OPENAPI_3
        raise OpenAPILoadError(
            message=(
                f"Spec at '{source_url}' declares OpenAPI version '{openapi_field}', "
                f"which is not supported. Supported OpenAPI major version: "
                f"{_SUPPORTED_OPENAPI_MAJOR}."
            ),
            source_url=source_url,
            underlying_error=f"openapi field value: {openapi_field!r}",
        )

    # --- Unknown ---
    raise OpenAPILoadError(
        message=(
            f"Spec at '{source_url}' does not declare a recognisable version field. "
            "Expected either a top-level 'swagger' key (Swagger 2.0) or an "
            "'openapi' key (OpenAPI 3.x). "
            f"Top-level keys found: {sorted(spec.keys())}."
        ),
        source_url=source_url,
    )


# ---------------------------------------------------------------------------
# Phase 2b — Structural validation
# ---------------------------------------------------------------------------


def _validate_spec_structure(
    spec: dict[str, object],
    dialect: SpecDialect,
    source_url: str,
) -> None:
    """
    Validate the dereferenced spec against the appropriate dialect schema.

    Swagger 2.0 structural validation is skipped because
    openapi-spec-validator's OpenAPIV2SpecValidator rejects valid Swagger 2.0
    specs that use ``type: file`` on formData parameters (Swagger 2.0 extension
    not in JSON Schema Draft 4). Phase 2a and 2c guarantees still apply.

    For OpenAPI 3.x, the appropriate validator class is selected based on
    the minor version (3.0.x -> OpenAPIV30SpecValidator, 3.1.x -> OpenAPIV31SpecValidator).
    """
    if dialect is SpecDialect.SWAGGER_2:
        log.debug(
            "openapi_structural_validation_skipped",
            source_url=source_url,
            dialect=dialect,
            reason=(
                "openapi-spec-validator rejects valid Swagger 2.0 specs that "
                "use type:file on formData parameters. Validation skipped; "
                "Phase 2a and 2c guarantees still apply."
            ),
        )
        return

    openapi_version = str(spec.get(_OPENAPI_KEY, "3.0.0"))
    if openapi_version.startswith("3.1"):
        validator_class: type[OpenAPIV30SpecValidator] | type[OpenAPIV31SpecValidator] = (
            OpenAPIV31SpecValidator
        )
        version_label = "OpenAPI 3.1.x"
    else:
        validator_class = OpenAPIV30SpecValidator
        version_label = "OpenAPI 3.0.x"

    log.debug(
        "openapi_validating_spec",
        source_url=source_url,
        dialect=dialect,
        validator=version_label,
    )

    try:
        validator = validator_class(spec)
        validator.validate()
    except Exception as exc:  # noqa: BLE001
        raise OpenAPILoadError(
            message=(
                f"Spec at '{source_url}' failed {version_label} structural "
                f"validation. The document is syntactically valid YAML/JSON "
                f"but does not conform to the {version_label} schema. "
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

    Args:
        spec: Fully dereferenced and validated spec dict.
        source_url: Original source URL, used only for error messages.

    Raises:
        OpenAPILoadError: If the spec has no paths or no HTTP operations.
    """
    http_methods: frozenset[str] = frozenset(
        {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
    )

    paths = spec.get(OPENAPI_PATHS_KEY)

    if not isinstance(paths, dict) or len(paths) < MINIMUM_PATH_COUNT:
        raise OpenAPILoadError(
            message=(
                f"Spec at '{source_url}' declares no paths. "
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
                f"Spec at '{source_url}' declares {len(paths)} path(s) "
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
