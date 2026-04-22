"""
tests_integration/test_02_discovery.py

Integration tests for Phase 2 (OpenAPI Discovery) and Phase 3 (Context Construction).

Executable Documentation contract
----------------------------------
These tests specify the exact state that AttackSurface and TargetContext must
represent after Phase 2 and Phase 3 complete. Reading this file answers:

    "Given a known OpenAPI spec, what AttackSurface does the system build,
     and what filter methods does it expose for the tests to consume?"

    "Given a ToolConfig and AttackSurface, what TargetContext is constructed,
     and what guarantees does it provide to every test that receives it?"

Design: no network calls
------------------------
build_attack_surface() accepts a pre-dereferenced spec dict. This suite calls
it directly with the REFERENCE_SPEC fixture, bypassing the HTTP fetch step that
load_openapi_spec() performs. This makes the discovery tests hermetic: they
verify the transformation of spec → surface, not the reachability of a server.

The REFERENCE_SPEC and its expected-count constants are defined in conftest.py
so that a single authoritative source governs both the input and the expected
outputs. If the spec changes, the constants and the tests fail together —
there is no way to update one without updating the other.

Phase 2 contract (from engine.py docstring):
    Fetch, dereference, and validate the OpenAPI spec.
    Build AttackSurface from the dereferenced spec.
    Raises OpenAPILoadError on failure [BLOCKS STARTUP].

Phase 3 contract:
    Build TargetContext (frozen) from ToolConfig + AttackSurface.
    Build TestContext (mutable, empty).
    Build EvidenceStore (deque, maxlen=100).
    Build SecurityClient (context manager, not yet open).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from src.core.context import TargetContext, TestContext
from src.core.exceptions import OpenAPILoadError
from src.core.models import AttackSurface, SpecDialect
from src.discovery.surface import build_attack_surface

from tests_integration.conftest import (
    EXPECTED_AUTHENTICATED_ENDPOINTS,
    EXPECTED_DEPRECATED_ENDPOINTS,
    EXPECTED_PUBLIC_ENDPOINTS,
    EXPECTED_SPEC_TITLE,
    EXPECTED_SPEC_VERSION,
    EXPECTED_TOTAL_ENDPOINTS,
    _url,
)

# ===========================================================================
# Section A — AttackSurface structure
# ===========================================================================


class TestAttackSurfaceStructure:
    """
    Verify the structural invariants of the AttackSurface built from REFERENCE_SPEC.

    These tests pin the exact shape that build_attack_surface() must produce.
    They act as a regression guard: if a change in surface.py alters how the
    spec is parsed, these tests fail immediately and the breakage is localised.
    """

    def test_surface_is_frozen_model(self, reference_surface: AttackSurface) -> None:
        """
        AttackSurface must be immutable after construction (frozen Pydantic model).

        The engine stores a single AttackSurface in TargetContext and shares it
        across all tests. If a test could mutate it, every subsequent test would
        operate on corrupted state. The frozen guarantee makes sharing safe.
        """
        with pytest.raises(ValidationError):
            reference_surface.spec_title = "tampered"  # type: ignore[misc]

    def test_spec_metadata_is_extracted(self, reference_surface: AttackSurface) -> None:
        """
        spec_title and spec_version must be read from info.title and info.version.

        These values appear in the HTML report header. Incorrect values produce
        a report that misidentifies the assessed API — a traceability failure.
        """
        assert reference_surface.spec_title == EXPECTED_SPEC_TITLE
        assert reference_surface.spec_version == EXPECTED_SPEC_VERSION

    def test_total_endpoint_count_matches_spec(self, reference_surface: AttackSurface) -> None:
        """
        The number of EndpointRecord objects must equal the number of (path, method)
        pairs declared in the spec.

        An incorrect count means either endpoints were silently dropped (false
        negative: untested surface) or phantom endpoints were added (false positive:
        tests probe paths that don't exist).
        """
        assert reference_surface.total_endpoint_count == EXPECTED_TOTAL_ENDPOINTS

    def test_unique_path_count_is_correct(self, reference_surface: AttackSurface) -> None:
        """
        unique_path_count must reflect the number of distinct URL paths, not
        the number of (path, method) pairs.

        Tests that iterate over paths (e.g. shadow API fuzzing) use this to
        avoid probing the same path multiple times for different methods.
        """
        # REFERENCE_SPEC has 4 paths: /health, /api/v1/users/me, /api/v1/users,
        # /api/v1/users/{id} — all distinct.
        expected_unique_paths = 4
        assert reference_surface.unique_path_count == expected_unique_paths

    def test_dialect_is_openapi_3(self, reference_surface: AttackSurface) -> None:
        """
        A spec with "openapi: 3.0.x" must produce a surface with dialect=OPENAPI_3.

        The dialect controls how parameters and request bodies are extracted
        from each operation. A wrong dialect classification causes the parameter
        extraction logic to read the wrong keys, producing empty ParameterInfo
        lists and missing input-validation test coverage.
        """
        assert reference_surface.dialect == SpecDialect.OPENAPI_3


# ===========================================================================
# Section B — AttackSurface filter methods
# ===========================================================================


class TestAttackSurfaceFilterMethods:
    """
    Verify that every filter method on AttackSurface returns the correct subset.

    Tests consume these methods during Phase 5 to select the operations they
    need to probe. An incorrect filter means a test targets the wrong endpoints,
    producing either false positives or false negatives.
    """

    def test_get_authenticated_endpoints(self, reference_surface: AttackSurface) -> None:
        """
        get_authenticated_endpoints() must return only endpoints with at least
        one security requirement declared in the spec.

        Domain 2 (Authorization) tests call this method to build their probing
        list. Missing authenticated endpoints means auth bypass tests are never
        run against those operations.
        """
        auth_endpoints = reference_surface.get_authenticated_endpoints()
        assert len(auth_endpoints) == EXPECTED_AUTHENTICATED_ENDPOINTS
        paths = {ep.path for ep in auth_endpoints}
        assert "/health" not in paths, (
            "/health is public and must not appear in authenticated endpoints"
        )

    def test_get_public_endpoints(self, reference_surface: AttackSurface) -> None:
        """
        get_public_endpoints() must return only endpoints with no security requirement.

        These endpoints are probed without credentials in Black Box tests.
        Including authenticated endpoints here would cause false-negative results
        (the probe succeeds because auth is not required, not because it was bypassed).
        """
        public_endpoints = reference_surface.get_public_endpoints()
        assert len(public_endpoints) == EXPECTED_PUBLIC_ENDPOINTS
        assert public_endpoints[0].path == "/health"

    def test_get_deprecated_endpoints(self, reference_surface: AttackSurface) -> None:
        """
        get_deprecated_endpoints() must return only endpoints marked deprecated:true.

        Test 0.3 uses this method to build its probing list. Missing a deprecated
        endpoint means the test returns PASS when it should detect a violation.
        """
        deprecated = reference_surface.get_deprecated_endpoints()
        assert len(deprecated) == EXPECTED_DEPRECATED_ENDPOINTS
        assert deprecated[0].path == "/api/v1/users/{id}"
        assert deprecated[0].method == "DELETE"

    def test_get_endpoints_with_path_parameters(self, reference_surface: AttackSurface) -> None:
        """
        get_endpoints_with_path_parameters() must return only endpoints that declare
        at least one path-level parameter in the spec.

        Tests that substitute real resource IDs (Domain 3, Domain 2 IDOR) rely
        on this method to identify which endpoints need parameterised payloads.
        """
        parameterised = reference_surface.get_endpoints_with_path_parameters()
        paths = {ep.path for ep in parameterised}
        assert "/api/v1/users/{id}" in paths

    def test_get_endpoints_by_method(self, reference_surface: AttackSurface) -> None:
        """
        get_endpoints_by_method() must filter by HTTP method (case-insensitive normalised
        to uppercase in EndpointRecord).

        Tests that probe only write operations (POST, PUT, PATCH, DELETE) use
        this to avoid sending mutating requests to read-only endpoints.
        """
        delete_endpoints = reference_surface.get_endpoints_by_method("DELETE")
        assert len(delete_endpoints) == 1
        assert delete_endpoints[0].path == "/api/v1/users/{id}"

        get_endpoints = reference_surface.get_endpoints_by_method("GET")
        assert len(get_endpoints) == 2  # /health + /api/v1/users/me

    def test_filter_methods_return_copies_not_views(self, reference_surface: AttackSurface) -> None:
        """
        Filter methods must return independent copies, not views into the internal list.

        A test that mutates the returned list must not affect the surface. The
        surface is shared across all tests via TargetContext; mutation would
        cause non-deterministic behaviour depending on test execution order.
        """
        auth_endpoints = reference_surface.get_authenticated_endpoints()
        original_count = reference_surface.total_endpoint_count
        auth_endpoints.clear()
        # Surface must be unchanged after the caller mutates the returned list.
        assert reference_surface.total_endpoint_count == original_count

    def test_deprecated_count_property(self, reference_surface: AttackSurface) -> None:
        """
        AttackSurface.deprecated_count must equal the length of
        get_deprecated_endpoints().

        Both are read by report/builder.py for the summary statistics table.
        An inconsistency between them would produce an incorrect report.
        """
        assert reference_surface.deprecated_count == len(
            reference_surface.get_deprecated_endpoints()
        )


# ===========================================================================
# Section C — build_attack_surface error handling
# ===========================================================================


class TestBuildAttackSurfaceErrorHandling:
    """
    build_attack_surface() must raise OpenAPILoadError for malformed specs,
    not propagate raw KeyError/TypeError/AttributeError from internal parsing.

    OpenAPILoadError is what engine.py catches in Phase 2. Any other exception
    type propagates as an unhandled crash with a confusing traceback.
    """

    def test_missing_paths_key_raises_openapi_load_error(self) -> None:
        """
        A spec dict without a 'paths' key must raise OpenAPILoadError.

        The 'paths' object is the only required input to build_attack_surface.
        A spec that passed schema validation but somehow lacks paths would
        produce an empty surface with no indication that something is wrong —
        unless this guard is in place.
        """
        spec_without_paths: dict[str, object] = {
            "openapi": "3.0.3",
            "info": {"title": "Broken", "version": "0.0.0"},
        }
        with pytest.raises(OpenAPILoadError):
            build_attack_surface(spec=spec_without_paths, dialect=SpecDialect.OPENAPI_3)

    def test_empty_paths_produces_empty_surface(self) -> None:
        """
        A spec with an empty paths dict must produce an AttackSurface with
        zero endpoints — not raise an exception.

        An API with no documented operations is unusual but valid. The surface
        must be constructed correctly so that tests return SKIP (no endpoints
        to probe) rather than ERROR (unexpected crash).
        """
        spec_empty_paths: dict[str, object] = {
            "openapi": "3.0.3",
            "info": {"title": "Empty API", "version": "0.0.0"},
            "paths": {},
        }
        surface = build_attack_surface(spec=spec_empty_paths, dialect=SpecDialect.OPENAPI_3)
        assert surface.total_endpoint_count == 0
        assert surface.unique_path_count == 0


# ===========================================================================
# Section D — TargetContext construction (Phase 3)
# ===========================================================================


class TestTargetContextConstruction:
    """
    Verify the TargetContext invariants that the engine establishes in Phase 3.

    TargetContext is the "frozen snapshot" of everything a test needs to know
    about the target. These tests verify that it faithfully carries the values
    from config and AttackSurface without loss or transformation.
    """

    def test_target_context_is_frozen(self, reference_target: TargetContext) -> None:
        """
        TargetContext must be immutable after construction.

        TargetContext is shared across all tests in Phase 5. A mutable context
        would allow one test to alter the base_url and corrupt all subsequent
        tests' HTTP request construction.
        """
        with pytest.raises(ValidationError):
            reference_target.base_url = "http://evil.example.com"  # type: ignore[misc, assignment]

    def test_attack_surface_is_accessible(
        self, reference_target: TargetContext, reference_surface: AttackSurface
    ) -> None:
        """
        The attack_surface stored in TargetContext must be the exact surface
        object built by Phase 2.

        A test that calls target.attack_surface must get the same surface that
        was built from the spec — not None, not a copy with different values.
        """
        assert reference_target.attack_surface is not None
        assert reference_target.attack_surface.total_endpoint_count == (
            reference_surface.total_endpoint_count
        )

    def test_admin_api_available_false_when_url_is_none(
        self, reference_target: TargetContext
    ) -> None:
        """
        admin_api_available must return False when admin_api_url is None.

        Every WHITE_BOX test checks this computed field before attempting an
        Admin API call. If it incorrectly returns True, tests will attempt
        connections to a None URL and crash with AttributeError.

        The reference_target fixture does not configure admin_api_url,
        making it the canonical Black Box scenario.
        """
        assert reference_target.admin_api_available is False

    def test_admin_api_available_true_when_url_is_configured(
        self, reference_surface: AttackSurface
    ) -> None:
        """
        admin_api_available must return True when admin_api_url is configured.

        Without this, _requires_admin_api() would return SKIP for all WHITE_BOX
        tests even when the Admin API is reachable — hiding configuration audit
        findings.
        """
        target_with_admin = TargetContext(
            base_url=_url("http://localhost:8000"),
            openapi_spec_url=_url("http://localhost:3000/swagger.v1.json"),
            admin_api_url=_url("http://localhost:8001"),
            attack_surface=reference_surface,
        )
        assert target_with_admin.admin_api_available is True

    def test_endpoint_base_url_has_no_trailing_slash(self, reference_target: TargetContext) -> None:
        """
        endpoint_base_url() must return the base URL without a trailing slash.

        Tests build request URLs with f"{target.endpoint_base_url()}{path}".
        If the base URL retains a trailing slash and path starts with '/',
        the result is a double-slash URL (e.g. http://localhost:8000//api/v1/…)
        that some servers reject with 400 Bad Request.
        """
        base = reference_target.endpoint_base_url()
        assert not base.endswith("/"), (
            f"endpoint_base_url() returned '{base}' which ends with '/'. "
            "This will produce double-slash URLs when concatenated with endpoint paths."
        )

    def test_test_context_starts_empty(self, empty_test_context: TestContext) -> None:
        """
        A freshly constructed TestContext must have no tokens and no registered resources.

        Tests check token availability before using them. A pre-populated context
        would cause tests to believe authentication has already succeeded and skip
        the authentication step, producing misleading results.
        """
        assert not empty_test_context.has_token("admin")
        assert not empty_test_context.has_token("user_a")
        assert not empty_test_context.has_token("user_b")
