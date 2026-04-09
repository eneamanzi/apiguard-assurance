"""
tests_e2e/test_01_smoke_connectivity.py

Smoke Test — Phase 1 and 2 Pipeline Connectivity against a live target.

Purpose
-------
This is the entry point for the E2E test suite. It validates that the tool's
discovery pipeline can survive contact with a real, non-trivial API specification
and a live Gateway. Before any security test is run, we must be confident that:

    1. The configuration layer loads the real config.yaml correctly.
    2. The OpenAPI discovery pipeline can fetch, dereference, and validate
       Forgejo's real (and large) Swagger specification without crashing.
    3. The AttackSurface built from the real spec is non-trivial: it must
       contain a meaningful number of endpoints covering multiple HTTP methods
       and authentication requirements.
    4. The SecurityClient can establish a TCP connection through Kong and
       receive a structurally valid HTTP response.
    5. Kong's proxy is forwarding requests correctly (not returning errors
       that would indicate a misconfigured route).

What this test does NOT validate
---------------------------------
Security guarantees. This is a smoke test, not a security assessment.
The question here is: "Can the tool see the target?" — not "Is the target secure?".

Execution
---------
These tests require the full Docker stack to be running and healthy:

    cd ~/apiguard-assurance
    docker compose up -d
    docker compose ps   # wait until all services show (healthy)

    # Then run only E2E tests (excluded from the default testpaths):
    pytest tests_e2e/ -v

Environment variables must be set (via .env or shell export):
    ADMIN_USERNAME, ADMIN_PASSWORD
    USER_A_USERNAME, USER_A_PASSWORD
    USER_B_USERNAME, USER_B_PASSWORD
"""

from __future__ import annotations

import structlog
from src.config.schema import ToolConfig
from src.core.client import SecurityClient
from src.core.context import TargetContext
from src.core.models import AttackSurface, SpecDialect

log: structlog.BoundLogger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Thresholds for the real Forgejo spec
# ---------------------------------------------------------------------------

# Forgejo's Swagger 2.0 spec is one of the most comprehensive real-world API
# specifications available as an open-source reference. As of Forgejo 14.x,
# the spec exposes several hundred endpoints. These lower bounds are
# deliberately conservative to allow for minor version differences without
# breaking the smoke test — we only assert that the surface is "real",
# not that it has an exact count.
MINIMUM_EXPECTED_ENDPOINTS: int = 50
MINIMUM_EXPECTED_UNIQUE_PATHS: int = 30
MINIMUM_EXPECTED_AUTHENTICATED_ENDPOINTS: int = 10

# The Forgejo API prefix. All documented routes in its Swagger spec sit under /api/v1.
FORGEJO_API_PREFIX: str = "/api/v1"

# The one public endpoint guaranteed to exist in Forgejo regardless of auth configuration.
FORGEJO_HEALTH_PATH: str = "/api/healthz"


# ===========================================================================
# Section A — Configuration layer (Phase 1 equivalent)
# ===========================================================================


class TestConfigurationSmoke:
    """
    Verify that load_config() produces a coherent ToolConfig from the real
    config.yaml and the .env file.

    These tests are the minimal gating check before any network I/O is
    attempted. A malformed config must fail here with a ConfigurationError,
    not later with an AttributeError during Phase 2.
    """

    def test_config_loads_without_error(self, e2e_config: ToolConfig) -> None:
        """
        load_config() must return a ToolConfig instance for the real config.yaml.

        If this test fails, no other E2E test can run: the tool cannot even
        start without a valid configuration.
        """
        assert isinstance(e2e_config, ToolConfig), (
            "load_config() must return a ToolConfig instance. "
            "Check config.yaml syntax and all required environment variables."
        )

    def test_base_url_points_to_kong_proxy(self, e2e_config: ToolConfig) -> None:
        """
        target.base_url must point to Kong's proxy port (8000), not Forgejo directly.

        All test traffic must flow through Kong so that the gateway's security
        controls are the ones being assessed. Traffic bypassing Kong would
        invalidate every security finding.
        """
        base_url = str(e2e_config.target.base_url)
        assert "8000" in base_url, (
            f"target.base_url '{base_url}' does not reference Kong's proxy port (8000). "
            "Verify that config.yaml points to http://localhost:8000."
        )

    def test_openapi_spec_url_points_to_forgejo_direct(self, e2e_config: ToolConfig) -> None:
        """
        openapi_spec_url must reference Forgejo's direct port (3000).

        The spec is fetched from Forgejo directly because Kong's declarative
        configuration does not expose a specific route for the Swagger endpoint.
        Fetching through Kong would return a 404 for that path.
        """
        spec_url = str(e2e_config.target.openapi_spec_url)
        assert "3000" in spec_url, (
            f"openapi_spec_url '{spec_url}' does not reference Forgejo's direct port (3000). "
            "The spec must be fetched from Forgejo at http://localhost:3000/swagger.v1.json."
        )

    def test_admin_api_url_points_to_kong_admin(self, e2e_config: ToolConfig) -> None:
        """
        admin_api_url must reference Kong's Admin API port (8001).

        WHITE_BOX tests (Domain 4, 6) query Kong's Admin API to inspect
        gateway configuration. An absent or wrong admin_api_url causes all P3
        tests to return SKIP, reducing assessment coverage.
        """
        assert e2e_config.target.admin_api_url is not None, (
            "admin_api_url is not configured. "
            "Set target.admin_api_url in config.yaml (e.g., http://localhost:8001) "
            "to enable WHITE_BOX configuration audit tests."
        )
        admin_url = str(e2e_config.target.admin_api_url)
        assert "8001" in admin_url, (
            f"admin_api_url '{admin_url}' does not reference Kong's Admin API port (8001)."
        )

    def test_all_three_credential_pairs_are_configured(self, e2e_config: ToolConfig) -> None:
        """
        Admin, user_a, and user_b credentials must all be present.

        GREY_BOX tests (Domain 2, 3, 5) require tokens for at least two
        distinct roles. Missing any pair causes the corresponding tests to SKIP,
        reducing the effectiveness of the assessment for the thesis evaluation.
        """
        credentials = e2e_config.credentials
        assert credentials.has_admin_credentials(), (
            "Admin credentials are not configured. "
            "Set ADMIN_USERNAME and ADMIN_PASSWORD environment variables."
        )
        assert credentials.has_user_a_credentials(), (
            "user_a credentials are not configured. "
            "Set USER_A_USERNAME and USER_A_PASSWORD environment variables."
        )
        assert credentials.has_user_b_credentials(), (
            "user_b credentials are not configured. "
            "Set USER_B_USERNAME and USER_B_PASSWORD environment variables."
        )


# ===========================================================================
# Section B — OpenAPI Discovery (Phase 2 equivalent)
# ===========================================================================


class TestOpenAPIDiscoverySmoke:
    """
    Verify that the discovery pipeline survives the real Forgejo Swagger spec.

    Forgejo's Swagger 2.0 specification is a large, complex document with
    hundreds of paths and cross-referenced schemas. The discovery pipeline
    must handle it without crashing, regardless of its size or any non-standard
    extensions (like Forgejo's use of 'type: file' for upload parameters).

    These tests are the regression guard for the _NonValidatingResolvingParser
    design: if prance's internals change and break the $ref dereferencing,
    these tests will fail before any security test runs.
    """

    def test_attack_surface_is_an_attack_surface_instance(
        self, e2e_attack_surface: AttackSurface
    ) -> None:
        """
        build_attack_surface() must return an AttackSurface, not raise.

        This is the most fundamental check: the entire discovery pipeline
        (fetch → dereference → validate → surface-build) must complete
        without raising OpenAPILoadError or any other exception.
        """
        assert isinstance(e2e_attack_surface, AttackSurface), (
            "build_attack_surface() did not return an AttackSurface. "
            "Check the discovery pipeline for errors."
        )

    def test_spec_dialect_is_detected_as_swagger_2(self, e2e_attack_surface: AttackSurface) -> None:
        """
        Forgejo uses Swagger 2.0. The dialect detection must classify it correctly.

        An incorrect dialect classification causes surface.py to use the wrong
        parameter-extraction logic, producing an AttackSurface with no
        ParameterInfo objects — making Domain 3 input-validation tests blind.
        """
        assert e2e_attack_surface.dialect == SpecDialect.SWAGGER_2, (
            f"Expected SpecDialect.SWAGGER_2 for Forgejo's spec. "
            f"Got: {e2e_attack_surface.dialect}. "
            "Verify that the openapi_spec_url points to swagger.v1.json (Swagger 2.0)."
        )

    def test_spec_title_is_non_empty(self, e2e_attack_surface: AttackSurface) -> None:
        """
        The spec title must be extracted correctly and must not be 'Unknown'.

        'Unknown' indicates that the info.title key was absent or malformed
        in the spec. This would make the HTML report header uninformative.
        """
        assert e2e_attack_surface.spec_title not in ("Unknown", ""), (
            f"spec_title is '{e2e_attack_surface.spec_title}'. "
            "The spec's info.title field was not extracted correctly."
        )
        log.info(
            "e2e_smoke_spec_title_confirmed",
            spec_title=e2e_attack_surface.spec_title,
            spec_version=e2e_attack_surface.spec_version,
        )

    def test_spec_version_is_non_empty(self, e2e_attack_surface: AttackSurface) -> None:
        """
        The spec version must be extracted and must not be 'Unknown'.
        """
        assert e2e_attack_surface.spec_version not in ("Unknown", ""), (
            f"spec_version is '{e2e_attack_surface.spec_version}'. "
            "The spec's info.version field was not extracted correctly."
        )

    def test_surface_has_minimum_endpoint_count(self, e2e_attack_surface: AttackSurface) -> None:
        """
        The real Forgejo spec must produce at least MINIMUM_EXPECTED_ENDPOINTS endpoints.

        An endpoint count below the threshold signals that the dereferencing or
        surface-building pipeline dropped paths silently. With Forgejo 14.x,
        the actual count is in the hundreds — this lower bound is a safety net.
        """
        count = e2e_attack_surface.total_endpoint_count
        assert count >= MINIMUM_EXPECTED_ENDPOINTS, (
            f"AttackSurface has {count} endpoints — below the minimum of "
            f"{MINIMUM_EXPECTED_ENDPOINTS}. "
            "The discovery pipeline may have silently dropped paths."
        )
        log.info(
            "e2e_smoke_endpoint_count_confirmed",
            total_endpoints=count,
            unique_paths=e2e_attack_surface.unique_path_count,
        )

    def test_surface_has_minimum_unique_path_count(self, e2e_attack_surface: AttackSurface) -> None:
        """
        The surface must expose at least MINIMUM_EXPECTED_UNIQUE_PATHS distinct paths.
        """
        count = e2e_attack_surface.unique_path_count
        assert count >= MINIMUM_EXPECTED_UNIQUE_PATHS, (
            f"AttackSurface has {count} unique paths — below the minimum of "
            f"{MINIMUM_EXPECTED_UNIQUE_PATHS}."
        )

    def test_authenticated_endpoints_exist_in_surface(
        self, e2e_attack_surface: AttackSurface
    ) -> None:
        """
        The surface must contain authenticated endpoints.

        Domain 1 (Authentication) and Domain 2 (Authorization) tests depend
        on a non-empty list of authenticated endpoints. An empty list means the
        security requirement was not extracted from the spec, making auth tests blind.
        """
        auth_endpoints = e2e_attack_surface.get_authenticated_endpoints()
        assert len(auth_endpoints) >= MINIMUM_EXPECTED_AUTHENTICATED_ENDPOINTS, (
            f"Found only {len(auth_endpoints)} authenticated endpoints. "
            f"Expected at least {MINIMUM_EXPECTED_AUTHENTICATED_ENDPOINTS}. "
            "Verify that the spec's global 'security' array or operation-level "
            "security requirements are being parsed correctly."
        )

    def test_forgejo_api_prefix_present_in_surface(self, e2e_attack_surface: AttackSurface) -> None:
        """
        At least one endpoint must have a path starting with FORGEJO_API_PREFIX.

        This confirms that the surface reflects Forgejo's actual REST API structure,
        not a mismatched or stub specification.
        """
        api_paths = [
            ep.path for ep in e2e_attack_surface.endpoints if ep.path.startswith(FORGEJO_API_PREFIX)
        ]
        assert len(api_paths) > 0, (
            f"No endpoint paths start with '{FORGEJO_API_PREFIX}'. "
            "The AttackSurface does not reflect Forgejo's API structure. "
            "Verify that the correct spec URL is configured."
        )

    def test_multiple_http_methods_are_present(self, e2e_attack_surface: AttackSurface) -> None:
        """
        The surface must contain endpoints for at least GET, POST, and DELETE.

        A surface missing entire HTTP method categories indicates that the
        surface builder is filtering too aggressively. Domain 2 (Authorization)
        tests explicitly require DELETE endpoints to verify operation-level
        authorization.
        """
        methods_in_surface = {ep.method for ep in e2e_attack_surface.endpoints}
        for expected_method in ("GET", "POST", "DELETE"):
            assert expected_method in methods_in_surface, (
                f"HTTP method '{expected_method}' is absent from the AttackSurface. "
                f"Present methods: {sorted(methods_in_surface)}. "
                "Check the OPENAPI_HTTP_METHODS constant in discovery/surface.py."
            )

    def test_surface_contains_endpoints_with_path_parameters(
        self, e2e_attack_surface: AttackSurface
    ) -> None:
        """
        At least one endpoint must declare path parameters.

        Forgejo's API is resource-oriented: most write operations target specific
        resources via {owner}/{repo} path parameters. If no parameterised endpoints
        are found, the BOLA tests (Domain 2) will have no targets to probe.
        """
        parameterised = e2e_attack_surface.get_endpoints_with_path_parameters()
        assert len(parameterised) > 0, (
            "No endpoints with path parameters found in the AttackSurface. "
            "Check that ParameterInfo extraction handles Swagger 2.0 path parameters."
        )


# ===========================================================================
# Section C — Network Connectivity (SecurityClient smoke)
# ===========================================================================


class TestNetworkConnectivitySmoke:
    """
    Verify that SecurityClient can successfully communicate with the real target
    through Kong's proxy.

    These tests do not assert security guarantees. They assert transport-level
    correctness: can we establish a connection, send a request, and receive a
    structurally valid HTTP response?

    The Forgejo health endpoint is the ideal probe: it is public (no auth),
    has a stable path, and is explicitly designed for liveness checks.
    """

    def test_health_endpoint_returns_valid_http_response(
        self,
        e2e_client: SecurityClient,
        e2e_target_reachable: None,
    ) -> None:
        """
        A GET to the Forgejo health endpoint must return a valid httpx.Response.

        This test validates the full transport layer:
            - TCP connection to Kong
            - Kong routing the /api prefix to Forgejo
            - Forgejo processing the request and returning a response
            - httpx parsing the response
            - SecurityClient returning the (response, record) tuple

        A transport-level failure here indicates a Docker stack issue, not a
        tool bug — and the test will fail with a clear SecurityClientError.
        """
        response, record = e2e_client.request(
            method="GET",
            path=FORGEJO_HEALTH_PATH,
            test_id="smoke_01",
        )

        assert response is not None, "SecurityClient returned a None response."
        assert record is not None, "SecurityClient returned a None EvidenceRecord."

        log.info(
            "e2e_smoke_health_request_completed",
            path=FORGEJO_HEALTH_PATH,
            status_code=response.status_code,
            record_id=record.record_id,
        )

    def test_health_endpoint_returns_2xx_status(
        self,
        e2e_client: SecurityClient,
        e2e_target_reachable: None,
    ) -> None:
        """
        The health endpoint must return a 2xx status code.

        Forgejo's /api/healthz returns 200 OK when the service is healthy.
        Any other status indicates a service health problem that should be
        resolved before running the security assessment.
        """
        response, _ = e2e_client.request(
            method="GET",
            path=FORGEJO_HEALTH_PATH,
            test_id="smoke_01",
        )

        assert 200 <= response.status_code < 300, (
            f"Health endpoint returned HTTP {response.status_code}. "
            "Expected a 2xx status. Forgejo may not be healthy. "
            f"Check 'docker compose ps' and 'docker logs forgejo'."
        )

    def test_evidence_record_is_correctly_structured(
        self,
        e2e_client: SecurityClient,
        e2e_target_reachable: None,
    ) -> None:
        """
        The EvidenceRecord returned by client.request() must be fully populated.

        This validates the SecurityClient's _build_evidence_record() method
        against a real response: the record must capture the actual URL, method,
        status code, and response headers from the live transaction.
        """
        response, record = e2e_client.request(
            method="GET",
            path=FORGEJO_HEALTH_PATH,
            test_id="smoke_01",
        )

        assert record.record_id == "smoke_01_001", (
            f"record_id '{record.record_id}' does not follow the expected format "
            "'smoke_01_001'. Check SecurityClient._next_record_id()."
        )
        assert record.request_method == "GET"
        assert "localhost" in record.request_url or "127.0.0.1" in record.request_url, (
            f"request_url '{record.request_url}' does not reference localhost. "
            "The SecurityClient may be constructing URLs incorrectly."
        )
        assert record.response_status_code == response.status_code, (
            "EvidenceRecord.response_status_code does not match the actual response status."
        )
        assert not record.is_pinned, (
            "A record returned by client.request() must have is_pinned=False. "
            "Only explicit store.pin_evidence() calls should set is_pinned=True."
        )

    def test_authorization_header_is_redacted_in_record(
        self,
        e2e_client: SecurityClient,
        e2e_target_reachable: None,
    ) -> None:
        """
        When an Authorization header is sent, it must appear as '[REDACTED]' in the record.

        This is the core privacy guarantee of EvidenceStore: JWT tokens must
        never be written to evidence.json in cleartext. This test sends a fake
        token and verifies the redaction at the record level.
        """
        _fake_token = "eyJhbGciOiJIUzI1NiJ9.fake.payload"  # noqa: S105
        _, record = e2e_client.request(
            method="GET",
            path=FORGEJO_HEALTH_PATH,
            test_id="smoke_01",
            headers={"Authorization": f"Bearer {_fake_token}"},
        )

        auth_in_record = record.request_headers.get("authorization", "")
        assert auth_in_record == "[REDACTED]", (
            f"Authorization header was not redacted. Found: '{auth_in_record}'. "
            "This is a credential leak — check EvidenceRecord.headers_must_be_lowercase."
        )
        assert _fake_token not in auth_in_record, (
            "The token value appeared in the redacted record. "
            "Credential leak in EvidenceRecord header validator."
        )

    def test_kong_proxy_routes_api_prefix_correctly(
        self,
        e2e_client: SecurityClient,
        e2e_target_reachable: None,
    ) -> None:
        """
        A request to /api/v1/repos/search must reach Forgejo (not return a Kong 404).

        This test verifies that Kong's declarative route for the /api prefix is
        working correctly. If Kong returns 404 for this path, the route is broken
        and no security test against API endpoints will work.

        We accept any response code except 404 or 502/503/504 (which indicate
        routing failures). A 401 Unauthorized is the expected response for an
        unauthenticated request to a protected search endpoint.
        """
        response, _ = e2e_client.request(
            method="GET",
            path="/api/v1/repos/search",
            test_id="smoke_01",
        )

        routing_failure_codes = {404, 502, 503, 504}
        assert response.status_code not in routing_failure_codes, (
            f"GET /api/v1/repos/search returned HTTP {response.status_code}. "
            "This status code indicates a Kong routing failure. "
            "Verify that kong/kong.yml declares the /api route and that Kong "
            "is healthy ('docker logs kong')."
        )
        log.info(
            "e2e_smoke_kong_routing_confirmed",
            path="/api/v1/repos/search",
            status_code=response.status_code,
        )


# ===========================================================================
# Section D — TargetContext construction (Phase 3 equivalent)
# ===========================================================================


class TestTargetContextSmoke:
    """
    Verify that a TargetContext can be constructed from real config + real surface.

    These tests bridge Phase 2 and Phase 5: they confirm that the frozen context
    objects the engine creates are coherent with the live environment.
    """

    def test_target_context_is_constructed(self, e2e_target_context: TargetContext) -> None:
        """
        TargetContext must be constructable from real config and real surface.
        """
        assert e2e_target_context is not None
        assert e2e_target_context.attack_surface is not None

    def test_target_context_admin_api_is_available(self, e2e_target_context: TargetContext) -> None:
        """
        admin_api_available must return True given that admin_api_url is configured.

        If this fails, all WHITE_BOX tests will SKIP silently in the real run.
        """
        assert e2e_target_context.admin_api_available, (
            "TargetContext.admin_api_available is False. "
            "Verify that target.admin_api_url is set in config.yaml."
        )

    def test_endpoint_base_url_has_no_trailing_slash(
        self, e2e_target_context: TargetContext
    ) -> None:
        """
        endpoint_base_url() must return the Kong proxy URL without trailing slash.
        """
        url = e2e_target_context.endpoint_base_url()
        assert not url.endswith("/"), (
            f"endpoint_base_url() returned '{url}' with a trailing slash. "
            "This will produce double-slash URLs in test requests."
        )

    def test_surface_endpoint_count_matches_real_spec(
        self,
        e2e_target_context: TargetContext,
        e2e_attack_surface: AttackSurface,
    ) -> None:
        """
        The surface stored in TargetContext must have the same endpoint count
        as the independently-built surface.

        This verifies that no endpoint data is lost during the TargetContext
        construction step.
        """
        assert e2e_target_context.attack_surface is not None
        assert (
            e2e_target_context.attack_surface.total_endpoint_count
            == e2e_attack_surface.total_endpoint_count
        ), (
            "Endpoint count in TargetContext.attack_surface differs from the "
            "independently built AttackSurface. Data was lost during context construction."
        )
