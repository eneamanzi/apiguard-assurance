"""
src/tests/data/shadow_wordlists.py

Path wordlists for Domain 0 shadow API discovery tests.

This module is pure data: it defines no functions and performs no I/O.

Design rationale
----------------
Path wordlists are logic-free catalogues with independent lifecycles from the
tests that consume them.  Keeping them here (rather than inline in the test
modules) means:

  - The lists can be reviewed, extended, or trimmed without opening test files.
  - Two tests that happen to need an overlapping set of paths (0.1 and 0.2
    overlap conceptually) share a single source of truth.
  - The pattern is consistent with ``ssrf_payloads.py`` and
    ``injection_payloads.py`` already in this package.

Sources
-------
All paths are drawn from the following primary sources:

1. SecLists — danielmiessler/SecLists, file
   ``Discovery/Web-Content/api/api-endpoints.txt`` (MIT licence).
   URL: https://github.com/danielmiessler/SecLists

2. OWASP API Security Top 10 2023 — API9:2023 Improper Inventory Management.
   URL: https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/

3. OWASP Testing Guide v4.2 — WSTG-CONF-05: Enumerate Infrastructure and
   Application Admin Interfaces.
   URL: https://owasp.org/www-project-web-security-testing-guide/

4. Spring Boot Actuator documentation — common actuator endpoints exposed by
   default in development profiles.
   URL: https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html

5. Common debug/profiling endpoints for Go (``/debug/pprof``), Django
   (``__debug__``), and generic REST frameworks (``/api/explorer``).
"""

# ---------------------------------------------------------------------------
# Shadow API wordlist (Test 0.1)
# ---------------------------------------------------------------------------

# Common paths that are *not* part of a typical public API surface but are
# frequently left reachable on misconfigured gateways.  The list intentionally
# targets three categories:
#
#   1. Framework-specific maintenance endpoints (actuator, pprof, django debug)
#   2. Documentation endpoints that expose the full API spec or a UI for it
#   3. Generic admin / internal paths that should never be publicly reachable
#
# Note: the OpenAPI spec path itself is excluded at runtime by
# Test_0_1_ShadowApiDiscovery._build_exclusion_set().  Do not duplicate it
# here; the exclusion logic handles all variants.
SHADOW_API_WORDLIST: list[str] = [
    # --- Generic admin / internal ---
    "/api/admin",
    "/api/internal",
    "/api/debug",
    "/api/config",
    "/api/health",
    "/api/metrics",
    "/api/status",
    # --- Spring Boot Actuator ---
    "/api/actuator",
    "/api/actuator/env",
    "/api/actuator/heapdump",
    # --- OpenAPI / Swagger documentation ---
    "/api/swagger",
    "/api/swagger-ui",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api/openapi.json",
    "/api/openapi.yaml",
    # --- Versioned admin / internal variants ---
    "/api/v1/admin",
    "/api/v1/internal",
    "/api/v1/debug",
    "/api/v1/config",
    "/api/v2/admin",
    "/api/v2/internal",
    "/api/v2/debug",
    # --- Root-level debug / system endpoints ---
    "/debug",
    "/internal",
    "/admin",
    "/metrics",
    "/health",
    "/healthz",
    "/readyz",
    "/.well-known",
    "/.env",
    "/config",
    "/status",
    "/version",
    "/info",
    "/ping",
]

# ---------------------------------------------------------------------------
# Guaranteed-nonexistent path probes (Test 0.2)
# ---------------------------------------------------------------------------

# Paths chosen to be syntactically valid but semantically meaningless.
# The ``apiguard-probe`` infix and the numeric suffixes make accidental
# collision with any real application route vanishingly unlikely.
#
# Purpose: a correctly configured deny-by-default gateway must return 403 or
# 404 for every entry in this list.  A 2xx or 5xx response indicates that the
# gateway forwarded the request to the backend rather than blocking it.
DENY_BY_DEFAULT_NONEXISTENT_PATHS: list[str] = [
    "/nonexistent-apiguard-probe-xyz-123",
    "/api/nonexistent-apiguard-probe-abc-456",
    "/apiguard-shadow-probe-789",
    "/api/v99/nonexistent-probe",
]
