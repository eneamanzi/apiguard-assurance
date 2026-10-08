# 0.1 Shadow API Discovery

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0) · **Source of truth:**
> [`src/tests/domain_0/test_0_1_shadow_api_discovery.py`](../../../src/tests/domain_0/test_0_1_shadow_api_discovery.py) ·
> **Verified:** 2026-10-05

| | |
|---|---|
| Test ID | `0.1` |
| Name | All Exposed Endpoints Are Documented and Authorized |
| Domain | 0 - API Discovery and Inventory Management |
| Priority / strategy | P0 / BLACK_BOX |
| CWE / tags | CWE-1059 / `shadow-api`, `inventory`, `OWASP-API9:2023` |
| Depends on | none |
| Configuration | `tests.domain_0.test_0_1.method_probe_sample_size` (default 10, see [configuration](../../reference/configuration.md#testsdomain_0test_0_1---shadow-api-discovery)) |
| Companion test | [`ext.0.1.nuclei`](../external/domain-0/ext-0-1-nuclei.md) |

## What it checks

Every endpoint that answers on the gateway must be declared in the OpenAPI specification. Active but undocumented
endpoints ("shadow APIs") escape security review, rate limiting and authentication policies.

## How it works

Two sub-checks, all requests unauthenticated:

1. **Path fuzzing.** `GET` on each of the 37 paths in `SHADOW_API_WORDLIST`
   (`src/tests/data/shadow_wordlists.py`: `/api/admin`, `/api/internal`, `/actuator`-style paths,
   `/api/v1/*`, `/api/v2/*`, `/.env`, `/health`, …). Paths declared in the spec are skipped. When the spec is
   loaded from `openapi_spec_url`, the spec's own path (e.g. `/swagger.v1.json`) is also skipped.
2. **Undeclared methods.** For the first `method_probe_sample_size` endpoints of the attack surface (default 10),
   skipping paths with `{parameters}`,
   every method in `GET, POST, PUT, PATCH, DELETE` that the spec does not declare for that path is sent.

A response is **active** when its status is one of
`200, 201, 202, 204, 301, 302, 307, 308, 400, 401, 403, 405, 422, 429, 500, 502, 503`.

## Outcomes

| Status | When |
|---|---|
| PASS | No active undocumented path and no accepted undeclared method. |
| FAIL | One finding per active undocumented path (sub-check 1) and per undeclared method answering with an active status other than `405` (sub-check 2). |
| SKIP | The attack surface is not available. |
| ERROR | Unexpected exception. Transport errors on single probes are logged and the probe is skipped, not reported. |

Finding titles: `Shadow API endpoint detected (undocumented active path)`,
`Undeclared HTTP method accepted by endpoint`. References: CWE-1059, OWASP-API9:2023, NIST-SP-800-204-S3.1,
RFC-9110-S9.1.

## Oracle states

| State | Meaning |
|---|---|
| `SHADOW_API_ACTIVE` | Undocumented path answered with an active status (FAIL evidence). |
| `UNDECLARED_METHOD_ACTIVE` | Undeclared method answered with an active status other than `405` (FAIL evidence). |
| `METHOD_NOT_ALLOWED` | Undeclared method rejected with `405` (correct). |
| `CORRECTLY_DENIED` | Any non-active status (typically `404`, `410`). |

## Prerequisites and effects on the target

- Only the OpenAPI specification. No credentials, no Admin API.
- Sub-check 2 sends **`POST`, `PUT`, `PATCH`, `DELETE` without credentials** to documented paths where those
  methods are not declared. On a correctly configured target they are rejected; on a misconfigured one they may
  reach the backend.

## Coverage against the methodology

Source: [`methodology.it.md` §0.1](../../knowledge/methodology/methodology.it.md).

| Methodology sub-test | Status |
|---|---|
| Path enumeration via fuzzing | Implemented with a fixed 37-path list (the methodology refers to SecLists `API-endpoints.txt`); no case or trailing-slash variants. |
| HTTP method discovery | Implemented by sending undeclared methods directly (the methodology describes `OPTIONS` + `Allow` comparison); limited to the first `method_probe_sample_size` endpoints (default 10), parametric ones skipped: on the Forgejo spec only 3 of the first 10 are probed (Q-29). |
| Versioning completeness | Partial: only the `/api/v1/*` and `/api/v2/*` entries of the wordlist. |
| Documentation drift via Admin API | Not implemented. |

## Why it exists

OWASP API9:2023 (Improper Inventory Management), NIST SP 800-204 §3.1. Typical failures described in the
methodology: a legacy route left on the gateway after a version migration; a catch-all route forwarding
undocumented internal paths to the backend; older API versions still active but not documented.

Tooling decision ([`decisions.it.md` §0.1](../../knowledge/tools/decisions.it.md)): HYBRID test. The native part
compares responses against the project's own spec; the external part ([`ext.0.1.nuclei`](../external/domain-0/ext-0-1-nuclei.md))
detects known exposure patterns from community templates. Planned Cat A connectors ffuf (large wordlists) and
katana (JavaScript crawling) are not implemented ([roadmap](../../project/roadmap.md)).

## Limitations

- A `403` on an undocumented path is reported as a shadow API, because it shows that a route exists on the gateway.
- The module docstring mentions a version-discovery sub-check that is not implemented as a separate step.

## See also

- [`0.2 Deny-by-default`](0-2-deny-by-default.md) · [`0.3 Deprecated API enforcement`](0-3-deprecated-api-enforcement.md)
- [`../README.md`](../README.md) - all tests
