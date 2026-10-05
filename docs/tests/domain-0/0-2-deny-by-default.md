# 0.2 Deny-by-Default

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0) · **Source of truth:**
> [`src/tests/domain_0/test_0_2_deny_by_default.py`](../../../src/tests/domain_0/test_0_2_deny_by_default.py) ·
> **Verified:** 2026-10-05

| | |
|---|---|
| Test ID | `0.2` |
| Name | Gateway Deny-by-Default on Unregistered Paths |
| Domain | 0 - API Discovery and Inventory Management |
| Priority / strategy | P0 / BLACK_BOX |
| CWE | CWE-284 |
| Depends on | none |
| Configuration | [`tests.domain_0.test_0_2`](../../reference/configuration.md#testsdomain_0test_0_2---deny-by-default) |

## What it checks

The gateway must reject any request whose path does not match a registered route (`403`, `404` or `410`), without
forwarding it to a backend and without revealing which server answered. Path variants of a protected endpoint
must not bypass its authentication.

## How it works

All requests are unauthenticated `GET`s.

**Sub-check 1: unregistered paths.** Four paths that cannot exist
(`DENY_BY_DEFAULT_NONEXISTENT_PATHS` in `src/tests/data/shadow_wordlists.py`, e.g.
`/nonexistent-apiguard-probe-xyz-123`, `/api/v99/nonexistent-probe`). Each response is checked for:

- status not in `403, 404, 410` → the gateway did not block the request;
- a `Server` header that does not contain any of `gateway_server_identifiers` (default: kong, nginx, openresty,
  apache, caddy, traefik, envoy) → the reply came from a backend. A missing `Server` header is not a finding.

**Sub-check 2: path normalization on a protected endpoint.**

1. Pick one non-parametric path from the spec, in this order of preference: authenticated `GET`, authenticated
   any method, any `GET`, any path.
2. Baseline: `GET` the canonical path. Only if it answers `401` or `403` does the check continue; otherwise it is
   skipped with an InfoNote (`200` = public endpoint, other status = inconclusive).
3. Send the variants: trailing slash, double slash after the first segment, uppercase, URL-encoded last segment.
   A variant identical to the canonical path is not sent.
4. A variant answering `200` is an authentication bypass.

## Outcomes

| Status | When |
|---|---|
| PASS | All unregistered paths denied without backend `Server` header, and no variant answered `200`. InfoNotes explain a skipped sub-check 2. |
| FAIL | At least one finding: `Unregistered path not denied by Gateway`, `Backend application server identified in response to unregistered path`, `Authentication bypass via path normalization variant`. |
| SKIP | The attack surface is not available. |
| ERROR | Unexpected exception. |

References: CWE-284, NIST-SP-800-204-S4.1, OWASP-ASVS-v5.0.0-V4.1.1, CIS-Benchmark-API-GW-Controls-2.3.

InfoNotes for sub-check 2: `Path Normalization Sub-check Skipped: No Suitable Path`,
`… Skipped: Baseline Probe Failed`, `… Not Applicable: Public Endpoint`, `… Skipped: Unexpected Baseline Status`.

## Oracle states

| State | Meaning |
|---|---|
| `CORRECTLY_DENIED` | Unregistered path denied, no backend header. |
| `GATEWAY_BYPASS` | Unregistered path not denied (FAIL evidence). |
| `BACKEND_LEAKED` | Denied, but the `Server` header identifies a backend (FAIL evidence). |
| `BASELINE_AUTH_ENFORCED` | Canonical path answered `401`/`403`: variants are tested. |
| `BASELINE_PUBLIC` | Canonical path answered `200`: sub-check 2 not applicable. |
| `BASELINE_UNEXPECTED` | Canonical path answered another status: sub-check 2 skipped. |
| `AUTH_BYPASS_VIA_NORMALIZATION` | Variant answered `200` (FAIL evidence). |
| `AUTH_ENFORCED_ON_VARIANT` | Variant answered `401`/`403`. |
| `VARIANT_REJECTED` | Variant answered any other status. |

## Prerequisites and effects on the target

Only the OpenAPI specification. Read-only `GET` requests, no credentials.

## Configuration

| Key | Effect |
|---|---|
| `gateway_server_identifiers` | Substrings that identify the gateway in the `Server` header. Add your gateway's value if it is not in the default list, otherwise its own replies are reported as backend leaks. |

## Coverage against the methodology

Source: [`methodology.it.md` §0.2](../../knowledge/methodology/methodology.it.md).

| Methodology sub-test | Status |
|---|---|
| Unregistered path rejection | Implemented (4 fixed paths). Body inspection for stack traces is not done. |
| Default backend fallback detection | Implemented via the `Server` header only (other backend headers such as `X-Backend-Server` are not checked). |
| Path normalization consistency | Partial: one endpoint, four variants. Double encoding and `../` traversal are not sent. |

## Why it exists

NIST SP 800-204 §4.1, OWASP ASVS v5.0.0 V4.1.1. Typical failures: a catch-all route forwarding everything to the
backend; a gateway matching `/api/users` exactly while the backend normalises `/api//users` or `/API/USERS` and
serves it without authentication.

Tooling decision ([`decisions.it.md` §0.2](../../knowledge/tools/decisions.it.md)): native test; cherrybomb is an
optional Cat B complement (static spec analysis), not implemented.

## Limitations

- The URL-encoded variant uses `urllib.parse.quote`, which leaves ASCII letters unchanged: for a segment like
  `users` the variant equals the canonical path and is not sent. In practice it only applies to segments with
  reserved or non-ASCII characters.
- Only a `200` on a variant is a finding; other `2xx` codes are classified as `VARIANT_REJECTED`.

## See also

- [`0.1 Shadow API discovery`](0-1-shadow-api-discovery.md) · [`1.1 Authentication required`](../domain-1/1-1-authentication-required.md)
- [`../README.md`](../README.md)
