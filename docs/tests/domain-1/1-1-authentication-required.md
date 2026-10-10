# 1.1 Authentication Required

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0) · **Source of truth:**
> [`src/tests/domain_1/test_1_1_authentication_required.py`](../../../src/tests/domain_1/test_1_1_authentication_required.py) ·
> **Verified:** 2026-10-05

| | |
|---|---|
| Test ID | `1.1` |
| Name | Only Authenticated Requests Access Protected Resources |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P0 / BLACK_BOX |
| CWE | CWE-306 |
| Depends on | none |
| Configuration | [`tests.domain_1.test_1_1`](../../reference/configuration.md#testsdomain_1test_1_1---authentication-required), [`target.path_seed`](../../reference/configuration.md#target) |

## What it checks

Every endpoint that the specification declares as protected (a `security` requirement, global or per operation)
must reject requests without valid credentials with `401` or `403`.

## How it works

**Phase A: every protected endpoint, no credentials.** Each endpoint is requested with its **declared method**
(never a substitute `GET`). Path parameters are filled from `target.path_seed`, otherwise with a placeholder.
Method-safety rules:

| Method | Request sent |
|---|---|
| `GET`, `HEAD`, `OPTIONS` | As is. Missing parameters → `1`. |
| `POST`, `PUT`, `PATCH` | With an empty JSON body `{}`. Missing parameters → `1`. |
| `DELETE` on a path with parameters | Parameters from `path_seed`, otherwise `apiguard-probe`. |
| `DELETE` on a path without parameters | **Not sent** (counted as unprobed destructive endpoint; verify manually). |

Response classification:

| Response | Outcome |
|---|---|
| `401`, `403` | Enforced |
| any `2xx` | **Bypass** → finding |
| `404`, `405`, `410` | Inconclusive (separate counters for parametric and non-parametric paths) |
| `3xx` redirect, `429`, `5xx` | Inconclusive |

**Phases B, B.5, C** run on the first non-parametric endpoint that answered `401`/`403` (the "anchor"), without
valid credentials:

- **B, malformed tokens:** `Authorization: Bearer`, `Bearer null`, `Bearer undefined`,
  `no-scheme-apiguard-probe`, `Bearer XXXXXXXX` (`src/tests/data/auth_payloads.py`). A `2xx` is a finding.
- **B.5, header-name casing:** `authorization`, `AUTHORIZATION`, `AuThOrIzAtIoN` with value
  `Bearer apiguard-case-probe`. A `2xx` is a finding.
- **C, path normalization:** trailing slash, uppercase path, double leading slash. `401/403/404/405/410` are
  acceptable; a `2xx` is a finding.

If no non-parametric endpoint answered `401`/`403`, phases B to C are skipped.

## Outcomes

| Status | When |
|---|---|
| PASS | No bypass. The message gives the full breakdown (`Scope: X/Y protected endpoints probed. Outcomes: …`). |
| PASS + InfoNote | No bypass, but **no endpoint answered `401`/`403`**: `Observability Gap: No Positive Enforcement Evidence Obtained`. Authentication could not be confirmed; verify manually. |
| FAIL | At least one finding: `Protected endpoint accessible without authentication`, `Protected endpoint accepts malformed Authorization token`, `Auth enforcement bypassed via non-canonical header casing`, `Path normalisation bypass: protected endpoint accessible`. |
| SKIP | Attack surface unavailable, or the spec declares no protected endpoint. |
| ERROR | Unexpected exception. |

## Oracle states

| State | Meaning |
|---|---|
| `ENFORCED` | `401`/`403` in phase A. |
| `AUTH_BYPASS` | `2xx` in phase A (FAIL evidence). |
| `INCONCLUSIVE_PARAMETRIC` | `404`/`405`/`410` on a path with parameters: usually the placeholder ID does not exist. Fill `path_seed` to reduce these. |
| `INCONCLUSIVE_NOT_FOUND` | `404`/`405`/`410` on a path without parameters (anomalous: the documented path does not exist on the deployment). |
| `INCONCLUSIVE_REDIRECT`, `INCONCLUSIVE_RATELIMITED`, `INCONCLUSIVE_SERVER_ERROR` | `3xx`, `429`, `5xx`. |
| `MALFORMED_TOKEN_REJECTED` / `MALFORMED_TOKEN_BYPASS` | Phase B. |
| `HEADER_CASE_ENFORCED` / `HEADER_CASE_BYPASS` | Phase B.5. |
| `NORMALIZATION_ACCEPTABLE` / `NORMALIZATION_BYPASS` | Phase C. |

## Prerequisites and effects on the target

- OpenAPI specification with `security` declarations. No credentials.
- **Write methods are sent without credentials** (`POST`/`PUT`/`PATCH` with `{}`, `DELETE` on parametric paths).
  On a correctly protected target they are rejected before reaching the business logic. **The `DELETE` uses the
  resources listed in `path_seed`**: a target without authentication on that endpoint deletes them. This is
  intended: `path_seed` must list only test resources you can lose (on the lab, the ones the setup creates).
- After a successful unauthenticated `DELETE` (a finding) the resource is gone: later requests that use it, in this
  and in the following tests, end inconclusive or in error. The tool does not restore it (it cannot recreate a
  resource it did not create); restore the environment before the next run (on the lab: reset from scratch,
  [first assessment](../../getting-started/first-assessment.md) steps 2-3).
- Number of requests: one per protected endpoint (all of them by default) plus up to 11 for phases B to C.

## Configuration

| Key | Effect |
|---|---|
| `tests.domain_1.test_1_1.max_endpoints_cap` | `0` (default) probes all protected endpoints; `N` probes the first N. |
| `target.path_seed` | Real values for path parameters: fewer inconclusive results on parametric paths. |

## Coverage against the methodology

Source: [`methodology.it.md` §1.1](../../knowledge/methodology/methodology.it.md).

| Methodology sub-test | Status |
|---|---|
| Access without token on all protected endpoints | Implemented. |
| Empty and malformed token | Implemented (5 values, on one anchor endpoint). |
| Header case variations | Implemented (on one anchor endpoint). |
| Path normalization | Implemented (3 variants on one anchor endpoint; `../` variants not sent). Response-body inspection for leaked data is not done. |

## Why it exists

OWASP API2:2023 (Broken Authentication), NIST SP 800-63B-4 §4.3.1, OWASP ASVS v5.0.0 V6.3. It is the foundation
of the authenticated tests: if authentication is not enforced, the premises of the GREY_BOX tests do not hold.
Tooling decision ([`decisions.it.md` §1.1](../../knowledge/tools/decisions.it.md)): native only, no external
tool adds value.

## Limitations

- "Protected" means "declared as protected in the spec". An endpoint that should be protected but has no
  `security` entry is not tested here.
- Only `2xx` counts as bypass: a protected endpoint answering `404` to everyone is inconclusive, not compliant.

## See also

- [`0.2 Deny-by-default`](../domain-0/0-2-deny-by-default.md) · [`1.4 Token revocation`](1-4-token-revocation.md) · [`2.1 RBAC`](../domain-2/2-1-rbac-enforcement.md)
- [`../README.md`](../README.md)
