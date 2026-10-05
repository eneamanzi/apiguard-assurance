# 0.3 Deprecated API Enforcement

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0) · **Source of truth:**
> [`src/tests/domain_0/test_0_3_deprecated_api_enforcement.py`](../../../src/tests/domain_0/test_0_3_deprecated_api_enforcement.py) ·
> **Verified:** 2026-10-05

| | |
|---|---|
| Test ID | `0.3` |
| Name | Deprecated APIs Are Disabled or Under Enhanced Monitoring |
| Domain | 0 - API Discovery and Inventory Management |
| Priority / strategy | P0 / BLACK_BOX |
| CWE | CWE-1059 |
| Depends on | none |
| Configuration | none |

## What it checks

Endpoints marked `deprecated: true` in the specification must be either disabled (`410 Gone`) or announce their
decommission date with a `Sunset` header (RFC 8594). After the sunset date they must answer `410 Gone`.

## How it works

1. Collect the endpoints with `deprecated: true` from the specification.
2. Endpoints whose path contains `{parameters}` are not probed (coverage gap, reported in the message or an
   InfoNote). `target.path_seed` is not used by this test.
3. Each remaining endpoint is requested **with its declared method**, without credentials.
4. Classification of the response:

| Response | Verdict |
|---|---|
| `410` | Correctly decommissioned; the transaction is pinned in `evidence.json` as compliance evidence. |
| Active status (`200, 201, 202, 204, 400, 401, 403, 422`) without `Sunset` header | Finding: `Active deprecated endpoint missing Sunset header`. |
| Active status with a `Sunset` date in the past | Finding: `Post-sunset deprecated endpoint still serving requests`. |
| Active status with a future or unparseable `Sunset` date | Compliant. |
| Any other status (`404`, `405`, `5xx`, …) | Recorded, no verdict. |

## Outcomes

| Status | When |
|---|---|
| PASS | All probed deprecated endpoints are compliant. Non-probed parametric endpoints are listed in an InfoNote. |
| FAIL | At least one finding (message also reports the number of non-probed endpoints). |
| SKIP | No endpoint is marked `deprecated`, **or** all deprecated endpoints are parametric. A spec without deprecations is SKIP, not PASS: absence of declarations does not prove absence of deprecated functionality. |
| ERROR | Unexpected exception. |

References: CWE-1059, OWASP-API9:2023, RFC-8594, NIST-SP-800-204-S3.1.3.

## Oracle states

| State | Meaning |
|---|---|
| `SUNSET_MISSING` | Active without `Sunset` (FAIL evidence). |
| `POST_SUNSET_ACTIVE` | Active after the sunset date (FAIL evidence). |
| `DEPRECATED_ACTIVE_SUNSET_OK` | Active with a future or unparseable `Sunset`. |
| `CORRECTLY_DECOMMISSIONED` | `410 Gone`. |
| `OTHER_STATUS` | Any other status. |

## Prerequisites and effects on the target

- Only the OpenAPI specification.
- The declared method is used: a deprecated `POST`, `PUT` or `DELETE` endpoint receives that method, without
  credentials and without a body.

## Coverage against the methodology

Source: [`methodology.it.md` §0.3](../../knowledge/methodology/methodology.it.md).

| Methodology sub-test | Status |
|---|---|
| Deprecated endpoint accessibility + Sunset + post-sunset `410` | Implemented (declared method instead of `HEAD`; parametric paths excluded). |
| Differential rate limiting on deprecated endpoints | Not implemented (planned, needs GREY_BOX). |
| Differential logging verbosity | Not implemented (planned, needs log access). |

## Why it exists

OWASP API9:2023, NIST SP 800-204 §3.1.3. Deprecated endpoints get less patching and monitoring while remaining
reachable: a vulnerability fixed in v2 but not backported to v1, or a `Sunset` date announced and never enforced
("zombie API").

Tooling decision ([`decisions.it.md` §0.3](../../knowledge/tools/decisions.it.md)): native test; oasdiff is an
optional Cat B complement (spec version diff), not implemented.

## Limitations

- An unparseable `Sunset` value is treated as compliant.
- Results depend entirely on the spec declaring `deprecated: true`.

## See also

- [`0.1 Shadow API discovery`](0-1-shadow-api-discovery.md)
- [`../README.md`](../README.md)
