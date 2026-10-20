# 2.1 RBAC Enforcement

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0) · **Source of truth:**
> [`src/tests/domain_2/test_2_1_rbac_enforcement.py`](../../../src/tests/domain_2/test_2_1_rbac_enforcement.py) ·
> **Verified:** 2026-10-05

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("2.1", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `2.1` |
| Name | Only Authorized Users Access Privileged Endpoints |
| Domain | 2 - Authorization and Access Control |
| Priority / strategy | P2 / GREY_BOX |
| CWE | CWE-285 |
| Tags | `authorization`, `rbac`, `OWASP-API5:2023`, `OWASP-ASVS-V8.3.1`, `NIST-SP-800-53-AC-3` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT`, `admin_endpoint_paths` |
| Parameters | [`tests.domain_2.test_2_1`](../../reference/configuration.md#testsdomain_2test_2_1) |

<!-- [[[end]]] -->


## What it checks

An authenticated user without administrative role must not be able to call admin-only endpoints (broken
function-level authorization, OWASP API5:2023).

## How it works

1. Obtain the `user_a` credential with the configured authentication method (`credentials.auth_type`).
2. For each path in `admin_endpoint_paths` (no default; the Forgejo labs set `/api/v1/admin/users`), send
   `admin_endpoint_method` (default `GET`) with the `user_a` credential, sent as the run's credential placement says
   (Forgejo labs: `Authorization: token <value>`; crAPI: `Authorization: Bearer <value>`).
3. Oracle per response:

| Response | Verdict |
|---|---|
| `2xx` | Bypass → finding `RBAC Bypass: <METHOD> <path>` |
| `403`, `404` | Enforced |
| anything else (`401`, `405`, `5xx`, …) | Inconclusive, no finding |

## Outcomes

| Status | When |
|---|---|
| PASS | No configured admin endpoint returned `2xx`. |
| FAIL | At least one bypass. |
| SKIP | No admin path configured (`admin_endpoint_paths` empty, the default); no API credentials or no `user_a` credential. |
| ERROR | Token acquisition failed, or unexpected exception. |

References: CWE-285, OWASP-API5:2023, OWASP-ASVS-v5.0.0-V8.3.1, OWASP-ASVS-v5.0.0-V8.2.2, NIST-SP-800-53-Rev5-AC-3.

## Oracle states

`RBAC_ENFORCED`, `RBAC_BYPASS` (FAIL evidence), `RBAC_INCONCLUSIVE`.

## Prerequisites and effects on the target

- `user_a` username and password.
- The configured method is sent with a valid user token: if you configure `DELETE` or `POST` and the target is
  vulnerable, the operation is executed. The default (`GET`) is read-only.

## Configuration

Set `admin_endpoint_paths` to the target's admin-only endpoints; without them the test returns SKIP. Use paths the
target has: a path it does not have answers `404`, classified as enforced (Q-29).

## Coverage against the methodology

Source: [`guarantees.md` §2.1](../../knowledge/methodology/guarantees.md).

| Methodology sub-test | Status |
|---|---|
| Admin endpoints called with a user token | Implemented for the configured list, one method. Endpoints are not derived from the spec. |
| HTTP method confusion on each resource | Not implemented. |
| Role hierarchy (moderator vs admin) | Not implemented. |

## Why it exists

OWASP API5:2023, OWASP ASVS v5.0.0 V8.3.1 and V8.2.2, NIST SP 800-53 Rev. 5 AC-3. Authentication proves who the
caller is; authorization decides what they may do. A UI that hides an admin button does not stop a direct API call.

## Limitations

- `404` counts as enforced, so a wrong or non-existent path in the configuration produces a PASS. The module
  docstring describes `404` as inconclusive; the code treats it as enforced.
- Coverage is limited to the configured endpoints.

## See also

- [`1.1 Authentication required`](../domain-1/1-1-authentication-required.md)
- [`../README.md`](../README.md)
