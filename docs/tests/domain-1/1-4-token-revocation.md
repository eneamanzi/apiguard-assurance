# 1.4 Token Revocation

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0), **Forgejo/Gitea only** · **Source of
> truth:** [`src/tests/domain_1/test_1_4_token_revocation.py`](../../../src/tests/domain_1/test_1_4_token_revocation.py) ·
> **Verified:** 2026-10-05

| | |
|---|---|
| Test ID | `1.4` |
| Name | Revoked Token Rejected After Deletion |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P2 / WHITE_BOX (the API's administrator account) |
| CWE | CWE-613 |
| Depends on | none |
| Configuration | [`tests.domain_1.test_1_4`](../../reference/configuration.md#testsdomain_1test_1_4---token-revocation), admin credentials |

## What it checks

A token that has been explicitly revoked must be rejected immediately, not accepted until its natural expiry.

## How it works

The test uses the **revocation capability** of the configured authentication method (`credentials.auth_type`).
Only `forgejo_token` has it; with any other method the test returns SKIP.

1. The method creates a temporary token named `token_name` under the admin account: `POST
   /api/v1/users/{username}/tokens` with Basic Auth (a token left with the same name by an interrupted run is
   deleted first). A `DELETE` for it is registered for teardown as a safety net.
2. The method revokes it: `DELETE /api/v1/users/{username}/tokens/{name}`.
3. Re-use the revoked token: `GET /api/v1/user`, sent as the run's credential placement says (on the Forgejo labs
   `Authorization: token <value>`).
4. Oracle on step 3: `2xx` → FAIL; any other status → PASS.

The token API and the re-probe path are Forgejo/Gitea's (`src/tests/helpers/auth_forgejo.py` and the test
module). The test does not check that the token worked before the revocation (Q-29).

## Outcomes

| Status | When |
|---|---|
| PASS | The revoked token was not accepted (step 5 returned a non-`2xx` status). |
| FAIL | The revoked token was accepted (`2xx`). |
| SKIP | No API credentials configured; the authentication method cannot revoke a credential ("Not applicable: the authentication method '<auth_type>' cannot revoke a credential."); no admin account configured. |
| ERROR | Token creation or revocation failed, or an unexpected exception. |

References: CWE-613, OWASP-API2:2023, RFC-7009, OWASP-ASVS-v5.0.0-V7.4, NIST-SP-800-63B-4-S5.1.

## Oracle states

| State | Meaning |
|---|---|
| `TEMP_TOKEN_CREATED` / `TOKEN_CREATE_FAILED` / `TOKEN_CREATE_NO_VALUE` | Step 3. |
| `TEMP_TOKEN_DELETED` / `TOKEN_DELETE_FAILED` | Step 4. |
| `REVOKED_TOKEN_REJECTED` | Step 5 returned a non-`2xx` status. |
| `REVOKED_TOKEN_ACCEPTED` | Step 5 returned `2xx` (FAIL evidence). |

## Prerequisites and effects on the target

- Admin username and password (`credentials.admin_*`).
- **Creates and deletes an API token** on the admin account. If the run is interrupted between steps 3 and 4,
  teardown (Phase 6) deletes it.

## Coverage against the methodology

Source: [`methodology.it.md` §1.4](../../knowledge/methodology/methodology.it.md).

| Methodology sub-test | Status |
|---|---|
| Token reused after logout | Implemented as "API token reused after deletion" (Forgejo has no logout for API tokens). |
| Token reused after password change | Not implemented. |
| Idempotent concurrent logout | Not implemented. |

## Why it exists

OWASP API2:2023, RFC 7009, OWASP ASVS v5.0.0 V7.4, NIST SP 800-63B-4 §5.1. A purely stateless token checked only
for signature and expiry stays valid after logout or compromise until it expires. Tooling decision
([`decisions.it.md` §1.4](../../knowledge/tools/decisions.it.md)): native only (stateful login → revoke → replay
sequence).

## Limitations

- Any non-`2xx` response is a PASS, including `404` or `5xx`: a broken re-probe endpoint would look compliant.
- Not portable: requires the Forgejo/Gitea token API (Q-18).

## See also

- [`1.1 Authentication required`](1-1-authentication-required.md)
- [`../README.md`](../README.md)
