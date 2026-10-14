# 1.4 Token Revocation

> **Audience:** analysts, contributors · **Status:** implemented (v0.1.0) · **Source of truth:**
> [`src/tests/domain_1/test_1_4_token_revocation.py`](../../../src/tests/domain_1/test_1_4_token_revocation.py),
> [`src/tests/helpers/auth_login.py`](../../../src/tests/helpers/auth_login.py) · **Verified:** 2026-10-14 (login
> resource and `verify_request` on the Forgejo labs), 2026-10-05

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

The test uses the **revocation capability** of the configured authentication method (`credentials.auth_type`):
`login` has it when its [login resource](../../reference/configuration.md#resources) has a delete request; any other
case gives SKIP "Not applicable".

1. The method creates a temporary credential for the admin account: a new instance of the login resource (on the
   Forgejo labs, `POST /api/v1/users/{username}/tokens` with Basic Auth, token named `apiguard-<random>`). Its
   deletion is registered for teardown as a safety net.
2. The method revokes it: the resource's delete request, sent at once (Forgejo:
   `DELETE /api/v1/users/{username}/tokens/{id}`).
3. Re-use the revoked credential: `tests.domain_1.test_1_4.verify_request` (Forgejo labs: `GET /api/v1/user`), sent
   as the run's credential placement says (on the Forgejo labs `Authorization: token <value>`).
4. Oracle on step 3: `2xx` → FAIL; any other status → PASS.

No path is written in the test: the token API comes from the login resource, the check from `verify_request`. The
test does not check that the credential worked before the revocation (Q-29).

## Outcomes

| Status | When |
|---|---|
| PASS | The revoked token was not accepted (step 3 returned a non-`2xx` status). |
| FAIL | The revoked token was accepted (`2xx`). |
| SKIP | No API credentials configured; the authentication method cannot revoke a credential ("Not applicable: the authentication method '<auth_type>' cannot revoke a credential ..."); no `verify_request` configured; no admin account configured. |
| ERROR | Creation or revocation of the temporary credential failed (the message names the resource and the status), or an unexpected exception. |

References: CWE-613, OWASP-API2:2023, RFC-7009, OWASP-ASVS-v5.0.0-V7.4, NIST-SP-800-63B-4-S5.1.

## Oracle states

| State | Meaning |
|---|---|
| `TEMP_TOKEN_CREATED` | Step 1. |
| `TEMP_TOKEN_DELETED` / `TOKEN_DELETE_FAILED` | Step 2. |
| `REVOKED_TOKEN_REJECTED` | Step 3 returned a non-`2xx` status. |
| `REVOKED_TOKEN_ACCEPTED` | Step 3 returned `2xx` (FAIL evidence). |

## Prerequisites and effects on the target

- Admin username and password (`credentials.admin_*`), `auth_type: login` with a login resource that has a delete
  request, and `verify_request`.
- **Creates and revokes a credential** on the admin account (Forgejo: an API token). If the run is interrupted
  between steps 1 and 2, teardown (Phase 6) deletes it.

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
- Runs only with an authentication method that can revoke a credential: `login` with a login resource that has a
  delete request (token deletion). APIs that revoke with a logout request are not supported yet (a `revoke` request
  of the resource, to add when a target needs it); crAPI has no revocation, so 1.4 gives SKIP there.

## See also

- [`1.1 Authentication required`](1-1-authentication-required.md)
- [`../README.md`](../README.md)
