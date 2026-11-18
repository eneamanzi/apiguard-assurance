# 1.4 Credential Revocation

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_1/test_1_4_credential_revocation.py`](../../../src/tests/domain_1/test_1_4_credential_revocation.py), [`src/tests/helpers/anchor.py`](../../../src/tests/helpers/anchor.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("1.4", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `1.4` |
| Name | Credential Revocation |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P2 / WHITE_BOX |
| Effect | CHANGES_DATA |
| CWE | CWE-613 |
| Standards | `OWASP API2:2023`, `RFC 7009`, `OWASP ASVS v5.0.0-7.4.1` |
| Tags | `authentication`, `credential-lifecycle` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT`, `REVOCABLE_LOGIN` |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `1.2` and `1.3`.

## 1. Guarantee

A credential that has been revoked is refused. A target that keeps the guarantee invalidates the credential at the
server when it is revoked (a deleted token, a logout), so the act meant to end it ends it.

A PASS promises that a credential revoked through the login's own mechanism was refused afterwards. It promises
nothing about a credential that is merely invalid (`1.2`) or expired (`1.3`), and nothing about revocation by a
password change, which is a separate target-specific flow not covered here.

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 1.4) |
|---|---|
| `rejected_after_revocation` | "token after logout": create a credential, revoke it, reuse it, expect a refusal |
| left out | "token after password change" (a target-specific reset/OTP flow); "idempotent logout" (concurrency, not a revocation-enforcement question) |

### 2.2 Preconditions and reference responses

- the revocation capability: without it the test SKIPs (crAPI's stateless JWT has no logout);
- the anchor: without a genuinely protected read the test is `NOT_VERIFIABLE/NO_WORKING_ANCHOR`;
- the credential is confirmed to work at the anchor **before** revocation, so that "refused after revocation" is
  read against "accepted before it".

### 2.3 Probes

Create a credential through the configured login; confirm it answers 2xx at the anchor; revoke it (the login
method's delete request) and confirm the target accepted the revocation; send the revoked credential to the anchor
again. One created credential, revoked and cleaned up.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("1.4")) ]]] -->

| Case | Outcome / detail | Confidence |
|---|---|---|
| the revoked credential is refused (`400`, `401`, `403`) at the anchor | `ENFORCED/REFUSED_AFTER_REVOCATION` | - |
| it is served (`2xx`) with the answer it got before revocation | `VIOLATION/ACCEPTED_AFTER_REVOCATION` | CERTAIN |
| it is served with another answer (a `200` may carry an error) | `VIOLATION/ACCEPTED_AFTER_REVOCATION` | FIRM |
| it gets another answer (a redirect, `404`, ...) | `NOT_VERIFIABLE/NOT_A_REFUSAL` | - |
| no documented read accepts the new credential and refuses no credential | `NOT_VERIFIABLE/NO_WORKING_ANCHOR` | - |
| the delete request of the credential did not answer `2xx` | `NOT_VERIFIABLE/REVOCATION_NOT_CONFIRMED` | - |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("1.4", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("1.4", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 10 of 10 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `rejected_after_revocation/ENFORCED/REFUSED_AFTER_REVOCATION` | forgejo-kong: the lab as built: a token is created, accepted at the anchor GET /api/v1/user, deleted (204), and refused 401 when reused | OK |
| `rejected_after_revocation/VIOLATION/ACCEPTED_AFTER_REVOCATION/CERTAIN` | forgejo-kong: a temporary route GET ~/api/v1/user$ answers 200 {login: user-a} to any request with an Authorization header and 401 without: the deleted token gets the answer it got before revocation | OK |
| `rejected_after_revocation/VIOLATION/ACCEPTED_AFTER_REVOCATION/FIRM` | forgejo-kong: a temporary route GET ~/api/v1/user$ passes the two anchor reads (with and without the credential) to Forgejo and answers the reuse of the deleted token 200 with a JSON body of another shape | OK |
| `rejected_after_revocation/NOT_VERIFIABLE/NOT_A_REFUSAL` | forgejo-kong: the same counter route answering the reuse of the deleted token 404 | OK |
| `rejected_after_revocation/NOT_VERIFIABLE/NO_WORKING_ANCHOR` | forgejo-kong: the run reads a local copy of Forgejo's specification with its global security set to [], so no documented read requires authentication and none is a candidate anchor | OK |
| `rejected_after_revocation/NOT_VERIFIABLE/REVOCATION_NOT_CONFIRMED` | forgejo-kong: a temporary route DELETE ~/api/v1/users/[^/]+/tokens/[^/]+$ answers the first token deletion (the test's revocation) 404 itself; the teardown deletions pass to Forgejo, so no token is left behind | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: a temporary route GET ~/api/v1/user$ passes the two anchor reads to Forgejo and answers the reuse of the deleted token 503 | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: the same counter route answering the reuse 429 | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: the same counter route answering the reuse 500 | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: the same counter route sleeping 7 s on the reuse before proxying, with the run's read timeout at 5 s | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("1.4", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- Only revocation by the login's own mechanism (deletion, logout) is tested; revocation by a password change is a
  target-specific flow left to a configured path, not hard-coded.
- A stateless JWT with no revocation endpoint is SKIP, not a finding: the guarantee is about what revocation does,
  and there is no revocation to exercise.
- Concurrency (idempotent logout) is not tested: it is not a revocation-enforcement question.

## 6. Sources

- OWASP API2:2023 Broken Authentication: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- RFC 7009 (OAuth 2.0 Token Revocation): https://www.rfc-editor.org/rfc/rfc7009.html
- RFC 7519 section 4.1.7 (the `jti` claim): https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7
- OWASP ASVS v5.0.0-7.4.1 (termination disallows further use): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x16-V7-Session-Management.md
- CWE-613 Insufficient Session Expiration: https://cwe.mitre.org/data/definitions/613.html

## 7. Inputs

The login method's own revocation capability (`Need.REVOCABLE_LOGIN`: `auth_type: login` with a login resource
that has a delete request). An **anchor**: a documented read that answers 2xx with the credential and is refused (401 or 403)
without it (`src/tests/helpers/anchor.py`), so that a refusal after revocation is about the revocation and not
about a public endpoint. No configuration parameter: the protected endpoint is derived.

## 8. Outcomes

SKIP when the login cannot revoke a credential or no placement is configured. Otherwise FAIL when the revoked
credential is accepted, PASS when it is refused.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("1.4")) ]]] -->

- "Revoked credential still accepted: <method> <path>"

<!-- [[[end]]] -->

`evidence_ref` the reuse; `supporting_refs` the anchor accepted before revocation, refused without a credential, and the revocation.

## 10. Effects on the target

`CHANGES_DATA`: the test creates a credential and revokes it, both through the configured login, and cleans up. The
run order puts it after the read-only tests (rule 7).

## 11. Per gateway

Independent of the gateway: revocation is the application's (Forgejo deletes the token); the gateway forwards the
reuse request.

## 12. Configuration

None. The old `protected_endpoint` parameter is gone: the anchor is derived.

## 13. Remediation

Invalidate a credential at the server when it is revoked: keep a revocation list keyed by the token id, or issue
short-lived tokens with refresh rotation, so a deleted or logged-out token stops working at once
(ASVS v5.0.0-7.4.1, RFC 7009).
