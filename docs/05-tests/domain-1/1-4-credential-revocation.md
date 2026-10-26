# 1.4 Credential Revocation

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-22) ·
> **Source of truth:**
> [`src/tests/domain_1/test_1_4_credential_revocation.py`](../../../src/tests/domain_1/test_1_4_credential_revocation.py),
> [`src/tests/helpers/anchor.py`](../../../src/tests/helpers/anchor.py) · **Verified:** 2026-10-22

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("1.4", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `1.4` |
| Name | Credential Revocation |
| Domain | 1 - Identity and Authentication |
| Priority / strategy | P2 / WHITE_BOX |
| Effect | CHANGES_DATA |
| CWE | CWE-613 |
| Standards | `OWASP API2:2023`, `RFC 7009`, `RFC 7519, Section 4.1.7`, `OWASP ASVS v5.0.0-7.4.1` |
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

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 1.4) |
|---|---|
| `rejected_after_revocation` | "token after logout": create a credential, revoke it, reuse it, expect a refusal |
| left out | "token after password change" (a target-specific reset/OTP flow); "idempotent logout" (concurrency, not a revocation-enforcement question) |

## 3. Inputs

The login method's own revocation capability (`Need.REVOCABLE_LOGIN`: `auth_type: login` with a login resource
that has a delete request). An **anchor**: a documented read that answers 2xx with the credential and non-2xx
without it (`src/tests/helpers/anchor.py`), so that a refusal after revocation is about the revocation and not
about a public endpoint. No configuration parameter (the old test's `protected_endpoint` is derived now).

## 4. Preconditions and reference responses

- the revocation capability: without it the test SKIPs (crAPI's stateless JWT has no logout);
- the anchor: without a genuinely protected read the test is `NOT_VERIFIABLE/NO_WORKING_ANCHOR`;
- the credential is confirmed to work at the anchor **before** revocation, so that "refused after revocation" is
  read against "accepted before it".

## 5. Probes

Create a credential through the configured login; confirm it answers 2xx at the anchor; revoke it (the login
method's delete request) and confirm the target accepted the revocation; send the revoked credential to the anchor
again. One created credential, revoked and cleaned up.

## 6. Oracle

| Case | Outcome / detail | Confidence |
|---|---|---|
| the revoked credential is refused (non-2xx) | `ENFORCED/REFUSED_AFTER_REVOCATION` | - |
| it still answers 2xx | `VIOLATION/ACCEPTED_AFTER_REVOCATION` | CERTAIN: the credential outlives its revocation |
| the login cannot revoke | SKIP (the need is not met) | - |
| no anchor requires the credential | `NOT_VERIFIABLE/NO_WORKING_ANCHOR` | - |
| the target did not confirm the revocation | `NOT_VERIFIABLE/REVOCATION_NOT_CONFIRMED` | - |
| no credential placement configured | SKIP | - |
| unavailable, rate limited, no response, server error | `NOT_VERIFIABLE/` the reason | - |

## 7. Outcomes

SKIP when the login cannot revoke a credential or no placement is configured. Otherwise FAIL when the revoked
credential is accepted, PASS when it is refused.

## 8. Findings

"Revoked credential still accepted: `<method> <path>`", with the status; `evidence_ref` the reuse request,
`supporting_refs` the creation and the revocation records.

## 9. Effects on the target

`CHANGES_DATA`: the test creates a credential and revokes it, both through the configured login, and cleans up. The
run order puts it after the read-only tests (rule 7).

## 10. Per gateway

Independent of the gateway: revocation is the application's (Forgejo deletes the token); the gateway forwards the
reuse request.

## 11. Configuration

None. The old `protected_endpoint` parameter is gone: the anchor is derived.

## 12. Validation

Runs of 2026-10-22, the three tests of the group together:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, Forgejo + APISIX | **PASS** | a token is created, accepted at the anchor `GET /api/v1/user`, deleted (HTTP 204), and refused (401) when reused |
| crAPI + Kong | SKIP | the JWT is stateless and crAPI has no logout: `Need.REVOCABLE_LOGIN` not met |
| Forgejo + Kong, with the case below | **FAIL, 1 finding** | an endpoint that trusts any token without rechecking it answers 200 to the deleted token: `ACCEPTED_AFTER_REVOCATION` |

**The case the labs lack, and how to undo it.** Forgejo revokes correctly, so the violation was produced on the
Forgejo + Kong lab with a route that makes the anchor trust the header without revalidating it. In
`test-environments/forgejo-kong/kong/kong.yml`, inside `services[forgejo-service].routes`:

```yaml
      - name: review-stale-token-route
        paths:
          - '~/api/v1/user$'
        strip_path: false
        preserve_host: false
        protocols:
          - https
        https_redirect_status_code: 301
        plugins:
          - name: pre-function
            config:
              access:
                - |
                  if kong.request.get_header("authorization") then
                    return kong.response.exit(200, { login = "user-a" })
                  end
                  return kong.response.exit(401, { message = "token is required" })
```

Then `cd test-environments/forgejo-kong && docker compose --env-file ../../.env up -d --force-recreate --wait
kong`; undo with `git checkout test-environments/forgejo-kong/kong/kong.yml` and the same command. The lab was
checked back to its usual results afterwards.

Found while producing this case: the anchor must answer non-2xx without the credential, not only 2xx with it. An
earlier version accepted `/api/v1/orgs`, which is public on Forgejo (200 with no credential) while the spec marks
it protected; it answered 401 only because an *invalid* token was sent, which is a different thing from revocation.
The anchor now confirms both conditions (`src/tests/helpers/anchor.py`), which also sharpens test `1.2`.

**What each branch has been seen doing** (rule 9). Proven on a lab: `REFUSED_AFTER_REVOCATION` (Forgejo),
`ACCEPTED_AFTER_REVOCATION` (the case above), the SKIP for no revocation (crAPI). Still unproven:
`NO_WORKING_ANCHOR`, `REVOCATION_NOT_CONFIRMED`, the transport reasons.

## 13. Remediation

Invalidate a credential at the server when it is revoked: keep a revocation list keyed by the token id, or issue
short-lived tokens with refresh rotation, so a deleted or logged-out token stops working at once
(ASVS v5.0.0-7.4.1, RFC 7009).

## 14. Limitations

- Only revocation by the login's own mechanism (deletion, logout) is tested; revocation by a password change is a
  target-specific flow left to a configured path, not hard-coded.
- A stateless JWT with no revocation endpoint is SKIP, not a finding: the guarantee is about what revocation does,
  and there is no revocation to exercise.
- Concurrency (idempotent logout) is not tested: it is not a revocation-enforcement question.

## 15. Sources

- OWASP API2:2023 Broken Authentication: https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/
- RFC 7009 (OAuth 2.0 Token Revocation): https://www.rfc-editor.org/rfc/rfc7009.html
- RFC 7519 section 4.1.7 (the `jti` claim): https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.7
- OWASP ASVS v5.0.0-7.4.1 (termination disallows further use): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x16-V7-Session-Management.md
- CWE-613 Insufficient Session Expiration: https://cwe.mitre.org/data/definitions/613.html
