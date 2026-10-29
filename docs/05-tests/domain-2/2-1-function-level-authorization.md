# 2.1 Function-Level Authorization

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_2/test_2_1_function_level_authorization.py`](../../../src/tests/domain_2/test_2_1_function_level_authorization.py),
> [`src/discovery/derivation.py`](../../../src/discovery/derivation.py) · **Verified:** 2026-10-23

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("2.1", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `2.1` |
| Name | Function-Level Authorization |
| Domain | 2 - Authorization and Access Control |
| Priority / strategy | P1 / GREY_BOX |
| Effect | READ_ONLY |
| CWE | CWE-285 |
| Standards | `OWASP API5:2023`, `OWASP ASVS v5.0.0-8.2.1`, `OWASP ASVS v5.0.0-8.1.1`, `OWASP ASVS v5.0.0-8.3.1`, `NIST SP 800-53r5, Section 3.1` |
| Tags | `authorization`, `bfla` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT`, `ADMIN_ACCOUNT` (optional) |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `2.2`, `2.4`, `2.5` (authorization).

## 1. Guarantee

A privileged function (an admin or management operation) refuses an ordinary authenticated user. A PASS promises
that every privileged operation the tool probed turned user_a away. The threat is Broken Function Level Authorization
(OWASP API5:2023): the interface hides the admin action, but the API does not check the role, so a direct request
succeeds. ASVS v5.0.0-8.3.1 (enforce authorization at a trusted service layer). This test subsumes guarantee 2.3
(destructive operations need privilege): a destructive method that bypasses the role check is a function-level
failure.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 2.1) |
|---|---|
| `privileged_function_refuses_user` | "admin endpoint with a user token: expect 403, not 200", for every privileged operation |
| `method_not_confused` | "HTTP method confusion": the safe methods of one privileged path agree for user_a |
| left out | role hierarchy beyond user/admin (no moderator tier on the labs); OAuth scope escalation (no granular scopes); destructive-method probing on derived endpoints (rule 5: surfaced as `DESTRUCTIVE_NOT_PROBED`, not sent) |

## 3. Inputs

The privileged operations are derived (Phase-2 rule `privileged_endpoints`: a path segment `admin` or `management`);
the configuration's `admin_endpoint_paths` add or correct. The specification's `requires_auth` tells a public path
apart from a protected one. The admin account (optional) is the positive control.

## 4. Preconditions and reference responses

user_a is required (GREY_BOX). The admin account is an optional need: when present, the admin positive control proves
the operation exists and is genuinely privileged, so a refusal is about the role (CERTAIN) and a `404` is not
mistaken for enforcement. Without admin, the verdict rests on the path's shape and the spec's `security` (FIRM).

## 5. Probes

Only safe methods (GET, HEAD) of a privileged operation are sent, with the user_a credential; path parameters are
resolved from `path_seed`. A destructive method on a derived candidate is not sent (rule 5). READ_ONLY.

## 6. Oracle

**`privileged_function_refuses_user`** (per privileged operation)

| Case | Outcome / detail | Confidence |
|---|---|---|
| user_a served (2xx), the op requires auth | `VIOLATION/BFLA` | CERTAIN with the admin control, else FIRM |
| user_a served (2xx), the op is public in the spec | `NOT_APPLICABLE/PUBLIC_ENDPOINT` (that is 1.1's question) | - |
| user_a refused (401/403) | `ENFORCED/REFUSED` | - |
| user_a 404, admin served it | `ENFORCED/REFUSED_HIDDEN` | - |
| user_a 404, admin also non-2xx or no admin | `NOT_VERIFIABLE/ENDPOINT_NOT_CONFIRMED` | - |
| a destructive method, not sent | `NOT_VERIFIABLE/DESTRUCTIVE_NOT_PROBED` | - |
| unavailable, rate limited, no response, server error, other | `NOT_VERIFIABLE/<reason>` | - |

**`method_not_confused`**: safe methods of one path give user_a different outcomes -> `VIOLATION/METHOD_CONFUSION`
(CERTAIN); two or more agree -> `ENFORCED/METHODS_CONSISTENT`; one safe method only -> `NOT_APPLICABLE`.

## 7. Outcomes

SKIP without user_a or an attack surface. Otherwise FAIL on a BFLA or method confusion, PASS when every probed
privileged operation refused user_a (partial when operations stayed not verifiable).

## 8. Findings

"Ordinary user reached a privileged function: `<method> <path>`", `evidence_ref` the user_a request,
`supporting_refs` the admin positive control. "Inconsistent authorization across methods: `<path>`".

## 9. Effects on the target

`READ_ONLY`: safe methods only, no destructive request on a derived candidate.

## 10. Per gateway

Independent of the adapter: authorization is the application's or the gateway plugin's; the probe is an ordinary
request with user_a's credential.

## 11. Configuration

None. What counts as privileged is derived in Phase 2 by the rule `privileged_endpoints` (a documented path with an
`admin` or `management` segment, `src/discovery/derivation.py`); the method is the one the specification declares.
The old parameters that let the operator list privileged paths and their method are gone with the old test.

## 12. Validation

Runs of 2026-10-23:

| Lab | Status | Basis |
|---|---|---|
| crAPI + Kong | **FAIL** | `GET /workshop/api/management/users/all` answers 200 to user_a (BFLA, crAPI's management plane) |
| Forgejo + Kong, Forgejo + APISIX | **PASS** partial | the `/api/v1/admin/*` endpoints refuse user_a (403); parametric admin paths whose resource does not exist stay `NOT_VERIFIABLE/ENDPOINT_NOT_CONFIRMED`, and the destructive ones `DESTRUCTIVE_NOT_PROBED` |

Rule 9: BFLA present (crAPI), enforced (Forgejo). `DESTRUCTIVE_NOT_PROBED` surfaces crAPI's
`DELETE /identity/api/v2/admin/videos/{id}` (challenge 7) as unverified rather than omitting it. The `404` false PASS
of the old test is fixed (a `404` is enforced only when the admin control proves the operation exists).

## 13. Remediation

Enforce the role at a trusted service layer for every privileged operation and every method (ASVS v5.0.0-8.3.1); do
not rely on the interface hiding the action.

## 14. Limitations

- Destructive privileged methods are not probed (rule 5); they are reported as not verified, to be confirmed by a
  configured, confirmed operation.
- Role hierarchy beyond user/admin and OAuth scope escalation are out of scope (no lab exercises them).
- A privileged operation whose resource must exist first stays not verifiable when neither admin nor the seed
  supplies it.

## 15. Sources

- OWASP API5:2023 Broken Function Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- OWASP ASVS v5.0.0-8.1.1, v5.0.0-8.3.1 (Authorization): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md
- NIST SP 800-53 Rev.5 AC-3 (access enforcement): https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home
- CWE-285 Improper Authorization: https://cwe.mitre.org/data/definitions/285.html
