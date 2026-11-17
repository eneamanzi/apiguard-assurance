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
| Standards | `OWASP API5:2023`, `OWASP ASVS v5.0.0-8.2.1`, `OWASP ASVS v5.0.0-8.3.1`, `NIST SP 800-53r5, Section 3.1` |
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
succeeds. ASVS v5.0.0-8.3.1 (enforce authorization at a trusted service layer). It does not cover guarantee 2.3
(destructive operations need privilege), which has no test: a destructive method is never sent.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 2.1) |
|---|---|
| `privileged_function_refuses_user` | "admin endpoint with a user token: expect 403, not 200", for every privileged operation |
| `method_not_confused` | "HTTP method confusion": the safe methods of one privileged path agree for user_a |
| left out | role hierarchy beyond user/admin (no moderator tier on the labs); OAuth scope escalation (no granular scopes); destructive-method probing on derived endpoints (rule 5: surfaced as `DESTRUCTIVE_NOT_PROBED`, not sent) |

## 3. Inputs

The privileged operations are derived (Phase-2 rule `privileged_endpoints`: a path segment `admin` or `management`).
This test takes no parameter, so there is nothing to add or correct by hand (section 11). The specification's
`requires_auth` tells a public path apart from a protected one. The admin account (optional) is the positive
control.

## 4. Preconditions and reference responses

user_a is required (GREY_BOX). The admin account is an optional need: when present, the admin positive control proves
the operation exists and is genuinely privileged, so a refusal is about the role (CERTAIN) and a `404` is not
mistaken for enforcement. Without admin, the verdict rests on the path's shape and the spec's `security` (FIRM).

A refusal is evidence only if user_a's credential was accepted, and nothing else in the run proves that (a static
token is stored as configured, and may have expired). So when user_a is refused, the same safe request is sent with a
forged credential, a random value placed as the run's credential is: a refusal in the same category as the forged
credential's answer is not counted. When the forged credential is not refused, the control says nothing, and a `401`
to user_a is then not counted as a refusal either.

## 5. Probes

Only safe methods (GET, HEAD) of a privileged operation are sent, with the user_a credential, and with the forged
credential when user_a is refused; path parameters are
resolved from `path_seed`. A destructive method on a derived candidate is not sent (rule 5). READ_ONLY.

## 6. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("2.1")) ]]] -->

**`privileged_function_refuses_user`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| user_a is served (`2xx`) a privileged operation the specification protects, or that refuses an anonymous request | `VIOLATION/BFLA` | FIRM |
| user_a is served an operation that is public: declared so, and served anonymously too | `NOT_APPLICABLE/PUBLIC_ENDPOINT` | - |
| user_a is refused (`401`, `403`) unlike the forged credential, and the admin account (when configured) is served | `ENFORCED/REFUSED` | - |
| user_a gets `404` while the admin account is served | `ENFORCED/REFUSED_HIDDEN` | - |
| user_a and the admin account are both refused: a scope or a precondition, not the role | `NOT_VERIFIABLE/ADMIN_REFUSED_TOO` | - |
| user_a is refused like the forged credential, or `401` when the forged credential is not refused | `NOT_VERIFIABLE/CREDENTIAL_NOT_CONFIRMED` | - |
| user_a gets `404` and no admin account, or the admin account is not served either | `NOT_VERIFIABLE/ENDPOINT_NOT_CONFIRMED` | - |
| a destructive method of a privileged path, never sent | `NOT_VERIFIABLE/DESTRUCTIVE_NOT_PROBED` | - |
| user_a's answer is `REDIRECT`: neither served nor refused | `NOT_VERIFIABLE/REDIRECT` | - |
| user_a's answer is `METHOD_NOT_ALLOWED`: neither served nor refused | `NOT_VERIFIABLE/METHOD_NOT_ALLOWED` | - |
| user_a's answer is `INVALID_REQUEST`: neither served nor refused | `NOT_VERIFIABLE/INVALID_REQUEST` | - |
| user_a's answer is `OTHER`: neither served nor refused | `NOT_VERIFIABLE/OTHER` | - |
| no documented path has an `admin` or `management` segment | `NOT_APPLICABLE/NO_PRIVILEGED_ENDPOINT` | - |

**`method_not_confused`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the protected safe methods of one privileged path give user_a different outcomes | `VIOLATION/METHOD_CONFUSION` | FIRM |
| two or more protected safe methods of one privileged path agree | `ENFORCED/METHODS_CONSISTENT` | - |
| no privileged path has two decided protected safe methods | `NOT_APPLICABLE/SINGLE_SAFE_METHOD` | - |
| no documented path has an `admin` or `management` segment | `NOT_APPLICABLE/NO_PRIVILEGED_ENDPOINT` | - |

<!-- [[[end]]] -->

Until 2026-11-16 a refusal of user_a was `REFUSED` even when the admin account was refused too (a token without the scope refuses every account: the Forgejo labs passed so while the admin token lacked `read:admin`): now `ADMIN_REFUSED_TOO`; and an operation the specification does not protect (no `security`) was `PUBLIC_ENDPOINT` even when it refuses an anonymous request: now that refusal makes it protected, and serving user_a is a BFLA. ASVS 8.1.1 (the policy's documentation) is no longer cited.

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("2.1", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 7. Outcomes

SKIP without user_a or an attack surface. Otherwise FAIL on a BFLA or method confusion, PASS when every probed
privileged operation refused user_a (partial when operations stayed not verifiable).

## 8. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("2.1")) ]]] -->

- "Ordinary user reached a privileged function: <method> <template_path>"
- "Inconsistent authorization across methods: <path>"

<!-- [[[end]]] -->

`evidence_ref` user_a's answer; `supporting_refs` the admin positive control when it ran.

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

**2026-11-16, after the review** (domain 2 on the three labs as configured): Forgejo labs **PASS** partial (10 refused; one operation `ADMIN_REFUSED_TOO`, the admin refused as well), crAPI **FAIL** (`GET /workshop/api/management/users/all`), as before.


Runs of 2026-10-23; measured again on 2026-11-04 (2.1 alone), after the correction of the external audit, with the same verdicts:

| Lab | Status | Basis |
|---|---|---|
| crAPI + Kong | **FAIL** | `GET /workshop/api/management/users/all` answers 200 to user_a (BFLA, crAPI's management plane) |
| crAPI + Kong, user_a's token invalid (scratch configuration, `static_token`, 2026-11-04) | INCONCLUSIVE | user_a and the forged credential both get `401 "Invalid JWT Token!"`: `CREDENTIAL_NOT_CONFIRMED`, where the test would have counted a refusal before the correction |
| Forgejo + Kong, Forgejo + APISIX | **PASS** partial | the `/api/v1/admin/*` endpoints refuse user_a (403) while the forged credential gets 401; parametric admin paths whose resource does not exist stay `NOT_VERIFIABLE/ENDPOINT_NOT_CONFIRMED`, and the destructive ones `DESTRUCTIVE_NOT_PROBED` |

Rule 9: BFLA present (crAPI), enforced (Forgejo). `DESTRUCTIVE_NOT_PROBED` surfaces crAPI's
`DELETE /identity/api/v2/admin/videos/{id}` (challenge 7) as unverified rather than omitting it. The `404` false PASS
of the old test is fixed (a `404` is enforced only when the admin control proves the operation exists).

**What each branch has been seen doing** (rule 9). Proven on a lab: `BFLA` (crAPI), `REFUSED`,
`ENDPOINT_NOT_CONFIRMED` (both Forgejo labs), `DESTRUCTIVE_NOT_PROBED` (all three), `CREDENTIAL_NOT_CONFIRMED` (crAPI
with an invalid token), `SINGLE_SAFE_METHOD` (all three, section 6), and on 2026-11-15 with a specification of the
run only: `NO_PRIVILEGED_ENDPOINT` (Forgejo + Kong, the specification without its `/admin` paths: SKIP) and
`PUBLIC_ENDPOINT` (crAPI + Kong, `GET /workshop/api/management/users/all` marked `security: []`), and
`REFUSED_HIDDEN` (2026-11-15, Forgejo + Kong: 10 operations; a temporary route `/api/v1/admin` whose `pre-function`
turns Forgejo's `403` into a `404` in its `header_filter` phase, undone with `git checkout`, and the run's login
token given the `read:admin` scope as well). The two method branches, 2026-11-15 on Forgejo + Kong, with the
specification saved with a `HEAD` operation added to `/admin/orgs` (Forgejo answers `HEAD` there `405`, so on its
own the run is still `SINGLE_SAFE_METHOD`) and a temporary route `~/api/v1/admin/orgs$` for `HEAD` (undone with
`git checkout`): `METHODS_CONSISTENT` when the route's `pre-function` forwards the `HEAD` to Forgejo as a `GET`
(user_a `403`, the forged credential `401`, on both methods); `METHOD_CONFUSION` (FIRM, with a `BFLA` on the
`HEAD`) when it answers `200` itself. The transport reasons on 2026-11-15, the same lab, a temporary route `GET
~/api/v1/admin/orgs$` answering `503`, `429`, `500` or sleeping 7 s (the run's `target.read_timeout: 5.0`):
`UPSTREAM_UNAVAILABLE`, `RATE_LIMITED`, `SERVER_ERROR`, `NO_RESPONSE`. Every branch of this test has been seen.

**The admin control on the Forgejo labs.** Until 2026-11-15 the login resource of both Forgejo labs created tokens
with the scopes `read:repository`, `read:user`, `write:repository`, `write:user` only, the admin's included, and
Forgejo refused the `/api/v1/admin` operations to that token: the admin positive control could never confirm an
operation. Since 2026-11-15 the scopes include `read:admin`, the read access to the admin operations
([Forgejo, Access Token Scope](https://forgejo.org/docs/latest/user/token-scope/)), which is how `REFUSED_HIDDEN`
was produced. Measured the same day on both Forgejo labs: 2.1 still **PASS** partial; the 6 controls the run asks
are the `/api/v1/admin/quota/...` reads, which answer `404` to the admin as well, so they stay
`ENDPOINT_NOT_CONFIRMED`; 1.4 and 2.2, which use the same token, unchanged (PASS).

## 13. Remediation

Enforce the role at a trusted service layer for every privileged operation and every method (ASVS v5.0.0-8.3.1); do
not rely on the interface hiding the action.

## 14. Limitations

- Destructive privileged methods are never probed (rule 5); they are reported as not verified
  (`DESTRUCTIVE_NOT_PROBED`), and no configuration can authorise them.
- The privileged operations come only from the specification, by the names of their paths (`admin`,
  `management`): an administrator function under another name is not probed, and no configuration adds it (until
  2026-11-04 the docs promised one).
- Role hierarchy beyond user/admin and OAuth scope escalation are out of scope (no lab exercises them).
- A privileged operation whose resource must exist first stays not verifiable when neither admin nor the seed
  supplies it.
- A catch-all `2xx` on a privileged path is not compared with a random path: it would read as a BFLA.
- Only documented safe methods are sent: a privileged `GET` matched by a rule on `GET` only is not probed with `HEAD`.

## 15. Sources

- OWASP API5:2023 Broken Function Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- OWASP ASVS v5.0.0-8.1.1, v5.0.0-8.3.1 (Authorization): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md
- NIST SP 800-53 Rev.5 AC-3 (access enforcement): https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home
- CWE-285 Improper Authorization: https://cwe.mitre.org/data/definitions/285.html
