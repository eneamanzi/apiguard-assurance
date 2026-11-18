# 2.1 Function-Level Authorization

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_2/test_2_1_function_level_authorization.py`](../../../src/tests/domain_2/test_2_1_function_level_authorization.py), [`src/discovery/derivation.py`](../../../src/discovery/derivation.py)

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

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 2.1) |
|---|---|
| `privileged_function_refuses_user` | "admin endpoint with a user token: expect 403, not 200", for every privileged operation |
| `method_not_confused` | "HTTP method confusion": the safe methods of one privileged path agree for user_a |
| left out | role hierarchy beyond user/admin (no moderator tier on the labs); OAuth scope escalation (no granular scopes); destructive-method probing on derived endpoints (rule 5: surfaced as `DESTRUCTIVE_NOT_PROBED`, not sent) |

### 2.2 Preconditions and reference responses

user_a is required (GREY_BOX). The admin account is an optional need: when present, the admin positive control proves
the operation exists and is genuinely privileged, so a refusal is about the role (CERTAIN) and a `404` is not
mistaken for enforcement. Without admin, the verdict rests on the path's shape and the spec's `security` (FIRM).

A refusal is evidence only if user_a's credential was accepted, and nothing else in the run proves that (a static
token is stored as configured, and may have expired). So when user_a is refused, the same safe request is sent with a
forged credential, a random value placed as the run's credential is: a refusal in the same category as the forged
credential's answer is not counted. When the forged credential is not refused, the control says nothing, and a `401`
to user_a is then not counted as a refusal either.

### 2.3 Probes

Only safe methods (GET, HEAD) of a privileged operation are sent, with the user_a credential, and with the forged
credential when user_a is refused; path parameters are
resolved from `path_seed`. A destructive method on a derived candidate is not sent (rule 5). READ_ONLY.

## 3. Oracle

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

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("2.1", page=cog.inFile)) ]]] -->

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

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("2.1", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 21 of 21 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `privileged_function_refuses_user/VIOLATION/BFLA/FIRM` | crapi-kong: the lab as built: GET /workshop/api/management/users/all answers 200 to user_a | OK |
| `privileged_function_refuses_user/NOT_APPLICABLE/PUBLIC_ENDPOINT` | crapi-kong: the run reads a local copy of crAPI's specification where GET /workshop/api/management/users/all is replaced by an operation with security [] (public), and a temporary route answers it 200 to user_a and to an anonymous request (crAPI itself refuses the anonymous one) | OK |
| `privileged_function_refuses_user/ENFORCED/REFUSED` | forgejo-kong: the lab as built: the /api/v1/admin reads refuse user_a 403, the forged credential gets 401, and the admin token (scope read:admin) is served | OK |
| `privileged_function_refuses_user/ENFORCED/REFUSED_HIDDEN` | forgejo-kong: a temporary route /api/v1/admin whose pre-function turns Forgejo's 403 into 404 in its header_filter phase; the admin token (read:admin, as the lab is built since 2026-11-15) is served, user_a gets 404 and the forged credential 401 | OK |
| `privileged_function_refuses_user/NOT_VERIFIABLE/ADMIN_REFUSED_TOO` | forgejo-kong: the lab as built: one /api/v1/admin read refuses user_a and the admin token alike | OK |
| `privileged_function_refuses_user/NOT_VERIFIABLE/CREDENTIAL_NOT_CONFIRMED` | crapi-kong: user_a given a static token crAPI does not accept: user_a and the forged credential both get 401 "Invalid JWT Token!" on GET /workshop/api/management/users/all | OK |
| `privileged_function_refuses_user/NOT_VERIFIABLE/ENDPOINT_NOT_CONFIRMED` | forgejo-kong: the lab as built: the /api/v1/admin/quota reads answer 404 to user_a and to the admin token as well | OK |
| `privileged_function_refuses_user/NOT_VERIFIABLE/DESTRUCTIVE_NOT_PROBED` | forgejo-kong: the lab as built: the specification documents POST, PATCH and DELETE on /api/v1/admin paths, never sent | OK |
| `privileged_function_refuses_user/NOT_VERIFIABLE/REDIRECT` | forgejo-kong: a temporary route GET ~/api/v1/admin/orgs$ answers 302 to https://localhost:8443/ itself | OK |
| `privileged_function_refuses_user/NOT_VERIFIABLE/METHOD_NOT_ALLOWED` | forgejo-kong: the run reads a local copy of Forgejo's specification with a HEAD operation added to /admin/orgs; Forgejo answers HEAD there 405 | OK |
| `privileged_function_refuses_user/NOT_VERIFIABLE/INVALID_REQUEST` | forgejo-kong: a temporary route GET ~/api/v1/admin/orgs$ answers 400 itself | OK |
| `privileged_function_refuses_user/NOT_VERIFIABLE/OTHER` | forgejo-kong: a temporary route GET ~/api/v1/admin/orgs$ answers 418 itself (OTHER in response_category.py) | OK |
| `privileged_function_refuses_user/NOT_APPLICABLE/NO_PRIVILEGED_ENDPOINT` | forgejo-kong: the run reads a local copy of Forgejo's specification whose paths are replaced by GET /version only, so no path has an admin or management segment | OK |
| `method_not_confused/VIOLATION/METHOD_CONFUSION/FIRM` | forgejo-kong: the specification copy with HEAD added to /admin/orgs, and a temporary route HEAD ~/api/v1/admin/orgs$ answering 200 itself while GET refuses user_a 403 | OK |
| `method_not_confused/ENFORCED/METHODS_CONSISTENT` | forgejo-kong: the specification copy with HEAD added to /admin/orgs, and a temporary route HEAD ~/api/v1/admin/orgs$ whose pre-function forwards the HEAD to Forgejo as a GET (user_a 403, the forged credential 401, on both methods) | OK |
| `method_not_confused/NOT_APPLICABLE/SINGLE_SAFE_METHOD` | forgejo-kong: the lab as built: every privileged path documents a single safe method (GET) | OK |
| `method_not_confused/NOT_APPLICABLE/NO_PRIVILEGED_ENDPOINT` | forgejo-kong: the run reads a local copy of Forgejo's specification whose paths are replaced by GET /version only | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: a temporary route GET ~/api/v1/admin/orgs$ answers 503 itself | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: a temporary route GET ~/api/v1/admin/orgs$ answers 429 itself | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: a temporary route GET ~/api/v1/admin/orgs$ answers 500 itself | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: a temporary route GET ~/api/v1/admin/orgs$ sleeps 7 s before answering, past the run's read timeout of 5 s | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("2.1", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- Destructive privileged methods are never probed (rule 5); they are reported as not verified
  (`DESTRUCTIVE_NOT_PROBED`), and no configuration can authorise them.
- The privileged operations come only from the specification, by the names of their paths (`admin`,
  `management`): an administrator function under another name is not probed, and no configuration adds it.
- Role hierarchy beyond user/admin and OAuth scope escalation are out of scope (no lab exercises them).
- A privileged operation whose resource must exist first stays not verifiable when neither admin nor the seed
  supplies it.
- A catch-all `2xx` on a privileged path is not compared with a random path: it would read as a BFLA.
- Only documented safe methods are sent: a privileged `GET` matched by a rule on `GET` only is not probed with `HEAD`.

## 6. Sources

- OWASP API5:2023 Broken Function Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- OWASP ASVS v5.0.0-8.1.1, v5.0.0-8.3.1 (Authorization): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md
- NIST SP 800-53 Rev.5 AC-3 (access enforcement): https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home
- CWE-285 Improper Authorization: https://cwe.mitre.org/data/definitions/285.html

## 7. Inputs

The privileged operations are derived (Phase-2 rule `privileged_endpoints`: a path segment `admin` or `management`).
This test takes no parameter, so there is nothing to add or correct by hand (section 12). The specification's
`requires_auth` tells a public path apart from a protected one. The admin account (optional) is the positive
control.

## 8. Outcomes

SKIP without user_a or an attack surface. Otherwise FAIL on a BFLA or method confusion, PASS when every probed
privileged operation refused user_a (partial when operations stayed not verifiable).

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("2.1")) ]]] -->

- "Ordinary user reached a privileged function: <method> <template_path>"
- "Inconsistent authorization across methods: <path>"

<!-- [[[end]]] -->

`evidence_ref` user_a's answer; `supporting_refs` the admin positive control when it ran.

## 10. Effects on the target

`READ_ONLY`: safe methods only, no destructive request on a derived candidate.

## 11. Per gateway

Independent of the adapter: authorization is the application's or the gateway plugin's; the probe is an ordinary
request with user_a's credential.

## 12. Configuration

None. What counts as privileged is derived in Phase 2 by the rule `privileged_endpoints` (a documented path with an
`admin` or `management` segment, `src/discovery/derivation.py`); the method is the one the specification declares.

## 13. Remediation

Enforce the role at a trusted service layer for every privileged operation and every method (ASVS v5.0.0-8.3.1); do
not rely on the interface hiding the action.
