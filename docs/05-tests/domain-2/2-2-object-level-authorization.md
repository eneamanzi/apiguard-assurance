# 2.2 Object-Level Authorization

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_2/test_2_2_object_level_authorization.py`](../../../src/tests/domain_2/test_2_2_object_level_authorization.py),
> [`src/tests/helpers/owned_object.py`](../../../src/tests/helpers/owned_object.py) · **Verified:** 2026-10-23

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("2.2", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `2.2` |
| Name | Object-Level Authorization |
| Domain | 2 - Authorization and Access Control |
| Priority / strategy | P0 / GREY_BOX |
| Effect | CHANGES_DATA |
| CWE | CWE-639 |
| Standards | `OWASP API1:2023`, `OWASP ASVS v5.0.0-8.2.2`, `NIST SP 800-162, Section 2.3` |
| Tags | `authorization`, `bola` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT`, `SECOND_USER_ACCOUNT`, `owned_object_resources` |
| Parameters | [`tests.domain_2.test_2_2`](../../03-reference/01-configuration.md#testsdomain_2test_2_2) |

<!-- [[[end]]] -->

**Same group:** tests `2.1`, `2.4`, `2.5` (authorization).

## 1. Guarantee

An object refuses a user who does not own it. A PASS promises that an object created by user_a was refused to user_b,
whether user_b tried to read, modify or delete it. The threat is Broken Object Level Authorization (OWASP API1:2023,
number one in the list): the API uses a client-supplied identifier without checking it belongs to the authenticated
user. ASVS v5.0.0-8.2.2 (data-specific access restricted to consumers with explicit permissions).

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 2.2) |
|---|---|
| `cross_user_read` | "cross-user data access: userA's object, requested by userB, expect 403/404": the object's own read, then (since 2026-11-05) every other documented read of the object, its sub-resources |
| `cross_user_modify` | "modifying others' objects: userB modifies userA's object, expect 403; a userA read confirms it was not changed" |
| `cross_user_delete` | "delete by a non-owner (2.3): userB deletes userA's object, expect 403" |
| left out | sequential ID enumeration (an object-discovery technique, not an enforcement question); UUID entropy (a cryptographic-quality check, not authorization) |

## 3. Inputs

A disposable object owned by user_a, created through a configured `resources:` resource
(`owned_object_resources`); its identifiers (the resource's `values`) name the path parameters of the object's by-id
operations, which are found on the surface (`src/tests/helpers/owned_object.py`). Two accounts: user_a (owner) and
user_b (the other user).

## 4. Preconditions and reference responses

user_a and user_b are required. The object is created as user_a and user_a is confirmed to be served it (the
positive control): without that a user_b refusal says nothing, so the sub-test is NOT_VERIFIABLE. The violation is
proven by contrast (user_a owns the object, user_b does not).

A refusal is evidence only if user_b's credential was accepted, and nothing else in the run proves that (a static
token is stored as configured, and may have expired). So the object's read is also sent with a forged credential, a
random value placed as the run's credential is: when the target refuses it (401, 403, 404), a user_b refusal in the
same category could be a credential not accepted and is not counted. When the read does not refuse a forged
credential (crAPI serves its orders without checking one), the control says nothing, and a 401 to user_b is then not
counted as a refusal either.

## 5. Probes

Create the object as user_a; read it with a forged credential (the control above); confirm user_a reads it; user_b
reads it; user_b modifies it (and user_a re-reads to
confirm); user_b deletes it (last, it may remove the object); delete the object as user_a. CHANGES_DATA: the object
is user_a's own, created and destroyed within the run.

## 6. Oracle (per sub-test)

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("2.2")) ]]] -->

**`cross_user_read`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| user_b is refused (`401`, `403`, `404`) unlike the forged credential | `ENFORCED/REFUSED` | - |
| user_b is refused like the forged credential, or `401` when the forged credential is not refused | `NOT_VERIFIABLE/CREDENTIAL_NOT_CONFIRMED` | - |
| user_b's answer is neither `2xx` nor a refusal (a redirect, `400`, `405`) | `NOT_VERIFIABLE/NOT_A_REFUSAL` | - |
| the prepared resource did not create the object | `NOT_VERIFIABLE/OBJECT_NOT_CREATED` | - |
| user_b is served (`2xx`) user_a's object with the owner's answer | `VIOLATION/BOLA_READ` | CERTAIN |
| user_b is served with another answer (a `200` may carry an error) | `VIOLATION/BOLA_READ` | FIRM |
| user_b is served a sub-resource read after the object's own read refused user_b | `VIOLATION/BOLA_READ_SUBRESOURCE` | FIRM |
| user_a is not served its own object's read | `NOT_VERIFIABLE/OWNER_NOT_SERVED` | - |
| user_a is not served a sub-resource read either (not unavailable, a real refusal) | `NOT_APPLICABLE/OWNER_NOT_SERVED_HERE` | - |
| no documented read addresses the object | `NOT_APPLICABLE/NO_READ_OPERATION` | - |

**`cross_user_modify`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| user_b is refused (`401`, `403`, `404`) unlike the forged credential | `ENFORCED/REFUSED` | - |
| user_b is refused like the forged credential, or `401` when the forged credential is not refused | `NOT_VERIFIABLE/CREDENTIAL_NOT_CONFIRMED` | - |
| user_b's answer is neither `2xx` nor a refusal (a redirect, `400`, `405`) | `NOT_VERIFIABLE/NOT_A_REFUSAL` | - |
| the prepared resource did not create the object | `NOT_VERIFIABLE/OBJECT_NOT_CREATED` | - |
| user_b's empty-bodied `PATCH`/`PUT` on user_a's object is accepted (`2xx`) | `VIOLATION/BOLA_MODIFY` | FIRM |
| no documented `PATCH`/`PUT` addresses the object | `NOT_APPLICABLE/NO_MODIFY_OPERATION` | - |

**`cross_user_delete`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| user_b is refused (`401`, `403`, `404`) unlike the forged credential | `ENFORCED/REFUSED` | - |
| user_b is refused like the forged credential, or `401` when the forged credential is not refused | `NOT_VERIFIABLE/CREDENTIAL_NOT_CONFIRMED` | - |
| user_b's answer is neither `2xx` nor a refusal (a redirect, `400`, `405`) | `NOT_VERIFIABLE/NOT_A_REFUSAL` | - |
| the prepared resource did not create the object | `NOT_VERIFIABLE/OBJECT_NOT_CREATED` | - |
| user_b's `DELETE` is accepted, and the object served to user_a before is gone after | `VIOLATION/BOLA_DELETE` | CERTAIN |
| user_b's `DELETE` is accepted, and the object is not shown gone | `VIOLATION/BOLA_DELETE` | FIRM |
| user_b's `DELETE` is accepted, and user_a is still served the object: nothing was deleted | `NOT_VERIFIABLE/DELETE_NOT_APPLIED` | - |
| no documented `DELETE` addresses the object | `NOT_APPLICABLE/NO_DELETE_OPERATION` | - |

<!-- [[[end]]] -->

Until 2026-11-16: a user_b read served was CERTAIN even when the answer was not the owner's (a `200` error envelope): now FIRM then; a delete answered `2xx` was CERTAIN on a `404` afterwards even when the owner's read had not been served before, and FIRM when the object was still there: now CERTAIN only served-then-gone, and `DELETE_NOT_APPLIED` (not verifiable) when the owner still reads it; an owner's sub-resource read that was unavailable or throttled was `OWNER_NOT_SERVED_HERE` (not applicable, hiding the unverified read); a creation without an answer ended the test in ERROR.

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("2.2", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | `NOT_VERIFIABLE/SERVER_ERROR` |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 7. Outcomes

SKIP without the two accounts or `owned_object_resources`. Otherwise FAIL on any cross-user access, PASS when user_b
is refused on every operation.

## 8. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("2.2")) ]]] -->

- "User reached another user's object: <method> <template>"

<!-- [[[end]]] -->

`evidence_ref` user_b's answer; for a sub-resource, `supporting_refs` user_b's refusal on the object itself.

## 9. Effects on the target

`CHANGES_DATA`: creates a disposable object owned by user_a and deletes it; user_b's modify/delete attempts act on
that object only. An object that cannot be deleted (a crAPI order, no delete request) stays and is named in a note
of the result (until 2026-11-04 only in the log). Runs after the read-only tests (rule 7).

## 10. Per gateway

Independent of the adapter: ownership is the application's; the probe is an ordinary request with user_b's
credential.

## 11. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("2.2", page=cog.inFile)) ]]] -->

Section [`tests.domain_2.test_2_2`](../../03-reference/01-configuration.md#testsdomain_2test_2_2) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `owned_object_resources` | list | empty, **needed to run** | The config.yaml `resources:` resources that each create a disposable object owned by user_a, whose identifiers (its `values`) name the path parameters of the object's by-id operations. Each is tested in turn, so several object types are covered. Without any the test cannot run (BOLA needs an owned object). |

<!-- [[[end]]] -->

## 12. Validation

**2026-11-16, after the review** (domain 2 on the three labs as configured): Forgejo labs **PASS**, crAPI **FAIL** (`BOLA_READ` CERTAIN on `/workshop/api/shop/orders/{order_id}`, user_b got the owner's answer), as before.


Runs of 2026-10-23; measured again on 2026-11-04 (2.2 alone), after the corrections of that day, with the same verdicts:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, Forgejo + APISIX | **PASS** | user_a creates a private repo (the `repository` resource); user_b is refused the read, the modify and the delete (404 each), while the forged credential gets 401: user_b's credential was accepted. Since 2026-11-05 the repository's other reads are asked as well: 35 sub-resources (branches, hooks, collaborators, ...) refused to user_b, 14 not served to the owner either (`OWNER_NOT_SERVED_HERE`); the repo is deleted (204) |
| crAPI + Kong | **FAIL**, 1 finding | user_a creates a shop order (the `order` resource); user_b **reads it (GET /workshop/api/shop/orders/7 -> 200): a real BOLA**; the modify is refused (PUT -> 403, crAPI checks ownership on write but not on read); delete is NOT_APPLICABLE (crAPI has no order delete). The order's read is served even to the forged credential (crAPI checks no credential there, test 1.1's finding), so the control says nothing and the 403 on the modify counts as a refusal because it is not a 401 |
| crAPI + Kong, user_b's token invalid (scratch configuration, `static_token`, 2026-11-04) | **FAIL**, 1 finding | the read is still served; the modify answers `401 "Invalid JWT Token!"`: `CREDENTIAL_NOT_CONFIRMED`, where the test reported ENFORCED before the correction |

Rule 9, both sides proven: VIOLATION on crAPI (`cross_user_read` BOLA on an order), ENFORCED on Forgejo (and on
crAPI's `cross_user_modify`). crAPI shows a real asymmetry: the read drops the ownership check while the write keeps
it. `cross_user_delete` is NOT_APPLICABLE where the object type has no delete operation. `BOLA_READ_SUBRESOURCE` is
unproven: no lab drops the check on a part of an object it keeps on the object (crAPI's order has a single read, and
its read is a BOLA, so its parts are not asked). `CREDENTIAL_NOT_CONFIRMED`
is proven with an invalid user_b token; `NOT_A_REFUSAL` is not reached by the labs.

**What each branch has been seen doing** (rule 9). Proven on a lab: `BOLA_READ` (crAPI), `REFUSED` (both Forgejo
labs, crAPI's modify), `OWNER_NOT_SERVED_HERE` (both Forgejo labs), `NO_*_OPERATION` for the delete (crAPI),
`CREDENTIAL_NOT_CONFIRMED` (crAPI with an invalid token), `OBJECT_NOT_CREATED` (crAPI after about ten runs without a
reset, [compatibility](../../03-reference/06-compatibility.md#what-the-tool-detects-measured-against-a-vulnerable-target)),
and on 2026-11-15 on Forgejo + Kong with temporary routes on `forgejo-service` in `kong/kong.yml`, scoped by path
and method so that the owner's own GET and the object's creation still reach Forgejo (undone with `git checkout`,
the lab checked back):

| The route (path regex + methods) | Result |
|---|---|
| `~/api/v1/repos/user-a/[^/]+$` PATCH/PUT answer `200`; the same path DELETE answer `200`; `~/api/v1/repos/user-a/[^/]+/branches$` GET answer `200` | FAIL, `BOLA_MODIFY`, `BOLA_DELETE`, `BOLA_READ_SUBRESOURCE` (all FIRM) |
| `~/api/v1/repos/user-a/[^/]+$` PATCH/PUT answer `400` | `NOT_A_REFUSAL` on `cross_user_modify` (a `400` is neither a refusal nor a 2xx) |
| `~/api/v1/repos/user-a/[^/]+$` GET answer `404` (the owner's own read too) | `OWNER_NOT_SERVED` on `cross_user_read`; `cross_user_modify` and `cross_user_delete` then `CREDENTIAL_NOT_CONFIRMED`, their positive control gone |

The `DELETE` route of the first row answered the test's own clean-up as well, so that run left its repository on the
lab (`user-a/apiguard-repo-2948a565`, found and deleted by hand on 2026-11-15; only `user-a/test-repo` remains). To
repeat it, delete the run's repository afterwards, or scope the route to user_b's credential.

On 2026-11-15 as well, Forgejo + Kong: `NO_MODIFY_OPERATION` and `NO_READ_OPERATION`, with the specification saved
without `PATCH`/`PUT`, then without `GET`/`HEAD`, on every path whose parameters are the object's (`{owner}`,
`{repo}`); and `UPSTREAM_UNAVAILABLE`, `RATE_LIMITED`, `SERVER_ERROR`, `NO_RESPONSE` on `cross_user_read`, with a
temporary route `GET ~/api/v1/repos/user-a/[^/]+$` whose counter lets the first two reads through (the forged
credential, the owner) and answers user_b's read `503`, `429`, `500`, or sleeps 7 s on it and on its two retries
(the run's `target.read_timeout: 5.0`). No repository was left behind. Every branch of this test has been seen.

## 13. Remediation

Check object ownership at the server for every object operation (`WHERE id = ? AND owner = token-user`), and return
the same answer (404) for "not yours" and "not found" so existence is not disclosed (CWE-639).

## 14. Limitations

- **The object comes from a configured resource, and automatic derivation was measured and rejected.** Deriving a
  candidate object from the target instead (list a collection as one role, take an identifier, check it is not in
  the other role's listing) was designed and probed against the three labs on 2026-10-29, with reads only: it found
  **no owned object on any of them**. On crAPI the vehicle listing of challenge 1 answers `200 []`, because a crAPI
  vehicle must be claimed with a VIN and a pincode sent by email and the lab never claims one; the order collection
  is the object already configured; the community posts are public, so the ownership check rejects them. On both
  Forgejo labs the collections a user owns (`/user/keys`, `/user/hooks`, `/user/gpg_keys`, `/user/starred`) answer
  `200 []` on a fresh deployment, and the four that do return an identifier (`/orgs`, `/licenses`, `/repos/search`,
  `/users/search`) are public collections the ownership check rejects, correctly. The measurement says something
  about the problem, not about this tool: **establishing ownership cannot be made target-agnostic**, because it
  needs either an object the tool created or the knowledge of which collection one role owns, and a fresh
  deployment offers neither. Hence the object stays configured, and an API with no creatable, by-id object in
  `owned_object_resources` gets no verdict from this test.
- Delete is optional: an object type with no delete operation (a crAPI order) is not cleaned up by the tool, the lab
  reset removes it.
- Sequential ID enumeration is not performed (it is object discovery, not an enforcement question).
- One object is tested per configured resource (`owned_object_resources`). Every documented read of the object is
  probed (a read is one whose path parameters are all the object's identifiers), but the sub-resource reads only once
  the object's own read refused user_b, since that refusal is what a served sub-resource is read against. One
  modification and one deletion are probed (the first documented), so an ownership gap on another write is not
  covered. An object type with no resource configured is not covered either.
- A refusal of a modify or a delete is not checked against the owner's own write (a scope-limited user_b token, or a gateway that does not route the method, reads as an ownership check).

## 15. Sources

- OWASP API1:2023 Broken Object Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP ASVS v5.0.0-8.2.2 (data-specific access, IDOR/BOLA): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md
- NIST SP 800-162 section 2.3 (Basic ABAC Concepts: an access decision evaluates the attributes of the subject and
  **of the object**, `Owner` among them, which is the ownership this test checks): https://csrc.nist.gov/pubs/sp/800/162/upd2/final
- CWE-639 Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
