# 2.2 Object-Level Authorization

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_2/test_2_2_object_level_authorization.py`](../../../src/tests/domain_2/test_2_2_object_level_authorization.py), [`src/tests/helpers/owned_object.py`](../../../src/tests/helpers/owned_object.py)

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

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 2.2) |
|---|---|
| `cross_user_read` | "cross-user data access: userA's object, requested by userB, expect 403/404": the object's own read, then every other documented read of the object, its sub-resources |
| `cross_user_modify` | "modifying others' objects: userB modifies userA's object, expect 403; a userA read confirms it was not changed" |
| `cross_user_delete` | "delete by a non-owner (2.3): userB deletes userA's object, expect 403" |
| left out | sequential ID enumeration (an object-discovery technique, not an enforcement question); UUID entropy (a cryptographic-quality check, not authorization) |

### 2.2 Preconditions and reference responses

user_a and user_b are required. The object is created as user_a and user_a is confirmed to be served it (the
positive control): without that a user_b refusal says nothing, so the sub-test is NOT_VERIFIABLE. The violation is
proven by contrast (user_a owns the object, user_b does not).

A refusal is evidence only if user_b's credential was accepted, and nothing else in the run proves that (a static
token is stored as configured, and may have expired). So the object's read is also sent with a forged credential, a
random value placed as the run's credential is: when the target refuses it (401, 403, 404), a user_b refusal in the
same category could be a credential not accepted and is not counted. When the read does not refuse a forged
credential (crAPI serves its orders without checking one), the control says nothing, and a 401 to user_b is then not
counted as a refusal either.

### 2.3 Probes

Create the object as user_a; read it with a forged credential (the control above); confirm user_a reads it; user_b
reads it; user_b modifies it (and user_a re-reads to
confirm); user_b deletes it (last, it may remove the object); delete the object as user_a. CHANGES_DATA: the object
is user_a's own, created and destroyed within the run.

## 3. Oracle (per sub-test)

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

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("2.2", page=cog.inFile)) ]]] -->

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

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("2.2", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 28 of 28 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `cross_user_read/ENFORCED/REFUSED` | forgejo-kong: the lab as built: user_a's private repository is read by user_b, Forgejo answers 404 while the forged credential gets 401 | OK |
| `cross_user_read/NOT_VERIFIABLE/CREDENTIAL_NOT_CONFIRMED` | forgejo-kong: a counter route on the repository's read passes the forged credential's and the owner's reads to Forgejo and answers user_b's read 401, as Forgejo answers the forged credential | OK |
| `cross_user_read/NOT_VERIFIABLE/NOT_A_REFUSAL` | forgejo-kong: a counter route answers user_b's read of the repository 400 (the first two reads, forged and owner, reach Forgejo) | OK |
| `cross_user_read/NOT_VERIFIABLE/OBJECT_NOT_CREATED` | forgejo-kong: the repository resource's create body is given a name Forgejo refuses (spaces), so the create answers 422 and no object exists | OK |
| `cross_user_read/VIOLATION/BOLA_READ/CERTAIN` | crapi-kong: the lab as built: user_b reads user_a's shop order (GET /workshop/api/shop/orders/{order_id} -> 200) with the owner's answer | OK |
| `cross_user_read/VIOLATION/BOLA_READ/FIRM` | forgejo-kong: a counter route passes the forged and owner reads of the repository to Forgejo and answers user_b's read 200 with a JSON envelope of another shape | OK |
| `cross_user_read/VIOLATION/BOLA_READ_SUBRESOURCE/FIRM` | forgejo-kong: a route answers GET /api/v1/repos/user-a/<repo>/branches 200 to everyone, after the repository's own read refused user_b (404) | OK |
| `cross_user_read/NOT_VERIFIABLE/OWNER_NOT_SERVED` | forgejo-kong: a route answers the repository's read 404 to everyone, the owner included | OK |
| `cross_user_read/NOT_APPLICABLE/OWNER_NOT_SERVED_HERE` | forgejo-kong: the lab as built: of the repository's sub-resource reads, 14 are not served to the owner either | OK |
| `cross_user_read/NOT_APPLICABLE/NO_READ_OPERATION` | forgejo-kong: the specification's local copy without GET/HEAD on every path whose parameters are only {owner} and {repo} | OK |
| `cross_user_modify/ENFORCED/REFUSED` | forgejo-kong: the lab as built: user_b's empty PATCH on user_a's repository answers 404 while the forged credential gets 401 | OK |
| `cross_user_modify/NOT_VERIFIABLE/CREDENTIAL_NOT_CONFIRMED` | forgejo-kong: the repository's read answers 404 to everyone, so the forged credential's control is 404 and user_b's PATCH, refused 404 by Forgejo, is in the same category | OK |
| `cross_user_modify/NOT_VERIFIABLE/NOT_A_REFUSAL` | forgejo-kong: a route answers PATCH/PUT on the repository 400 | OK |
| `cross_user_modify/NOT_VERIFIABLE/OBJECT_NOT_CREATED` | forgejo-kong: the repository resource's create body is given a name Forgejo refuses (spaces): no object, every sub-test records it | OK |
| `cross_user_modify/VIOLATION/BOLA_MODIFY/FIRM` | forgejo-kong: a route answers PATCH/PUT on the repository 200 | OK |
| `cross_user_modify/NOT_APPLICABLE/NO_MODIFY_OPERATION` | forgejo-kong: the specification's local copy without PATCH/PUT on every path whose parameters are only {owner} and {repo} | OK |
| `cross_user_delete/ENFORCED/REFUSED` | forgejo-kong: the lab as built: user_b's DELETE on user_a's repository answers 404 while the forged credential gets 401 | OK |
| `cross_user_delete/NOT_VERIFIABLE/CREDENTIAL_NOT_CONFIRMED` | forgejo-kong: the repository's read answers 404 to everyone, so the forged control is 404 and user_b's DELETE, refused 404 by Forgejo, is in the same category | OK |
| `cross_user_delete/NOT_VERIFIABLE/NOT_A_REFUSAL` | forgejo-kong: a route answers the first DELETE on the repository (user_b's) 405 and passes the later one (the test's clean-up) to Forgejo | OK |
| `cross_user_delete/NOT_VERIFIABLE/OBJECT_NOT_CREATED` | forgejo-kong: the repository resource's create body is given a name Forgejo refuses (spaces): no object, every sub-test records it | OK |
| `cross_user_delete/VIOLATION/BOLA_DELETE/CERTAIN` | forgejo-kong: a route answers the first DELETE on the repository (user_b's) 200 without reaching Forgejo and marks it gone, the repository's read then answers the owner 404; the clean-up DELETE reaches Forgejo | OK |
| `cross_user_delete/VIOLATION/BOLA_DELETE/FIRM` | forgejo-kong: a route answers the first DELETE on the repository 200 and the repository's read then answers the owner 403 (neither gone nor served); the clean-up DELETE reaches Forgejo | OK |
| `cross_user_delete/NOT_VERIFIABLE/DELETE_NOT_APPLIED` | forgejo-kong: a route answers the first DELETE on the repository 200 without reaching Forgejo, so the owner's read after it is still served; the clean-up DELETE reaches Forgejo | OK |
| `cross_user_delete/NOT_APPLICABLE/NO_DELETE_OPERATION` | crapi-kong: the lab as built: crAPI documents no DELETE for a shop order | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: a route answers the repository's read 503: the owner's read (positive control) is unavailable on cross_user_read | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: a route answers the repository's read 429: the owner's read is throttled on cross_user_read | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: a route answers the repository's read 500: the owner's read fails on cross_user_read | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: a route makes the repository's read sleep 7 s, past the run's 5 s read timeout, on every attempt | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("2.2", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- **The object comes from a configured resource, and automatic derivation was measured and rejected.** Deriving a
  candidate object from the target instead (list a collection as one role, take an identifier, check it is not in
  the other role's listing) was designed and probed against the three labs, with reads only: it found
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
  probed (a read whose path parameters are all the object's identifiers, a query parameter named as one counting
  too), but the sub-resource reads only once
  the object's own read refused user_b, since that refusal is what a served sub-resource is read against. One
  modification and one deletion are probed (the first documented), so an ownership gap on another write is not
  covered. An object type with no resource configured is not covered either.
- A refusal of a modify or a delete is not checked against the owner's own write (a scope-limited user_b token, or a gateway that does not route the method, reads as an ownership check).

## 6. Sources

- OWASP API1:2023 Broken Object Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP ASVS v5.0.0-8.2.2 (data-specific access, IDOR/BOLA): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md
- NIST SP 800-162 section 2.3 (Basic ABAC Concepts: an access decision evaluates the attributes of the subject and
  **of the object**, `Owner` among them, which is the ownership this test checks): https://csrc.nist.gov/pubs/sp/800/162/upd2/final
- CWE-639 Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html

## 7. Inputs

A disposable object owned by user_a, created through a configured `resources:` resource
(`owned_object_resources`); its identifiers (the resource's `values`) name the path or query parameters of the object's
by-id operations, which are found on the surface (`src/tests/helpers/owned_object.py`). Two accounts: user_a and
user_b (the other user).

## 8. Outcomes

SKIP without the two accounts or `owned_object_resources`. Otherwise FAIL on any cross-user access, PASS when user_b
is refused on every operation.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("2.2")) ]]] -->

- "User reached another user's object: <method> <template>"

<!-- [[[end]]] -->

`evidence_ref` user_b's answer; for a sub-resource, `supporting_refs` user_b's refusal on the object itself.

## 10. Effects on the target

`CHANGES_DATA`: creates a disposable object owned by user_a and deletes it; user_b's modify/delete attempts act on
that object only. An object that cannot be deleted (a crAPI order, no delete request) stays and is named in a note
of the result. Runs after the read-only tests (rule 7).

## 11. Per gateway

Independent of the adapter: ownership is the application's; the probe is an ordinary request with user_b's
credential.

## 12. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("2.2", page=cog.inFile)) ]]] -->

Section [`tests.domain_2.test_2_2`](../../03-reference/01-configuration.md#testsdomain_2test_2_2) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `owned_object_resources` | list | empty, **needed to run** | The config.yaml `resources:` resources that each create a disposable object owned by user_a, whose identifiers (its `values`) name the path or query parameters of the object's by-id operations. Each is tested in turn, so several object types are covered. Without any the test cannot run (BOLA needs an owned object). |

<!-- [[[end]]] -->

## 13. Remediation

Check object ownership at the server for every object operation (`WHERE id = ? AND owner = token-user`), and return
the same answer (404) for "not yours" and "not found" so existence is not disclosed (CWE-639).
