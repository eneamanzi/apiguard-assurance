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
| `cross_user_read` | "cross-user data access: userA's object, requested by userB, expect 403/404" |
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

## 5. Probes

Create the object as user_a; confirm user_a reads it; user_b reads it; user_b modifies it (and user_a re-reads to
confirm); user_b deletes it (last, it may remove the object); delete the object as user_a. CHANGES_DATA: the object
is user_a's own, created and destroyed within the run.

## 6. Oracle (per sub-test)

| Case | Outcome / detail | Confidence |
|---|---|---|
| user_b served (2xx) user_a's object | `VIOLATION/BOLA_READ` \| `BOLA_MODIFY` \| `BOLA_DELETE` | CERTAIN (proven by contrast) |
| user_b refused | `ENFORCED/REFUSED` | - |
| user_a not served its own object | `NOT_VERIFIABLE/OWNER_NOT_SERVED` | - |
| no read / modify / delete operation on the object | `NOT_APPLICABLE/NO_*_OPERATION` | - |
| unavailable, rate limited, no response, server error | `NOT_VERIFIABLE/<reason>` | - |

## 7. Outcomes

SKIP without the two accounts or `owned_object_resources`. Otherwise FAIL on any cross-user access, PASS when user_b
is refused on every operation.

## 8. Findings

"User reached another user's object: `<method> <path>`", `evidence_ref` the user_b request. The user_a positive
control and the post-modify read are in the transaction log as the contrast.

## 9. Effects on the target

`CHANGES_DATA`: creates a disposable object owned by user_a and deletes it; user_b's modify/delete attempts act on
that object only. Runs after the read-only tests (rule 7).

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

Runs of 2026-10-23:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, Forgejo + APISIX | **PASS** | user_a creates a private repo (the `repository` resource); user_b is refused the read (403), the modify (404) and the delete (404); the repo is deleted (204) |
| crAPI + Kong | **FAIL**, 1 finding | user_a creates a shop order (the `order` resource); user_b **reads it (GET /workshop/api/shop/orders/7 -> 200): a real BOLA**; the modify is refused (PUT -> 403, crAPI checks ownership on write but not on read); delete is NOT_APPLICABLE (crAPI has no order delete) |

Rule 9, both sides proven: VIOLATION on crAPI (`cross_user_read` BOLA on an order), ENFORCED on Forgejo (and on
crAPI's `cross_user_modify`). crAPI shows a real asymmetry: the read drops the ownership check while the write keeps
it. `cross_user_delete` is NOT_APPLICABLE where the object type has no delete operation.

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
- Only one object is tested; a per-endpoint ownership gap on a different object type is not covered.

## 15. Sources

- OWASP API1:2023 Broken Object Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP ASVS v5.0.0-8.2.2 (data-specific access, IDOR/BOLA): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md
- NIST SP 800-162 section 2.3 (Basic ABAC Concepts: an access decision evaluates the attributes of the subject and
  **of the object**, `Owner` among them, which is the ownership this test checks): https://csrc.nist.gov/pubs/sp/800/162/upd2/final
- CWE-639 Authorization Bypass Through User-Controlled Key: https://cwe.mitre.org/data/definitions/639.html
