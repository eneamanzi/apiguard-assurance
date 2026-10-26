# Group E: guarantees 2.1, 2.2, 2.4, 2.5 (working file)

> **Audience:** the owner and me, during the review. Method: the six phases in
> [`test-review.md`](../test-review.md) (How we work).

| Phase | State |
|---|---|
| 1. Collection | done 2026-10-22 (below) |
| 2. Design | decided 2026-10-22; split go-ahead: **2.1 + 2.4 first**, then 2.2 + 2.5 (owner decisions below) |
| 3. Code | done 2026-10-23 (2.1, 2.4, 2.2, 2.5) |
| 4. Proof | done 2026-10-23 |
| 5. Self-review | done 2026-10-23 (fixes below) |
| 6. Documentation | done 2026-10-23 |

### 2.2 + 2.5 results and review (2026-10-23)

**New `Need.SECOND_USER_ACCOUNT`** (user_b), wired like the others. **Disposable owned object** mechanism
(`src/tests/helpers/owned_object.py`): the test creates an object owned by user_a through a configured `resources:`
resource (new per-test parameter `owned_object_resources`), finds the object's by-id operations by resolving their
path parameters from the resource's `values` (keeping the operations that use the **most** of them, so a less
specific resource sharing one parameter is not mistaken for the object), has user_b attack it, and deletes it.
`create_resource` gained an `extra_body` for 2.5's mass-assignment probe.

**2.2** (cross_user_read/modify/delete) and **2.5** (no_sensitive_field, mass_assignment) proven on **Forgejo**
(the `repository` resource, a private repo): all ENFORCED (Forgejo checks ownership, ignores injected fields) ->
2.2 PASS, 2.5 PASS. This is the weakness-absent side.

**Self-review fixes (both real oracle defects):**
1. `object_operations` first picked `GET /api/v1/packages/{owner}` (a different resource sharing the `owner`
   parameter) instead of `/repos/{owner}/{repo}`, so cross_user_read was OWNER_NOT_SERVED. Fixed: keep only the
   operations that use the most of the object's identifiers.
2. mass_assignment reported a false VIOLATION on Forgejo: the injected boolean `admin: true` matched the repo's
   legitimate `permissions.admin: true`. Fixed: inject only **unique string sentinels**; a boolean reflected in a
   response cannot be told from a legitimately-true field (a false positive). `role_field_filtering` folded into
   `no_sensitive_field` (a sensitive field is caught by its name for any role; labelling an "admin-only non-sensitive"
   field generically is not reliable).

**crAPI (the weakness-present side) is covered** by a disposable `order` resource (a shop order owned by user_a, created with the user's JWT, product 1 quantity 1; crAPI has no order delete, so the lab reset removes it). Real findings: **2.2 FAIL** -- `cross_user_read` is a BOLA (user_b reads user_a's order, GET /orders/7 -> 200), while `cross_user_modify` is ENFORCED (PUT -> 403: crAPI checks ownership on write but not on read) and `cross_user_delete` is NOT_APPLICABLE (no order delete); **2.5 FAIL** -- the order response carries `card_number` (excessive data exposure), `mass_assignment` ENFORCED. So both sides of rule 9 are proven, on both labs, agnostically (no code specific to either target; the object is a config-declared resource).

ASVS verified on source (v5.0.0): 8.2.2 (data-specific access / BOLA), 14.2.6 (no excessive data in responses).

### 2.1 + 2.4 results and review (2026-10-23)

New Phase-2 rule `privileged_endpoints` (a path segment `admin`/`management`), proven on the labs: crAPI 2 ops
(`GET /workshop/api/management/users/all`, `DELETE /identity/api/v2/admin/videos/{id}`), Forgejo 28 `/api/v1/admin/*`.

| Lab | 2.1 | 2.4 |
|---|---|---|
| Forgejo + Kong, Forgejo + APISIX | **PASS** partial (11 enforced: admin endpoints refuse user_a; 31 not verifiable) | **SKIP** (version absent: Forgejo has only `/api/v1`) |
| crAPI + Kong | **FAIL** (BFLA: `GET /workshop/api/management/users/all` answers 200 to user_a, challenge 7's management plane) | **PASS** (version siblings refused or absent, no auth drop) |

Rule 9: 2.1 present (crAPI FAIL) + absent (Forgejo PASS). 2.4 enforced + version-absent proven; the **VIOLATION
branch** (a version that drops auth) is not on the labs (crAPI's version drift is rate-limiting, not an auth drop)
and is documented lab-unproven, not produced with a gateway change (owner: save tokens, 2026-10-23).

**Self-review fixes:**
1. 2.1 was silently dropping privileged **destructive** operations (not sent, rule 5). Now each is surfaced
   `NOT_VERIFIABLE/DESTRUCTIVE_NOT_PROBED`, so crAPI's `DELETE .../admin/videos/{id}` (challenge 7) is visible as
   unverified rather than omitted (the not-verifiable count rose from 14 to 31).
2. 2.4 probed every protected endpoint against every version candidate (242 requests on Forgejo for a SKIP). Now it
   calibrates the candidate version once (one representative probe); an absent version is one
   `NOT_APPLICABLE/VERSION_ABSENT` instead of hundreds of probes.

ASVS verified on source (v5.0.0): 2.1/2.4 cite 8.1.1 (access-control policy enforced), 8.3.1 (function-level).

Group E is authorization, the OWASP API number-one category: 2.1 (function-level, who may call what), 2.2 (object
level, whose objects), 2.4 (the same policy on equivalent endpoints), 2.5 (object property level, which fields and
which writes). Only `2.1` exists on `main`; 2.2, 2.4, 2.5 are new. The guarantees share two roles and the idea of an
object a role owns, which is why they are one group.

---

### Decided (owner, 2026-10-22)

1. **Split go-ahead:** 2.1 + 2.4 first (they share the derived knowledge), then 2.2 + 2.5 once object-sourcing is
   settled.
2. **New `Need` for user_b:** approved (for 2.2, second half).
3. **`admin`-segment derivation rule:** approved. 2.1 derives privileged endpoints from a path segment
   `admin`/`management`; the configuration adds or corrects, it is no longer the required list.
4. **Scope cut:** confirmed. Out (with the reason): UUID entropy (a cryptographic-quality check, not authorization),
   role hierarchy beyond user/admin (no moderator tier on the labs), GraphQL parity (no GraphQL), OAuth scope
   escalation (no granular scopes). In: BFLA, method confusion, cross-user read/modify/delete, version-sibling
   consistency, sensitive-field, mass assignment.
5. **Object-sourcing for 2.2/2.5 (deferred to the second half):** owner asked whether crAPI's setup can seed a
   path_seed too. It can: crAPI signs up user_a/user_b and associates a vehicle per user. Plan: runtime discovery
   first (log in as user_a, `GET /identity/api/v2/vehicle/vehicles`, take the id); if the vehicle is not listed
   without the email-verify flow, extend the crAPI setup to capture each user's vehicle id into a path_seed. Decided
   concretely when 2.2/2.5 are built, checked on the lab then.

## Phase 1: collection (2026-10-22)

### The guarantees (methodology, read on `04-guarantees.md`)

| # | Guarantee | Question | References (to verify on source) |
|---|---|---|---|
| 2.1 | only authorised users reach privileged endpoints | does a privileged function refuse an ordinary user? | API5:2023 (BFLA), ASVS V8.3.1/V8.2.2, NIST 800-53 AC-3 |
| 2.2 | users access only their own data (BOLA) | does an object refuse a user who does not own it? | API1:2023 (BOLA), CWE-639, ASVS V8.2.2, NIST 800-162 |
| 2.4 | authorization is consistent across equivalent endpoints | does an older version / alternative path drop the check? | API8:2023, ASVS V8.1, NIST 800-53 AC-3 |
| 2.5 | the API does not expose excessive data, nor accept excessive writes | does a response leak fields, or a write set fields the user may not? | API3:2023 (BOPLA), ASVS V8.2.3/V14.2.6, NIST 800-53 SC-4 |
| 2.3 | destructive operations require privilege | (merged: see the boundary) | API5:2023, ASVS V8.2.1/V8.1.1, NIST 800-53 AC-6 |

### Roles and objects on the labs

| Fact | Forgejo (Kong, APISIX) | crAPI (Kong) |
|---|---|---|
| admin account | yes (`admin_username`) | yes (`CRAPI_ADMIN_EMAIL`) |
| user_a account | yes | yes |
| user_b account | yes (`user_b_username`) | yes (`CRAPI_USER_B_EMAIL`) |
| a `Need` naming user_b | **none** (B3: the role exists, the labs configure it, no test uses it) | same |
| objects user_a owns, by id | `path_seed`: `owner`/`repo`/`org`/`user-id: 2`/`repository-id: 1`/`id: 1` | **no `path_seed`**: only the login resource |
| a known object of user_b | none declared | none declared |
| admin / privileged endpoint | `/api/v1/admin/users` (the old 2.1 config) | `/workshop/api/management/users/all` (BFLA, answers 200 to user_a: challenge 7) |

So the two accounts exist on every lab, but **only Forgejo pre-seeds objects**, and neither lab declares an object
owned by user_b or marks which of user_a's objects is private. BOLA and property-level tests therefore need either
runtime discovery of an owned object, or a per-role prepared object in the configuration.

### Derived knowledge available (Phase 2, `src/discovery/derivation.py`)

- `service_prefixes` and `version_siblings` exist (version siblings feed 2.4: crAPI has `v2`/`v3` of `check-otp`,
  `v2.7`/`v4.0` of `login-with-token`; Forgejo `/api/v1` only).
- **No `admin`-segment rule yet.** 2.1 today takes admin paths from the configuration; deriving them (a path with an
  `admin`/`management` segment) is a new rule to add with 2.1 and prove on the labs (rule 5). The spec has them
  (Forgejo `/api/v1/admin/...`, crAPI `/workshop/api/management/...`, `/identity/api/v2/admin/...`).

### The current `2.1` (on `main`) and its defects (review notes)

Probes `admin_endpoint_paths` (configured) with a user_a token, expects 403. Defects (Q-29, Q-32): a `404` counts as
enforced, so a wrong admin path gives a false PASS; the paths come from the configuration while the specification has
them; no BFLA (an ordinary user reaching an admin function that answers 2xx); no method confusion; no role hierarchy;
the positive control is missing (it never confirms the endpoint exists and that user_a is authenticated).

### crAPI category cases (from `challenges.md`, already mapped in `test-review.md`)

| Challenge | Category | Test |
|---|---|---|
| 7 delete another user's video via an admin endpoint | BFLA | 2.1 |
| 1, 2 another user's vehicle / mechanic reports | BOLA | 2.2 |
| 8, 9, 10 order/video properties set through the body | mass assignment | 2.5 |
| 4, 5 other users' data, an internal video property in the response | excessive data | 2.5 |
| 3 another user's password reset via an older API version | version drift | 2.4 (and 1.7) |

---

## Phase 2: design (presented 2026-10-22)

### The boundary (one question, one test; rule 10)

| Question | Test |
|---|---|
| does a **privileged function** refuse an ordinary user (an admin/management endpoint answering 2xx to user_a)? does a **method** on a resource drop the check the others enforce? | **2.1** (function level, BFLA; **2.3 merged**: a destructive method that needs privilege is a function-level check) |
| does an **object** refuse a user who does not own it (user_b reads/modifies/deletes user_a's object)? | **2.2** (object level, BOLA) |
| does an **equivalent endpoint** (an older version, an alternative path) enforce the same policy as the one it mirrors? | **2.4** (consistency) |
| does a **response carry a field** the user may not see, or a **write set a field** the user may not (mass assignment)? | **2.5** (object property level) |

Where 2.3's cases land: "delete by a non-owner" is object level, so it is **2.2** (a DELETE is one of the methods
user_b tries on user_a's object); "a destructive method needs a higher privilege/scope than the read" is function
level, so it is **2.1** (method confusion includes the destructive methods). 2.3 does not become its own test; its id
stays retired (as the review planned).

Each test asks one question and shares the rest: the two roles (a new `Need` for user_b), the positive control per
role (`src/core/references.py`), and an **owned object** (how 2.2 and 2.5 get one is the central decision below).

### Compact design, per test

**2.1 Function-Level Authorization (BFLA).** GREY_BOX (needs user_a; the admin account only to confirm the endpoint
is genuinely privileged, optional), effect depends (BFLA reads are READ_ONLY; method confusion that writes is
CHANGES_DATA). CWE-285 (Improper Authorization) or CWE-284. Sub-tests: `privileged_function_refuses_user` (an
admin/management endpoint answers non-2xx to user_a, confirmed to exist via the admin positive control, so a 404 is
not read as enforced), `method_not_confused` (for a resource user_a may read, the other methods it should not use
are refused). Derive the privileged endpoints (the new `admin`-segment rule) and let the configuration add or correct.
Oracle: user_a gets 2xx on a privileged endpoint that admin also gets 2xx on -> VIOLATION (BFLA); 403/404-with-the-
endpoint-proven-to-exist -> ENFORCED; endpoint not proven to exist -> NOT_VERIFIABLE (fixes the false PASS).

**2.2 Object-Level Authorization (BOLA).** GREY_BOX, needs user_a **and user_b**. Effect: reads READ_ONLY,
modify/delete CHANGES_DATA. CWE-639. Sub-tests: `cross_user_read` (user_b reads user_a's object -> expect non-2xx),
`cross_user_modify` (user_b PATCH/PUT -> non-2xx, confirmed by a user_a read afterwards), `cross_user_delete` (user_b
DELETE -> non-2xx). The hard part is getting **user_a's object id**: see the decision below. Oracle: user_b served
user_a's object -> VIOLATION (CERTAIN, proven by contrast: user_a is served, user_b is not expected to be); refused ->
ENFORCED; the object id could not be obtained -> NOT_VERIFIABLE.

**2.4 Authorization Consistency.** BLACK_BOX/GREY_BOX. API8:2023. Sub-test `equivalent_endpoints_consistent`: for a
documented endpoint that enforces a policy (a credential is required, or a role), its **version siblings**
(`version_siblings`, already derived) and alternative representations are sent the same request and must answer the
same way. crAPI's `v2`/`v3` of `check-otp` (challenge 3) is the category case. Oracle: a sibling that serves what the
documented one refuses -> VIOLATION; same answer -> ENFORCED; no sibling exists -> NOT_APPLICABLE. This test reuses
0.1/0.2's version-sibling knowledge and does not re-derive it (rule 10).

**2.5 Object Property Level (BOPLA: excessive data + mass assignment).** GREY_BOX, needs user_a (admin optional for
the role-filtering sub-test). API3:2023. Sub-tests: `no_sensitive_field` (a response carries no field from a
sensitive-name list: `password`, `*hash`, `ssn`, `credit*`, `*secret`, `*token`, derived from the spec's own schema
where possible, ASVS V14.2.6), `role_field_filtering` (a field admin sees is absent for user_a, field-by-field,
ASVS V8.2.3 - optional, needs admin), `mass_assignment` (create/update an object sending a field the schema marks
`readOnly` or an ownership field, then read it back: the server must ignore the body's value). Oracle: a sensitive
field present -> VIOLATION (FIRM: the name is a heuristic); a readOnly/ownership field accepted from the body ->
VIOLATION (CERTAIN, read back confirms it). crAPI challenges 4,5 (excessive data) and 8,9,10 (mass assignment) are
the category cases.

### The three situations (rule 9) and feasibility

- **Present:** crAPI is the positive case for every category (BFLA 7, BOLA 1/2, mass assignment 8/9/10, excessive
  data 4/5, version drift 3): the group's strongest reason to run against it.
- **Absent:** Forgejo enforces object ownership and admin endpoints, so it is the negative case.
- **Not verifiable:** where an owned object id cannot be obtained, or no privileged endpoint is proven to exist.

### The decisions for the owner (phase-2 go-ahead)

1. **A new `Need` for the second account (user_b).** 2.2 cannot run without two ordinary accounts. The role
   (`ROLE_USER_B`) and the lab credentials already exist (B3); what is missing is a `Need.SECOND_USER_ACCOUNT` (name
   to confirm) and its check in `src/core/test_needs.py`, plus the engine providing its credential as it already does
   for user_a and admin. This is the same mechanism as group B, extended to a third role. **Your go on adding the
   need.**

2. **How 2.2 and 2.5 get an object user_a owns (the central choice).**
   - **(a) Runtime discovery (agnostic, my recommendation).** Log in as user_a, GET a documented collection it can
     list, take the id of an object from the response, and use that id for the cross-user and property probes. No new
     configuration; works on any API that lists a user's objects. The risk: on an API that lists nothing (crAPI has
     no path_seed and some lists need an object created first), the test is NOT_VERIFIABLE rather than a false pass.
   - **(b) A per-role prepared object in the configuration.** Declare, per role, an owned object path/id (an
     extension of `path_seed`/`resources`). Reliable and explicit, but a new configuration parameter and lab setup
     per lab, and less agnostic. 
   - **(c) Hybrid.** Runtime discovery first; the configuration supplies an owned object only where discovery cannot
     (crAPI). My lean: (a) as the default with (c)'s fallback, so the common case needs no configuration and the hard
     lab is still covered. This may add one optional parameter (an owned-object path per role): **your call, since it
     is a new parameter.**

3. **Scope: which methodology sub-tests are in, which are out.** I propose **in**: BFLA, method confusion,
   cross-user read/modify/delete, version-sibling consistency, sensitive-field, mass assignment. I propose **out**
   (NOT_VERIFIABLE or a later review, with the reason): UUID entropy (a cryptographic-quality check, not an
   authorization one), role hierarchy beyond two roles (the labs have user/admin, no moderator tier), GraphQL parity
   (no lab exposes GraphQL), OAuth scope escalation (the labs use no granular OAuth scopes). **Confirm the cut.**

4. **The `admin`-segment derivation rule for 2.1.** Adding a Phase-2 rule that marks a path with an `admin` or
   `management` segment as privileged (proven on the labs: Forgejo `/api/v1/admin`, crAPI `/workshop/api/management`,
   `/identity/api/v2/admin`), the configuration still able to add or correct. **Confirm** (it is an internal design
   call, but it changes derived knowledge several tests read, so I flag it).

This group is the largest; if you prefer, we can split the go-ahead (e.g. approve 2.1 + 2.4 first, then 2.2 + 2.5
once the object-sourcing decision is settled), rather than one go for all four.
