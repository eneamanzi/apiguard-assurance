# Group A: guarantees 0.2, 0.3, 0.4 (working file)

> **Audience:** the owner and me, during the review. Not published documentation: each test page below replaces the
> one in `docs/05-tests/` only when its code is written and verified on the labs. Method: the six phases in
> [`test-review.md`](../test-review.md) (How we work).

| Phase | State |
|---|---|
| 1. Collection | done 2026-10-22 (below) |
| 2. Design | done 2026-10-22, agreed by the owner (its four open points are in the review box) |
| 3. Code | done 2026-10-22 |
| 4. Proof | done 2026-10-22, the three labs |
| 5. Self-review | done 2026-10-22, two corrections (review box) |
| 6. Documentation | done 2026-10-22; the owner's commit left |

**The design is now the three test pages**, which replaced the drafts this file held:
[`0.2`](../../05-tests/domain-0/0-2-paths-without-a-route.md),
[`0.3`](../../05-tests/domain-0/0-3-deprecated-operations.md),
[`0.4`](../../05-tests/domain-0/0-4-backend-without-the-gateway.md). What stays here is the collection of
phase 1, the boundary between the three questions, and the review.

The three guarantees share the gateway's routes and backend addresses, the specification, and the question "what
does the gateway do with a request it has no route for", so they are collected and designed once.

---

## Phase 1: collection (2026-10-22)

Every fact below was read or measured today, read-only, on the three running labs. Nothing was created or changed.

### 1.1 The gateway's routes and backend addresses

Read from each admin plane (`/routes`, `/services`, `/upstreams/<name>/targets` on Kong; `/apisix/admin/routes`,
`/apisix/admin/upstreams` on APISIX).

| Lab | Route | Path, as the gateway matches it | Backend address |
|---|---|---|---|
| Forgejo + Kong | `forgejo-api-route` | `/api`, string prefix | `forgejo:3000` |
| | `forgejo-spec-route` | `~/swagger\.v1\.json$`, regex | `forgejo:3000` |
| | `hmac-audit-route` | `/hmac-audit-probe-not-a-real-path`, string prefix | `forgejo:3000` |
| Forgejo + APISIX | `forgejo-api-route` | `/api` and `/api/*`, segment | `forgejo:3000` |
| | `forgejo-spec-route` | `/swagger.v1.json`, exact | `forgejo:3000` |
| | `hmac-audit-route` | `/hmac-audit-probe-not-a-real-path`, exact | `forgejo:3000` |
| crAPI + Kong | `identity-route` | `/identity`, string prefix | `crapi-identity:8080` |
| | `community-route` | `/community`, string prefix | `crapi-community:8087` |
| | `workshop-route` | `/workshop`, string prefix | `crapi-workshop:8000` |
| | `hmac-audit-route` | `/hmac-audit-probe-not-a-real-path`, string prefix | `crapi-identity:8080` |

No lab has a route that covers every path. Kong's admin plane gives the backend as the name and port the operator
configured (`forgejo:3000`); APISIX's Control API gives the node already resolved (`172.21.0.4:3000`), which matters
for 0.4 below.

### 1.2 What each gateway answers for a path it has no route for

Unauthenticated `GET`, one request each.

| Lab | Path | Status | Who answered, and how it is recognised |
|---|---|---|---|
| Forgejo + Kong | `/zz-no-route-at-all-7f3a` | 404 | the gateway: `{"message":"no Route matched with those values","request_id":...}` |
| Forgejo + Kong | `/api-docs` | 404 | **Forgejo**: `Not found.` The route `/api` matches the path as a string, so `/api-docs` starts with it and is forwarded |
| Forgejo + APISIX | `/zz-no-route-at-all-7f3a` | 404 | the gateway: `{"error_msg":"404 Route Not Found"}`, `Server: APISIX` |
| Forgejo + APISIX | `/api-docs` | 404 | the gateway, the same answer: `/api/*` matches by segment, so `/api-docs` matches no route |
| crAPI + Kong | `/zz-no-route-at-all-7f3a` | 404 | the gateway: `no Route matched with those values` |
| crAPI + Kong | `/identity-docs` | **401** | **crAPI identity**: `CRAPIResponse(message=Invalid Token, status=401)`. The route `/identity` forwarded it |

The two Kong labs therefore hold a real violation of 0.2, and APISIX holds the correct behaviour: the three
situations of rule 9 are on the labs as they stand. Neither Kong lab sends a `Server` header; APISIX sends
`Server: APISIX`.

**The answer that matters is who answered, not the status code.** All six answers above are 4xx; two of them are a
backend's. A list of gateway names in a `Server` header cannot tell them apart (Kong sends none here), but the
gateway's own answer, measured on a path that certainly has no route, can.

### 1.3 Normalization variants: not this group's question

Measured on the canonical documented path of each lab (12 variants: trailing slash, uppercase, double slash, dot and
dot-dot segments, encoded separators, trailing encoded space, `;x=1`, `.json`). No variant answered `2xx` on any
lab. Kong normalizes `/api/v1/./user` and `/api/v1/x/../user` and routes them to the endpoint, which answers `401`
as the canonical path does; APISIX does not normalize them, so Forgejo answers `404`. On crAPI the canonical
`/identity/api/v2/user/dashboard` answers `404` while several variants answer `401`.

Topic 7b (owner, 2026-10-20) already decided that the variants belong to the tests whose control is decided on the
path (1.1, 2.1) and that 0.2 drops them. The measurements above are left here for group B.

### 1.4 Deprecated operations in the specifications

| Specification | Operations | Marked `deprecated: true` |
|---|---|---|
| Forgejo (`/swagger.v1.json`, basePath `/api/v1`) | 304 paths | 4: `POST /org/{org}/repos`, `DELETE` and `PATCH /repos/{owner}/{repo}/issues/{index}/comments/{id}`, `GET /repos/{owner}/{repo}/times/{user}` |
| crAPI 1.1.6 | 40 paths | none |

All four have parameters in the path, which is why the old test probed none of them: it excluded every path holding
`{`. The one read-only operation among them is fillable from the lab's `path_seed` (`owner`, `repo`, `user`), and
answers:

```
GET /api/v1/repos/user-a/test-repo/times/user-a   (Basic Auth of user A)
HTTP/1.1 200 OK        no Deprecation header, no Sunset header
```

So the reference lab holds a real violation of 0.3, which the old test could not see. crAPI holds the "nothing to
check" situation.

### 1.5 Reaching the backend without the gateway

From where the tool runs (the host of the three labs):

| Address | Where it comes from | Result |
|---|---|---|
| `forgejo:3000` | Kong's target of `forgejo-upstream` | the name does not resolve (`Temporary failure in name resolution`) |
| `crapi-identity:8080`, `crapi-workshop:8000`, `crapi-community:8087` | Kong's targets | the names do not resolve |
| `172.22.0.3:3000` (Forgejo + Kong), `172.21.0.4:3000` (Forgejo + APISIX) | the container addresses; APISIX's Control API publishes exactly this form (`ip:port`) | **`GET /api/v1/version` answers 200 in about 1 ms, without passing through the gateway** |

Two conclusions for the design of 0.4:

1. the verdict depends on where the tool runs, and the test must say so: a name that does not resolve proves
   nothing about isolation, it only says the tool is not on that network;
2. the two adapters give addresses of different kinds, so the same guarantee is verifiable on the APISIX lab
   (an address that answers) and not verifiable on the Kong labs (a name that does not resolve). Both are correct
   answers, and together they are two of rule 9's three situations.

Also measured, as context for the page: from inside the lab network the backend answers `200` on
`http://forgejo:3000/api/v1/version`, so the isolation is a property of the network the request starts from.

### 1.6 Sources, verified today

| Source | What it gives | Used by |
|---|---|---|
| NIST SP 800-228 (June 2025, update of 2026-03-13), REC-API-13, section 3.2.1 | "Validate each request and response per the API schema before it is processed by the business logic" | 0.2 |
| the same, section 2.1 | "Rogue or shadow APIs ... often bypass standard security review practices"; "Zombie or deprecated APIs: APIs may have been replaced or superseded by newer systems but have not yet been entirely removed ... They risk falling behind the latest security policies and protections" | 0.3 (the threat) |
| the same, REC-API-4.4, section 3.1.1 | "Establish strategies regarding API versioning, deprecation, and sunsetting, including a focus on secure migration paths" | 0.3 |
| the same, section 4.1 | "Because a shared gateway is located at the perimeter, it can be bypassed (e.g., via an attacker pivoting inside the perimeter), which in turn bypasses the policy checks that are enforced by that gateway. This can be mitigated with techniques like service-to-service access policies that ensure that applications only receive traffic via the centralized gateway" | 0.4 |
| RFC 9745 (March 2025, Standards Track) | the `Deprecation` response header field, a Structured Field date (`Deprecation: @1688169599`), and the `deprecation` link relation | 0.3 |
| RFC 8594 | the `Sunset` response header field | 0.3 |
| RFC 9110 section 15.5.11 | `410 Gone` | 0.3 |
| CWE 4.20, the pages of CWE-183, 284, 420, 441, 668, 684, 1059, 1104 | each entry's abstraction level and whether MITRE allows mapping to it (see the review box) | all three |
| OWASP ASVS 5.0.0, chapters V4, V13, V15 | **no** requirement that the gateway must refuse unregistered paths, and none about deprecated endpoints. `4.1.1` (cited by the old 0.2) is about `Content-Type`; `13.2.1` is about authenticating backend-to-backend communication, which is a different guarantee from 0.4's reachability | all three |

The old 0.2 cites `OWASP-ASVS-v5.0.0-V4.1.1`, `NIST-SP-800-204-S4.1` and `CIS-Benchmark-API-GW-Controls-2.3`. The
first is wrong (see above), the third could not be found as a published identifier, and NIST SP 800-228 is both
newer and specific to APIs. All three references are replaced.

---

## Phase 2: design (the boundary, and what the code added)

### 2.1 The boundary: which question belongs to which test

The rule is rule 10, one question one test. Written out so that no test in this group checks another's question.

| Question | Test |
|---|---|
| does a path answer that the specification does not document? | `ext.0.1.ffuf` |
| does an undeclared method answer? an undocumented version? does a gateway route cover paths the specification does not document? | `0.1` |
| **does something answer a path the gateway has no route for?** | **`0.2`** |
| **is an operation the specification marks deprecated still served, and does it declare its deprecation and sunset?** | **`0.3`** |
| **can a backend be reached without passing through the gateway?** | **`0.4`** |
| does a path require a credential, including under its normalization variants? | `1.1` |
| do equivalent paths to one operation enforce the same controls? | `2.4` |
| does a response name the server and its version? | `6.2` |
| does a path disclose credentials or debug data? | `6.4` |
| are backend-to-backend calls authenticated? | not a guarantee today (see 0.4's limitations) |

Three consequences, applied below: 0.2 says nothing about whether a path should exist (that is 0.1) nor about what
it answers to a credential (1.1); 0.3 says nothing about paths the specification does not document (0.1); 0.4 says
nothing about what the backend answers once reached (every other test asks that through the gateway).

### 2.2 What is shared, and what each test needs

- **The gateway's routes** (`target.gateway.routes()`): read by 0.1 (already) and 0.2. Optional need in both: the
  test runs without a gateway and the sub-test that needs the routes is not applicable.
- **The backend addresses**: `target.gateway.target_health()` already gives `backend` and `target` on both
  adapters. 0.4 only. No new concept is needed.
- **The reference responses** (`context.references`): 0.2 needs one reference the mechanism does not provide today,
  the gateway's own refusal (2.3 below); 0.3 needs the positive control to know a credential works.
- **`path_seed`**: 0.3, to fill the parameters of a deprecated path.

### 2.3 One new mechanism: the gateway's own refusal

0.2 has to tell "the gateway refused it" from "something behind the gateway answered". Today `ReferenceResponses`
answers a different question (does this path answer like an unknown sibling of its parent). The new reference is a
single measurement per run:

**`ReferenceResponses.gateway_refusal()`**: two `GET` requests to random paths at the root, under no documented
prefix and under no route, taken as the answer the gateway gives when nothing matches. It returns its fingerprint
when the two agree, and "cannot tell" when they differ. Cached run-wide like the calibration, measured on first use.

Judgement, for a candidate path that no route covers: an answer whose fingerprint is unlike the gateway's refusal
means something other than the gateway answered it, because with no route matched the gateway has nothing else to
answer. A `2xx` means it was served. If the gateway's refusal cannot be measured, or if it cannot be told apart
from the backend's own refusal under a documented path, 0.2 answers "not verifiable" and says which.

This is the whole of what 0.2 needs, and it stays in `core/references.py` because it is a reference response, not
test logic. 0.4 and 0.3 need nothing new.

### 2.4 What phases 3 to 5 added to the design

| # | Change | Why |
|---|---|---|
| 1 | **0.2 judges one route path at a time**, not one neighbour at a time; the first proof decides and the rest are not sent | The first run on Forgejo + Kong gave 6 findings for 2 over-matching routes: the three neighbours of a route path are three proofs of one fact |
| 2 | **0.2 counts a 401 or 403 as `NOT_VERIFIABLE/REFUSED_BEFORE_ROUTING`** | Found in the same run: three of those six findings were Kong's own `hmac-auth` plugin answering `401` on the route it over-matches. The request was stopped at the gateway, so nothing escaped, and the old oracle called it "answered by something other than the gateway". The same rule as 0.1's: an answer that refuses the request says nothing about what is behind it |
| 3 | **0.2 does not probe a route path matched by a regular expression** (`NOT_APPLICABLE/REGEX_ROUTE_PATH`, named in a note) | A neighbour cannot be built from a regex without interpreting it (the adapter keeps the regex as the path's value), and a regex route may legitimately match a path this test would count as unrouted |
| 4 | **0.4 needs the gateway** (`needs`, strategy WHITE_BOX) instead of declaring it optional | Its only sub-test does nothing without the backend addresses, so a SKIP with the reason is honest where 0.1 and 0.2 still run other sub-tests |
| 5 | **`SecurityClient.request(origin=...)`** | 0.4 has to ask a second address, and the client is the single HTTP entry point (hard rule), so the capability belongs there: the record keeps the address actually asked, and the run's TLS settings apply to it |
| 6 | **`ReferenceResponses.gateway_refusal()` and `random_token()`** in `src/core/references.py` | The refusal is a reference response, not test logic (topic 7a); `random_token()` makes the neutral random name public for a test that builds a path of its own |
| 7 | **`TestInfo.cwe` is optional** | Decision 3 below |
| 8 | The APISIX lab's `tests.domain_0.test_0_2.gateway_server_identifiers` block removed | The parameter is gone: that lab needed its own list of gateway names, and now needs none |

### 2.5 Results on the labs (phase 4, 2026-10-22)

Each test page's Validation section holds the detail and the evidence; in short:

| Lab | `0.2` | `0.3` | `0.4` |
|---|---|---|---|
| Forgejo + Kong | FAIL 1 (route `/api` forwards `/api-<rand>` to Forgejo) | FAIL 1 (deprecated `times/{user}`, no Sunset) | PASS partial (1 enforced, 1 not resolvable) |
| Forgejo + APISIX | PASS complete (5 enforced) | FAIL 1 (the same) | **FAIL 1, CERTAIN** (`172.21.0.4:3000` answers directly) |
| crAPI + Kong | FAIL 2 (`/workshop-<rand>` reaches Spring, `/community-<rand>` reaches Go) | SKIP (nothing deprecated) | PASS partial (2 enforced, 3 not resolvable, 1 another service) |

Every finding was checked against the recorded answer, to see which component answered: Forgejo's `Not found.`,
Spring's HTML 404 page and Go's `404 page not found` against the gateways' own `no Route matched` and
`404 Route Not Found`.


## Review box

### Problems found in the tests on `main`

| # | Where | Problem | Decided |
|---|---|---|---|
| 1 | `test_0_2_deny_by_default.py`, sub-check 1 | the response is classified as the backend's when the `Server` header holds no known gateway name. Neither Kong lab sends a `Server` header at all, and APISIX sends `APISIX`, which is not in the default list: the check is unreliable in both directions | replaced by the measured gateway refusal (2.3); the parameter is removed |
| 2 | the same, sub-check 1 | the paths probed are a fixed list of "guaranteed nonexistent" strings, which never touches the neighbours of the real routes, where the forwarding happens | the probes are derived from the route paths |
| 3 | the same, sub-check 2 | the normalization variants are 0.2's, and 1.1 has its own with different variants and a different oracle | 0.2 drops them (topic 7b); the phase 1 measurements go to group B |
| 4 | the same, references | `ASVS v5.0.0-4.1.1` is about `Content-Type`; `CIS-Benchmark-API-GW-Controls-2.3` could not be found as a published identifier | all references replaced, each verified on its source (1.6) |
| 5 | `test_0_3_deprecated_api_enforcement.py` | every path holding `{` is excluded, so on the reference lab all four deprecated operations were skipped and the real violation was never seen | the paths are filled from `path_seed` |
| 6 | the same | an unparseable `Sunset` counts as compliant | `NOT_VERIFIABLE/SUNSET_NOT_A_DATE` |
| 7 | the same | it reads only `Sunset`; RFC 9745 made `Deprecation` a Standards Track header in March 2025 | both are read |
| 8 | the same | a `404` is treated as the endpoint being gone | judged against the calibration, and `404` is not the `410` the standard asks for |

### Research

- **oasdiff** (the methodology's optional tool for 0.3) compares two OpenAPI specifications and reports what
  changed between them, including newly deprecated operations. It needs a previous version of the specification,
  which the target does not serve and only the operator could supply, and what it reports is a property of the
  documents, not of the running API. **Decision: not used by 0.3.** To be recorded in
  `06-knowledge/05-tool-decisions.md`.
- **cherrybomb** (the methodology's optional tool for 0.2) checks a specification for its own problems and runs
  tests derived from it. It does not read the gateway's routes, which is where 0.2's question lives.
  **Decision: not used by 0.2.** Same record.
- **The CWE of each test was checked on its MITRE page for abstraction level and mapping status**, because MITRE
  marks the most abstract entries as not to be used. Chosen: `CWE-183` Permissive List of Allowed Inputs for 0.2
  (Base, allowed: the gateway's routes are a list of allowed paths, and a route matched as a string prefix makes
  that list too permissive), `CWE-684` for 0.3 (see below), `CWE-420` Unprotected Alternate Channel for 0.4 (Base,
  allowed: "the product protects a primary channel, but it does not use the same level of protection for an
  alternate channel", which is the gateway and the backend's own address). Discarded for being too abstract to map:
  `CWE-284` Improper Access Control (Pillar, discouraged), `CWE-668` Exposure of Resource to Wrong Sphere (Class,
  discouraged), `CWE-441` Unintended Proxy (Class, and its subject is the loss of the request's original source,
  not the routing).
- No external tool is proposed for group A: the three questions all rest on knowledge only the gateway's admin
  plane and the specification hold.

### Decided by the owner (2026-10-22)

1. **No new parameter for 0.4.** The parameter proposed (addresses the operator knows) was not the best design: the
   second candidate of 0.4's section 5, the target's own host with the backend's port, is derived from what the
   gateway already says and answers the same need on the labs, so rule 5 (derive first) is kept and no knob is
   added. Finding this also produced the false positive the oracle now excludes: with the three labs running,
   `localhost:8000` answers with the other lab's Kong, not with crAPI's workshop backend, so an HTTP answer at a
   port of the target's host counts only when it looks like the application does through the gateway.
2. **0.2's sampling maximum is a constant** of the module. The sampling rule was sharpened at the same time: how
   many neighbours a route path gets follows the match type the adapter reports (three for `PREFIX`, one for
   `EXACT` and `REGEX`), since the match type is what decides whether a neighbour can match at all.
3. **0.3 declares no primary CWE**, and the declaration changes to allow that (owner: "nothing is forced").
   No catalogue entry describes "a deprecated operation is still served": CWE-1104 is limited to third-party
   components; CWE-1059 (insufficient technical documentation) is **prohibited** for mapping, the same problem as
   6.2's CWE-16 (topic 8); CWE-684 would fit only loosely and is a Class entry allowed with review. So
   `TestInfo.cwe` becomes optional (change to the common part, below) and 0.3 rests on its standards, which are
   exact: RFC 9745, RFC 8594, RFC 9110 section 15.5.11, API9:2023, NIST SP 800-228.
4. **0.3 leaves out the mirror case** (an operation the server flags as deprecated while the specification does
   not): it is 0.3's question, but finding it needs a probe of the whole documented surface, which no single
   guarantee justifies; written in the page's limitations.

### A change to the common part this group needs

`TestInfo.cwe` becomes optional (`str | None`, default `None`), for decision 3. What it touches, read today: the
validator that checks the form (applied only when a value is given), the cross-check that the primary CWE is not
repeated in `references`, `cwe_id` in `src/core/models/results.py` and in the report builder (`str | None`), and
the two places in `scripts/generate_docs.py` that print it (a dash when there is none). The report template already
guards it (`{% if row.cwe_id %}`) and the renderer already prints a dash for an empty value, so neither changes.

### Changes outside this group's own files, deferred

Deferred to the list in [`test-review.md`](../test-review.md) ("Documentation changes to apply later"), as guarantee
0.1's were: those pages describe the tool as a whole and are rewritten once, when the review has passed through
every group.

- `06-knowledge/04-guarantees.md`: sections 0.2 and 0.3 aligned with what is implemented; 0.4 added as a new
  guarantee.
- `06-knowledge/05-tool-decisions.md`: oasdiff (0.3) and cherrybomb (0.2) recorded as not used, with the reasons in
  Research above.
- `03-reference/06-compatibility.md` (Test portability: 0.2 and 0.3 need only the specification and the target URL;
  0.4 needs the gateway's admin plane), `roadmap.md` (0.2 and 0.3 rewritten, 0.4 added), `CHANGELOG.md`, the usage
  guides.
- `OPEN_QUESTIONS.md`: the Q-29 items for 0.2 (the `Server` header check, the fixed list of nonexistent paths) and
  for 0.3 (the unparseable `Sunset` counted as compliant) are answered by this group.
