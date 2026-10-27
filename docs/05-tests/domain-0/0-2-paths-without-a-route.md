# 0.2 Paths Without a Route

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-22) ·
> **Source of truth:**
> [`src/tests/domain_0/test_0_2_paths_without_a_route.py`](../../../src/tests/domain_0/test_0_2_paths_without_a_route.py) ·
> **Verified:** 2026-10-22

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("0.2", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `0.2` |
| Name | Paths Without a Route |
| Domain | 0 - API Discovery and Inventory Management |
| Priority / strategy | P0 / BLACK_BOX |
| Effect | READ_ONLY |
| CWE | CWE-183 |
| Standards | `OWASP API8:2023`, `NIST SP 800-228, Section 3.2.1` |
| Tags | `inventory`, `gateway-routing` |
| Prerequisites | none |
| Needs | `GATEWAY` (optional) |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `0.3` and `0.4` (the review of guarantees 0.2, 0.3 and 0.4 together).

## 1. Guarantee

The gateway answers a request whose path matches none of its routes itself, and does not forward it. What is
forwarded without a route arrives at a backend without the policies the gateway attaches to its routes
(authentication, rate limiting, request signing), because those are configured per route.

A PASS promises that none of the paths tried reached something behind the gateway. It does not promise that no such
path exists, and it says nothing about whether a path ought to exist (test `0.1`), about what a path answers to a
credential (test `1.1`), or about reaching the backend without the gateway at all (test `0.4`).

NIST SP 800-228 REC-API-13 (section 3.2.1) asks that every request be validated against the API schema "before it
is processed by the business logic"; a path with no route is not in the schema and must not reach it.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 0.2) |
|---|---|
| `unrouted_paths` | "unregistered path rejection": what the gateway answers where no route matches, and whether that answer can be told from a backend's own |
| `near_route_paths` | the same question just outside each route path, which is where a gateway matching route paths as plain strings forwards |
| left out | "default backend fallback detection" by the `Server` header: replaced, see the oracle. "Path normalization consistency": the question of tests `1.1` and `2.1` |

## 3. Inputs

- the gateway's route paths and how each one is matched (`RoutePath`, `RouteMatch` `PREFIX`, `EXACT`, `REGEX`),
  through the optional need: the test knows no gateway's own syntax;
- the documented paths, to leave them alone;
- no configuration parameter.

## 4. Preconditions and reference responses

- **the gateway's own refusal** (`ReferenceResponses.gateway_refusal()`, measured once per run): two unauthenticated
  `GET` requests to random paths at the root. Unlike a calibration point it has no spoiling rule, because a refusal
  is what is being measured. Without it no verdict is given;
- **a backend's own refusal**, from the calibration of the shortest documented paths, used as a guard: when the two
  refusals cannot be told apart, a forwarded path would be indistinguishable from a refused one, and the test says
  so instead of claiming a PASS.

## 5. Probes

1. the two requests of the refusal, shared with any other test that needs it;
2. for each route path, the paths just outside it: the route path with a character that is not a separator and then
   random characters (`/api` gives `/api-<rand>`, `/api<rand>`, `/api.<rand>`). A segment-wise matcher refuses them,
   a plain-string matcher forwards them;
3. how many per route path follows the match type, which is what decides whether a neighbour can match at all:
   three for `PREFIX`, one for `EXACT` (a cheap check that the gateway is not more tolerant than its configuration
   says), none for `REGEX`, which cannot be turned into a neighbouring path without interpreting it;
4. **one judgement per route path**, not per probe: the neighbours are several proofs of the same fact, so the first
   proof decides and the rest are not sent;
5. sampling, when a gateway has many route paths: they are grouped by their first segment and taken group by group,
   shortest of each group first, up to 50. The shortest path of a group is the one whose neighbours are most likely
   to be forwarded;
6. every probe is an unauthenticated `GET`; a path a route covers segment by segment, or one the specification
   documents, is not sent.

## 6. Oracle

What counts as a path the gateway has no route for: one that is neither equal to nor, segment by segment, under any
route path. A route path matched as a plain string also matches its neighbours, so the route registers more paths
than the API documents, which is what CWE-183 describes.

| Case | Outcome / detail | Confidence |
|---|---|---|
| the answer is `2xx` | `VIOLATION/SERVED_WITHOUT_ROUTE` | CERTAIN: something behind the gateway served it |
| the answer refuses the request (401, 403) | `NOT_VERIFIABLE/REFUSED_BEFORE_ROUTING`: the policy of the over-matched route may have stopped it at the gateway, or a backend may have refused it after being reached | - |
| the answer is unlike the gateway's refusal | `VIOLATION/ANSWERED_WITHOUT_ROUTE` | FIRM: with no route matched the gateway has no other answer, so another component answered |
| the answer is like the gateway's refusal | `ENFORCED/REFUSED_BY_GATEWAY` | - |
| the route path is matched by a regular expression | `NOT_APPLICABLE/REGEX_ROUTE_PATH`, named in a note | - |
| every neighbour is covered by another route | `NOT_APPLICABLE/COVERED_BY_ROUTE` | - |
| the refusal's two probes answered differently | `NOT_VERIFIABLE/REFUSAL_UNSTABLE` | - |
| the gateway's refusal cannot be told from a backend's own | `NOT_VERIFIABLE/REFUSALS_INDISTINGUISHABLE` | - |
| no documented path gave a reliable backend refusal for the guard | `NOT_VERIFIABLE/BACKEND_REFUSAL_UNKNOWN` | - |
| a route covers every path (a `/` prefix) | `NOT_VERIFIABLE/CATCH_ALL_ROUTE`, with the route named | - |
| the routes cannot be read | `NOT_VERIFIABLE/ROUTES_NOT_READABLE`; `NOT_APPLICABLE/ROUTES_NOT_SUPPORTED`, `NO_GATEWAY` | - |
| unavailable, rate limited, no response, server error | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE`, `RATE_LIMITED`, `NO_RESPONSE`, `SERVER_ERROR` | - |

The `Server` header is not used. Measured on the labs (2026-10-22): neither Kong lab sends one and APISIX sends
`Server: APISIX`, so the old check (a response is a backend's when the header holds no known gateway name) was
unreliable in both directions, and it needed a list of gateway names in the configuration.

## 7. Outcomes

No SKIP of its own: without a gateway the test still runs and `near_route_paths` is not applicable. How a
sub-test's status follows from its judgements is rule 2 of the
[assessment model](../../04-architecture/03-assessment-model.md#rules-every-test-follows).

## 8. Findings

One per route path: "Answered without a route: GET `<path>`", with the status, the route it sits next to, that
route's path and match type, and its backend; `evidence_ref` the probe, `supporting_refs` the refusal's two probes.

## 9. Effects on the target

`READ_ONLY`: at most three unauthenticated `GET` requests per sampled route path, on paths that do not exist, plus
the two of the refusal. Nothing is created or changed. A path the gateway forwards reaches the application, which
answers from its own handling of an unknown path.

## 10. Per gateway

Independent of the gateway: the match type comes from the adapter and the gateway's refusal is measured, not listed.
Kong matches a route path as a string prefix by default, so the neighbours of each route path are forwarded; APISIX
matches `/api/*` by segment and refuses them.

## 11. Configuration

None. The old parameter `gateway_server_identifiers` is removed: the APISIX lab needed its own
list of gateway names, and now needs nothing. The sampling maximum is a constant of the module (owner, 2026-10-22).

## 12. Validation

Runs of 2026-10-22, the three tests of the group together, every lab healthy afterwards:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong | FAIL, 1 finding | `unrouted_paths` PASS complete (Kong answers an unrouted path with `{"message":"no Route matched with those values"}`); `near_route_paths`: `/api-<rand>` is answered by Forgejo with `Not found.`, a different shape, so Kong's route `/api` forwards what it has no route for; the hmac route's neighbours answer `401` from Kong's own plugin, counted `REFUSED_BEFORE_ROUTING`; the `~/swagger\.v1\.json$` route path is `REGEX_ROUTE_PATH` |
| crAPI + Kong | FAIL, 2 findings | `/workshop-<rand>` gets Spring's HTML 404 page, the same answer the workshop backend gives for an unknown path under `/workshop/api/`; `/community-<rand>` gets Go's `404 page not found`: both reached their backend. `/identity-<rand>` answers `401` and is not counted |
| Forgejo + APISIX | PASS complete, 5 enforced | every neighbour of every route path gets APISIX's own `{"error_msg":"404 Route Not Found"}` |
| any | NOT_VERIFIABLE | a target whose two refusals cannot be told apart, or a catch-all route: not on the labs |

**What each branch has been seen doing** (rule 9). Proven on a lab: `REFUSED_BY_GATEWAY`, `ANSWERED_WITHOUT_ROUTE`,
`REFUSED_BEFORE_ROUTING`, `REGEX_ROUTE_PATH`. Still unproven: `SERVED_WITHOUT_ROUTE`, `REFUSAL_UNSTABLE`,
`REFUSALS_INDISTINGUISHABLE`, `BACKEND_REFUSAL_UNKNOWN`, `CATCH_ALL_ROUTE`, `COVERED_BY_ROUTE`, the gateway reasons
and the transport reasons.

## 13. Remediation

Make the route paths match whole path segments instead of string prefixes (Kong: an exact path, or a regular
expression anchored on a segment boundary), and attach the policies to the route rather than to the backend.

## 14. Limitations

- The test proves that something other than the gateway answered; with another intermediary in front (a content
  delivery network, a web application firewall) that answer may come from the intermediary rather than from the
  backend.
- A route path matched by a regular expression is not interpreted: no neighbour is built for it, and a path counted
  as unrouted may be matched by one of them. The note names them.
- A forwarded path far from every route is `ext.0.1.ffuf`'s business.
- An over-matched route whose policy refuses every request is reported as not verifiable, not as a pass: the policy
  did apply, but nothing proves a backend would not have been reached without it.

## 15. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- NIST SP 800-228 section 3.2.1 (REC-API-13): https://doi.org/10.6028/NIST.SP.800-228
- CWE-183 Permissive List of Allowed Inputs: https://cwe.mitre.org/data/definitions/183.html
