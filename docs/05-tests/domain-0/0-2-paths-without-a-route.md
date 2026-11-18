# 0.2 Paths Without a Route

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_0/test_0_2_paths_without_a_route.py`](../../../src/tests/domain_0/test_0_2_paths_without_a_route.py)

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

**Same group:** tests `0.3` and `0.4`.

## 1. Guarantee

The gateway answers a request whose path matches none of its routes itself, and does not forward it. What is
forwarded without a route arrives at a backend without the policies the gateway attaches to its routes
(authentication, rate limiting, request signing), because those are configured per route.

A PASS promises that none of the paths tried reached something behind the gateway. It does not promise that no such
path exists, and it says nothing about whether a path ought to exist (test `0.1`), about what a path answers to a
credential (test `1.1`), or about reaching the backend without the gateway at all (test `0.4`).

NIST SP 800-228 REC-API-13 (section 3.2.1) asks that every request be validated against the API schema "before it
is processed by the business logic"; a path with no route is not in the schema and must not reach it.

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 0.2) |
|---|---|
| `unrouted_paths` | "unregistered path rejection": what the gateway answers where no route matches, and whether that answer can be told from a backend's own |
| `near_route_paths` | the same question just outside each route path, which is where a gateway matching route paths as plain strings forwards |
| left out | "default backend fallback detection" by the `Server` header: replaced, see the oracle. "Path normalization consistency": the question of tests `1.1` and `2.1` |

### 2.2 Preconditions and reference responses

- **the gateway's own refusal** (`ReferenceResponses.gateway_refusal()`, measured once per run): two unauthenticated
  `GET` requests to random paths at the root. Unlike a calibration point it has no spoiling rule, because a refusal
  is what is being measured. Without it no verdict is given;
- **a backend's own refusal**, from the calibration of the shortest documented paths, used as a guard: when the two
  refusals cannot be told apart, a forwarded path would be indistinguishable from a refused one, and the test says
  so instead of claiming a PASS.

### 2.3 Probes

1. the two requests of the refusal, shared with any other test that needs it;
2. for each route path, the paths just outside it: the route path with a character that is not a separator and then
   random characters (`/api` gives `/api-<rand>`, `/api<rand>`, `/api.<rand>`). A segment-wise matcher refuses them,
   a plain-string matcher forwards them;
3. how many per route path follows the match type, which is what decides whether a neighbour can match at all:
   three for `PREFIX`, one for `EXACT` (a cheap check that the gateway is not more tolerant than its configuration
   says), none for `REGEX`, which cannot be turned into a neighbouring path without interpreting it;
4. **one judgement per route path**, not per probe: the neighbours are several proofs of the same fact, so the first
   proof of something answering decides and the rest are not sent. When no neighbour proves anything, the best news
   wins: one neighbour the gateway refused with its own answer gives `ENFORCED` even if another answered `401`,
   which is ambiguous (`REFUSED_BEFORE_ROUTING`). The reason is that a `401` from the over-matched route's own
   plugin is the gateway answering, not forwarding, so it is not evidence against the guarantee; it is simply not
   evidence for it either, which is why a route path whose neighbours *all* answer that way is `NOT_VERIFIABLE`
   (measured on both Kong labs);
5. sampling, when a gateway has many route paths: they are grouped by their first segment and taken group by group,
   shortest of each group first, up to 50. The shortest path of a group is the one whose neighbours are most likely
   to be forwarded;
6. every probe is an unauthenticated `GET`; a path a route covers segment by segment, or one the specification
   documents, is not sent.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("0.2")) ]]] -->

**`unrouted_paths`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the gateway's refusal at random root paths differs from a backend's own refusal | `ENFORCED/REFUSED_BY_GATEWAY` | - |
| a random path at the root is served (`2xx`) | `VIOLATION/SERVED_WITHOUT_ROUTE` | CERTAIN |
| the two random root paths answered differently | `NOT_VERIFIABLE/REFUSAL_UNSTABLE` | - |
| an enabled route covers every path (a `/` prefix, a regex matching a random root path, or no path at all) | `NOT_VERIFIABLE/CATCH_ALL_ROUTE` | - |
| none of the shortest documented paths gives a reliable backend refusal | `NOT_VERIFIABLE/BACKEND_REFUSAL_UNKNOWN` | - |
| the gateway's refusal has the backend refusal's fingerprint | `NOT_VERIFIABLE/REFUSALS_INDISTINGUISHABLE` | - |

**`near_route_paths`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a neighbour of a route path (outside it by whole segments) is served (`2xx`) | `VIOLATION/SERVED_WITHOUT_ROUTE` | CERTAIN |
| a neighbour answers unlike the gateway's refusal, neither `2xx` nor `401`, `403` | `VIOLATION/ANSWERED_WITHOUT_ROUTE` | FIRM |
| no neighbour answered, and one got the gateway's refusal | `ENFORCED/REFUSED_BY_GATEWAY` | - |
| no neighbour answered or got the gateway's refusal, and one was refused (`401`, `403`) | `NOT_VERIFIABLE/REFUSED_BEFORE_ROUTING` | - |
| every neighbour is documented or covered by a route segment by segment | `NOT_APPLICABLE/COVERED_BY_ROUTE` | - |
| the route path is a regular expression | `NOT_APPLICABLE/REGEX_ROUTE_PATH` | - |
| the gateway's refusal is not trusted (`unrouted_paths` not ENFORCED) | `NOT_VERIFIABLE/REFUSAL_NOT_TRUSTED` | - |
| no gateway configured | `NOT_APPLICABLE/NO_GATEWAY` | - |
| the gateway's adapter does not read routes | `NOT_APPLICABLE/ROUTES_NOT_SUPPORTED` | - |
| the gateway has routes, and they could not be read | `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | - |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("0.2", page=cog.inFile)) ]]] -->

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

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("0.2", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 19 of 19 produced cases gave the declared outcome; 1 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `unrouted_paths/ENFORCED/REFUSED_BY_GATEWAY` | forgejo-kong: the lab as built: Kong answers a random root path with {"message":"no Route matched with those values"}, unlike Forgejo's own 404 | OK |
| `unrouted_paths/VIOLATION/SERVED_WITHOUT_ROUTE/CERTAIN` | forgejo-kong: a prefix route /zqxv whose pre-function answers 200: Kong matches the random root probes (/zqxv<hex>) with it as a plain-string prefix, so a root path is served; not a catch-all for the code (not '/', not a regex) | OK |
| `unrouted_paths/NOT_VERIFIABLE/REFUSAL_UNSTABLE` | forgejo-kong: a route ~/zqxv[0-9a-f]+$ whose pre-function answers 404 with one of two body shapes in turn, so the two root probes differ | OK |
| `unrouted_paths/NOT_VERIFIABLE/CATCH_ALL_ROUTE` | forgejo-kong: a route with path / on forgejo-service: every path has a route | OK |
| `unrouted_paths/NOT_VERIFIABLE/BACKEND_REFUSAL_UNKNOWN` | forgejo-kong: the forgejo container stopped: no documented path gives a reliable backend refusal | OK |
| `unrouted_paths/NOT_VERIFIABLE/REFUSALS_INDISTINGUISHABLE` | forgejo-kong: a prefix route /zqxv on forgejo-service whose pre-function prefixes the path with /api/v1: the root probes get Forgejo's own 404, the same fingerprint as the backend refusal | OK |
| `near_route_paths/VIOLATION/SERVED_WITHOUT_ROUTE/CERTAIN` | forgejo-kong: a prefix route /review-served whose pre-function answers 200: Kong also matches /review-served-<random> with it, and that neighbour is served | OK |
| `near_route_paths/VIOLATION/ANSWERED_WITHOUT_ROUTE/FIRM` | forgejo-kong: the lab as built: Kong's prefix route /api forwards /api-<rand>, which Forgejo answers with its own 'Not found.' | OK |
| `near_route_paths/ENFORCED/REFUSED_BY_GATEWAY` | forgejo-apisix: the lab as built: APISIX matches /api/* by segment and refuses every neighbour with its own 404 Route Not Found | OK |
| `near_route_paths/NOT_VERIFIABLE/REFUSED_BEFORE_ROUTING` | forgejo-kong: the lab as built: the neighbours of /hmac-audit-probe-not-a-real-path answer 401 from Kong's hmac-auth plugin | OK |
| `near_route_paths/NOT_APPLICABLE/COVERED_BY_ROUTE` | forgejo-kong: prefix routes /review-cov and /review-cov/inner: every neighbour of the second falls under the first segment by segment | OK |
| `near_route_paths/NOT_APPLICABLE/REGEX_ROUTE_PATH` | forgejo-kong: the lab as built: the route path ~/swagger\.v1\.json$ is a regular expression | OK |
| `near_route_paths/NOT_VERIFIABLE/REFUSAL_NOT_TRUSTED` | forgejo-kong: the forgejo container stopped: unrouted_paths is BACKEND_REFUSAL_UNKNOWN, so the gateway's refusal is not trusted | OK |
| `near_route_paths/NOT_APPLICABLE/NO_GATEWAY` | forgejo-kong: the run's configuration has no gateway section | OK |
| `near_route_paths/NOT_APPLICABLE/ROUTES_NOT_SUPPORTED` | not producible (code): no adapter without routes exists: both the Kong and the APISIX adapter read routes, so the NOT_SUPPORTED answer cannot be reached | - |
| `near_route_paths/NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | forgejo-kong: the run's gateway.admin.url points to a closed port | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: a route ~/api[-.]?zqxv[0-9a-f]+$ (the three neighbours of /api) whose pre-function answers 503 | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: the same route answering 429 | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: the same route answering 500 | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: the same route sleeping 7 s, with the run's read timeout at 5 s | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("0.2", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- The test proves that something other than the gateway answered; with another intermediary in front (a content
  delivery network, a web application firewall) that answer may come from the intermediary rather than from the
  backend.
- A route path matched by a regular expression is not interpreted: no neighbour is built for it, and a path counted
  as unrouted may be matched by one of them. The note names them.
- A forwarded path far from every route is `ext.0.1.ffuf`'s business.
- An over-matched route whose policy refuses every request is reported as not verifiable, not as a pass: the policy
  did apply, but nothing proves a backend would not have been reached without it.
- A neighbour refused with `401`/`403` unlike the gateway's no-route answer proves a route matched it (the policies of that route ran), but it is `REFUSED_BEFORE_ROUTING`, not a finding.
- A route matched by host or header only (no path) covers every path of its host, but the routes concept carries
  no host: it is not taken for a catch-all, so on a gateway routing this host that way the root probes may reach a
  backend (a route of another host would otherwise hide the check on every gateway that routes by host).

## 6. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- NIST SP 800-228 section 3.2.1 (REC-API-13): https://doi.org/10.6028/NIST.SP.800-228
- CWE-183 Permissive List of Allowed Inputs: https://cwe.mitre.org/data/definitions/183.html

## 7. Inputs

- the gateway's route paths and how each one is matched (`RoutePath`, `RouteMatch` `PREFIX`, `EXACT`, `REGEX`),
  through the optional need: the test knows no gateway's own syntax;
- the documented paths, to leave them alone;
- no configuration parameter.

## 8. Outcomes

No SKIP of its own: without a gateway the test still runs and `near_route_paths` is not applicable. How a
sub-test's status follows from its judgements is rule 2 of the
[assessment model](../../04-architecture/03-assessment-model.md#rules-every-test-follows).

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("0.2")) ]]] -->

- "Answered without a route: GET <path>"
- "A path with no route is served"

<!-- [[[end]]] -->

`evidence_ref` the neighbour's answer.

## 10. Effects on the target

`READ_ONLY`: at most three unauthenticated `GET` requests per sampled route path, on paths that do not exist, plus
the two of the refusal. Nothing is created or changed. A path the gateway forwards reaches the application, which
answers from its own handling of an unknown path.

## 11. Per gateway

Independent of the gateway: the match type comes from the adapter and the gateway's refusal is measured, not listed.
Kong matches a route path as a string prefix by default, so the neighbours of each route path are forwarded; APISIX
matches `/api/*` by segment and refuses them.

## 12. Configuration

None. The sampling maximum is a constant of the module.

## 13. Remediation

Make the route paths match whole path segments instead of string prefixes (Kong: an exact path, or a regular
expression anchored on a segment boundary), and attach the policies to the route rather than to the backend.
