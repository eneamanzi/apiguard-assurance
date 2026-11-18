# 0.1 Undeclared Methods, Undocumented Versions and Gateway Route Drift

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_0/test_0_1_shadow_api_discovery.py`](../../../src/tests/domain_0/test_0_1_shadow_api_discovery.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("0.1", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `0.1` |
| Name | Undeclared Methods, Undocumented Versions and Gateway Route Drift |
| Domain | 0 - API Discovery and Inventory Management |
| Priority / strategy | P0 / BLACK_BOX |
| Effect | STRESSES_TARGET |
| CWE | CWE-912 |
| Standards | `OWASP API9:2023`, `OWASP ASVS v5.0.0-4.1.4`, `OWASP WSTG-v42-CONF-06` |
| Tags | `inventory`, `shadow-api` |
| Prerequisites | none |
| Needs | `GATEWAY` (optional) |
| Parameters | none |

<!-- [[[end]]] -->

**Same guarantee:** [`ext.0.1.ffuf`](../external/domain-0/ext-0-1-ffuf.md) searches for undocumented paths; this
test asks what only the specification can reveal.

## 1. Guarantee

Every endpoint active behind the gateway is documented in the OpenAPI specification (OWASP API9:2023). An
undeclared method, an undocumented version or a gateway route nobody documented is attack surface no review
covered.

- **A PASS promises:** of the documented paths, none accepted a method the specification does not declare; no
  version next to the documented ones answered; and (with the gateway) every enabled route has a documented path
  under it.
- **It does not promise** anything about what those endpoints do: whether they require a credential is test 1.1,
  the right role test 2.1, whether they leak data test 6.4, whether equivalent paths enforce the same controls
  test 2.4, whether a documented deprecated version is switched off test 0.3.

ASVS v5.0.0-4.1.4: only the HTTP methods the API supports can be used, and unused methods are blocked.

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Methodology sub-test (guarantee 0.1) | Sub-test | Coverage |
|---|---|---|
| Path enumeration by fuzzing | - | `ext.0.1.ffuf` |
| HTTP method discovery | `undeclared_methods` | every documented path, every method of `GET, POST, PUT, PATCH, DELETE` the specification does not declare for it (`HEAD` is implied by `GET`, RFC 9110 §9.3.2); and `TRACE` once per service, judged on its echo (below) |
| Versioning completeness | `undocumented_versions` | the versions next to the documented ones, from the derivation rule `version_siblings`, each probed with a method the specification declares on the path it lends; whether two **documented** versions enforce the same controls is test 2.4 |
| Documentation drift via the Admin API | `gateway_route_drift` | the gateway's routes against the documented paths, when a gateway is configured (optional need) |

### 2.2 Preconditions and reference responses

- **Calibration** (`src/core/references.py`): an undeclared method is compared with the same method on random
  siblings of the path, a version with random siblings under the same parent. On a path with parameters the random
  siblings are the same route as the probe (only the values change), so there the comparison proves nothing and is
  not used to judge (Oracle).
- **No positive control:** the test asks whether something exists, not who may use it.

### 2.3 Probes

- **`undeclared_methods`,** per documented path, each undeclared method:
  - a path with parameters is probed on random values of each parameter's declared type, never on the operator's
    resources (`path_seed`), so that nothing real can be changed; the price is that only an executed method (2xx)
    or a refused one (405) is evidence there: a handled method on an object that does not exist and an ignored one
    can answer alike (both 404 on Forgejo);
  - a path without parameters is probed as it is, with an empty JSON body for `POST`, `PUT`, `PATCH`;
  - what an accepted write surely created is deleted at once: the object its `Location` names, or the random path an
    accepted `PUT` wrote to on a path with parameters. Any other accepted write (a `POST` without `Location`, a `PUT`
    or `PATCH` on a real path, a `DELETE`) is named in a note of the result and never followed by a `DELETE`, which
    on a real path could remove a real resource.
- **`undocumented_versions`:** one request per derived candidate. The path probed is chosen by a stated rule: of
  that version group, a `GET` path first (read-only), a path of any documented method otherwise, preferring one
  without parameters and then the shortest; a method with a body is sent with an empty one. Probing `GET` only left
  a group whose every path is a `POST` unverifiable (crAPI's `/identity/api/auth/`).
- **`gateway_route_drift`:** no request to the API; the gateway's routes read through the adapter.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("0.1")) ]]] -->

**`undeclared_methods`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| an undeclared method, or TRACE, answers `405` or `501` | `ENFORCED/METHOD_REJECTED` | - |
| a path without parameters answers the method like its random siblings, not `2xx` | `ENFORCED/METHOD_NOT_SERVED` | - |
| a path without parameters serves the method (`2xx`) unlike its random siblings | `VIOLATION/UNDECLARED_METHOD_HANDLED` | CERTAIN |
| a path with parameters serves the method (`2xx`) on a random object | `VIOLATION/UNDECLARED_METHOD_HANDLED` | FIRM |
| a path without parameters answers the method unlike its siblings, neither `2xx` nor a refusal | `VIOLATION/UNDECLARED_METHOD_KNOWN` | FIRM |
| refused (`401`, `403`) unlike the siblings, or TRACE refused: an authentication before the method | `NOT_VERIFIABLE/REFUSED_BEFORE_METHOD` | - |
| answered like the siblings, which are refused (`401`, `403`) | `NOT_VERIFIABLE/REFUSED_BEFORE_ROUTING` | - |
| a path with parameters answers neither `2xx` nor `405` | `NOT_VERIFIABLE/NONEXISTENT_OBJECT` | - |
| a path next to a documented one with a parameter in its place answers otherwise than its siblings | `NOT_VERIFIABLE/SIBLING_ROUTE_DOCUMENTED` | - |
| served `2xx` exactly as its random siblings (a catch-all) | `NOT_VERIFIABLE/SERVED_LIKE_UNKNOWN` | - |
| the calibration of the random siblings is unreliable | `NOT_VERIFIABLE/CALIBRATION_UNSTABLE` | - |
| TRACE answers `2xx` with the request line sent back | `VIOLATION/TRACE_ECHOED` | CERTAIN |
| TRACE answers `2xx` without the echo | `NOT_VERIFIABLE/TRACE_SERVED_NO_ECHO` | - |
| TRACE answers anything else (not found, invalid) | `ENFORCED/TRACE_NOT_SERVED` | - |

**`undocumented_versions`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| answers like a path under a random version | `ENFORCED/VERSION_ABSENT` | - |
| answers unlike a random version, neither not found nor refused | `VIOLATION/UNDOCUMENTED_VERSION` | TENTATIVE |
| not found or refused unlike a random version: the version may exist without this path | `NOT_VERIFIABLE/VERSION_UNCLEAR` | - |
| refused (`401`, `403`) like a random version | `NOT_VERIFIABLE/REFUSED_BEFORE_ROUTING` | - |
| the calibration of the random versions is unreliable | `NOT_VERIFIABLE/CALIBRATION_UNSTABLE` | - |
| no documented path has a version segment | `NOT_APPLICABLE/NO_VERSIONED_PATH` | - |
| the version group documents no operation to lend | `NOT_APPLICABLE/NO_PATH_IN_GROUP` | - |

**`gateway_route_drift`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| an enabled route each of whose paths has a documented path (after the base URL's path) or the specification under it | `ENFORCED/ROUTE_DOCUMENTED` | - |
| an enabled route with a path under which no documented path falls | `VIOLATION/ROUTE_NOT_DOCUMENTED` | CERTAIN |
| a route's regular expression does not compile in Python | `NOT_VERIFIABLE/ROUTE_NOT_READ` | - |
| a disabled route (or one of a disabled service) | `NOT_APPLICABLE/ROUTE_DISABLED` | - |
| no gateway configured | `NOT_APPLICABLE/NO_GATEWAY` | - |
| the gateway's adapter does not read routes | `NOT_APPLICABLE/ROUTES_NOT_SUPPORTED` | - |
| the gateway has routes, and they could not be read | `NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | - |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("0.1", page=cog.inFile)) ]]] -->

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

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("0.1", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 27 of 27 produced cases gave the declared outcome; 5 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `undeclared_methods/ENFORCED/METHOD_REJECTED` | forgejo-kong: the lab as built: Forgejo answers 405 to an undeclared method on most documented paths | OK |
| `undeclared_methods/ENFORCED/METHOD_NOT_SERVED` | forgejo-kong: the lab as built: on a path without parameters Forgejo answers an undeclared method exactly as an unknown path | OK |
| `undeclared_methods/VIOLATION/UNDECLARED_METHOD_HANDLED/CERTAIN` | forgejo-kong: a Kong route on /api/v1/version (documented GET only) answers 200 to POST, PUT, PATCH, DELETE, while its random siblings reach Forgejo | OK |
| `undeclared_methods/VIOLATION/UNDECLARED_METHOD_HANDLED/FIRM` | forgejo-kong: a Kong route on /api/v1/users/<any>/heatmap (documented GET only) answers 200 to POST, PUT, PATCH, DELETE: the probe on a random username is served | OK |
| `undeclared_methods/VIOLATION/UNDECLARED_METHOD_KNOWN/FIRM` | forgejo-kong: a Kong route on /api/v1/settings/api (documented GET only, no documented /settings/{x}) answers 400 to POST, PUT, PATCH, DELETE, unlike its random siblings (Forgejo) | OK |
| `undeclared_methods/NOT_VERIFIABLE/REFUSED_BEFORE_METHOD` | crapi-kong: the lab as built: crAPI's PUT /workshop/api/shop/orders answers 401 where PUT on random siblings gets the router's 404 | OK |
| `undeclared_methods/NOT_VERIFIABLE/REFUSED_BEFORE_ROUTING` | crapi-kong: the lab as built: crAPI's identity service answers 401 to any method on any path, its random siblings included | OK |
| `undeclared_methods/NOT_VERIFIABLE/NONEXISTENT_OBJECT` | forgejo-kong: the lab as built: on paths with parameters Forgejo answers 404 on the random object | OK |
| `undeclared_methods/NOT_VERIFIABLE/SIBLING_ROUTE_DOCUMENTED` | forgejo-kong: a Kong route on /api/v1/users/search (next to the documented /users/{username}) answers 400 to its undeclared methods | OK |
| `undeclared_methods/NOT_VERIFIABLE/SERVED_LIKE_UNKNOWN` | forgejo-kong: a Kong route ~/api/v1/[^/]+$ answers 200 with the same body to every method, so a documented path is served as its random siblings are | OK |
| `undeclared_methods/NOT_VERIFIABLE/CALIBRATION_UNSTABLE` | forgejo-kong: a Kong route matching the tool's random probe names (zqxv + hex) answers 404 with one of two JSON body shapes in turn, so the two calibration probes differ | OK |
| `undeclared_methods/VIOLATION/TRACE_ECHOED/CERTAIN` | not producible (gateway): Kong answers TRACE itself with 405, before any route (each gateway of the labs answers 405); TRACE_ECHOED was seen only on a scratch server that echoes it | - |
| `undeclared_methods/NOT_VERIFIABLE/TRACE_SERVED_NO_ECHO` | not producible (gateway): Kong answers TRACE itself with 405, before any route (each gateway of the labs answers 405): TRACE never reaches a route or the backend | - |
| `undeclared_methods/ENFORCED/TRACE_NOT_SERVED` | not producible (gateway): Kong answers TRACE itself with 405, before any route (each gateway of the labs answers 405): the answer is always METHOD_REJECTED | - |
| `undocumented_versions/ENFORCED/VERSION_ABSENT` | forgejo-kong: the lab as built: /api/v2/orgs answers as a path under a random version | OK |
| `undocumented_versions/VIOLATION/UNDOCUMENTED_VERSION/TENTATIVE` | forgejo-kong: a Kong route ~/api/v2/orgs$ answers 200, while random versions reach Forgejo and get its 404 | OK |
| `undocumented_versions/NOT_VERIFIABLE/VERSION_UNCLEAR` | forgejo-kong: a Kong route ~/api/v2/orgs$ answers 404 with a JSON body of its own shape, unlike Forgejo's 404 to a random version | OK |
| `undocumented_versions/NOT_VERIFIABLE/REFUSED_BEFORE_ROUTING` | crapi-kong: the lab as built: crAPI's /identity/api/v1 and /v3 answer 401 like any path of the identity service | OK |
| `undocumented_versions/NOT_VERIFIABLE/CALIBRATION_UNSTABLE` | forgejo-kong: a Kong route matching the tool's random probe names (zqxv + hex) answers 404 with one of two JSON body shapes in turn | OK |
| `undocumented_versions/NOT_APPLICABLE/NO_VERSIONED_PATH` | forgejo-kong: the run reads a copy of Forgejo's specification with basePath /api/vlatest, so no segment has the form v<number> | OK |
| `undocumented_versions/NOT_APPLICABLE/NO_PATH_IN_GROUP` | not producible (code): a candidate version comes from a group that documents at least one operation (src/discovery/derivation.py, version_siblings), and since the sample accepts any method that operation is always found (the same pattern on the same documented paths) | - |
| `gateway_route_drift/ENFORCED/ROUTE_DOCUMENTED` | forgejo-kong: the lab as built: forgejo-api-route (/api) and forgejo-spec-route have documented paths, or the specification, under them | OK |
| `gateway_route_drift/VIOLATION/ROUTE_NOT_DOCUMENTED/CERTAIN` | forgejo-kong: the lab as built: hmac-audit-route (/hmac-audit-probe-not-a-real-path) has no documented path under it | OK |
| `gateway_route_drift/NOT_VERIFIABLE/ROUTE_NOT_READ` | forgejo-kong: a Kong route whose regular expression uses \p{L}, accepted by Kong and not compiled by Python's re | OK |
| `gateway_route_drift/NOT_APPLICABLE/ROUTE_DISABLED` | forgejo-apisix: hmac-audit-route given status 0 through APISIX's Admin API | OK |
| `gateway_route_drift/NOT_APPLICABLE/NO_GATEWAY` | forgejo-kong: the run's configuration has no gateway section | OK |
| `gateway_route_drift/NOT_APPLICABLE/ROUTES_NOT_SUPPORTED` | not producible (code): no adapter without routes exists | - |
| `gateway_route_drift/NOT_VERIFIABLE/CONCEPT_NOT_ACCESSIBLE` | forgejo-kong: the run's gateway.admin.url points to a closed port | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: the forgejo container stopped: Kong cannot reach the backend and answers 502/503 to the method and version probes | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: a Kong route on /api/v1/version answers 429 to PUT, PATCH, DELETE (undeclared there) | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | crapi-kong: the lab as built: crAPI's undeclared GET on /workshop/api/shop/orders answers 500 | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: a Kong route on /api/v1/version makes POST (undeclared) sleep 7 s, beyond the run's read timeout of 5 s | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("0.1", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- A service that refuses every unauthenticated request before it looks at the method (crAPI's identity: 401 to any
  path and any method) cannot be judged from outside: those cases are `NOT_VERIFIABLE`, and the sub-test's coverage
  becomes partial. Judging them would need a credential, which this test does not use (that is tests 1.1 and 2.1).
- `undocumented_versions` tries the neighbours of the documented versions, not every name a version could have, and
  probes one path per group: a version active on another path only is not seen. A version the specification does
  document, next to a newer one, is not its question (test 2.4 asks whether both enforce the same controls).
- On a path with parameters only an executed method (`2xx`, FIRM) or a refused one (`405`) is evidence: a handled
  method on an object that does not exist answers "not found" like an ignored one, so it is `NOT_VERIFIABLE`
 .
- `gateway_route_drift` compares paths, not methods: a route allowing more methods than the specification declares
  is seen by `undeclared_methods` instead.
- A method refused by an authentication before dispatch is not probed with a credential: sending an undeclared write as user_a could change data, so the case stays `REFUSED_BEFORE_METHOD`.

## 6. Sources

- OWASP API9:2023: https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management/
- CWE-912 Hidden Functionality: https://cwe.mitre.org/data/definitions/912.html
- ASVS 5.0.0 4.1.4: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x13-V4-API-and-Web-Service.md
- WSTG 4.2 CONF-06 Test HTTP Methods: https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods.md
- RFC 9110 §9.3.2 (HEAD), §15.5.6 (405): https://www.rfc-editor.org/rfc/rfc9110

## 7. Inputs

- **Specification:** the documented paths with their methods and the declared types of their parameters.
- **Derived knowledge** (Phase 2): `version_siblings`, the undocumented versions next to the documented ones
  (Forgejo `/api/v2`; crAPI `/identity/api/v1` and `v3`, `/identity/api/auth/v1` and `v5`, `/community/api/v1`
  and `v3`).
- **Gateway** (optional): the `routes` concept, through the adapter.
- **Configuration:** none. The operator's resources (`target.path_seed`) are deliberately not used: see Probes.

## 8. Outcomes

SKIP only when the attack surface is not available (an infrastructure error of Phase 2). Without a gateway the test
runs and `gateway_route_drift` is `NOT_APPLICABLE`.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("0.1")) ]]] -->

- "Undeclared method handled: <method> <path>"
- "Undeclared method known: <method> <path>"
- "Undocumented API version answers: <method> <path>"
- "Gateway route without documented paths: <name>"
- "TRACE enabled: <template>"

<!-- [[[end]]] -->

Each names the method and path, or the route; `evidence_ref` the answer, or the routes concept for a route.

## 10. Effects on the target

`STRESSES_TARGET`: on an API with many documented paths the method probes are its largest part (about five requests
per path). **It also changes data:** undeclared `POST`, `PUT`, `PATCH` and `DELETE` are sent, on random
non-existent identifiers for a path with parameters, and with an empty body on a path without them. Anything created is deleted at once, and what cannot be deleted is named in the result.
The run order puts this test after the read-only ones.

## 11. Per gateway

`gateway_route_drift` needs an adapter that reads routes (Kong, APISIX); on another gateway it is not applicable.
The other two sub-tests do not depend on the gateway.

## 12. Configuration

None: the test has no parameters and uses no prepared resource.

## 13. Remediation

Declare the method in the specification or block it at the gateway; remove an old version or document it; remove
gateway routes nothing documented uses.
