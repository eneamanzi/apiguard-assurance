# 0.1 Undeclared Methods, Undocumented Versions and Gateway Route Drift

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-21) ·
> **Source of truth:**
> [`src/tests/domain_0/test_0_1_shadow_api_discovery.py`](../../../src/tests/domain_0/test_0_1_shadow_api_discovery.py) ·
> **Verified:** 2026-10-21

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

## 2. Sub-tests and coverage of the methodology

| Methodology sub-test (guarantee 0.1) | Sub-test | Coverage |
|---|---|---|
| Path enumeration by fuzzing | - | `ext.0.1.ffuf` |
| HTTP method discovery | `undeclared_methods` | every documented path, every method of `GET, POST, PUT, PATCH, DELETE` the specification does not declare for it (`HEAD` is implied by `GET`, RFC 9110 §9.3.2) |
| Versioning completeness | `undocumented_versions` | the versions next to the documented ones, from the derivation rule `version_siblings`, each probed with a method the specification declares on the path it lends; whether two **documented** versions enforce the same controls is test 2.4 |
| Documentation drift via the Admin API | `gateway_route_drift` | the gateway's routes against the documented paths, when a gateway is configured (optional need) |

## 3. Inputs

- **Specification:** the documented paths with their methods and the declared types of their parameters.
- **Derived knowledge** (Phase 2): `version_siblings`, the undocumented versions next to the documented ones
  (Forgejo `/api/v2`; crAPI `/identity/api/v1` and `v3`, `/identity/api/auth/v1` and `v5`, `/community/api/v1`
  and `v3`).
- **Gateway** (optional): the `routes` concept, through the adapter.
- **Configuration:** none. The operator's resources (`target.path_seed`) are deliberately not used: see Probes.

## 4. Preconditions and reference responses

- **How the target refuses an unsupported method** is learned, not assumed: before probing a path, the test asks it
  with `APIGUARDPROBE`, a method no API implements and no server can act on. That answer is the path's reference.
  The run logs each one (`test_0_1_method_reference`) and the result carries a note counting them, so that the
  report says what the target answers.
- **Calibration** (`src/core/references.py`) for `undocumented_versions`: a version answers when it answers unlike
  random siblings under the same parent.
- **No positive control:** the test asks whether something exists, not who may use it.

## 5. Probes

- **`undeclared_methods`,** per documented path: one `APIGUARDPROBE` (the reference), then each undeclared method.
  - a path with parameters is probed on random values of each parameter's declared type, never on the operator's
    resources (`path_seed`): the question is whether the endpoint knows the method, which a non-existent object
    answers just as well (a handled method says "not found", an unsupported one is refused), and nothing real can be
    changed;
  - a path without parameters is probed as it is, with an empty JSON body for `POST`, `PUT`, `PATCH`;
  - anything a handled write creates (a `2xx` with `Location`, or an accepted `PUT`) is deleted at once; what cannot
    be deleted is named in a note of the result.
- **`undocumented_versions`:** one request per derived candidate. The path probed is chosen by a stated rule: of
  that version group, a `GET` path first (read-only), a path of any documented method otherwise, preferring one
  without parameters and then the shortest; a method with a body is sent with an empty one. Probing `GET` only left
  a group whose every path is a `POST` unverifiable (crAPI's `/identity/api/auth/`).
- **`gateway_route_drift`:** no request to the API; the gateway's routes read through the adapter.

## 6. Oracle

**`undeclared_methods`** (one judgement per path and method):

| Case | Outcome / detail | Confidence |
|---|---|---|
| `METHOD_NOT_ALLOWED` (405, 501), the standard refusal | `ENFORCED/METHOD_REJECTED` | - |

| the same answer as the same method on random siblings, and that answer is a refusal of the request itself (401, 403): the target did not look at the method | `NOT_VERIFIABLE/REFUSED_BEFORE_ROUTING` | - |
| the same answer as the same method on random siblings | `ENFORCED/METHOD_NOT_SERVED` | - |
| `SERVED` (2xx): the method was executed | `VIOLATION/UNDECLARED_METHOD_HANDLED` | CERTAIN: the observed behaviour |
| a different answer from the same method on random siblings | `VIOLATION/UNDECLARED_METHOD_KNOWN` | FIRM: it rests on the assumption that a different answer means the endpoint knows the method |
| unavailable, rate limited, server error, no response | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE`, `RATE_LIMITED`, `SERVER_ERROR`, `NO_RESPONSE` | - |

**`undocumented_versions`:**

| Case | Outcome / detail | Confidence |
|---|---|---|
| answers unlike the random siblings of its parent | `VIOLATION/UNDOCUMENTED_VERSION` | TENTATIVE: the candidate comes from a heuristic rule |
| answers like an unknown sibling, or `NOT_FOUND` | `ENFORCED/VERSION_ABSENT` | - |
| no documented path carries a version segment | `NOT_APPLICABLE/NO_VERSIONED_PATH` | - |
| the version group documents no operation | `NOT_APPLICABLE/NO_PATH_IN_GROUP` | - |
| calibration unstable, or a spoiling answer | `NOT_VERIFIABLE/CALIBRATION_UNSTABLE`, `NOT_VERIFIABLE/<category>` | - |

**`gateway_route_drift`:**

| Case | Outcome / detail | Confidence |
|---|---|---|
| an enabled route with a path under which no documented operation (nor the specification) falls | `VIOLATION/ROUTE_NOT_DOCUMENTED` | CERTAIN: the configuration read |
| an enabled route whose every path covers documented operations, or is their parent | `ENFORCED/ROUTE_DOCUMENTED` | - |
| a disabled route | `NOT_APPLICABLE/ROUTE_DISABLED` | - |
| no gateway configured | `NOT_APPLICABLE/NO_GATEWAY` | - |
| the gateway does not expose its routes | `NOT_APPLICABLE/ROUTES_NOT_SUPPORTED` | - |
| the routes could not be read | `NOT_VERIFIABLE/ROUTES_NOT_READABLE` | - |

How a route path matches (prefix, exact, regular expression) is the adapter's answer, not this test's guess: each
adapter translates its gateway's own syntax (Kong writes a regular expression as `~<expression>`, APISIX a prefix as
`<path>*`) into the neutral vocabulary of the `routes` concept. A gateway with another syntax needs only its
adapter.

## 7. Outcomes

SKIP only when the attack surface is not available (an infrastructure error of Phase 2). Without a gateway the test
runs and `gateway_route_drift` is `NOT_APPLICABLE`.

## 8. Findings

One per path and undeclared method, per undocumented version, per route without documentation. Each carries its
proof: the test's own request (`evidence_ref`), the calibration probes for a version (`supporting_refs`), the
routes read for a route.

## 9. Effects on the target

`STRESSES_TARGET`: on an API with many documented paths the method probes are its largest part (about five requests
per path). **It also changes data:** undeclared `POST`, `PUT`, `PATCH` and `DELETE` are sent, on random
non-existent identifiers for a path with parameters, and with an empty body on a path without them. Anything created is deleted at once, and what cannot be deleted is named in the result.
The run order puts this test after the read-only ones.

## 10. Per gateway

`gateway_route_drift` needs an adapter that reads routes (Kong, APISIX); on another gateway it is not applicable.
The other two sub-tests do not depend on the gateway.

## 11. Configuration

None: the test has no parameters and uses no prepared resource.

## 12. Validation

Runs of 2026-10-22, the two tests of the guarantee together; every lab healthy afterwards and its test
resources intact.

| Lab | Sub-test | Result | Basis |
|---|---|---|---|
| Forgejo + Kong | `undeclared_methods` | PASS partial (1046 enforced: 907 `METHOD_REJECTED`, 139 `METHOD_NOT_SERVED`; 1 `REFUSED_BEFORE_ROUTING`) | Forgejo refuses an undeclared method with 405, or answers it exactly as it answers an unknown path; on one path it answers 401 to both, which proves nothing |
| Forgejo + Kong | `undocumented_versions` | PASS complete | `/api/v2/orgs` (the only candidate: Forgejo documents `v1` alone) answers as an unknown path |
| Forgejo + Kong | `gateway_route_drift` | **FAIL**, 1 finding | the lab's route `/hmac-audit-probe-not-a-real-path` (added for test 3.3) has no documented path under it: a true drift |
| Forgejo + APISIX | all three | the same as Forgejo + Kong | only the gateway changes |
| crAPI + Kong, identity service | `undeclared_methods` | the honest limit | a service that refuses every unauthenticated request before it looks at the method cannot be judged from outside: its 47 paths are reported as not verified, and the sub-test's coverage says so |
| crAPI + Kong | `undeclared_methods` | **FAIL**, 1 finding; 107 enforced, 48 not verifiable | `PUT /workshop/api/shop/orders` answers `401 "JWT Token required!"` while `PUT` on random paths under `/workshop/api/shop/` gets the router's 404: the endpoint knows `PUT`, which the specification does not declare (FIRM). The 47 paths of the identity service answer 401 to any method, exactly as their random siblings do: `REFUSED_BEFORE_ROUTING`, not enforced. An undeclared `GET` on the orders path answers 500: `NOT_VERIFIABLE/SERVER_ERROR` |
| crAPI + Kong | `undocumented_versions` | PASS complete (6 probed) | `/identity/api/v1`, `/v3`, `/community/api/v1`, `/v3` (GET) and `/identity/api/auth/v1`, `/v5` (POST `check-otp`, the group's only method) answer as unknown paths |
| crAPI + Kong | `gateway_route_drift` | **FAIL**, 1 finding | the same lab route as the Forgejo labs |
| any | not verifiable | INCONCLUSIVE | a target whose answers cannot be calibrated: not seen on the labs |

Request volume (the method probes are almost all of it): about 1350 on Forgejo (304 documented paths), 200 on
crAPI (40). The calibration points are measured once per run and reused across tests, paths and methods: 126 on
Forgejo, 41 on crAPI (both tests of the guarantee together).

**What each branch has been seen doing** (rule 9). Proven on a lab: `METHOD_REJECTED`, `METHOD_NOT_SERVED`,
`REFUSED_BEFORE_ROUTING` (crAPI's identity), `UNDECLARED_METHOD_KNOWN` (crAPI's `PUT`), `SERVER_ERROR`,
`VERSION_ABSENT`, `NO_PATH_IN_GROUP` (before the rule was widened to any documented method),
`ROUTE_DOCUMENTED`, `ROUTE_NOT_DOCUMENTED`, and with a configuration of its own `NO_GATEWAY` (the test runs, the
sub-test is not applicable) and `ROUTES_NOT_READABLE` (an Admin API address where nothing answers).
Proven with a temporary change to the Forgejo + Kong lab's gateway (2026-10-22, below):
`UNDECLARED_METHOD_HANDLED` on four methods with the removal of what the accepted `PUT` created, and
`UNDOCUMENTED_VERSION`. Still unproven: `CALIBRATION_UNSTABLE` (the mechanism itself is verified in
`src/core/references.py`), `ROUTE_DISABLED` (no Kong route can be disabled; APISIX's can) and
`ROUTES_NOT_SUPPORTED` (no adapter without routes exists).

### Seeing the two cases the labs do not produce

Add this to `test-environments/forgejo-kong/kong/kong.yml`, at the end of `services:`. The
[`request-termination`](https://developer.konghq.com/plugins/request-termination/) plugin answers on the route
without reaching Forgejo, so nothing of the application is touched.

```yaml
  - name: review-probe-dummy
    url: http://forgejo-upstream
    connect_timeout: 5000
    read_timeout: 30000
    write_timeout: 30000
    routes:
      # A documented path (GET only in the specification) answers 200 to every method.
      - name: review-served-method-route
        paths: [/api/v1/version]
        strip_path: false
        protocols: [https]
        plugins:
          - name: request-termination
            config: { status_code: 200, content_type: "application/json", body: '{"review":"served"}' }
      # One undocumented version answers, while its random siblings reach Forgejo and get its 404.
      - name: review-undocumented-version-route
        paths: ['~/api/v2/orgs$']
        strip_path: false
        protocols: [https]
        plugins:
          - name: request-termination
            config: { status_code: 200, content_type: "application/json", body: '{"review":"v2"}' }
```

Load it, run the test, then undo it (from `test-environments/forgejo-kong`):

```bash
docker compose --env-file ../../.env up -d --force-recreate --wait kong
cd ../.. && hatch run apiguard run -c test-environments/forgejo-kong/config.yaml
git checkout test-environments/forgejo-kong/kong/kong.yml
cd test-environments/forgejo-kong && docker compose --env-file ../../.env up -d --force-recreate --wait kong
```

Expected: `undeclared_methods` FAIL with four findings (`POST`, `PUT`, `PATCH`, `DELETE` on `/api/v1/version`,
CERTAIN; the accepted `PUT` is followed by the test's own `DELETE`, which the plugin answers 200, so nothing is
reported as left behind); `undocumented_versions` FAIL with one finding (`GET /api/v2/orgs`, TENTATIVE);
`gateway_route_drift` FAIL with two findings (the lab's hmac route and the regular-expression route added here,
which matches no documented path). After undoing it, the test is back to one finding.

## 13. Remediation

Declare the method in the specification or block it at the gateway; remove an old version or document it; remove
gateway routes nothing documented uses.

## 14. Limitations

- A service that refuses every unauthenticated request before it looks at the method (crAPI's identity: 401 to any
  path and any method) cannot be judged from outside: those cases are `NOT_VERIFIABLE`, and the sub-test's coverage
  becomes partial. Judging them would need a credential, which this test does not use (that is tests 1.1 and 2.1).
- `undocumented_versions` tries the neighbours of the documented versions, not every name a version could have, and
  probes one path per group: a version active on another path only is not seen. A version the specification does
  document, next to a newer one, is not its question (test 2.4 asks whether both enforce the same controls).
- A handled method on a path with parameters answers "not found" rather than succeeding, so it is reported with
  confidence FIRM, not CERTAIN: the proof is the difference from an unsupported method, not an executed operation.
- `gateway_route_drift` compares paths, not methods: a route allowing more methods than the specification declares
  is seen by `undeclared_methods` instead.

## 15. Sources

- OWASP API9:2023: https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management/
- CWE-912 Hidden Functionality: https://cwe.mitre.org/data/definitions/912.html
- ASVS 5.0.0 4.1.4: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x13-V4-API-and-Web-Service.md
- WSTG 4.2 CONF-06 Test HTTP Methods: https://github.com/OWASP/wstg/blob/v4.2/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods.md
- RFC 9110 §9.3.2 (HEAD), §15.5.6 (405): https://www.rfc-editor.org/rfc/rfc9110
