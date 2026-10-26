# ext.0.1.ffuf Undocumented Paths Answer

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-21) ·
> **Source of truth:**
> [`src/external_tests/ext_test_0_1_undocumented_paths_ffuf.py`](../../../../src/external_tests/ext_test_0_1_undocumented_paths_ffuf.py),
> [`src/connectors/ffuf.py`](../../../../src/connectors/ffuf.py) · **Verified:** 2026-10-21

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("ext.0.1.ffuf", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `ext.0.1.ffuf` |
| Name | Undocumented Paths Answer (ffuf path search, re-verified) |
| Domain | 0 - API Discovery and Inventory Management |
| Priority / strategy | P0 / BLACK_BOX |
| Effect | STRESSES_TARGET |
| CWE | CWE-912 |
| Standards | `OWASP API9:2023`, `OWASP ASVS v5.0.0-13.4.5`, `OWASP WSTG-v42-CONF-04`, `OWASP WSTG-v42-CONF-05` |
| Tags | `inventory`, `shadow-api` |
| Prerequisites | none |
| Needs | - |
| Parameters | [`tests.domain_0.ext_0_1_ffuf`](../../../03-reference/01-configuration.md#testsdomain_0ext_0_1_ffuf) |
| Tool | `ffuf` ([`external_tools.ffuf`](../../../03-reference/01-configuration.md#external_tools)) |

<!-- [[[end]]] -->

**Tools:** ffuf 2.3.0 and SecLists 2026.1 (pinned by `install_tools.sh`). **Same guarantee:** test `0.1`
(undeclared methods, undocumented versions, gateway routes).

## 1. Guarantee

Every endpoint that answers behind the gateway is documented in the OpenAPI specification (OWASP API9:2023): an
undocumented path escapes review, rate limiting and authentication policies. This test searches for undocumented
paths. A PASS promises that none of the paths tried answered unlike an unknown one; it does not promise that no
other undocumented path exists, nor anything about what a path does: whether it requires a credential is test
1.1, whether it shows credentials test 6.4, whether the gateway forwards paths it has no route for test 0.2.

ASVS v5.0.0-13.4.5 (L2): documentation and monitoring endpoints are not exposed unless explicitly intended.

## 2. Sub-tests

| Sub-test | Methodology (guarantee 0.1) |
|---|---|
| `undocumented_paths` | path enumeration by fuzzing: implemented with ffuf; case and trailing-slash variants are applied by the tests that judge a control on the path (1.1) |

## 3. Inputs

- **Base paths** (one ffuf run each): the root, the service prefixes derived from the specification
  (`service_prefixes`: `/api` on Forgejo, `/identity/api`, `/community/api`, `/workshop/api` on crAPI) and the
  version directories of the documented paths (`/api/v1/`, `/identity/api/v2/`, ...).
- **Words** under every base path: SecLists `Discovery/Web-Content/common-api-endpoints-mazen160.txt` (174 API words)
  and the tool's 35 sensitive paths (`src/core/sensitive_paths.py`: Spring Boot Actuator, profilers, debuggers,
  status pages, API descriptions, `.env`, `.git`, each with its source); from the root also SecLists
  `Discovery/Web-Content/api/api-endpoints.txt` (285 whole paths); the user's list (`wordlist`), optional.
- **Specification:** the documented paths (to leave them out) and its own URL.

## 4. Preconditions and reference responses

Calibration (`src/core/references.py`), measured once per run and shared by every test:

- **each base path searched** is calibrated before its result is trusted: what an unknown path answers there. A base
  path that refuses an unknown path (401, 403) instead of reporting it missing hides its paths from an
  unauthenticated search, and is recorded `NOT_VERIFIABLE/SEARCH_BLIND` instead of counting as verified;
- **each undocumented candidate** is compared with random siblings under its parent; a point whose two random
  answers differ cannot judge.

No positive control: the test asks whether a path exists, not who may use it.

## 5. Probes

1. ffuf, one run per base path, unauthenticated `GET`, at `external_tools.ffuf.rate_limit_rps`, with its own
   calibration (`-ac`): one run over several base paths would calibrate once, while the services behind one gateway
   answer an unknown path differently (crAPI: identity 401, community and workshop 404 with different bodies).
2. Left out, listed in a note: a path matching a documented template (`/repos/a/b` for `/repos/{owner}/{repo}`), a
   parent of documented paths (`/api`), the specification's URL; on a base path where ffuf kept more than 100
   answers its calibration did not hold, and the base path is not verifiable.
3. Every remaining candidate: one `GET` by the test with the tool's client, judged against the calibration.

## 6. Oracle

| Case | Outcome / detail | Confidence |
|---|---|---|
| the candidate answers unlike its unknown siblings | `VIOLATION/UNDOCUMENTED_PATH` | FIRM: it exists; it may be harmless |
| it answers "not found" (404, 410) in another shape: another component said it (Kong's route `/api` also matches `/api-docs`, which Forgejo answers 404) | `NOT_APPLICABLE/NOT_FOUND` | - |
| it answers like an unknown sibling (a false positive of ffuf) | `NOT_APPLICABLE/LIKE_UNKNOWN` | - |
| the calibration is unstable | `NOT_VERIFIABLE/CALIBRATION_UNSTABLE` | - |
| unavailable, rate limited, no response | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE`, `RATE_LIMITED`, `NO_RESPONSE` | - |
| more than 100 answers kept by ffuf on one base path | `NOT_VERIFIABLE/TOOL_CALIBRATION_FAILED` | - |
| a base path refuses an unknown path (401, 403): the search is blind there | `NOT_VERIFIABLE/SEARCH_BLIND` | - |
| the search ended with no violation, on at least one base path that could tell | `ENFORCED/NO_UNDOCUMENTED_PATH` | - |

## 7. Outcomes

SKIP when ffuf is not installed or `external_tools.ffuf` is disabled; ERROR when the SecLists lists are missing
(`install_tools.sh` not run) or ffuf fails or reaches `timeout_seconds`.

## 8. Findings

One per undocumented path: "Undocumented path answers: GET `<path>`", the status and its category, the calibration
pattern; `evidence_ref` the test's own request, `supporting_refs` the calibration probes.

## 9. Effects on the target

`STRESSES_TARGET`: thousands of unauthenticated `GET` requests at `rate_limit_rps` (default 30 per second), then one
`GET` per candidate. Nothing is created or changed.

## 10. Per gateway

Independent of the gateway: the calibration learns each service's "not found" (Kong's own 404, APISIX's, the
application's).

## 11. Configuration

`external_tools.ffuf` (`enabled`, `timeout_seconds`, `expected_version`, `wordlist_dir`, `per_request_timeout`,
`rate_limit_rps`) and `tests.domain_0.ext_0_1_ffuf.wordlist`: [configuration reference](../../../03-reference/01-configuration.md).
For a deep search, Assetnote's `httparchive_apiroutes` (364,056 paths, https://wordlists.assetnote.io/) as
`wordlist`: at 30 requests per second about 3.4 hours per base path.

## 12. Validation

Runs of 2026-10-22, the two tests of the guarantee together (ffuf 2.3.0, SecLists 2026.1, 30 requests per
second); every lab healthy afterwards:

| Lab | Base paths | Status | Basis |
|---|---|---|---|
| Forgejo + Kong | 3 (`/`, `/api/`, `/api/v1/`), 36 s | FAIL, 2 findings | `/api/healthz` (200, Forgejo's health endpoint) and `/api/swagger` (200, its Swagger page): neither is in the specification (`basePath /api/v1`); `/api-doc` and `/api-docs` reach Forgejo through Kong's prefix route `/api` and answer 404: not found |
| Forgejo + APISIX | 3, 37 s | FAIL, 2 findings | the same two paths (APISIX matches `/api/*` by segment: `/api-docs` gets APISIX's own 404) |
| crAPI + Kong | 10 (the root, three service prefixes, six version directories), 83 s | PASS **partial**: 2 `SEARCH_BLIND` | no undocumented path among the lists on the eight base paths that can tell; `/identity/api/` and `/identity/api/v2/` answer 401 to an unknown path, so the search is blind there and the result says so |
| any | - | INCONCLUSIVE | a target whose answers cannot be calibrated, or unavailable: not seen on the labs |

Each finding points to the test's own request and to the two calibration probes of its parent; the labs were
healthy after the runs.

**What each branch has been seen doing** (rule 9). Proven on a lab: `UNDOCUMENTED_PATH`, `NOT_FOUND`,
`LIKE_UNKNOWN`, `SEARCH_BLIND` (crAPI's identity) and `TOOL_CALIBRATION_FAILED` (on 2026-10-21, before the whole
paths of the list were routed to their own base path, ffuf kept 212 answers on Forgejo's root). Still unproven:
`CALIBRATION_UNSTABLE` (the mechanism itself is verified in `src/core/references.py`) and the transport reasons.

## 13. Remediation

Document the path in the specification, or remove it; do not expose monitoring, debugging or documentation endpoints
that clients do not need.

## 14. Limitations

- The search finds what the lists contain.
- A path that answers "not found" without a credential is not reported, even when it exists (an application that
  hides its endpoints behind a 404, as crAPI's dashboard does): without a credential nothing proves it.
- A service that answers every unauthenticated request the same way (crAPI's identity: 401 to any path) hides its
  paths from the search: ffuf is never given credentials. The result says so (`SEARCH_BLIND`) instead of claiming a
  clean search, and when no base path can tell, the sub-test is INCONCLUSIVE.
- ffuf's own requests are not TLS-verified (`InsecureSkipVerify` is hard-coded in ffuf): it sends no credentials,
  the run's TLS check verified the target, and every candidate is requested again with the verified client.
- Endpoints known only to a JavaScript front end need a crawler (not used).

## 15. Sources

- OWASP API9:2023: https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management/
- CWE-912 Hidden Functionality: https://cwe.mitre.org/data/definitions/912.html
- ASVS 5.0.0 13.4.5: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md
- WSTG 4.2 CONF-04, CONF-05: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing
- ffuf: https://github.com/ffuf/ffuf; SecLists: https://github.com/danielmiessler/SecLists
