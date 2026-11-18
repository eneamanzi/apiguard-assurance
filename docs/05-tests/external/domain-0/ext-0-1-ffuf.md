# ext.0.1.ffuf Undocumented Paths Answer

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/external_tests/ext_test_0_1_undocumented_paths_ffuf.py`](../../../../src/external_tests/ext_test_0_1_undocumented_paths_ffuf.py), [`src/connectors/ffuf.py`](../../../../src/connectors/ffuf.py)

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

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 0.1) |
|---|---|
| `undocumented_paths` | path enumeration by fuzzing: implemented with ffuf; case and trailing-slash variants are applied by the tests that judge a control on the path (1.1) |

### 2.2 Preconditions and reference responses

Calibration (`src/core/references.py`), measured once per run and shared by every test:

- **each base path searched** is calibrated before its result is trusted: what an unknown path answers there. A base
  path that refuses an unknown path (401, 403) instead of reporting it missing hides its paths from an
  unauthenticated search, and is recorded `NOT_VERIFIABLE/SEARCH_BLIND` instead of counting as verified;
- **each undocumented candidate** is compared with random siblings under its parent; a point whose two random
  answers differ cannot judge.

No positive control: the test asks whether a path exists, not who may use it.

### 2.3 Probes

1. ffuf, one run per base path, unauthenticated `GET`, at `external_tools.ffuf.rate_limit_rps`, with its own
   calibration (`-ac`): one run over several base paths would calibrate once, while the services behind one gateway
   answer an unknown path differently (crAPI: identity 401, community and workshop 404 with different bodies).
2. Left out, listed in a note: a path matching a documented template (`/repos/a/b` for `/repos/{owner}/{repo}`), a
   parent of documented paths (`/api`), the specification's URL; on a base path where ffuf kept more than 100
   answers its calibration did not hold, and the base path is not verifiable.
3. Every remaining candidate: one `GET` by the test with the tool's client, judged against the calibration.

## 3. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("ext.0.1.ffuf")) ]]] -->

| Case | Outcome / detail | Confidence |
|---|---|---|
| the candidate answers unlike random siblings under its parent | `VIOLATION/UNDOCUMENTED_PATH` | FIRM |
| the candidate answers `404` or `410` in another shape (another component said not found) | `NOT_APPLICABLE/NOT_FOUND` | - |
| the candidate answers like a random sibling (a false positive of ffuf) | `NOT_APPLICABLE/LIKE_UNKNOWN` | - |
| the calibration of a base path or of a candidate's parent is unstable | `NOT_VERIFIABLE/CALIBRATION_UNSTABLE` | - |
| a base path answers an unknown path with `401`, `403` or a redirect: the search is blind there | `NOT_VERIFIABLE/SEARCH_BLIND` | - |
| ffuf kept more than 100 answers on one base path (its calibration did not hold) | `NOT_VERIFIABLE/TOOL_CALIBRATION_FAILED` | - |
| a base path was not searched to the end within the time limit | `NOT_VERIFIABLE/SEARCH_INCOMPLETE` | - |
| no violation, on at least one base path the search can tell | `ENFORCED/NO_UNDOCUMENTED_PATH` | - |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("ext.0.1.ffuf", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | judged by the oracle above: a `500` is compared with the calibration like any other answer: a path whose `500` differs from a random path's answer exists. |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 4. Validation

### 4.1 Oracle cases

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("ext.0.1.ffuf", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../../experiments/README.md), campaign at commit `fc60b6f`. 11 of 11 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `undocumented_paths/VIOLATION/UNDOCUMENTED_PATH/FIRM` | forgejo-kong: the lab as built: /api/healthz and /api/swagger answer 200 and are not in the specification | OK |
| `undocumented_paths/NOT_APPLICABLE/NOT_FOUND` | forgejo-kong: the lab as built: /api-doc and /api-docs reach Forgejo through Kong's prefix route /api and answer Forgejo's 404, unlike Kong's own 404 for a random root path | OK |
| `undocumented_paths/NOT_APPLICABLE/LIKE_UNKNOWN` | forgejo-kong: the lab as built: ffuf keeps /api-docs/v1/openapi.json, which on re-verification answers 404 like its random siblings | OK |
| `undocumented_paths/NOT_VERIFIABLE/CALIBRATION_UNSTABLE` | forgejo-kong: a temporary Kong route matching the tool's random probe names (zqxv<hex>) answers 404 with one of two body shapes in turn, so the calibration of every base path and candidate parent is unstable | OK |
| `undocumented_paths/NOT_VERIFIABLE/SEARCH_BLIND` | crapi-kong: the lab as built: /identity/api/ and /identity/api/v2/ answer 401 to an unknown path | OK |
| `undocumented_paths/NOT_VERIFIABLE/TOOL_CALIBRATION_FAILED` | forgejo-kong: a temporary Kong route /api/v1/ answers 200 with a random number of lines, so ffuf keeps more than 100 answers on that base path | OK |
| `undocumented_paths/NOT_VERIFIABLE/SEARCH_INCOMPLETE` | forgejo-kong: ffuf limited to 5 requests per second with the minimum time limit of 60 s: the root alone (about 500 words) needs about 100 s, so no base path is searched to the end | OK |
| `undocumented_paths/ENFORCED/NO_UNDOCUMENTED_PATH` | crapi-kong: the lab as built: no undocumented path among the lists on the eight base paths that can tell | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: a temporary Kong route GET ~/api/healthz$ lets ffuf's request through to Forgejo and answers the test's re-verification 503 | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: the same route answers the test's re-verification of /api/healthz 429 | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: the same route sleeps 7 s on the test's re-verification of /api/healthz, beyond the run's read timeout of 5 s | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("ext.0.1.ffuf", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- The search finds what the lists contain.
- A path that answers "not found" without a credential is not reported, even when it exists (an application that
  hides its endpoints behind a 404, as crAPI's dashboard does): without a credential nothing proves it.
- A service that answers every unauthenticated request the same way (crAPI's identity: 401 to any path) hides its
  paths from the search: ffuf is never given credentials. The result says so (`SEARCH_BLIND`) instead of claiming a
  clean search, and when no base path can tell, the sub-test is INCONCLUSIVE.
- ffuf's own requests are not TLS-verified (`InsecureSkipVerify` is hard-coded in ffuf): it sends no credentials,
  the run's TLS check verified the target, and every candidate is requested again with the verified client.
- Endpoints known only to a JavaScript front end need a crawler (not used).

## 6. Sources

- OWASP API9:2023: https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management/
- CWE-912 Hidden Functionality: https://cwe.mitre.org/data/definitions/912.html
- ASVS 5.0.0 13.4.5: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x22-V13-Configuration.md
- WSTG 4.2 CONF-04, CONF-05: https://github.com/OWASP/wstg/tree/v4.2/document/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing
- ffuf: https://github.com/ffuf/ffuf; SecLists: https://github.com/danielmiessler/SecLists

## 7. Inputs

- **Base paths** (one ffuf run each): the root, the service prefixes derived from the specification
  (`service_prefixes`: `/api` on Forgejo, `/identity/api`, `/community/api`, `/workshop/api` on crAPI) and the
  version directories of the documented paths (`/api/v1/`, `/identity/api/v2/`, ...).
- **Words** under every base path: SecLists `Discovery/Web-Content/common-api-endpoints-mazen160.txt` (174 API words)
  and the tool's 38 sensitive paths (`src/core/sensitive_paths.py`: Spring Boot Actuator, profilers, debuggers,
  status pages, API descriptions, `.env`, `.git`, each with its source); from the root also SecLists
  `Discovery/Web-Content/api/api-endpoints.txt` (285 whole paths); the user's list (`wordlist`), optional.
- **Specification:** the documented paths (to leave them out) and its own URL.

## 8. Outcomes

SKIP when ffuf is not installed or `external_tools.ffuf` is disabled; ERROR when the SecLists lists are missing
(`install_tools.sh` not run) or ffuf fails or reaches `timeout_seconds`, including during a search: ffuf stops
itself at its `-maxtime` with exit code 0 and a partial output, which is not a finished search with nothing found.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("ext.0.1.ffuf")) ]]] -->

- "Undocumented path answers: GET <path>"

<!-- [[[end]]] -->

`evidence_ref` the re-verification request; the tool's raw output is kept as an artifact.

## 10. Effects on the target

`STRESSES_TARGET`: thousands of unauthenticated `GET` requests at `rate_limit_rps` (default 30 per second), then one
`GET` per candidate. Nothing is created or changed.

## 11. Per gateway

Independent of the gateway: the calibration learns each service's "not found" (Kong's own 404, APISIX's, the
application's).

## 12. Configuration

<!-- [[[cog import generate_docs as g; cog.out(g.test_params("ext.0.1.ffuf", page=cog.inFile)) ]]] -->

Section [`tests.domain_0.ext_0_1_ffuf`](../../../03-reference/01-configuration.md#testsdomain_0ext_0_1_ffuf) of `config.yaml`:

| Key | Type | Default | Description |
|---|---|---|---|
| `wordlist` | string \| null | none | A list of the user's (one word or path per line), tried under every base path besides the default lists, e.g. Assetnote's `httparchive_apiroutes` for a deep search (364,056 paths: at 30 requests per second about 3.4 hours per base path). Relative to the working directory. |

<!-- [[[end]]] -->

`external_tools.ffuf` (`enabled`, `timeout_seconds`, `expected_version`, `wordlist_dir`, `per_request_timeout`,
`rate_limit_rps`) and `tests.domain_0.ext_0_1_ffuf.wordlist`: [configuration reference](../../../03-reference/01-configuration.md).
For a deep search, Assetnote's `httparchive_apiroutes` (364,056 paths, https://wordlists.assetnote.io/) as
`wordlist`: at 30 requests per second about 3.4 hours per base path.

## 13. Remediation

Document the path in the specification, or remove it; do not expose monitoring, debugging or documentation endpoints
that clients do not need.
