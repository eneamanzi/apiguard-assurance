# 2.4 Authorization Consistency

> **Audience:** analysts, contributors · **Source of truth:**
> [`src/tests/domain_2/test_2_4_authorization_consistency.py`](../../../src/tests/domain_2/test_2_4_authorization_consistency.py), [`src/discovery/derivation.py`](../../../src/discovery/derivation.py)

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("2.4", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `2.4` |
| Name | Authorization Consistency |
| Domain | 2 - Authorization and Access Control |
| Priority / strategy | P1 / BLACK_BOX |
| Effect | READ_ONLY |
| CWE | CWE-285 |
| Standards | `OWASP API9:2023`, `OWASP API8:2023`, `OWASP ASVS v5.0.0-6.3.4`, `CWE-288`, `NIST SP 800-53r5, Section 3.1` |
| Tags | `authorization`, `consistency` |
| Prerequisites | none |
| Needs | - |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `2.1`, `2.2`, `2.5` (authorization).

## 1. Guarantee

An older or alternative version of an operation enforces the same authorization as the documented one. A PASS
promises that no version sibling served, without a credential, a request the documented operation refuses. The
threat (OWASP API8:2023) is a versioning drift: `GET /api/v2/users/{id}` requires a credential, the new or old
`/api/v3/users/{id}` forgets the check. ASVS v5.0.0-8.1.1 (one access-control policy, enforced the same everywhere).

## 2. Test

### 2.1 Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 2.4) |
|---|---|
| `version_sibling_consistent` | "versioned endpoint parity: for each v1 endpoint requiring auth, test v2/v3 without a token, expect 401" |
| left out | alternate-format parity (`.json`/`.xml`) and alias endpoints (no lab exposes them); GraphQL-vs-REST parity (no GraphQL) |

### 2.2 Preconditions and reference responses

The attack surface must be present. The reference is the documented operation itself: the same unauthenticated
request is sent to it and to the sibling, so the violation is proven by contrast (the documented one refuses, the
sibling serves) rather than by the heuristic alone.

### 2.3 Probes

For each version candidate, up to three of its siblings are probed first: when all of them answer `404`, the version
is taken as absent, one `NOT_APPLICABLE` instead of a probe per endpoint (one `404` could be one operation the version
lacks, not the version). Where the version exists, each protected operation is compared:
the documented path without a credential, then the sibling without a credential. Safe methods only. READ_ONLY.

## 3. Oracle (`version_sibling_consistent`)

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("2.4")) ]]] -->

| Case | Outcome / detail | Confidence |
|---|---|---|
| the documented operation refuses an anonymous request and its version sibling serves it (`2xx`), unlike a random path under that version | `VIOLATION/VERSION_DROPS_AUTH` | CERTAIN |
| the same, the random path's answer unreliable | `VIOLATION/VERSION_DROPS_AUTH` | FIRM |
| the sibling is served exactly as a random path under its version (a catch-all) | `NOT_VERIFIABLE/SERVED_LIKE_UNKNOWN` | - |
| both refuse, and a random path under the sibling's version is not refused alike | `ENFORCED/SIBLING_REFUSED` | - |
| the sibling is refused exactly as a random path under its version | `NOT_VERIFIABLE/REFUSED_BEFORE_ROUTING` | - |
| the sibling is refused and a random path under its version answers unstably | `NOT_VERIFIABLE/CALIBRATION_UNSTABLE` | - |
| the documented operation answers neither `2xx` nor a refusal (`404`, ...) | `NOT_VERIFIABLE/DOCUMENTED_NOT_JUDGEABLE` | - |
| the sibling's answer is `REDIRECT` | `NOT_VERIFIABLE/REDIRECT` | - |
| the sibling's answer is `METHOD_NOT_ALLOWED` | `NOT_VERIFIABLE/METHOD_NOT_ALLOWED` | - |
| the sibling's answer is `INVALID_REQUEST` | `NOT_VERIFIABLE/INVALID_REQUEST` | - |
| the sibling's answer is `OTHER` | `NOT_VERIFIABLE/OTHER` | - |
| the documented operation is served without a credential | `NOT_APPLICABLE/DOCUMENTED_NOT_PROTECTED` | - |
| the sibling answers `404` | `NOT_APPLICABLE/SIBLING_ABSENT` | - |
| up to three siblings answer `404` while their documented operation does not, and none answers otherwise | `NOT_APPLICABLE/VERSION_ABSENT` | - |
| no safe operation has a version sibling | `NOT_APPLICABLE/NO_VERSION_SIBLING` | - |

<!-- [[[end]]] -->

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("2.4", page=cog.inFile)) ]]] -->

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

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_validation("2.4", page=cog.inFile)) ]]] -->

Every case of the oracle, produced on a lab and judged by the code: E1, [oracle validation](../../../experiments/README.md), campaign at commit `fc60b6f`. 19 of 19 produced cases gave the declared outcome; 0 no lab can produce.

| Case | Lab, how it is produced | Result |
|---|---|---|
| `version_sibling_consistent/VIOLATION/VERSION_DROPS_AUTH/CERTAIN` | forgejo-kong: the v2 forwarding to v1, and a temporary route GET ~/api/v2/user$ answering 200 without a credential while GET /api/v1/user refuses 401 and a random path under /api/v2 gets Forgejo's 404 | OK |
| `version_sibling_consistent/VIOLATION/VERSION_DROPS_AUTH/FIRM` | forgejo-kong: the same served GET ~/api/v2/user$, with a route answering the random probe names (zqxv + hex) 404 with one of two body shapes in turn, so the random path under /api/v2 is unreliable | OK |
| `version_sibling_consistent/NOT_VERIFIABLE/SERVED_LIKE_UNKNOWN` | forgejo-kong: a temporary prefix route /api/v2 answering 200 with one fixed body to every request, so each sibling is served exactly as a random path under /api/v2 | OK |
| `version_sibling_consistent/ENFORCED/SIBLING_REFUSED` | forgejo-kong: the v2 forwarding to v1 (a service url http://forgejo-upstream/api/v1, route /api/v2, strip_path true): the v2 siblings refuse 401 like v1, while a random path under /api/v2 gets Forgejo's 404 | OK |
| `version_sibling_consistent/NOT_VERIFIABLE/REFUSED_BEFORE_ROUTING` | crapi-kong: the lab as built: the v1 and v3 siblings of the protected identity operations answer 401 exactly as a random path under /identity/api/v1/ and /v3/ | OK |
| `version_sibling_consistent/NOT_VERIFIABLE/CALIBRATION_UNSTABLE` | forgejo-kong: the v2 forwarding to v1, and a route matching the random probe names (zqxv + hex) answering 404 with one of two body shapes in turn | OK |
| `version_sibling_consistent/NOT_VERIFIABLE/DOCUMENTED_NOT_JUDGEABLE` | crapi-kong: the lab as built: the two community operations answer 404 with the seeded identifiers | OK |
| `version_sibling_consistent/NOT_VERIFIABLE/REDIRECT` | forgejo-kong: the v2 forwarding to v1, and a route GET ~/api/v2/user/repos$ answering 302 to https://localhost:8443/ itself (GET /api/v1/user/repos refuses 401) | OK |
| `version_sibling_consistent/NOT_VERIFIABLE/METHOD_NOT_ALLOWED` | forgejo-kong: the v2 forwarding to v1, and a route GET ~/api/v2/user/repos$ answering 405 itself | OK |
| `version_sibling_consistent/NOT_VERIFIABLE/INVALID_REQUEST` | forgejo-kong: the v2 forwarding to v1, and a route GET ~/api/v2/user/repos$ answering 400 itself | OK |
| `version_sibling_consistent/NOT_VERIFIABLE/OTHER` | forgejo-kong: the v2 forwarding to v1, and a route GET ~/api/v2/user/repos$ answering 418 itself (OTHER in response_category.py) | OK |
| `version_sibling_consistent/NOT_APPLICABLE/DOCUMENTED_NOT_PROTECTED` | forgejo-kong: the v2 forwarding to v1: the documented reads Forgejo serves without a credential | OK |
| `version_sibling_consistent/NOT_APPLICABLE/SIBLING_ABSENT` | forgejo-kong: the v2 forwarding to v1, and a route GET ~/api/v2/user/repos$ answering 404 itself | OK |
| `version_sibling_consistent/NOT_APPLICABLE/VERSION_ABSENT` | forgejo-kong: the lab as built: Forgejo documents only /api/v1, and three /api/v2 siblings answer 404 while their v1 operation does not | OK |
| `version_sibling_consistent/NOT_APPLICABLE/NO_VERSION_SIBLING` | forgejo-kong: the run reads a copy of Forgejo's specification with basePath /api/vlatest, so no documented path has a version segment and no sibling is derived | OK |
| `*/NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` | forgejo-kong: the forgejo container stopped (the specification read from a copy taken before): Kong answers 502/503 to the documented operations | OK |
| `*/NOT_VERIFIABLE/RATE_LIMITED` | forgejo-kong: the v2 forwarding to v1, and a route GET ~/api/v2/user/repos$ answering 429 itself | OK |
| `*/NOT_VERIFIABLE/SERVER_ERROR` | forgejo-kong: the v2 forwarding to v1, and a route GET ~/api/v2/user/repos$ answering 500 itself | OK |
| `*/NOT_VERIFIABLE/NO_RESPONSE` | forgejo-kong: the v2 forwarding to v1, and a route GET ~/api/v2/user/repos$ sleeping 7 s, past the run's read timeout of 5 s | OK |

<!-- [[[end]]] -->

### 4.2 Results on the labs

<!-- [[[cog import generate_docs as g; cog.out(g.lab_results("2.4", page=cog.inFile)) ]]] -->

No E2 campaign yet ([experiments](../../../experiments/README.md)).

<!-- [[[end]]] -->

## 5. Limitations

- Only version siblings are compared; alternate formats, aliases and GraphQL are out of scope (no lab exposes them).
- A sibling that needs a path parameter the seed does not supply may answer `404` and read as absent.
- The check is unauthenticated: a version that enforces authentication but drops a finer role check is not caught
  here (that is 2.1's question on the sibling, if it is documented).

## 6. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- OWASP ASVS v5.0.0-8.1.1 (Authorization documentation and enforcement): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md
- NIST SP 800-53 Rev.5 AC-3 (access enforcement): https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home
- CWE-285 Improper Authorization: https://cwe.mitre.org/data/definitions/285.html

## 7. Inputs

The version siblings derived in Phase 2 (`version_siblings`: the undocumented API versions next to the documented
ones). For each documented protected safe-method operation, the sibling path is built by swapping its version
segment. No configuration, no credential.

## 8. Outcomes

SKIP when no protected operation has a version sibling, and when every candidate version the specification
suggests is absent from the target: in that second case the test adds the note "No second version to compare",
naming the candidate it probed, so the SKIP is not silent. Otherwise FAIL on a version that drops the check, PASS
when every existing sibling enforces the same policy.

## 9. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("2.4")) ]]] -->

- "Version sibling drops the authorization check: <method> <sib_path>"

<!-- [[[end]]] -->

`evidence_ref` the sibling's answer; `supporting_refs` the random path's calibration when it decided.

## 10. Effects on the target

`READ_ONLY`: unauthenticated safe requests, nothing changed.

## 11. Per gateway

Independent of the adapter: a version drift is usually a duplicate or misaligned gateway route; the probe observes
it from outside.

## 12. Configuration

None. The siblings are derived; the configuration adds nothing here.

## 13. Remediation

Apply one authorization policy to every version of an operation, or retire the undocumented versions; a gateway
route for an old version must carry the same auth plugin as the current one (ASVS v5.0.0-8.1.1).
