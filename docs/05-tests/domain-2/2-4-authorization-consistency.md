# 2.4 Authorization Consistency

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_2/test_2_4_authorization_consistency.py`](../../../src/tests/domain_2/test_2_4_authorization_consistency.py),
> [`src/discovery/derivation.py`](../../../src/discovery/derivation.py) · **Verified:** 2026-10-23

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("2.4", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `2.4` |
| Name | Authorization Consistency |
| Domain | 2 - Authorization and Access Control |
| Priority / strategy | P1 / BLACK_BOX |
| Effect | READ_ONLY |
| CWE | CWE-285 |
| Standards | `OWASP API8:2023`, `OWASP ASVS v5.0.0-8.1.1`, `NIST SP 800-53, Section 3` |
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

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 2.4) |
|---|---|
| `version_sibling_consistent` | "versioned endpoint parity: for each v1 endpoint requiring auth, test v2/v3 without a token, expect 401" |
| left out | alternate-format parity (`.json`/`.xml`) and alias endpoints (no lab exposes them); GraphQL-vs-REST parity (no GraphQL) |

## 3. Inputs

The version siblings derived in Phase 2 (`version_siblings`: the undocumented API versions next to the documented
ones). For each documented protected safe-method operation, the sibling path is built by swapping its version
segment. No configuration, no credential.

## 4. Preconditions and reference responses

The attack surface must be present. The reference is the documented operation itself: the same unauthenticated
request is sent to it and to the sibling, so the violation is proven by contrast (the documented one refuses, the
sibling serves) rather than by the heuristic alone.

## 5. Probes

For each version candidate, one representative sibling is probed first: an absent version (a `404`) is one
`NOT_APPLICABLE` instead of a probe per endpoint. Where the version exists, each protected operation is compared:
the documented path without a credential, then the sibling without a credential. Safe methods only. READ_ONLY.

## 6. Oracle (`version_sibling_consistent`)

| Case | Outcome / detail | Confidence |
|---|---|---|
| documented refused without a credential, sibling served (2xx) | `VIOLATION/VERSION_DROPS_AUTH` | CERTAIN (proven by contrast) |
| documented refused, sibling also refused | `ENFORCED/SIBLING_REFUSED` | - |
| documented refused, sibling absent (404) | `NOT_APPLICABLE/SIBLING_ABSENT` | - |
| the candidate version is entirely absent | `NOT_APPLICABLE/VERSION_ABSENT` (one per version) | - |
| documented not refused without a credential (public) | `NOT_APPLICABLE/DOCUMENTED_NOT_PROTECTED` (that is 1.1's question) | - |
| unavailable, rate limited, no response, server error, other | `NOT_VERIFIABLE/<reason>` | - |

## 7. Outcomes

SKIP when no protected operation has a version sibling, and when every candidate version the specification
suggests is absent from the target: in that second case the test adds the note "No second version to compare",
naming the candidate it probed, so the SKIP is not silent. Otherwise FAIL on a version that drops the check, PASS
when every existing sibling enforces the same policy.

## 8. Findings

"Version sibling drops the authorization check: `<method> <sibling>`", `evidence_ref` the sibling request; the
documented refusal is in the transaction log as the contrast.

## 9. Effects on the target

`READ_ONLY`: unauthenticated safe requests, nothing changed.

## 10. Per gateway

Independent of the adapter: a version drift is usually a duplicate or misaligned gateway route; the probe observes
it from outside.

## 11. Configuration

None. The siblings are derived; the configuration adds nothing here.

## 12. Validation

Runs of 2026-10-23:

| Lab | Status | Basis |
|---|---|---|
| crAPI + Kong | **PASS** | the `v1`/`v3` siblings of the protected `community/api/v2` operations are refused or absent (no auth drop) |
| Forgejo + Kong, Forgejo + APISIX | **SKIP** | Forgejo documents only `/api/v1`; the candidate `/api/v2` is entirely absent (`VERSION_ABSENT`), one probe. The note names it (verified 2026-10-27) |

Rule 9: enforced (crAPI siblings refuse) and version-absent (Forgejo) are proven. The **VIOLATION branch** (a version
that serves without the auth the documented one requires) is not present on the labs: crAPI's version drift
(challenge 3) is a rate-limiting weakness of an older flow, not an authorization drop. It is documented lab-unproven
rather than produced with a gateway change (owner: save tokens, 2026-10-23); the branch's logic is the inversion of
the proven `SIBLING_REFUSED` contrast.

## 13. Remediation

Apply one authorization policy to every version of an operation, or retire the undocumented versions; a gateway
route for an old version must carry the same auth plugin as the current one (ASVS v5.0.0-8.1.1).

## 14. Limitations

- Only version siblings are compared; alternate formats, aliases and GraphQL are out of scope (no lab exposes them).
- A sibling that needs a path parameter the seed does not supply may answer `404` and read as absent.
- The check is unauthenticated: a version that enforces authentication but drops a finer role check is not caught
  here (that is 2.1's question on the sibling, if it is documented).

## 15. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- OWASP ASVS v5.0.0-8.1.1 (Authorization documentation and enforcement): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x17-V8-Authorization.md
- NIST SP 800-53 Rev.5 AC-3 (access enforcement): https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home
- CWE-285 Improper Authorization: https://cwe.mitre.org/data/definitions/285.html
