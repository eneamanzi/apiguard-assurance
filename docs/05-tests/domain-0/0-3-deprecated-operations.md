# 0.3 Deprecated Operations Still Served

> **Audience:** analysts, contributors · **Status:** rewritten in the test review (2026-10-22) ·
> **Source of truth:**
> [`src/tests/domain_0/test_0_3_deprecated_operations.py`](../../../src/tests/domain_0/test_0_3_deprecated_operations.py) ·
> **Verified:** 2026-10-22

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("0.3", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `0.3` |
| Name | Deprecated Operations Still Served |
| Domain | 0 - API Discovery and Inventory Management |
| Priority / strategy | P0 / BLACK_BOX |
| Effect | READ_ONLY |
| CWE | none |
| Standards | `OWASP API9:2023`, `RFC 9745`, `RFC 8594`, `RFC 9110, Section 15.5.11`, `NIST SP 800-228, Section 3.1.1` |
| Tags | `inventory`, `deprecation` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT` (optional) |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `0.2` and `0.4`.

## 1. Guarantee

An operation the specification marks `deprecated: true` is either switched off, answering `410 Gone`, or still
served while declaring its own deadline: a `Sunset` date in the future (RFC 8594), and ideally the `Deprecation`
date that RFC 9745 made a Standards Track header in March 2025. NIST SP 800-228 section 2.1 states the risk:
deprecated APIs "may have been replaced or superseded by newer systems but have not yet been entirely removed" and
"risk falling behind the latest security policies and protections".

A PASS promises that every deprecated operation the test could reach is handled that way. It promises nothing about
operations the specification does not mark deprecated (an undocumented older version is test `0.1`'s question) and
nothing about what an operation returns.

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 0.3) |
|---|---|
| `deprecated_operations` | all three methodology sub-tests, judged per operation: "deprecated endpoint accessibility", "Sunset header presence", "post-sunset enforcement" |
| left out | the differential sub-tests (two versions of one operation): test `2.4`'s question. An operation the server flags as deprecated while the specification does not: it is this guarantee's question, but finding it needs a probe of the whole documented surface, which this test does not make (see the limitations) |

## 3. Inputs

- the operations the specification marks deprecated (`AttackSurface`, `is_deprecated`);
- `path_seed`, to fill the parameters of a deprecated path;
- the `user_a` credential when one is configured (optional need), for an operation that refuses without it.

## 4. Preconditions and reference responses

- the **calibration** of the operation's own siblings, with the same method and credential condition: an answer that
  differs from a random sibling's is the operation's own, one that matches says only that nothing is there;
- no positive control: the only verdict that rests on a refusal is `NOT_VERIFIABLE`, which claims nothing.

## 5. Probes

1. every deprecated operation whose method is safe (`GET`, `HEAD`) and whose path can be filled: one request
   without a credential;
2. the same request with the `user_a` credential when the first was refused (401, 403);
3. a deprecated operation whose method writes is **not** sent: the test is `READ_ONLY`. Those operations are counted
   `WRITE_METHOD_NOT_PROBED` and named in a note.

## 6. Oracle

| Case | Outcome / detail | Confidence |
|---|---|---|
| `410 Gone` | `ENFORCED/SWITCHED_OFF` | - |
| served, with a `Sunset` date in the future | `ENFORCED/SUNSET_DECLARED` | - |
| served, with a `Sunset` date in the past | `VIOLATION/PAST_SUNSET_STILL_SERVED` | FIRM |
| served, with a `Deprecation` header and no `Sunset` | `VIOLATION/DEPRECATION_WITHOUT_SUNSET`: the deprecation is announced, the deadline is not | FIRM |
| served, with neither header | `VIOLATION/DEPRECATED_WITHOUT_SUNSET` | FIRM |
| served, with a `Sunset` that is not a date | `NOT_VERIFIABLE/SUNSET_NOT_A_DATE` (the old test counted this as compliant) | - |
| the answer is the same as a random sibling's | `NOT_APPLICABLE/NOT_SERVED`: not served to this caller, though `404` is not the `410` the standard asks for | - |
| refused without and with the credential | `NOT_VERIFIABLE/REFUSED_BEFORE_ANSWER` | - |
| the calibration cannot be trusted | `NOT_VERIFIABLE/CALIBRATION_UNRELIABLE` | - |
| a path parameter has no value in `path_seed` | `NOT_VERIFIABLE/PATH_NOT_FILLABLE`, named in a note | - |
| the method writes | `NOT_VERIFIABLE/WRITE_METHOD_NOT_PROBED`, named in a note | - |
| unavailable, rate limited, no response, server error | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE`, `RATE_LIMITED`, `NO_RESPONSE`, `SERVER_ERROR` | - |

A `Deprecation` date in the past is not a violation: RFC 9745 says the date "may be in the past (the resource was
deprecated at that date)". The deadline is `Sunset`'s business.

## 7. Outcomes

SKIP when the specification marks no operation `deprecated: true`: the absence of a declaration is not evidence that
no deprecated functionality is served, and that question belongs to test `0.1`.

## 8. Findings

One per operation: "Deprecated operation still served: `GET <path>`" (or "Operation served after its sunset"), with
the status, the headers found or missing and the date read; `evidence_ref` the request, `supporting_refs` the
calibration probes.

## 9. Effects on the target

`READ_ONLY`: one request per deprecated read-only operation, two when the first was refused. An operation whose
method writes is never sent.

## 10. Per gateway

Independent of the gateway: both headers come from the application, and a gateway adding them in a response
transformation is a correct way of satisfying the guarantee.

## 11. Configuration

None. Everything comes from the specification and `path_seed`.

## 12. Validation

Runs of 2026-10-22, the three tests of the group together:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, Forgejo + APISIX | FAIL, 1 finding | the specification marks four operations deprecated; `GET /api/v1/repos/{owner}/{repo}/times/{user}`, filled from the lab's `path_seed`, answers `200` unlike a random sibling and sends neither `Deprecation` nor `Sunset`. The other three write (`POST /org/{org}/repos`, `DELETE` and `PATCH .../comments/{id}`) and are named in a note |
| crAPI + Kong | SKIP | crAPI 1.1.6 marks no operation `deprecated: true` |
| any | ENFORCED | an operation answering `410`, or carrying a future `Sunset`: not on the labs |

All four deprecated operations of the reference lab have parameters in their path, and the old test excluded every
path holding `{`, which is why the violation the lab holds had never been seen.

**What each branch has been seen doing** (rule 9). Proven on a lab: `DEPRECATED_WITHOUT_SUNSET`,
`WRITE_METHOD_NOT_PROBED`, and the SKIP. Still unproven: `SWITCHED_OFF`, `SUNSET_DECLARED`,
`PAST_SUNSET_STILL_SERVED`, `DEPRECATION_WITHOUT_SUNSET`, `SUNSET_NOT_A_DATE`, `NOT_SERVED`,
`REFUSED_BEFORE_ANSWER`, `CALIBRATION_UNRELIABLE`, `PATH_NOT_FILLABLE` and the transport reasons.

## 13. Remediation

Switch the operation off and answer `410 Gone`, or declare `Deprecation` (RFC 9745) and `Sunset` (RFC 8594) with a
future date and a `Link` to the replacement.

## 14. Limitations

- Only operations the specification marks `deprecated: true` are examined. An operation deprecated in fact but not
  in the document is invisible here, and so is the mirror case (the server sends `Deprecation` while the
  specification does not mark it): finding that needs a probe of the whole documented surface.
- A deprecated operation whose method writes is not probed.
- A parametric path needs a value in `path_seed` for each of its parameters.
- No primary CWE: the catalogue holds no entry describing an API operation still served after being deprecated
  (the whole dictionary of CWE 4.20 was searched on 2026-10-22; CWE-1104 is limited to third-party components and
  CWE-1059 is prohibited for mapping). The guarantee rests on the standards above.

## 15. Sources

- OWASP API9:2023 Improper Inventory Management: https://api-security.owasp.org/editions/2023/en/0xa9-improper-inventory-management/
- RFC 9745, The Deprecation HTTP Response Header Field: https://www.rfc-editor.org/rfc/rfc9745.html
- RFC 8594, The Sunset HTTP Header Field: https://www.rfc-editor.org/rfc/rfc8594.html
- RFC 9110 section 15.5.11, 410 Gone: https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.11
- NIST SP 800-228 sections 2.1 and 3.1.1 (REC-API-4.4): https://doi.org/10.6028/NIST.SP.800-228
