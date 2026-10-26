# 6.1 Error and Information Disclosure

> **Audience:** analysts, contributors · **Status:** new in the test review (2026-10-23) ·
> **Source of truth:**
> [`src/tests/domain_6/test_6_1_information_disclosure.py`](../../../src/tests/domain_6/test_6_1_information_disclosure.py),
> [`src/tests/helpers/response_inspector.py`](../../../src/tests/helpers/response_inspector.py) · **Verified:** 2026-10-23

<!-- [[[cog import generate_docs as g; cog.out(g.test_header("6.1", page=cog.inFile)) ]]] -->

|  |  |
|---|---|
| Test ID | `6.1` |
| Name | Error and Information Disclosure |
| Domain | 6 - Configuration and Hardening |
| Priority / strategy | P2 / GREY_BOX |
| Effect | READ_ONLY |
| CWE | CWE-209 |
| Standards | `OWASP API8:2023`, `OWASP ASVS v5.0.0-13.4.2`, `OWASP ASVS v5.0.0-13.4.6`, `OWASP ASVS v5.0.0-16.5.1` |
| Tags | `information-disclosure`, `error-handling` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT` |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `6.2`, `6.4` (what a response lets out). `6.3` (layer-7 smuggling) is deferred.

## 1. Guarantee

A response, in an error or a normal condition, discloses no internal information. A PASS promises a provoked error
carried no stack trace, a sampled response no debug field, and no response a leaky version header. The threat (OWASP
API8:2023, CWE-209): a stack trace or a version header fingerprints the backend and its CVEs; a residual `_debug`
field exposes the internal architecture. ASVS v5.0.0-16.5.1 (a generic message to the client), v5.0.0-13.4.6 (no
version disclosure).

## 2. Sub-tests and coverage of the methodology

| Sub-test | Methodology (guarantee 6.1) |
|---|---|
| `no_stack_trace` | "stack trace detection on provoked errors": a malformed request leaks no exception, path, class or framework version |
| `no_debug_field` | "debug field detection in a normal response": no `_debug`/`_sql`/`_internal` field |
| `no_leaky_header` | "header information leakage": no `X-Powered-By`, no versioned `Server`, no internal `X-*` |
| left out | authentication-error enumeration (test 1.7); the correlation-ID check (not reproducible from outside) |

## 3. Inputs

A sample of documented operations, one per service prefix (`src/tests/helpers/sampling.py`), for the normal-response
checks; a documented write endpoint for the error provocation (malformed JSON). user_a to reach authenticated
endpoints. The response-inspection helpers do the detection.

## 4. Preconditions and reference responses

user_a is required (GREY_BOX). No reference responses: the detection is on the response content itself.

## 5. Probes

For each sampled endpoint, a normal GET (debug fields in the body, leaky headers). One malformed-JSON request to a
write endpoint to provoke an error (stack trace in the body). READ_ONLY.

## 6. Oracle (per sub-test)

| Case | Outcome / detail | Confidence |
|---|---|---|
| a provoked error carries an internal-detail marker | `VIOLATION/STACK_TRACE` | FIRM (a keyword heuristic) |
| a sampled response carries a debug field | `VIOLATION/DEBUG_FIELD` | FIRM |
| a sampled response carries a leaky header | `VIOLATION/LEAKY_HEADER` | CERTAIN |
| none found | `ENFORCED` | - |
| no endpoint to probe | `NOT_APPLICABLE` | - |

## 7. Outcomes

SKIP without user_a or a surface. FAIL on any leak; PASS when the provoked error and the sampled responses are
clean.

## 8. Findings

"Error response leaks internal detail", "Response carries a debug field: ...", "Response carries a leaky header:
...", each with the sampled response as evidence.

## 9. Effects on the target

`READ_ONLY`: sampled reads plus one malformed request (rejected, nothing created).

## 10. Per gateway

Independent of the adapter: the leak is the backend's (a stack trace, a debug field) or the stack's (a version
header, which the gateway should strip).

## 11. Configuration

None.

## 12. Validation

Runs of 2026-10-23:

| Lab | Status | Basis |
|---|---|---|
| Forgejo + Kong, crAPI + Kong, Forgejo + APISIX | **PASS** | the sampled responses carry no debug field or leaky header; the provoked error carries no stack trace |

Rule 9: the ENFORCED side is proven on the three labs. The VIOLATION branches (a stack trace, a leaky header) are
lab-unproven: the labs leak none, and injecting a leaky header through the gateway proved fiddly (Kong strips the
injection). The detectors are the well-tested `response_inspector` helpers, and test 6.2 proves the header-reading
path end-to-end on crAPI; producing a live leak is offered as a follow-up.

## 13. Remediation

Return a generic message with a correlation ID to the client and keep the detail in the server logs (ASVS
v5.0.0-16.5.1); strip version and `X-Powered-By` headers at the gateway (v5.0.0-13.4.6); remove debug fields from
production responses.

## 14. Limitations

- Detection is by keyword/field-name/header-name heuristics: an oddly-shaped leak is missed, a benign match is a
  FIRM (not CERTAIN) finding.
- The error is provoked with one malformed-JSON request; a leak that needs a specific input shape is not triggered.
- The sample is one endpoint per service: a leak on an un-sampled endpoint of the same service is missed.

## 15. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- OWASP ASVS v5.0.0-13.4.2 (debug modes disabled), v5.0.0-13.4.6 (no version disclosure): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x22-V13-Configuration.md
- OWASP ASVS v5.0.0-16.5.1 (generic error message): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
- CWE-209 Generation of Error Message Containing Sensitive Information: https://cwe.mitre.org/data/definitions/209.html
