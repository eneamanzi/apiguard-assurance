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
| Effect | CHANGES_DATA |
| CWE | CWE-209 |
| Standards | `OWASP API8:2023`, `OWASP ASVS v5.0.0-13.4.2`, `OWASP ASVS v5.0.0-13.4.6`, `OWASP ASVS v5.0.0-16.5.1` |
| Tags | `information-disclosure`, `error-handling` |
| Prerequisites | none |
| Needs | `USER_ACCOUNT` |
| Parameters | none |

<!-- [[[end]]] -->

**Same group:** tests `6.2`, `6.4` (what a response lets out). Guarantee `6.3` (layer-7 hardening) has no test of its own; its CORS and timeout parts are covered by `6.2` and `4.2`.

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
| `no_leaky_header` | "header information leakage": no `X-Powered-By`, no `X-AspNet-Version`, no `Server` carrying a version; other internal `X-*` headers and a gateway's own (`Via: 1.1 kong/3.9.1`, `X-Kong-*`) are not judged (the page promised them until 2026-11-05) |
| left out | authentication-error enumeration (test 1.7); the correlation-ID check (not reproducible from outside) |

## 3. Inputs

A sample of documented operations, one per service prefix (`src/tests/helpers/sampling.py`), for the normal-response
checks; a documented write endpoint for the error provocation (malformed JSON). user_a to reach authenticated
endpoints. The response-inspection helpers do the detection.

## 4. Preconditions and reference responses

user_a is required (GREY_BOX). No reference responses: the detection is on the response content itself.

## 5. Probes

For each sampled endpoint, a normal GET (debug fields in the body, leaky headers). One malformed-JSON request to a
write endpoint, declared `Content-Type: application/json` so that the server's JSON parser runs, to provoke an error
(stack trace in the body). CHANGES_DATA, for the reason in section 9.

## 6. Oracle (per sub-test)

| Case | Outcome / detail | Confidence |
|---|---|---|
| the answer to the malformed body carries an internal-detail marker | `VIOLATION/STACK_TRACE` | FIRM (a keyword heuristic) |
| the malformed body was not parsed into an error (`401`, `403`, `404`, `415`, `429`, unavailable, or accepted) | `NOT_VERIFIABLE/ERROR_NOT_PROVOKED`: a clean body proves nothing when no error happened | - |
| a sampled response carries a debug field | `VIOLATION/DEBUG_FIELD` | FIRM |
| a sampled response carries a leaky header | `VIOLATION/LEAKY_HEADER` | CERTAIN |
| none found | `ENFORCED/CLEAN` for the debug-field and leaky-header sub-tests; `ENFORCED/NO_STACK_TRACE` when the malformed body was rejected by the parser (`400`, `422`) or caused a server error (`5xx`) | - |
| no documented `GET` to sample (debug fields, headers), no attack surface, or no write endpoint to send the malformed body to (stack trace) | `NOT_APPLICABLE/NO_READ_ENDPOINT`, `NO_ENDPOINT`, `NO_ERROR_PROBE` | - |

## 7. Outcomes

SKIP without user_a or a surface. FAIL on any leak; PASS when the provoked error and the sampled responses are
clean.

## 8. Findings

"Error response leaks internal detail", "Response carries a debug field: ...", "Response carries a leaky header:
...", each with, as its proof, the response of the endpoint the finding names as its example (until 2026-11-03
it was the last response sampled, which need not be the one that leaked).

## 9. Effects on the target

`CHANGES_DATA`: sampled reads plus one request with a malformed body (`{"apiguard": "unterminated`) to the
shortest documented write operation. No JSON parser can build an object from it, so a `POST` creates nothing, and
on the three labs nothing was created or changed. The declaration is `CHANGES_DATA` all the same, because on a
target whose shortest documented write is a `PUT` on an existing object, a server that read an unparseable body as
an empty one would replace that object: what the test sends is a write, and the effects table an operator reads
before a production run says what is sent, not what a well-behaved server does with it.

## 10. Per gateway

Independent of the adapter: the leak is the backend's (a stack trace, a debug field) or the stack's (a version
header, which the gateway should strip).

## 11. Configuration

None.

## 12. Validation

Runs of 2026-11-03:

| Lab | Status | Basis |
|---|---|---|
| crAPI + Kong | **PASS**, `complete` | the sampled responses carry no debug field or leaky header; the malformed body to `POST /identity/api/auth/login` reaches the parser and is rejected with `400 "Failed to read request"`, a problem-details body with no trace (`ENFORCED/NO_STACK_TRACE`). Before the probe declared `Content-Type: application/json` the same request got `415` and was counted a pass anyway |
| Forgejo + Kong, Forgejo + APISIX | **PASS**, `partial` | no debug field or leaky header; the malformed body to `POST /api/v1/orgs` is refused with `403` (the token lacks the `write:organization` scope) before anything parses it, so no error was provoked: `NOT_VERIFIABLE/ERROR_NOT_PROVOKED`. Until 2026-11-03 that refusal counted as "no stack trace" and the test reported `complete` |

Rule 9: the ENFORCED sides are proven on the labs (no trace on crAPI, no debug field or leaky header on all three),
and so is `ERROR_NOT_PROVOKED` (Forgejo). The VIOLATION branches (a stack trace, a leaky header) are
lab-unproven: the labs leak none, and injecting a leaky header through the gateway proved fiddly (Kong strips the
injection). The detectors are the well-tested `response_inspector` helpers, and test 6.2 proves the header-reading
path end-to-end on crAPI. Producing a live leak would need an announced change to a lab and has not been done.

## 13. Remediation

Return a generic message with a correlation ID to the client and keep the detail in the server logs (ASVS
v5.0.0-16.5.1); strip version and `X-Powered-By` headers at the gateway (v5.0.0-13.4.6); remove debug fields from
production responses.

## 14. Limitations

- What counts as a stack trace is a list of markers (`src/tests/data/inspector_patterns.py`) and a file-system path
  that starts a value (`"/app/main.py"`, `/usr/src/...`): a path inside a URL (`https://host/home/...`) and the
  generic `app/` and `at /` no longer count (until 2026-11-05 they did, false findings).
- An answer of an unavailable or throttled backend (`503`, `429`) is not looked at for debug fields or headers; with
  no usable answer the two sub-tests are `NOT_VERIFIABLE/NO_USABLE_RESPONSE` (until 2026-11-05 a sample that all
  failed was CLEAN).
- Detection is by keyword/field-name/header-name heuristics: an oddly-shaped leak is missed, a benign match is a
  FIRM (not CERTAIN) finding.
- The error is provoked with one malformed-JSON request; a leak that needs a specific input shape is not triggered.
- The sample is one endpoint per service: a leak on an un-sampled endpoint of the same service is missed.

## 15. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- OWASP ASVS v5.0.0-13.4.2 (debug modes disabled), v5.0.0-13.4.6 (no version disclosure): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x22-V13-Configuration.md
- OWASP ASVS v5.0.0-16.5.1 (generic error message): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
- CWE-209 Generation of Error Message Containing Sensitive Information: https://cwe.mitre.org/data/definitions/209.html
