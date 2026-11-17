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
| `no_debug_field` | "debug field detection in a normal response": no debug-named field (`_debug`, `_sql...`, `debugInfo`, `stackTrace`, `shardKey`, ...) at any depth of a served JSON body (until 2026-11-16 top-level keys of an object only, and by substring, so `search_query` counted) |
| `no_leaky_header` | "header information leakage": no `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, and no `Server` or `Via` naming a version (`Via: 1.1 kong/3.9.3`, judged since 2026-11-16: the gateway's own version is disclosed at the boundary like the backend's); other internal `X-*` headers and `X-Kong-*` are not judged |
| left out | authentication-error enumeration (test 1.7); the correlation-ID check (not reproducible from outside); the methodology's other error probes (a type mismatch, a missing required field, an oversized payload) and the consistency of error verbosity across error kinds |

## 3. Inputs

A sample of documented operations, one per service prefix (`src/tests/helpers/sampling.py`), for the normal-response
checks; up to five documented writes for the error provocation (malformed JSON), without path parameters first. user_a to reach authenticated
endpoints. The response-inspection helpers do the detection.

## 4. Preconditions and reference responses

user_a is required (GREY_BOX). No reference responses: the detection is on the response content itself.

## 5. Probes

For each sampled endpoint, a normal GET (debug fields in the body, leaky headers). Malformed-JSON requests to the
documented writes in turn, declared `Content-Type: application/json` so that the server's JSON parser runs, until one
is parsed into an error (a `400`, `422` or server error), at most five (until 2026-11-16 only the first: on the
Forgejo labs it is refused by the token's scope, `403`, so no error was ever provoked there). The request's own URL
and path are taken out of the error body before it is scanned (an echoed `/app/...` path is not the server's).
CHANGES_DATA, for the reason in section 9.

## 6. Oracle

<!-- [[[cog import generate_docs as g; cog.out(g.oracle_table("6.1")) ]]] -->

**`no_stack_trace`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| the answer to a malformed JSON body carries a stack trace, a file-system path or a framework version (the request's own path left out) | `VIOLATION/STACK_TRACE` | FIRM |
| the malformed body is rejected by the parser (`400`, `422`) or causes a server error, with no such marker | `ENFORCED/NO_STACK_TRACE` | - |
| none of up to 5 writes parsed the body (refused before parsing, `404`, `415`, accepted): no error was provoked | `NOT_VERIFIABLE/ERROR_NOT_PROVOKED` | - |
| the specification documents no write (`POST`, `PUT`, `PATCH`) | `NOT_APPLICABLE/NO_ERROR_PROBE` | - |

**`no_debug_field`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a served JSON body has a debug-named field at any depth (`_debug`, `_sql...`, `debugInfo`, `stackTrace`, `shardKey`, ...) | `VIOLATION/DEBUG_FIELD` | FIRM |
| the served JSON bodies looked at carry no debug-named field | `ENFORCED/CLEAN` | - |
| no sampled read was served a JSON object (or an array of objects): no field was looked at | `NOT_VERIFIABLE/NO_JSON_OBJECT` | - |
| the specification documents no `GET` or `HEAD` | `NOT_APPLICABLE/NO_READ_ENDPOINT` | - |

**`no_leaky_header`**

| Case | Outcome / detail | Confidence |
|---|---|---|
| a sampled answer carries a leaky header naming a version | `VIOLATION/LEAKY_HEADER` | CERTAIN |
| a sampled answer carries `X-Powered-By` or `X-AspNet*` without a version | `VIOLATION/LEAKY_HEADER` | FIRM |
| no sampled answer carries a leaky header | `ENFORCED/CLEAN` | - |
| the specification documents no `GET` or `HEAD` | `NOT_APPLICABLE/NO_READ_ENDPOINT` | - |

<!-- [[[end]]] -->

Until 2026-11-16: a sampled answer that was not a served JSON object (Forgejo's `/api/v1/orgs` is an array, a HEAD
has no body, a refusal is not the normal response) counted as `CLEAN` without a field looked at, so the Forgejo labs
passed `no_debug_field` with nothing examined; a leaky header was CERTAIN without a version; a `429` or an
unavailable backend on the error probe was `ERROR_NOT_PROVOKED`; `NO_ENDPOINT` (no attack surface) was a case the
code could not reach and is gone.

<!-- [[[cog import generate_docs as g; cog.out(g.uninformative_answers("6.1", page=cog.inFile)) ]]] -->

The answers that say nothing about the guarantee by themselves, one rule for every test ([assessment model](../../04-architecture/03-assessment-model.md#answers-that-say-nothing-about-the-guarantee)), generated from the code:

| Answer | Sub-tests | Outcome / detail |
|---|---|---|
| `UPSTREAM_UNAVAILABLE` | every sub-test | `NOT_VERIFIABLE/UPSTREAM_UNAVAILABLE` |
| `RATE_LIMITED` | every sub-test | `NOT_VERIFIABLE/RATE_LIMITED` |
| `SERVER_ERROR` | every sub-test | judged by the oracle above: a `500` is the error this test provokes, and its body is where a stack trace or a debug field shows: it is examined. |
| `NO_RESPONSE` | every sub-test | `NOT_VERIFIABLE/NO_RESPONSE` |

<!-- [[[end]]] -->

## 7. Outcomes

SKIP without user_a or a surface. FAIL on any leak; PASS when the provoked error and the sampled responses are
clean.

## 8. Findings

<!-- [[[cog import generate_docs as g; cog.out(g.finding_titles("6.1")) ]]] -->

- "Response carries a leaky header: <names>"
- "Response carries a debug field: <names>"
- "Error response leaks internal detail: <method> <path>"

<!-- [[[end]]] -->

Each has, as its proof, the response of the endpoint the finding names as its example (until 2026-11-03 it was the
last response sampled). Each cites its own requirement: the stack trace ASVS v5.0.0-16.5.1, the debug field 13.4.2
(debug modes disabled), the header 13.4.6 (until 2026-11-16 the stack trace cited 13.4.2).

## 9. Effects on the target

`CHANGES_DATA`: sampled reads plus up to five requests with a malformed body (`{"apiguard": "unterminated`) to the
shortest documented write operations. No JSON parser can build an object from it, so a `POST` creates nothing, and
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

**2026-11-16, after the review** (6.1 with 6.2 and 6.4 on the three labs as configured): **PASS** complete on each.
On the two Forgejo labs `no_stack_trace` is now proven: the first write (`POST /api/v1/orgs`) is refused by the
token's scope (`403`), the second (`POST /api/v1/markup`) parses the body and answers `422` with no marker (until that
day this sub-test was `ERROR_NOT_PROVOKED` there); and `no_debug_field` looked into the array `/api/v1/orgs` answers.
On crAPI the first write (`POST /identity/api/auth/login`) answers `400`.

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

**What each branch has been seen doing** (rule 9). Proven on a lab: `NO_STACK_TRACE` (crAPI), `CLEAN` (all three),
`ERROR_NOT_PROVOKED` (both Forgejo labs), and on 2026-11-15 (Forgejo + Kong, the specification saved with its
reads only, then with its writes only) `NO_ERROR_PROBE` and `NO_READ_ENDPOINT`. `NO_ENDPOINT` is not reachable:
without an attack surface the test skips before the sub-test (`_requires_attack_surface`).

**The violations, produced on 2026-11-15** (Forgejo + Kong, temporary routes on `forgejo-service` in
`kong/kong.yml`, undone with `git checkout`, the lab checked back). The test samples `GET /api/v1/orgs` and sends
its malformed body to `POST /api/v1/orgs`; each route answers itself through a `pre-function`:
- `STACK_TRACE` (FIRM): `POST` answered `500` with a body holding `Caused by: java.lang.NullPointerException`;
- `DEBUG_FIELD` (FIRM): `GET` answered `200` with the object `{"_debug": "info", "data": 1}`;
- `LEAKY_HEADER` (CERTAIN): `GET` answered with `X-AspNet-Version: 4.0.30319`. `X-Powered-By` was tried first and
  never reached the test: the lab's `response-transformer` removes it from every answer of the service.

Every branch of this test has been seen, except `NO_ENDPOINT`, which cannot occur.

## 13. Remediation

Return a generic message with a correlation ID to the client and keep the detail in the server logs (ASVS
v5.0.0-16.5.1); strip version and `X-Powered-By` headers at the gateway (v5.0.0-13.4.6); remove debug fields from
production responses.

## 14. Limitations

- What counts as a stack trace is a list of markers (`src/tests/data/inspector_patterns.py`) and a file-system path
  that starts a value (`"/app/main.py"`, `/usr/src/...`): a path inside a URL (`https://host/home/...`) and the
  generic `app/` and `at /` no longer count (until 2026-11-05 they did, false findings).
- An answer of an unavailable or throttled backend (`503`, `429`), or no answer, is not looked at for debug fields or
  headers; with no usable answer the two sub-tests are `NOT_VERIFIABLE` with the reason of the answers left out
  (`NO_USABLE_RESPONSE` until 2026-11-16; until 2026-11-05 a sample that all failed was CLEAN).
- Detection is by keyword/field-name/header-name heuristics: an oddly-shaped leak is missed, a benign match is a
  FIRM (not CERTAIN) finding.
- The error is provoked with malformed JSON only, on up to five writes; a leak that needs a specific input shape is
  not triggered.
- A debug-named field documented in the operation's response schema is still reported (FIRM): the names are a list,
  not a comparison with the specification.
- The sample is one endpoint per service: a leak on an un-sampled endpoint of the same service is missed.

## 15. Sources

- OWASP API8:2023 Security Misconfiguration: https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- OWASP ASVS v5.0.0-13.4.2 (debug modes disabled), v5.0.0-13.4.6 (no version disclosure): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x22-V13-Configuration.md
- OWASP ASVS v5.0.0-16.5.1 (generic error message): https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
- CWE-209 Generation of Error Message Containing Sensitive Information: https://cwe.mitre.org/data/definitions/209.html
